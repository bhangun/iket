package oauth2client

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"io/ioutil"
	"math/big"

	"github.com/bhangun/iket/pkg/plugin"
)

type OIDCClientConfig struct {
	IssuerURL      string   `json:"issuer_url"`
	ClientID       string   `json:"client_id"`
	ClientSecret   string   `json:"client_secret"`
	RedirectURI    string   `json:"redirect_uri"`
	Scopes         []string `json:"scopes"`
	AuthPath       string   `json:"auth_path"`     // e.g. /auth/oidc/login
	CallbackPath   string   `json:"callback_path"` // e.g. /auth/oidc/callback
	LogoutPath     string   `json:"logout_path"`   // e.g. /auth/oidc/logout
	CookieName     string   `json:"cookie_name"`
	CookieDomain   string   `json:"cookie_domain"`
	CookieSecure   bool     `json:"cookie_secure"`
	CookieHTTPOnly bool     `json:"cookie_httponly"`
	SessionTTL     int      `json:"session_ttl"` // seconds
}

type OIDCClientPlugin struct {
	config OIDCClientConfig
}

func (p *OIDCClientPlugin) Name() string { return "oauth2client" }

func (p *OIDCClientPlugin) Initialize(config map[string]interface{}) error {
	// TODO: Parse config into OIDCClientConfig
	b, _ := json.Marshal(config)
	return json.Unmarshal(b, &p.config)
}

// SessionData holds tokens, expiry, and user info
type SessionData struct {
	AccessToken  string                 `json:"access_token"`
	IDToken      string                 `json:"id_token"`
	RefreshToken string                 `json:"refresh_token"`
	Expiry       time.Time              `json:"expiry"`
	UserInfo     map[string]interface{} `json:"userinfo,omitempty"`
}

// --- PKCE, State, Nonce helpers ---
func generateRandomString(n int) (string, error) {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, n)
	for i := range b {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(letters))))
		if err != nil {
			return "", err
		}
		b[i] = letters[num.Int64()]
	}
	return string(b), nil
}

func sha256Base64URL(s string) string {
	h := sha256.Sum256([]byte(s))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

// --- Middleware ---
func (p *OIDCClientPlugin) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess, err := p.getSession(r)
		if err != nil || sess == nil || sess.AccessToken == "" || time.Now().After(sess.Expiry) {
			if strings.HasPrefix(r.URL.Path, p.config.CallbackPath) {
				p.handleCallback(w, r)
				return
			}
			if strings.HasPrefix(r.URL.Path, p.config.AuthPath) {
				p.handleLogin(w, r)
				return
			}
			if strings.HasPrefix(r.URL.Path, p.config.LogoutPath) {
				p.handleLogout(w, r)
				return
			}
			p.redirectToOIDC(w, r)
			return
		}
		if time.Now().After(sess.Expiry) && sess.RefreshToken != "" {
			newSess, err := p.refreshTokens(sess.RefreshToken)
			if err == nil {
				p.setSession(w, newSess)
				sess = newSess
			}
		}
		if sess.AccessToken != "" {
			r.Header.Set("Authorization", "Bearer "+sess.AccessToken)
		}
		next.ServeHTTP(w, r)
	})
}

func (p *OIDCClientPlugin) isAuthenticated(r *http.Request) bool {
	// TODO: Check session/cookie for valid token
	cookie, err := r.Cookie(p.config.CookieName)
	return err == nil && cookie.Value != ""
}

func (p *OIDCClientPlugin) getAccessTokenFromSession(r *http.Request) string {
	// TODO: Decrypt and validate session cookie, extract access_token
	cookie, err := r.Cookie(p.config.CookieName)
	if err != nil {
		return ""
	}
	return cookie.Value // Placeholder: should decode JWT or session data
}

func (p *OIDCClientPlugin) redirectToOIDC(w http.ResponseWriter, r *http.Request) {
	// Build OIDC auth URL
	authURL := fmt.Sprintf("%s/protocol/openid-connect/auth?client_id=%s&response_type=code&scope=%s&redirect_uri=%s",
		p.config.IssuerURL,
		url.QueryEscape(p.config.ClientID),
		url.QueryEscape(strings.Join(p.config.Scopes, " ")),
		url.QueryEscape(p.config.RedirectURI),
	)
	http.Redirect(w, r, authURL, http.StatusFound)
}

func (p *OIDCClientPlugin) handleLogin(w http.ResponseWriter, r *http.Request) {
	// Generate PKCE, state, nonce
	codeVerifier, _ := generateRandomString(64)
	codeChallenge := sha256Base64URL(codeVerifier)
	state, _ := generateRandomString(32)
	nonce, _ := generateRandomString(32)
	// Store PKCE, state, nonce in a short-lived cookie
	meta := map[string]string{"code_verifier": codeVerifier, "state": state, "nonce": nonce}
	b, _ := json.Marshal(meta)
	metaCookie := &http.Cookie{
		Name:     p.config.CookieName + "_meta",
		Value:    base64.RawURLEncoding.EncodeToString(b),
		Path:     "/",
		Domain:   p.config.CookieDomain,
		Secure:   p.config.CookieSecure,
		HttpOnly: true,
		Expires:  time.Now().Add(10 * time.Minute),
	}
	http.SetCookie(w, metaCookie)
	// Build OIDC auth URL with PKCE, state, nonce
	authURL := fmt.Sprintf("%s/protocol/openid-connect/auth?client_id=%s&response_type=code&scope=%s&redirect_uri=%s&code_challenge=%s&code_challenge_method=S256&state=%s&nonce=%s",
		p.config.IssuerURL,
		url.QueryEscape(p.config.ClientID),
		url.QueryEscape(strings.Join(p.config.Scopes, " ")),
		url.QueryEscape(p.config.RedirectURI),
		url.QueryEscape(codeChallenge),
		url.QueryEscape(state),
		url.QueryEscape(nonce),
	)
	http.Redirect(w, r, authURL, http.StatusFound)
}

func (p *OIDCClientPlugin) handleCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")
	if code == "" || state == "" {
		http.Error(w, "Missing code or state", http.StatusBadRequest)
		return
	}
	// Retrieve PKCE, state, nonce from meta cookie
	metaCookie, err := r.Cookie(p.config.CookieName + "_meta")
	if err != nil {
		http.Error(w, "Missing PKCE/meta cookie", http.StatusBadRequest)
		return
	}
	metaBytes, _ := base64.RawURLEncoding.DecodeString(metaCookie.Value)
	var meta map[string]string
	json.Unmarshal(metaBytes, &meta)
	if meta["state"] != state {
		http.Error(w, "Invalid state", http.StatusBadRequest)
		return
	}
	codeVerifier := meta["code_verifier"]
	// Exchange code for tokens (with PKCE)
	tokens, err := p.exchangeCodeForTokensPKCE(code, codeVerifier)
	if err != nil {
		http.Error(w, "Token exchange failed: "+err.Error(), http.StatusUnauthorized)
		return
	}
	// Optionally, validate nonce in ID token (TODO: parse and check nonce)
	// Call userinfo endpoint
	userinfo, _ := p.fetchUserInfo(tokens.AccessToken)
	tokens.UserInfo = userinfo
	// Set session cookie
	p.setSession(w, tokens)
	// Clear meta cookie
	metaCookie = &http.Cookie{
		Name:     p.config.CookieName + "_meta",
		Value:    "",
		Path:     "/",
		Domain:   p.config.CookieDomain,
		Secure:   p.config.CookieSecure,
		HttpOnly: true,
		Expires:  time.Unix(0, 0),
	}
	http.SetCookie(w, metaCookie)
	// Redirect to home or original URL
	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(`<script>window.location = "/";</script>`))
}

func (p *OIDCClientPlugin) handleLogout(w http.ResponseWriter, r *http.Request) {
	p.clearSession(w)
	// Redirect to OIDC logout endpoint
	logoutURL := fmt.Sprintf("%s/protocol/openid-connect/logout?redirect_uri=%s",
		p.config.IssuerURL,
		url.QueryEscape(p.config.RedirectURI),
	)
	http.Redirect(w, r, logoutURL, http.StatusFound)
}

// --- Token Exchange/Refresh ---
func (p *OIDCClientPlugin) exchangeCodeForTokens(code string) (*SessionData, error) {
	tokenURL := fmt.Sprintf("%s/protocol/openid-connect/token", p.config.IssuerURL)
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("redirect_uri", p.config.RedirectURI)
	data.Set("client_id", p.config.ClientID)
	data.Set("client_secret", p.config.ClientSecret)
	resp, err := http.PostForm(tokenURL, data)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("token endpoint error: %s", string(body))
	}
	var tokens struct {
		AccessToken  string `json:"access_token"`
		IDToken      string `json:"id_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &tokens); err != nil {
		return nil, err
	}
	return &SessionData{
		AccessToken:  tokens.AccessToken,
		IDToken:      tokens.IDToken,
		RefreshToken: tokens.RefreshToken,
		Expiry:       time.Now().Add(time.Duration(tokens.ExpiresIn) * time.Second),
	}, nil
}

func (p *OIDCClientPlugin) refreshTokens(refreshToken string) (*SessionData, error) {
	tokenURL := fmt.Sprintf("%s/protocol/openid-connect/token", p.config.IssuerURL)
	data := url.Values{}
	data.Set("grant_type", "refresh_token")
	data.Set("refresh_token", refreshToken)
	data.Set("client_id", p.config.ClientID)
	data.Set("client_secret", p.config.ClientSecret)
	resp, err := http.PostForm(tokenURL, data)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("refresh endpoint error: %s", string(body))
	}
	var tokens struct {
		AccessToken  string `json:"access_token"`
		IDToken      string `json:"id_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &tokens); err != nil {
		return nil, err
	}
	return &SessionData{
		AccessToken:  tokens.AccessToken,
		IDToken:      tokens.IDToken,
		RefreshToken: tokens.RefreshToken,
		Expiry:       time.Now().Add(time.Duration(tokens.ExpiresIn) * time.Second),
	}, nil
}

// --- Token Exchange/Refresh with PKCE ---
func (p *OIDCClientPlugin) exchangeCodeForTokensPKCE(code, codeVerifier string) (*SessionData, error) {
	tokenURL := fmt.Sprintf("%s/protocol/openid-connect/token", p.config.IssuerURL)
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("redirect_uri", p.config.RedirectURI)
	data.Set("client_id", p.config.ClientID)
	data.Set("code_verifier", codeVerifier)
	resp, err := http.PostForm(tokenURL, data)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("token endpoint error: %s", string(body))
	}
	var tokens struct {
		AccessToken  string `json:"access_token"`
		IDToken      string `json:"id_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &tokens); err != nil {
		return nil, err
	}
	return &SessionData{
		AccessToken:  tokens.AccessToken,
		IDToken:      tokens.IDToken,
		RefreshToken: tokens.RefreshToken,
		Expiry:       time.Now().Add(time.Duration(tokens.ExpiresIn) * time.Second),
	}, nil
}

// --- UserInfo Endpoint ---
func (p *OIDCClientPlugin) fetchUserInfo(accessToken string) (map[string]interface{}, error) {
	userinfoURL := fmt.Sprintf("%s/protocol/openid-connect/userinfo", p.config.IssuerURL)
	req, _ := http.NewRequest("GET", userinfoURL, nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("userinfo endpoint error: %d", resp.StatusCode)
	}
	var userinfo map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&userinfo)
	return userinfo, nil
}

// --- Session Management (Encrypted, Signed) ---
func (p *OIDCClientPlugin) getSession(r *http.Request) (*SessionData, error) {
	cookie, err := r.Cookie(p.config.CookieName)
	if err != nil {
		return nil, err
	}
	return decodeSession(cookie.Value, p.config.ClientSecret)
}

func (p *OIDCClientPlugin) setSession(w http.ResponseWriter, sess *SessionData) {
	val, err := encodeSession(sess, p.config.ClientSecret)
	if err != nil {
		return
	}
	cookie := &http.Cookie{
		Name:     p.config.CookieName,
		Value:    val,
		Path:     "/",
		Domain:   p.config.CookieDomain,
		Secure:   p.config.CookieSecure,
		HttpOnly: p.config.CookieHTTPOnly,
		Expires:  sess.Expiry,
	}
	http.SetCookie(w, cookie)
}

func (p *OIDCClientPlugin) clearSession(w http.ResponseWriter) {
	cookie := &http.Cookie{
		Name:     p.config.CookieName,
		Value:    "",
		Path:     "/",
		Domain:   p.config.CookieDomain,
		Secure:   p.config.CookieSecure,
		HttpOnly: p.config.CookieHTTPOnly,
		Expires:  time.Unix(0, 0),
	}
	http.SetCookie(w, cookie)
}

// --- Session Encoding/Decoding (AES-GCM encrypted, HMAC-SHA256 signed, base64) ---
func encodeSession(sess *SessionData, secret string) (string, error) {
	b, err := json.Marshal(sess)
	if err != nil {
		return "", err
	}
	enc, err := encrypt(b, secret)
	if err != nil {
		return "", err
	}
	sig := sign(enc, secret)
	return base64.RawURLEncoding.EncodeToString(enc) + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

func decodeSession(val, secret string) (*SessionData, error) {
	parts := strings.Split(val, ".")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid session format")
	}
	enc, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, err
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	if !verify(enc, sig, secret) {
		return nil, fmt.Errorf("invalid session signature")
	}
	b, err := decrypt(enc, secret)
	if err != nil {
		return nil, err
	}
	var sess SessionData
	if err := json.Unmarshal(b, &sess); err != nil {
		return nil, err
	}
	return &sess, nil
}

// --- AES-GCM encryption helpers ---
func encrypt(plaintext []byte, secret string) ([]byte, error) {
	key := sha256.Sum256([]byte(secret))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

func decrypt(ciphertext []byte, secret string) ([]byte, error) {
	key := sha256.Sum256([]byte(secret))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < gcm.NonceSize() {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce := ciphertext[:gcm.NonceSize()]
	ciphertext = ciphertext[gcm.NonceSize():]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

func sign(data []byte, secret string) []byte {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write(data)
	return h.Sum(nil)
}

func verify(data, sig []byte, secret string) bool {
	expected := sign(data, secret)
	return hmac.Equal(expected, sig)
}

func init() {
	plugin.RegisterGlobal(&OIDCClientPlugin{})
}
