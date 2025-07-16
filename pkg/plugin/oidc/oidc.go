package oidc

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/MicahParks/keyfunc"
	"github.com/bhangun/iket/pkg/plugin"
	"github.com/golang-jwt/jwt/v4"
)

type OIDCPlugin struct {
	enabled bool
	Config  OIDCConfig
	JWKS    func(*jwt.Token) (interface{}, error)
}

func New(config map[string]interface{}) (plugin.Plugin, error) {
	cfg, err := loadConfig(config)
	if err != nil {
		return nil, err
	}

	jwsFunc, err := fetchJWKFunc(cfg.IssuerURL, cfg.CacheTTLSeconds)
	if err != nil {
		return nil, err
	}

	return &OIDCPlugin{
		Config: cfg,
		JWKS:   jwsFunc,
	}, nil
}

func (p *OIDCPlugin) Initialize(config map[string]interface{}) error {
	// Load configuration
	if enabled, ok := config["enabled"].(bool); ok {
		p.enabled = enabled
	}

	if !p.enabled {
		return nil
	}
	return nil
}

func init() {
	plugin.RegisterGlobal(&OIDCPlugin{})
}

func (p *OIDCPlugin) Execute(ctx context.Context, req *Request) (*Response, error) {
	authHeader := req.Header.Get("Authorization")
	if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
		return unauthorized("Missing bearer token"), nil
	}

	tokenStr := strings.TrimPrefix(authHeader, "Bearer ")

	token, err := jwt.Parse(tokenStr, p.JWKS)
	if err != nil || !token.Valid {
		return unauthorized("Invalid or expired token"), nil
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return unauthorized("Invalid token claims"), nil
	}

	if !p.Config.AllowIssuerAny {
		if claims["iss"] != p.Config.IssuerURL {
			return unauthorized("Invalid issuer"), nil
		}
	}

	// Check roles
	if len(p.Config.RequiredRoles) > 0 {
		roles := extractRealmRoles(claims)
		if !hasAnyRole(roles, p.Config.RequiredRoles) {
			return unauthorized("Forbidden: insufficient roles"), nil
		}
	}

	// Inject user info into context
	req.Context = context.WithValue(req.Context, "user_id", claims["sub"])
	req.Context = context.WithValue(req.Context, "username", claims["preferred_username"])
	req.Context = context.WithValue(req.Context, "roles", extractRealmRoles(claims))

	return nil, nil
}

func (p *OIDCPlugin) Name() string {
	return "oidc"
}

// --- Local gateway types (if not imported) ---
type Request struct {
	Header  http.Header
	Context context.Context
}

type Response struct {
	StatusCode int
	Header     http.Header
	Body       []byte
}

// --- Helper to marshal JSON body ---
func toJSONBody(v interface{}) []byte {
	b, _ := json.Marshal(v)
	return b
}

func fetchJWKFunc(issuerURL string, cacheTTLSeconds int) (func(*jwt.Token) (interface{}, error), error) {
	jwksURL := fmt.Sprintf("%s/protocol/openid-connect/certs", issuerURL)

	options := keyfunc.Options{
		RefreshInterval: time.Duration(cacheTTLSeconds) * time.Second,
		RefreshErrorHandler: func(err error) {
			fmt.Printf("OIDC JWKS refresh error: %v\n", err)
		},
		RefreshUnknownKID: true,
		RefreshRateLimit:  time.Minute,
	}

	jwks, err := keyfunc.Get(jwksURL, options)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS: %w", err)
	}

	return jwks.Keyfunc, nil
}

func unauthorized(reason string) *Response {
	return &Response{
		StatusCode: http.StatusUnauthorized,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       toJSONBody(map[string]string{"error": reason}),
	}
}

func extractRealmRoles(claims jwt.MapClaims) []string {
	realmAccess, ok := claims["realm_access"].(map[string]interface{})
	if !ok {
		return nil
	}
	rolesRaw, ok := realmAccess["roles"].([]interface{})
	roles := []string{}
	for _, r := range rolesRaw {
		if role, ok := r.(string); ok {
			roles = append(roles, role)
		}
	}
	return roles
}

func hasAnyRole(actual []string, expected []string) bool {
	for _, want := range expected {
		for _, have := range actual {
			if want == have {
				return true
			}
		}
	}
	return false
}
