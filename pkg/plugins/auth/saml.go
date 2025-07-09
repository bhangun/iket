package auth

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
)

type SAMLConfig struct {
	EntityID          string
	AssertionURL      *url.URL
	IDPMetadataURL    string
	SigningCertPath   string
	SigningKeyPath    string
	SessionMaxAge     int64
	RequiredGroups    []string
	GroupAttribute    string
}

type SAMLPlugin struct {
	config      *SAMLConfig
	idpMetadata []byte
	sp         *samlsp.Middleware
}

// NewSAMLPlugin creates a new instance of SAMLPlugin
func NewSAMLPlugin() *SAMLPlugin {
	return &SAMLPlugin{}
}

func (p *SAMLPlugin) Name() string {
	return "auth"
}

type CertificateStore struct {
	signingCert *x509.Certificate
	signingKey  *rsa.PrivateKey
}

type Session struct {
	ID        string
	UserID    string
	Groups    []string
	ExpiresAt time.Time
	Claims    map[string]interface{}
}

func parseConfig(config map[string]interface{}) (*SAMLConfig, error) {
	var cfg SAMLConfig

	// Parse required fields
	entityID, ok := config["entity_id"].(string)
	if !ok || entityID == "" {
		return nil, fmt.Errorf("entity_id is required")
	}
	cfg.EntityID = entityID

	assertionURLStr, ok := config["assertion_url"].(string)
	if !ok || assertionURLStr == "" {
		return nil, fmt.Errorf("assertion_url is required")
	}
	assertionURL, err := url.Parse(assertionURLStr)
	if err != nil {
		return nil, fmt.Errorf("invalid assertion_url: %w", err)
	}
	cfg.AssertionURL = assertionURL

	// Parse optional fields
	if idpURL, ok := config["idp_metadata_url"].(string); ok {
		cfg.IDPMetadataURL = idpURL
	}

	if certPath, ok := config["cert_file"].(string); ok {
		cfg.SigningCertPath = certPath
	}

	if keyPath, ok := config["key_file"].(string); ok {
		cfg.SigningKeyPath = keyPath
	}

	if maxAge, ok := config["session_max_age"].(float64); ok {
		cfg.SessionMaxAge = int64(maxAge)
	} else {
		cfg.SessionMaxAge = 3600 // Default 1 hour
	}

	if groups, ok := config["required_groups"].([]interface{}); ok {
		for _, g := range groups {
			if group, ok := g.(string); ok {
				cfg.RequiredGroups = append(cfg.RequiredGroups, group)
			}
		}
	}

	if attr, ok := config["group_attribute"].(string); ok {
		cfg.GroupAttribute = attr
	} else {
		cfg.GroupAttribute = "groups" // Default attribute name
	}

	return &cfg, nil
}

func (p *SAMLPlugin) Initialize(config map[string]interface{}) error {
	// Parse configuration
	var err error
	p.config, err = parseConfig(config)
	if err != nil {
		return fmt.Errorf("failed to parse SAML config: %w", err)
	}

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Load IDP metadata
	if err := p.loadIDPMetadata(ctx); err != nil {
		return fmt.Errorf("failed to load IDP metadata: %w", err)
	}

	// Initialize SAML service provider
	if err := p.initializeSP(ctx); err != nil {
		return fmt.Errorf("failed to initialize SAML SP: %w", err)
	}

	return nil
}

func (p *SAMLPlugin) loadIDPMetadata(ctx context.Context) error {
	// Load IDP metadata from URL if provided
	if p.config.IDPMetadataURL != "" {
		req, err := http.NewRequestWithContext(ctx, "GET", p.config.IDPMetadataURL, nil)
		if err != nil {
			return fmt.Errorf("failed to create request: %w", err)
		}

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return fmt.Errorf("failed to fetch IDP metadata: %w", err)
		}
		defer resp.Body.Close()

		metadata, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("failed to read IDP metadata: %w", err)
		}

		p.idpMetadata = metadata
	} else {
		// Use default metadata for development
		defaultMetadata := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
		<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="%s">
			<md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
				<md:KeyDescriptor use="signing">
					<ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
						<ds:X509Data>
							<ds:X509Certificate>%s</ds:X509Certificate>
						</ds:X509Data>
					</ds:KeyInfo>
				</md:KeyDescriptor>
				<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="%s"/>
			</md:IDPSSODescriptor>
		</md:EntityDescriptor>`, p.config.EntityID, "MIIC...", p.config.AssertionURL.String())
		p.idpMetadata = []byte(defaultMetadata)
	}

	return nil
}

func (p *SAMLPlugin) initializeSP(ctx context.Context) error {
	// Load signing certificate and key
	cert, err := tls.LoadX509KeyPair(p.config.SigningCertPath, p.config.SigningKeyPath)
	if err != nil {
		return fmt.Errorf("failed to load signing certificate: %w", err)
	}

	// Parse certificate
	if cert.Leaf == nil {
		if cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0]); err != nil {
			return fmt.Errorf("failed to parse signing certificate: %w", err)
		}
	}

	// Parse IDP metadata
	idp := &saml.EntityDescriptor{}
	decoder := xml.NewDecoder(bytes.NewReader(p.idpMetadata))
	if err := decoder.Decode(idp); err != nil {
		return fmt.Errorf("failed to parse IDP metadata: %w", err)
	}

	// Create SAML service provider
	sp, err := samlsp.New(samlsp.Options{
		URL:              *p.config.AssertionURL,
		Key:              cert.PrivateKey.(*rsa.PrivateKey),
		Certificate:      cert.Leaf,
		IDPMetadata:      idp,
		EntityID:         p.config.EntityID,
		AllowIDPInitiated: true,
	})
	if err != nil {
		return fmt.Errorf("failed to create SAML SP: %w", err)
	}

	p.sp = sp
	return nil
}

func (p *SAMLPlugin) loadCertificates(config *SAMLConfig) (*CertificateStore, error) {
	// Implementation for loading certificates
	// This should load from config.SigningCertPath and config.SigningKeyPath
	return &CertificateStore{}, nil
}

func (p *SAMLPlugin) parseURL(rawurl string) *url.URL {
	u, _ := url.Parse(rawurl)
	return u
}

func (p *SAMLPlugin) Routes() http.Handler {
	return p.sp
}

func (p *SAMLPlugin) Middleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip SAML auth for non-protected paths
			if !p.isProtectedPath(r.URL.Path) {
				next.ServeHTTP(w, r)
				return
			}

			// Get session from request
			session, err := p.sp.Session.GetSession(r)
			if err != nil {
				// Redirect to IDP login
				p.sp.ServeHTTP(w, r)
				return
			}

			// Validate session with context
			ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
			defer cancel()

			if !p.validateSession(ctx, session) {
				// Session is invalid, redirect to IDP login
				p.sp.ServeHTTP(w, r)
				return
			}

			// Add user info to request context
			ctx = context.WithValue(ctx, "user", session.(*saml.Session).NameID)
			r = r.WithContext(ctx)

			// Call next handler
			next.ServeHTTP(w, r)
		})
	}
}

func (p *SAMLPlugin) isProtectedPath(path string) bool {
	// SAML endpoints are not protected
	samlPaths := []string{
		"/saml/metadata",
		"/saml/acs",
		"/saml/sso",
	}
	for _, samlPath := range samlPaths {
		if path == samlPath {
			return false
		}
	}

	// All other paths are protected
	return true
}

func (p *SAMLPlugin) validateSession(ctx context.Context, session interface{}) bool {
	customSession, ok := session.(*Session)
	if !ok {
		return false
	}

	// Check if session is expired
	if time.Now().After(customSession.ExpiresAt) {
		return false
	}

	// Check if user has required groups
	return p.hasRequiredGroups(customSession.Groups)
}

func (p *SAMLPlugin) hasRequiredGroups(userGroups []string) bool {
	if len(p.config.RequiredGroups) == 0 {
		return true
	}

	for _, required := range p.config.RequiredGroups {
		for _, group := range userGroups {
			if required == group {
				return true
			}
		}
	}

	return false
}

func (p *SAMLPlugin) getUserGroups(ctx context.Context, assertion *saml.Assertion) []string {
	groups := make([]string, 0)

	// Extract groups from assertion attributes
	for _, stmt := range assertion.AttributeStatements {
		for _, attr := range stmt.Attributes {
			if attr.Name == p.config.GroupAttribute {
				for _, value := range attr.Values {
					groups = append(groups, value.Value)
				}
			}
		}
	}

	return groups
}

func (p *SAMLPlugin) createSession(assertion *saml.Assertion) *Session {
	session := &Session{
		ID:        base64.StdEncoding.EncodeToString([]byte(assertion.ID)),
		UserID:    assertion.Subject.NameID.Value,
		ExpiresAt: time.Now().Add(time.Duration(p.config.SessionMaxAge) * time.Second),
		Claims:    make(map[string]interface{}),
	}

	// Extract attributes
	for _, stmt := range assertion.AttributeStatements {
		for _, attr := range stmt.Attributes {
			if len(attr.Values) > 0 {
				session.Claims[attr.Name] = attr.Values[0].Value
			}
		}
	}

	// Set groups
	session.Groups = p.getUserGroups(context.Background(), assertion)

	return session
}

func (p *SAMLPlugin) addSessionToContext(ctx context.Context, session *Session) context.Context {
	return context.WithValue(ctx, "session", session)
}
