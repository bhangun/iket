// plugins/auth/keycloak.go
package main

import (
	"context"
	// "encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/Nerzal/gocloak/v8"
)

// KeycloakPlugin implements the GatewayPlugin interface for Keycloak authentication
type KeycloakPlugin struct {
	name         string
	client       gocloak.GoCloak
	realm        string
	clientID     string
	clientSecret string
	publicKey    string
	cacheEnabled bool
	tokenCache   map[string]tokenInfo
	publicURLs   []string
}

type tokenInfo struct {
	roles       []string
	permissions []string
	expiry      time.Time
}

// Plugin is the exported symbol for the plugin system to load
var Plugin KeycloakPlugin

// Name returns the plugin name
func (p KeycloakPlugin) Name() string {
	return p.name
}

// Initialize sets up the Keycloak client with the provided configuration
func (p *KeycloakPlugin) Initialize(config map[string]interface{}) error {
	p.name = "keycloak"

	// Get the Keycloak configuration
	serverURL, ok := config["serverURL"].(string)
	if !ok {
		return fmt.Errorf("serverURL is required")
	}

	realm, ok := config["realm"].(string)
	if !ok {
		return fmt.Errorf("realm is required")
	}

	clientID, ok := config["clientID"].(string)
	if !ok {
		return fmt.Errorf("clientID is required")
	}

	clientSecret, ok := config["clientSecret"].(string)
	if !ok {
		return fmt.Errorf("clientSecret is required")
	}

	// Optional parameters
	p.cacheEnabled, _ = config["cacheEnabled"].(bool)

	if publicURLs, ok := config["publicURLs"].([]interface{}); ok {
		for _, url := range publicURLs {
			if urlStr, ok := url.(string); ok {
				p.publicURLs = append(p.publicURLs, urlStr)
			}
		}
	}

	log.Print(p.publicURLs)
	// Remove "/auth" from the server URL if present
	serverURL = strings.TrimSuffix(serverURL, "/auth")
	log.Print(serverURL)
	gocloak.SetAuthRealms("/realms")

	// Initialize the client
	p.client = gocloak.NewClient(serverURL)

	log.Print(p.client)

	p.realm = realm
	p.clientID = clientID
	p.clientSecret = clientSecret

	if p.cacheEnabled {
		p.tokenCache = make(map[string]tokenInfo)
	}

	// Get the public key for token validation
	ctx := context.Background()
	_, err := p.client.LoginClient(ctx, clientID, clientSecret, realm)
	if err != nil {
		return fmt.Errorf("failed to login to Keycloak: %w", err)
	}

	certs, err := p.client.GetCerts(ctx, realm)
	if err != nil {
		return fmt.Errorf("failed to get realm certificates: %w", err)
	}

	// Use the public key for token validation
	if certs != nil && len(*certs.Keys) > 0 {
		for _, key := range *certs.Keys {
			if *key.Use == "sig" && *key.Alg == "RS256" {
				p.publicKey = *key.N
				break
			}
		}
	}

	if p.publicKey == "" {
		return fmt.Errorf("could not find a suitable public key")
	}

	log.Printf("Keycloak plugin initialized for realm %s", realm)
	return nil
}

// Middleware returns a middleware function that checks for valid authentication
func (p *KeycloakPlugin) Middleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Check if the URL is public
			for _, publicURL := range p.publicURLs {
				if strings.HasPrefix(r.URL.Path, publicURL) {
					next.ServeHTTP(w, r)
					return
				}
			}

			// Get the Authorization header
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				w.WriteHeader(http.StatusUnauthorized)
				w.Write([]byte("Authorization header is required"))
				return
			}

			// Extract the token
			parts := strings.Split(authHeader, " ")
			if len(parts) != 2 || parts[0] != "Bearer" {
				w.WriteHeader(http.StatusUnauthorized)
				w.Write([]byte("Invalid authorization format"))
				return
			}

			token := parts[1]

			// Check token validity
			if !p.validateToken(r.Context(), token) {
				w.WriteHeader(http.StatusUnauthorized)
				w.Write([]byte("Invalid or expired token"))
				return
			}

			// Token is valid, proceed to the next handler
			next.ServeHTTP(w, r)
		})
	}
}

// validateToken checks if the token is valid
func (p *KeycloakPlugin) validateToken(ctx context.Context, token string) bool {
	// Check cache first if enabled
	if p.cacheEnabled {
		if info, ok := p.tokenCache[token]; ok {
			if time.Now().Before(info.expiry) {
				return true
			}
			// Token expired, remove from cache
			delete(p.tokenCache, token)
		}
	}

	// Validate the token
	_, claims, err := p.client.DecodeAccessToken(ctx, token, p.realm, p.clientSecret)
	if err != nil {
		log.Printf("Token validation error: %v", err)
		return false
	}

	// Check if the token is not expired
	var expiry time.Time
	if exp, ok := (*claims)["exp"].(float64); ok {
		expiry = time.Unix(int64(exp), 0)
		if time.Now().After(expiry) {
			return false
		}
	} else {
		return false
	}

	// If cache is enabled, store the token info
	if p.cacheEnabled {
		roles := make([]string, 0)
		permissions := make([]string, 0)

		// Extract roles from token if available
		if realmAccess, ok := (*claims)["realm_access"].(map[string]interface{}); ok {
			if rolesList, ok := realmAccess["roles"].([]interface{}); ok {
				for _, r := range rolesList {
					if role, ok := r.(string); ok {
						roles = append(roles, role)
					}
				}
			}
		}

		// Extract permissions if available
		if resourceAccess, ok := (*claims)["resource_access"].(map[string]interface{}); ok {
			if clientAccess, ok := resourceAccess[p.clientID].(map[string]interface{}); ok {
				if permList, ok := clientAccess["roles"].([]interface{}); ok {
					for _, p := range permList {
						if perm, ok := p.(string); ok {
							permissions = append(permissions, perm)
						}
					}
				}
			}
		}

		p.tokenCache[token] = tokenInfo{
			roles:       roles,
			permissions: permissions,
			expiry:      expiry,
		}
	}

	return true
}

// Shutdown performs any cleanup required by the plugin
func (p *KeycloakPlugin) Shutdown() error {
	log.Println("Shutting down Keycloak plugin")
	// Clear token cache
	if p.cacheEnabled {
		p.tokenCache = nil
	}
	return nil
}
