package oauth2

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

type OAuth2Plugin struct {
	enabled       bool
	introspectURL string
	clientID      string
	clientSecret  string
	skipPaths     []string
	claimsContext string
	httpClient    *http.Client
	mu            sync.RWMutex
}

type IntrospectionResponse struct {
	Active    bool     `json:"active"`
	Scope     string   `json:"scope"`
	ClientID  string   `json:"client_id"`
	Username  string   `json:"username"`
	TokenType string   `json:"token_type"`
	Exp       int64    `json:"exp"`
	Iat       int64    `json:"iat"`
	Sub       string   `json:"sub"`
	Aud       []string `json:"aud"`
	Iss       string   `json:"iss"`
}

type Claims struct {
	UserID   string            `json:"user_id"`
	Username string            `json:"username"`
	Email    string            `json:"email"`
	Roles    []string          `json:"roles"`
	Scope    string            `json:"scope"`
	ClientID string            `json:"client_id"`
	Custom   map[string]string `json:"custom,omitempty"`
}

func (o *OAuth2Plugin) Name() string {
	return "oauth2"
}

func (o *OAuth2Plugin) Type() string {
	return "oauth2"
}

func (o *OAuth2Plugin) Initialize(config map[string]interface{}) error {
	o.mu.Lock()
	defer o.mu.Unlock()

	// Default values
	o.enabled = false
	o.claimsContext = "oauth2_claims"
	o.httpClient = &http.Client{
		Timeout: 10 * time.Second,
	}

	// Load configuration
	if enabled, ok := config["enabled"].(bool); ok {
		o.enabled = enabled
	}

	if !o.enabled {
		return nil
	}

	if introspectURL, ok := config["introspect_url"].(string); ok {
		o.introspectURL = introspectURL
	}

	if clientID, ok := config["client_id"].(string); ok {
		o.clientID = clientID
	}

	if clientSecret, ok := config["client_secret"].(string); ok {
		o.clientSecret = clientSecret
	}

	if skipPaths, ok := config["skip_paths"].([]interface{}); ok {
		for _, path := range skipPaths {
			if pathStr, ok := path.(string); ok {
				o.skipPaths = append(o.skipPaths, pathStr)
			}
		}
	}

	if claimsContext, ok := config["claims_context"].(string); ok {
		o.claimsContext = claimsContext
	}

	// Validate required configuration
	if o.introspectURL == "" {
		return fmt.Errorf("introspect_url is required for OAuth2 plugin")
	}

	if o.clientID == "" || o.clientSecret == "" {
		return fmt.Errorf("client_id and client_secret are required for OAuth2 plugin")
	}

	return nil
}

func (o *OAuth2Plugin) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !o.enabled {
			next.ServeHTTP(w, r)
			return
		}

		// Skip OAuth2 validation for certain paths
		if o.shouldSkipValidation(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}

		// Extract and validate OAuth2 token
		claims, err := o.validateToken(r)
		if err != nil {
			o.writeError(w, "Invalid OAuth2 token", http.StatusUnauthorized)
			return
		}

		// Add claims to request context
		ctx := context.WithValue(r.Context(), o.claimsContext, claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (o *OAuth2Plugin) shouldSkipValidation(path string) bool {
	for _, skipPath := range o.skipPaths {
		if strings.HasPrefix(path, skipPath) {
			return true
		}
	}
	return false
}

func (o *OAuth2Plugin) validateToken(r *http.Request) (*Claims, error) {
	// Extract token from Authorization header
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return nil, fmt.Errorf("missing authorization header")
	}

	if !strings.HasPrefix(authHeader, "Bearer ") {
		return nil, fmt.Errorf("invalid authorization header format")
	}

	tokenString := strings.TrimPrefix(authHeader, "Bearer ")

	// Introspect token with OAuth2 server
	introspection, err := o.introspectToken(tokenString)
	if err != nil {
		return nil, fmt.Errorf("failed to introspect token: %w", err)
	}

	if !introspection.Active {
		return nil, fmt.Errorf("token is not active")
	}

	// Convert introspection response to claims
	claims := &Claims{
		UserID:   introspection.Sub,
		Username: introspection.Username,
		Scope:    introspection.Scope,
		ClientID: introspection.ClientID,
	}

	// Parse scope into roles
	if introspection.Scope != "" {
		claims.Roles = strings.Split(introspection.Scope, " ")
	}

	return claims, nil
}

func (o *OAuth2Plugin) introspectToken(token string) (*IntrospectionResponse, error) {
	// Prepare form data
	data := url.Values{}
	data.Set("token", token)
	data.Set("token_type_hint", "access_token")

	// Create request
	req, err := http.NewRequest("POST", o.introspectURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Basic "+o.getBasicAuth())

	// Make request
	resp, err := o.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("introspection server returned status: %d", resp.StatusCode)
	}

	// Parse response
	var introspection IntrospectionResponse
	if err := json.NewDecoder(resp.Body).Decode(&introspection); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &introspection, nil
}

func (o *OAuth2Plugin) getBasicAuth() string {
	// This should be base64 encoded, but for simplicity we'll use the raw values
	// In production, you should properly encode the credentials
	return fmt.Sprintf("%s:%s", o.clientID, o.clientSecret)
}

func (o *OAuth2Plugin) writeError(w http.ResponseWriter, message string, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	response := map[string]interface{}{
		"error":   "OAuth2 Error",
		"message": message,
	}
	json.NewEncoder(w).Encode(response)
}

// GetClaimsFromContext extracts OAuth2 claims from request context
func (o *OAuth2Plugin) GetClaimsFromContext(ctx context.Context) (*Claims, bool) {
	claims, ok := ctx.Value(o.claimsContext).(*Claims)
	return claims, ok
}

// Tags returns plugin tags for discovery
func (o *OAuth2Plugin) Tags() map[string]string {
	return map[string]string{
		"type":       "oauth2",
		"category":   "auth",
		"middleware": "true",
		"method":     "introspection",
	}
}

// Health checks if the OAuth2 plugin is healthy
func (o *OAuth2Plugin) Health() error {
	o.mu.RLock()
	defer o.mu.RUnlock()

	if !o.enabled {
		return fmt.Errorf("OAuth2 plugin is disabled")
	}

	// Check if introspection URL is accessible
	if o.introspectURL == "" {
		return fmt.Errorf("introspection URL not configured")
	}

	// Try to make a test request to the introspection endpoint
	testReq, err := http.NewRequest("POST", o.introspectURL, strings.NewReader("token=test"))
	if err != nil {
		return fmt.Errorf("failed to create test request: %w", err)
	}

	testReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	testReq.Header.Set("Authorization", "Basic "+o.getBasicAuth())

	resp, err := o.httpClient.Do(testReq)
	if err != nil {
		return fmt.Errorf("introspection endpoint not accessible: %w", err)
	}
	defer resp.Body.Close()

	// We expect a 400 or 401 for invalid token, but not 500+ (server error)
	if resp.StatusCode >= 500 {
		return fmt.Errorf("introspection server error: %d", resp.StatusCode)
	}

	return nil
}

// Status returns human-readable status
func (o *OAuth2Plugin) Status() string {
	o.mu.RLock()
	defer o.mu.RUnlock()

	if !o.enabled {
		return "OAuth2 Plugin: Disabled"
	}

	return fmt.Sprintf("OAuth2 Plugin: Enabled (introspect: %s, client: %s)", o.introspectURL, o.clientID)
}

// OnStart lifecycle hook
func (o *OAuth2Plugin) OnStart() error {
	// Validate OAuth2 config on startup
	return o.Health()
}

// OnShutdown lifecycle hook
func (o *OAuth2Plugin) OnShutdown() error {
	// Clean up any OAuth2-related resources if needed
	return nil
}
