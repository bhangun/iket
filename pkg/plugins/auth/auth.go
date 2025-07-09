package auth

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/bhangun/iket/pkg/plugin"
)

// AuthPlugin implements middleware for authentication
type AuthPlugin struct {
	apiKey string
	// Tag for reflection-based discovery
	PluginName string `plugin:"type" plugin:"auth"`
	// Health tracking
	lastHealthCheck time.Time
	isHealthy       bool
}

func NewAuthPlugin() *AuthPlugin {
	return &AuthPlugin{
		PluginName:      "auth",
		lastHealthCheck: time.Now(),
		isHealthy:       true,
	}
}

func (a *AuthPlugin) Name() string {
	return a.PluginName
}

// Type implements TypedPlugin interface
func (a *AuthPlugin) Type() plugin.PluginType {
	return plugin.AuthPlugin
}

// Tags implements TaggedPlugin interface
func (a *AuthPlugin) Tags() map[string]string {
	return map[string]string{
		"security": "authentication",
		"priority": "high",
		"category": "auth",
	}
}

func (a *AuthPlugin) Initialize(config map[string]interface{}) error {
	if apiKey, ok := config["api_key"].(string); ok {
		a.apiKey = apiKey
		a.isHealthy = true
	} else {
		a.isHealthy = false
		return fmt.Errorf("api_key is required for auth plugin")
	}
	return nil
}

// Health implements HealthChecker interface
func (a *AuthPlugin) Health() error {
	a.lastHealthCheck = time.Now()

	if a.apiKey == "" {
		a.isHealthy = false
		return fmt.Errorf("auth plugin not properly configured: missing api_key")
	}

	if time.Since(a.lastHealthCheck) > 5*time.Minute {
		// Simulate health degradation over time
		a.isHealthy = false
		return fmt.Errorf("auth plugin health check overdue")
	}

	a.isHealthy = true
	return nil
}

// Status implements StatusReporter interface
func (a *AuthPlugin) Status() string {
	if a.isHealthy {
		return "healthy"
	}
	return "unhealthy"
}

// Middleware creates an HTTP middleware that validates API keys
func (a *AuthPlugin) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip authentication for certain paths
		if a.shouldSkipAuth(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}

		// Extract API key from header
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Authorization header required", http.StatusUnauthorized)
			return
		}

		// Check if it's a Bearer token
		if !strings.HasPrefix(authHeader, "Bearer ") {
			http.Error(w, "Invalid authorization format", http.StatusUnauthorized)
			return
		}

		// Extract the token
		token := strings.TrimPrefix(authHeader, "Bearer ")

		// Validate the token
		if token != a.apiKey {
			http.Error(w, "Invalid API key", http.StatusUnauthorized)
			return
		}

		// Add user info to context
		ctx := context.WithValue(r.Context(), "authenticated", true)
		ctx = context.WithValue(ctx, "api_key", token)

		// Continue with the request
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// shouldSkipAuth determines if authentication should be skipped for the given path
func (a *AuthPlugin) shouldSkipAuth(path string) bool {
	// Skip auth for health checks and public endpoints
	skipPaths := []string{
		"/health",
		"/metrics",
		"/openapi",
		"/swagger-ui",
	}

	for _, skipPath := range skipPaths {
		if strings.HasPrefix(path, skipPath) {
			return true
		}
	}

	return false
}

// init registers the plugin
func init() {
	// This would be called when the package is imported
	// In a real implementation, you might want to register this differently
	// depending on your application's needs
}
