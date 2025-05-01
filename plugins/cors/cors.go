package main

import (
	"fmt"
	"net/http"
	"strings"
)

// CORSPlugin implements the GatewayPlugin interface for CORS handling
type CORSPlugin struct {
	name   string
	config map[string]interface{}
}

// Name returns the name of the plugin
func (p *CORSPlugin) Name() string {
	return p.name
}

// Initialize initializes the plugin with the provided configuration
func (p *CORSPlugin) Initialize(config map[string]interface{}) error {
	p.name = "cors"
	p.config = config
	return nil
}

// Middleware returns a middleware function for CORS handling
func (p *CORSPlugin) Middleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Get configuration values
			allowedOrigins, _ := p.config["allowedOrigins"].([]interface{})
			allowedMethods, _ := p.config["allowedMethods"].([]interface{})
			allowedHeaders, _ := p.config["allowedHeaders"].([]interface{})
			allowCredentials, _ := p.config["allowCredentials"].(bool)
			maxAge, _ := p.config["maxAge"].(int)

			// Convert interface slices to string slices
			origins := make([]string, len(allowedOrigins))
			for i, v := range allowedOrigins {
				origins[i] = fmt.Sprintf("%v", v)
			}

			methods := make([]string, len(allowedMethods))
			for i, v := range allowedMethods {
				methods[i] = fmt.Sprintf("%v", v)
			}

			headers := make([]string, len(allowedHeaders))
			for i, v := range allowedHeaders {
				headers[i] = fmt.Sprintf("%v", v)
			}

			// Get the origin from the request
			origin := r.Header.Get("Origin")

			// Check if the origin is allowed
			allowed := false
			for _, allowedOrigin := range origins {
				if allowedOrigin == "*" || allowedOrigin == origin {
					allowed = true
					break
				}
			}

			// If the origin is allowed, set the CORS headers
			if allowed {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Access-Control-Allow-Methods", strings.Join(methods, ", "))
				w.Header().Set("Access-Control-Allow-Headers", strings.Join(headers, ", "))
				w.Header().Set("Access-Control-Max-Age", fmt.Sprintf("%d", maxAge))

				if allowCredentials {
					w.Header().Set("Access-Control-Allow-Credentials", "true")
				}
			}

			// Handle preflight requests
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusOK)
				return
			}

			// Call the next handler
			next.ServeHTTP(w, r)
		})
	}
}

// Shutdown performs any cleanup operations
func (p *CORSPlugin) Shutdown() error {
	return nil
}

// Plugin is the exported symbol that the gateway will look for
var Plugin CORSPlugin
