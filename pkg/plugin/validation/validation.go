package validation

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

type ValidationPlugin struct {
	enabled    bool
	strictMode bool
	skipPaths  []string
}

func (v *ValidationPlugin) Name() string {
	return "validation"
}

func (v *ValidationPlugin) Type() string {
	return "validation"
}

func (v *ValidationPlugin) Initialize(config map[string]interface{}) error {
	enabled := true
	if val, ok := config["enabled"].(bool); ok {
		enabled = val
	}
	v.enabled = enabled

	if !enabled {
		return nil
	}

	// Configuration
	v.strictMode = false
	if strict, ok := config["strict_mode"].(bool); ok {
		v.strictMode = strict
	}

	// Skip paths
	if skipPaths, ok := config["skip_paths"].([]interface{}); ok {
		for _, path := range skipPaths {
			if pathStr, ok := path.(string); ok {
				v.skipPaths = append(v.skipPaths, pathStr)
			}
		}
	}

	return nil
}

func (v *ValidationPlugin) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !v.enabled {
			next.ServeHTTP(w, r)
			return
		}

		// Skip validation for certain paths
		if v.shouldSkipValidation(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}

		// Validate request
		if err := v.validateRequest(r); err != nil {
			v.writeValidationError(w, fmt.Sprintf("Request validation failed: %v", err), http.StatusBadRequest)
			return
		}

		// Continue with request
		next.ServeHTTP(w, r)
	})
}

func (v *ValidationPlugin) shouldSkipValidation(path string) bool {
	for _, skipPath := range v.skipPaths {
		if strings.HasPrefix(path, skipPath) {
			return true
		}
	}
	return false
}

func (v *ValidationPlugin) validateRequest(r *http.Request) error {
	// Only validate JSON requests
	contentType := r.Header.Get("Content-Type")
	if !strings.Contains(contentType, "application/json") {
		return nil
	}

	// Validate request body
	if err := v.validateRequestBody(r); err != nil {
		return fmt.Errorf("request body validation failed: %w", err)
	}

	return nil
}

func (v *ValidationPlugin) validateRequestBody(r *http.Request) error {
	if r.Body == nil {
		return nil
	}

	// Read body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return fmt.Errorf("failed to read request body: %w", err)
	}

	// Restore body for downstream handlers
	r.Body = io.NopCloser(strings.NewReader(string(body)))

	if len(body) == 0 {
		return nil
	}

	// Basic JSON validation
	var jsonData interface{}
	if err := json.Unmarshal(body, &jsonData); err != nil {
		return fmt.Errorf("invalid JSON in request body: %w", err)
	}

	// Additional validation can be added here
	// - Schema validation
	// - Required field validation
	// - Type validation
	// - Format validation

	return nil
}

func (v *ValidationPlugin) writeValidationError(w http.ResponseWriter, message string, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	response := map[string]interface{}{
		"error":   "Validation Error",
		"message": message,
	}
	json.NewEncoder(w).Encode(response)
}

// Tags returns plugin tags for discovery
func (v *ValidationPlugin) Tags() map[string]string {
	return map[string]string{
		"type":       "validation",
		"category":   "security",
		"middleware": "true",
		"strict":     fmt.Sprintf("%t", v.strictMode),
	}
}

// Health checks if the validation plugin is healthy
func (v *ValidationPlugin) Health() error {
	// Validation plugin is always healthy if enabled
	if !v.enabled {
		return fmt.Errorf("validation plugin is disabled")
	}
	return nil
}

// Status returns human-readable status
func (v *ValidationPlugin) Status() string {
	if !v.enabled {
		return "Validation Plugin: Disabled"
	}
	return fmt.Sprintf("Validation Plugin: Enabled (strict: %t, skip paths: %d)", v.strictMode, len(v.skipPaths))
}
