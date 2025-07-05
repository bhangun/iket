package config

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	"iket/internal/core/errors"
)

// ValidationRule defines a configuration validation rule
type ValidationRule interface {
	Validate(cfg *Config) error
}

// ConfigValidator validates configuration using a set of rules
type ConfigValidator struct {
	rules []ValidationRule
}

// NewConfigValidator creates a new validator with default rules
func NewConfigValidator() *ConfigValidator {
	return &ConfigValidator{
		rules: []ValidationRule{
			&ServerConfigRule{},
			&SecurityConfigRule{},
			&RoutesConfigRule{},
			&PluginsConfigRule{},
		},
	}
}

// AddRule adds a custom validation rule
func (v *ConfigValidator) AddRule(rule ValidationRule) {
	v.rules = append(v.rules, rule)
}

// Validate validates the configuration using all rules
func (v *ConfigValidator) Validate(cfg *Config) error {
	for _, rule := range v.rules {
		if err := rule.Validate(cfg); err != nil {
			return fmt.Errorf("validation failed: %w", err)
		}
	}
	return nil
}

// ServerConfigRule validates server configuration
type ServerConfigRule struct{}

func (r *ServerConfigRule) Validate(cfg *Config) error {
	if cfg.Server.Port <= 0 || cfg.Server.Port > 65535 {
		return errors.NewValidationError("server.port", "port must be between 1 and 65535")
	}

	if cfg.Server.ReadTimeout != "" {
		if _, err := time.ParseDuration(cfg.Server.ReadTimeout); err != nil {
			return errors.NewValidationError("server.readTimeout", "invalid duration format")
		}
	}

	if cfg.Server.WriteTimeout != "" {
		if _, err := time.ParseDuration(cfg.Server.WriteTimeout); err != nil {
			return errors.NewValidationError("server.writeTimeout", "invalid duration format")
		}
	}

	if cfg.Server.IdleTimeout != "" {
		if _, err := time.ParseDuration(cfg.Server.IdleTimeout); err != nil {
			return errors.NewValidationError("server.idleTimeout", "invalid duration format")
		}
	}

	return nil
}

// SecurityConfigRule validates security configuration
type SecurityConfigRule struct{}

func (r *SecurityConfigRule) Validate(cfg *Config) error {
	if cfg.Security.TLS.Enabled {
		if cfg.Security.TLS.CertFile == "" {
			return errors.NewValidationError("security.tls.certFile", "certificate file is required when TLS is enabled")
		}
		if cfg.Security.TLS.KeyFile == "" {
			return errors.NewValidationError("security.tls.keyFile", "private key file is required when TLS is enabled")
		}
	}

	if cfg.Security.EnableBasicAuth {
		if len(cfg.Security.BasicAuthUsers) == 0 {
			return errors.NewValidationError("security.basicAuthUsers", "at least one user is required when basic auth is enabled")
		}
	}

	// Validate clients map if present
	if cfg.Security.Clients != nil {
		if len(cfg.Security.Clients) == 0 {
			return errors.NewValidationError("security.clients", "at least one client must be configured if clients map is present")
		}
		for k, v := range cfg.Security.Clients {
			if k == "" || v == "" {
				return errors.NewValidationError("security.clients", "client ID and secret must not be empty")
			}
		}
	}

	return nil
}

// RoutesConfigRule validates routes configuration
type RoutesConfigRule struct{}

func (r *RoutesConfigRule) Validate(cfg *Config) error {
	if len(cfg.Routes) == 0 {
		return errors.NewValidationError("routes", "at least one route must be configured")
	}

	seenPaths := make(map[string]bool)

	for i, route := range cfg.Routes {
		// Set default values
		// Note: In Go, bool fields default to false when not specified in YAML
		// Since the comment says "default true", we need to handle this explicitly
		// We can't modify the route directly in the slice, so we'll handle this in the gateway logic
		// For now, routes without the Enabled field will be treated as enabled (true)

		// Validate path
		if route.Path == "" {
			return errors.NewValidationError(fmt.Sprintf("routes[%d].path", i), "path is required")
		}

		if !strings.HasPrefix(route.Path, "/") {
			return errors.NewValidationError(fmt.Sprintf("routes[%d].path", i), "path must start with /")
		}

		// Check for duplicate paths
		if seenPaths[route.Path] {
			return errors.NewValidationError(fmt.Sprintf("routes[%d].path", i), "duplicate path found")
		}
		seenPaths[route.Path] = true

		// Validate destination
		if route.Destination == "" {
			return errors.NewValidationError(fmt.Sprintf("routes[%d].destination", i), "destination is required")
		}

		// Validate destination URL
		if _, err := url.Parse(route.Destination); err != nil {
			return errors.NewValidationError(fmt.Sprintf("routes[%d].destination", i), "invalid destination URL")
		}

		// Validate methods
		if len(route.Methods) == 0 {
			return errors.NewValidationError(fmt.Sprintf("routes[%d].methods", i), "at least one HTTP method is required")
		}

		validMethods := map[string]bool{
			"GET": true, "POST": true, "PUT": true, "DELETE": true,
			"PATCH": true, "HEAD": true, "OPTIONS": true, "TRACE": true,
		}

		for _, method := range route.Methods {
			if !validMethods[strings.ToUpper(method)] {
				return errors.NewValidationError(fmt.Sprintf("routes[%d].methods", i), fmt.Sprintf("invalid HTTP method: %s", method))
			}
		}

		// Validate timeout if specified
		if route.Timeout != nil && *route.Timeout <= 0 {
			return errors.NewValidationError(fmt.Sprintf("routes[%d].timeout", i), "timeout must be positive")
		}

		// Validate rate limit if specified
		if route.RateLimit != nil && *route.RateLimit <= 0 {
			return errors.NewValidationError(fmt.Sprintf("routes[%d].rateLimit", i), "rate limit must be positive")
		}
	}

	return nil
}

// PluginsConfigRule validates plugins configuration
type PluginsConfigRule struct{}

func (r *PluginsConfigRule) Validate(cfg *Config) error {
	for pluginName, pluginConfig := range cfg.Plugins {
		if pluginName == "" {
			return errors.NewValidationError("plugins", "plugin name cannot be empty")
		}

		// Validate plugin configuration structure
		if pluginConfig == nil {
			return errors.NewValidationError(fmt.Sprintf("plugins.%s", pluginName), "plugin configuration cannot be nil")
		}

		// Add plugin-specific validation here
		switch pluginName {
		case "auth":
			if err := r.validateAuthPlugin(pluginConfig); err != nil {
				return err
			}
		case "rate":
			if err := r.validateRatePlugin(pluginConfig); err != nil {
				return err
			}
		case "cors":
			if err := r.validateCorsPlugin(pluginConfig); err != nil {
				return err
			}
		}
	}

	return nil
}

func (r *PluginsConfigRule) validateAuthPlugin(config map[string]interface{}) error {
	// Validate auth plugin specific configuration
	if provider, ok := config["provider"].(string); ok {
		validProviders := map[string]bool{
			"keycloak": true,
			"saml":     true,
			"basic":    true,
		}
		if !validProviders[provider] {
			return errors.NewValidationError("plugins.auth.provider", fmt.Sprintf("unsupported auth provider: %s", provider))
		}
	}

	return nil
}

func (r *PluginsConfigRule) validateRatePlugin(config map[string]interface{}) error {
	// Validate rate limiting plugin configuration
	if limit, ok := config["limit"].(float64); ok {
		if limit <= 0 {
			return errors.NewValidationError("plugins.rate.limit", "rate limit must be positive")
		}
	}

	if window, ok := config["window"].(string); ok {
		if _, err := time.ParseDuration(window); err != nil {
			return errors.NewValidationError("plugins.rate.window", "invalid duration format")
		}
	}

	return nil
}

func (r *PluginsConfigRule) validateCorsPlugin(config map[string]interface{}) error {
	// Validate CORS plugin configuration
	if origins, ok := config["origins"].([]interface{}); ok {
		for i, origin := range origins {
			if originStr, ok := origin.(string); ok {
				if originStr != "*" {
					if _, err := url.Parse(originStr); err != nil {
						return errors.NewValidationError(fmt.Sprintf("plugins.cors.origins[%d]", i), "invalid origin URL")
					}
				}
			}
		}
	}

	return nil
}
