package config

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/bhangun/iket/pkg/core/errors"
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
			&ServicesConfigRule{},
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

// ServicesConfigRule validates service-based configuration
type ServicesConfigRule struct{}

func (r *ServicesConfigRule) Validate(cfg *Config) error {
	if len(cfg.Services) == 0 {
		// Services are optional, so no error if not present
		return nil
	}

	for i, serviceConfig := range cfg.Services {
		// Validate service config version
		if serviceConfig.Version <= 0 {
			return errors.NewValidationError(fmt.Sprintf("services[%d].version", i), "version must be positive")
		}

		// Validate services array
		if len(serviceConfig.Services) == 0 {
			return errors.NewValidationError(fmt.Sprintf("services[%d].services", i), "at least one service must be configured")
		}

		// Validate cache TTL if specified
		if serviceConfig.CacheTTL != "" {
			if _, err := time.ParseDuration(serviceConfig.CacheTTL); err != nil {
				return errors.NewValidationError(fmt.Sprintf("services[%d].cache_ttl", i), "invalid duration format")
			}
		}

		// Validate timeout if specified
		if serviceConfig.Timeout != "" {
			if _, err := time.ParseDuration(serviceConfig.Timeout); err != nil {
				return errors.NewValidationError(fmt.Sprintf("services[%d].timeout", i), "invalid duration format")
			}
		}

		// Validate each service
		seenServiceNames := make(map[string]bool)
		for j, service := range serviceConfig.Services {
			// Validate service name
			if service.Name == "" {
				return errors.NewValidationError(fmt.Sprintf("services[%d].services[%d].name", i, j), "service name is required")
			}

			// Check for duplicate service names
			if seenServiceNames[service.Name] {
				return errors.NewValidationError(fmt.Sprintf("services[%d].services[%d].name", i, j), "duplicate service name found")
			}
			seenServiceNames[service.Name] = true

			// Validate host
			if service.Host == "" {
				return errors.NewValidationError(fmt.Sprintf("services[%d].services[%d].host", i, j), "host is required")
			}

			// Validate host URL
			if _, err := url.Parse(service.Host); err != nil {
				return errors.NewValidationError(fmt.Sprintf("services[%d].services[%d].host", i, j), "invalid host URL")
			}

			// Validate base path if specified
			if service.BasePath != "" && !strings.HasPrefix(service.BasePath, "/") {
				return errors.NewValidationError(fmt.Sprintf("services[%d].services[%d].base_path", i, j), "base path must start with /")
			}

			// Validate routes
			if len(service.Routes) == 0 {
				return errors.NewValidationError(fmt.Sprintf("services[%d].services[%d].routes", i, j), "at least one route must be configured")
			}

			// Validate each route in the service
			seenRoutePaths := make(map[string]bool)
			for k, route := range service.Routes {
				// Validate path
				if route.Path == "" {
					return errors.NewValidationError(fmt.Sprintf("services[%d].services[%d].routes[%d].path", i, j, k), "path is required")
				}

				if !strings.HasPrefix(route.Path, "/") {
					return errors.NewValidationError(fmt.Sprintf("services[%d].services[%d].routes[%d].path", i, j, k), "path must start with /")
				}

				// Check for duplicate paths within the service
				fullPath := service.BasePath + route.Path
				if seenRoutePaths[fullPath] {
					return errors.NewValidationError(fmt.Sprintf("services[%d].services[%d].routes[%d].path", i, j, k), "duplicate path found within service")
				}
				seenRoutePaths[fullPath] = true

				// Validate method (new format) or methods (old format)
				if route.Method == "" && len(route.Methods) == 0 {
					return errors.NewValidationError(fmt.Sprintf("services[%d].services[%d].routes[%d]", i, j, k), "either method or methods is required")
				}

				// Validate method if specified
				if route.Method != "" {
					validMethods := map[string]bool{
						"GET": true, "POST": true, "PUT": true, "DELETE": true,
						"PATCH": true, "HEAD": true, "OPTIONS": true, "TRACE": true,
					}
					if !validMethods[strings.ToUpper(route.Method)] {
						return errors.NewValidationError(fmt.Sprintf("services[%d].services[%d].routes[%d].method", i, j, k), fmt.Sprintf("invalid HTTP method: %s", route.Method))
					}
				}

				// Validate priority if specified
				if route.Priority < 0 {
					return errors.NewValidationError(fmt.Sprintf("services[%d].services[%d].routes[%d].priority", i, j, k), "priority must be non-negative")
				}

				// Validate backends
				if len(route.Backends) == 0 && !isPluginOrInternalRoute(route.Path) {
					return errors.NewValidationError(fmt.Sprintf("services[%d].services[%d].routes[%d].backend", i, j, k), "at least one backend must be configured unless this is a plugin or internal route")
				}

				for l, backend := range route.Backends {
					if backend.URLPattern == "" {
						return errors.NewValidationError(fmt.Sprintf("services[%d].services[%d].routes[%d].backend[%d].url_pattern", i, j, k, l), "url_pattern is required")
					}
				}
			}
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

// Add helper function to check if a route is plugin/static/internal
func isPluginOrInternalRoute(path string) bool {
	pluginPaths := []string{"/openapi", "/swagger-ui", "/docs", "/docs/", "/docs/{rest:.*}"}
	for _, p := range pluginPaths {
		if strings.HasPrefix(path, p) {
			return true
		}
	}
	return false
}
