package config

import (
	"fmt"
	"github.com/bhangun/iket/pkg/core/errors"
	"net/url"
	"time"
)

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
