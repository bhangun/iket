package config

import (
	"fmt"
	"net/url"
	"time"

	"github.com/bhangun/iket/pkg/core/errors"
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
		case "apikey":
			if err := r.validateAPIKeyPlugin(pluginConfig); err != nil {
				return err
			}
		}
	}

	return nil
}

func (r *PluginsConfigRule) validateAPIKeyPlugin(config map[string]interface{}) error {
	for _, key := range []string{"usage_observer_timeout", "usageObserverTimeout"} {
		value, ok := config[key]
		if !ok {
			continue
		}
		timeout, ok := value.(string)
		if !ok {
			return errors.NewValidationError("plugins.apikey."+key, "usage observer timeout must use a valid positive duration format")
		}
		parsed, err := time.ParseDuration(timeout)
		if err != nil || parsed <= 0 {
			return errors.NewValidationError("plugins.apikey."+key, "usage observer timeout must use a valid positive duration format")
		}
	}
	for _, key := range []string{"usage_observer_async", "usageObserverAsync"} {
		value, ok := config[key]
		if !ok {
			continue
		}
		if _, ok := value.(bool); !ok {
			return errors.NewValidationError("plugins.apikey."+key, "usage observer async must be a boolean")
		}
	}
	for _, key := range []string{"usage_observer_async_max_in_flight", "usageObserverAsyncMaxInFlight"} {
		value, ok := config[key]
		if !ok {
			continue
		}
		if _, ok := positiveIntPluginConfigValue(value); !ok {
			return errors.NewValidationError("plugins.apikey."+key, "usage observer async max in-flight must be a positive integer")
		}
	}
	return nil
}

func positiveIntPluginConfigValue(value interface{}) (int, bool) {
	maxInt := int64(^uint(0) >> 1)
	switch typed := value.(type) {
	case int:
		return typed, typed > 0
	case int64:
		if typed <= 0 || typed > maxInt {
			return 0, false
		}
		return int(typed), typed > 0
	case float64:
		if typed <= 0 || typed > float64(maxInt) {
			return 0, false
		}
		converted := int64(typed)
		if float64(converted) != typed {
			return 0, false
		}
		return int(converted), true
	default:
		return 0, false
	}
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
