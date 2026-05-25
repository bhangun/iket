package config

import (
	"strings"
	"testing"
)

func TestPluginsConfigRuleAllowsAPIKeyUsageObserverTimeout(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Plugins: map[string]map[string]interface{}{
			"apikey": {
				"usage_observer_timeout": "250ms",
			},
		},
	}

	if err := NewConfigValidator().Validate(cfg); err != nil {
		t.Fatalf("expected API-key usage observer timeout to validate, got %v", err)
	}
}

func TestPluginsConfigRuleAllowsAPIKeyUsageObserverAsync(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Plugins: map[string]map[string]interface{}{
			"apikey": {
				"usage_observer_async": true,
			},
		},
	}

	if err := NewConfigValidator().Validate(cfg); err != nil {
		t.Fatalf("expected API-key usage observer async flag to validate, got %v", err)
	}
}

func TestPluginsConfigRuleAllowsAPIKeyUsageObserverAsyncMaxInFlight(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Plugins: map[string]map[string]interface{}{
			"apikey": {
				"usage_observer_async":               true,
				"usage_observer_async_max_in_flight": 256,
			},
		},
	}

	if err := NewConfigValidator().Validate(cfg); err != nil {
		t.Fatalf("expected API-key usage observer async max in-flight to validate, got %v", err)
	}
}

func TestPluginsConfigRuleRejectsInvalidAPIKeyUsageObserverTimeout(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Plugins: map[string]map[string]interface{}{
			"apikey": {
				"usage_observer_timeout": "0s",
			},
		},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "usage observer timeout") {
		t.Fatalf("expected usage observer timeout validation error, got %v", err)
	}
}

func TestPluginsConfigRuleRejectsInvalidAPIKeyUsageObserverAsync(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Plugins: map[string]map[string]interface{}{
			"apikey": {
				"usage_observer_async": "true",
			},
		},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "usage observer async") {
		t.Fatalf("expected usage observer async validation error, got %v", err)
	}
}

func TestPluginsConfigRuleRejectsInvalidAPIKeyUsageObserverAsyncMaxInFlight(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Plugins: map[string]map[string]interface{}{
			"apikey": {
				"usage_observer_async":               true,
				"usage_observer_async_max_in_flight": 0,
			},
		},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "usage observer async max in-flight") {
		t.Fatalf("expected usage observer async max in-flight validation error, got %v", err)
	}
}
