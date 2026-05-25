package config

import (
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
			&StorageConfigRule{},
			&ServicesConfigRule{},
			&PluginsConfigRule{},
		},
	}
}

// ValidateConfig validates cfg with the default validation rules.
func ValidateConfig(cfg *Config) error {
	return NewConfigValidator().Validate(cfg)
}

// AddRule adds a custom validation rule
func (v *ConfigValidator) AddRule(rule ValidationRule) {
	v.rules = append(v.rules, rule)
}

// Validate validates the configuration using all rules
func (v *ConfigValidator) Validate(cfg *Config) error {
	for _, rule := range v.rules {
		if err := rule.Validate(cfg); err != nil {
			return errors.NewConfigError("validation failed", err)
		}
	}
	return nil
}
