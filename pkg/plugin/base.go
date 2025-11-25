package plugin

import (
	"context"
	"encoding/json"
	"fmt"
)

// BasePlugin provides common functionality that can be embedded in other plugins
type BasePlugin struct {
	name        string
	version     string
	description string
	config      map[string]interface{}
	enabled     bool
}

// NewBasePlugin creates a new base plugin
func NewBasePlugin(name, version, description string) *BasePlugin {
	return &BasePlugin{
		name:        name,
		version:     version,
		description: description,
		config:      make(map[string]interface{}),
		enabled:     true,
	}
}

// Name returns the plugin name
func (b *BasePlugin) Name() string {
	return b.name
}

// Type returns the plugin type (should be overridden by concrete plugins)
func (b *BasePlugin) Type() PluginType {
	return MiddlewarePlugin // Default, should be overridden
}

// Version returns the plugin version
func (b *BasePlugin) Version() string {
	return b.version
}

// Description returns the plugin description
func (b *BasePlugin) Description() string {
	return b.description
}

// Initialize initializes the plugin with configuration
func (b *BasePlugin) Initialize(config map[string]interface{}) error {
	b.config = config
	return nil
}

// Validate validates the plugin configuration
func (b *BasePlugin) Validate(config map[string]interface{}) error {
	// Default implementation - no validation
	return nil
}

// GetConfigSchema returns the JSON schema for plugin configuration
func (b *BasePlugin) GetConfigSchema() map[string]interface{} {
	return map[string]interface{}{
		"type":       "object",
		"properties": make(map[string]interface{}),
	}
}

// Start starts the plugin (optional)
func (b *BasePlugin) Start(ctx context.Context) error {
	// Default implementation - no start logic
	return nil
}

// Stop stops the plugin (optional)
func (b *BasePlugin) Stop(ctx context.Context) error {
	// Default implementation - no stop logic
	return nil
}

// Reload reloads the plugin configuration (optional)
func (b *BasePlugin) Reload(ctx context.Context, config map[string]interface{}) error {
	b.config = config
	return nil
}

// GetConfig returns the current plugin configuration
func (b *BasePlugin) GetConfig() map[string]interface{} {
	return b.config
}

// GetConfigValue returns a specific configuration value
func (b *BasePlugin) GetConfigValue(key string, defaultValue interface{}) interface{} {
	if val, exists := b.config[key]; exists {
		return val
	}
	return defaultValue
}

// GetConfigValueAsInt returns a configuration value as int
func (b *BasePlugin) GetConfigValueAsInt(key string, defaultValue int) int {
	if val, exists := b.config[key]; exists {
		if intVal, ok := val.(int); ok {
			return intVal
		}
		if floatVal, ok := val.(float64); ok {
			return int(float64(floatVal))
		}
	}
	return defaultValue
}

// GetConfigValueAsString returns a configuration value as string
func (b *BasePlugin) GetConfigValueAsString(key, defaultValue string) string {
	if val, exists := b.config[key]; exists {
		if strVal, ok := val.(string); ok {
			return strVal
		}
	}
	return defaultValue
}

// GetConfigValueAsBool returns a configuration value as bool
func (b *BasePlugin) GetConfigValueAsBool(key string, defaultValue bool) bool {
	if val, exists := b.config[key]; exists {
		if boolVal, ok := val.(bool); ok {
			return boolVal
		}
	}
	return defaultValue
}

// GetConfigValueAsFloat64 returns a configuration value as float64
func (b *BasePlugin) GetConfigValueAsFloat64(key string, defaultValue float64) float64 {
	if val, exists := b.config[key]; exists {
		if floatVal, ok := val.(float64); ok {
			return floatVal
		}
		if intVal, ok := val.(int); ok {
			return float64(intVal)
		}
	}
	return defaultValue
}

// GetConfigValueAsSlice returns a configuration value as []interface{}
func (b *BasePlugin) GetConfigValueAsSlice(key string, defaultValue []interface{}) []interface{} {
	if val, exists := b.config[key]; exists {
		if sliceVal, ok := val.([]interface{}); ok {
			return sliceVal
		}
	}
	return defaultValue
}

// GetConfigValueAsMap returns a configuration value as map[string]interface{}
func (b *BasePlugin) GetConfigValueAsMap(key string, defaultValue map[string]interface{}) map[string]interface{} {
	if val, exists := b.config[key]; exists {
		if mapVal, ok := val.(map[string]interface{}); ok {
			return mapVal
		}
	}
	return defaultValue
}

// ToJSON converts the plugin configuration to JSON
func (b *BasePlugin) ToJSON() ([]byte, error) {
	return json.Marshal(b.config)
}

// FromJSON loads the plugin configuration from JSON
func (b *BasePlugin) FromJSON(data []byte) error {
	var config map[string]interface{}
	if err := json.Unmarshal(data, &config); err != nil {
		return err
	}
	b.config = config
	return nil
}

// ValidateRequiredFields checks if required fields are present in the configuration
func (b *BasePlugin) ValidateRequiredFields(requiredFields []string) error {
	for _, field := range requiredFields {
		if _, exists := b.config[field]; !exists {
			return fmt.Errorf("required field '%s' is missing", field)
		}
	}
	return nil
}

// ValidateField validates a specific field with a custom validation function
func (b *BasePlugin) ValidateField(fieldName string, validator func(interface{}) error) error {
	if val, exists := b.config[fieldName]; exists {
		return validator(val)
	}
	return fmt.Errorf("field '%s' does not exist", fieldName)
}