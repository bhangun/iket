package config

import (
	"github.com/bhangun/iket/pkg/logging"
)

// LoadConfig loads configuration from the specified path
func LoadConfig(configPath, servicesPath string, logger *logging.Logger) (*Config, error) {
	provider := NewFileProvider(configPath, servicesPath, logger)
	cfg, err := provider.Load()
	if err != nil {
		return nil, err
	}

	// Expand env vars in plugin configs
	if cfg != nil && cfg.Plugins != nil {
		for _, pluginConfig := range cfg.Plugins {
			expandEnvVarsInMap(pluginConfig)
		}
	}

	// Validate configuration
	validator := NewConfigValidator()
	if err := validator.Validate(cfg); err != nil {
		return nil, err
	}

	// Log successful loading of both config files
	logger.LogConfigLoad(configPath, nil)
	if servicesPath != "" && servicesPath != configPath {
		logger.LogConfigLoad(servicesPath, nil)
	}
	return cfg, nil
}

// LoadFromFile loads configuration from a single file
func LoadFromFile(configPath string) (*Config, error) {
	provider := NewFileProvider(configPath, "", nil)
	return provider.Load()
}

// SaveConfig saves configuration to the specified path
func SaveConfig(cfg *Config, configPath, servicesPath string, logger *logging.Logger) error {
	provider := NewFileProvider(configPath, servicesPath, logger)
	return provider.Save(cfg)
}

// Validate validates the configuration
func (c *Config) Validate() error {
	validator := NewConfigValidator()
	return validator.Validate(c)
}

// GetPluginConfig returns configuration for a specific plugin
func (c *Config) GetPluginConfig(pluginName string) (map[string]interface{}, bool) {
	config, exists := c.Plugins[pluginName]
	return config, exists
}

// SetPluginConfig sets configuration for a specific plugin
func (c *Config) SetPluginConfig(pluginName string, config map[string]interface{}) {
	if c.Plugins == nil {
		c.Plugins = make(map[string]map[string]interface{})
	}
	c.Plugins[pluginName] = config
}
