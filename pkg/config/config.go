package config

// Config represents the main configuration structure
type Config struct {
	Server          ServerConfig                      `yaml:"server"`
	Security        SecurityConfig                    `yaml:"security"`
	Storage         StorageConfig                     `yaml:"storage,omitempty"`
	AIPolicyPresets map[string]AIPolicyPreset         `yaml:"aiPolicyPresets,omitempty" json:"ai_policy_presets,omitempty"`
	Services        []ServiceConfig                   `yaml:"services,omitempty"` // New service-based configuration
	Plugins         map[string]map[string]interface{} `yaml:"plugins"`
}
