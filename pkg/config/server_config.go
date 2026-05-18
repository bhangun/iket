package config

// ServerConfig represents server configuration
type ServerConfig struct {
	Port          int       `yaml:"port"`
	ReadTimeout   string    `yaml:"readTimeout"`
	WriteTimeout  string    `yaml:"writeTimeout"`
	IdleTimeout   string    `yaml:"idleTimeout"`
	PluginsDir    string    `yaml:"pluginsDir,omitempty"`
	EnableLogging bool      `yaml:"enableLogging"`
	TLS           TLSConfig `yaml:"tls,omitempty"`
}
