package main

import "time"

// Config represents the gateway configuration
type Config struct {
	Server ServerConfig `yaml:"server"`

	Security SecurityConfig `yaml:"security"`

	Routes []RouterConfig `yaml:"routes"`

	Plugins []PluginConfig `yaml:"plugins"`
}

type ServerConfig struct {
	Port             int           `yaml:"port"`
	ReadTimeout      time.Duration `yaml:"readTimeout"`
	WriteTimeout     time.Duration `yaml:"writeTimeout"`
	IdleTimeout      time.Duration `yaml:"idleTimeout"`
	PluginsDir       string        `yaml:"pluginsDir"`
	EnableLogging    bool          `yaml:"enableLogging"`
	TLSCertFile      string        `yaml:"tlsCertFile"`
	TLSKeyFile       string        `yaml:"tlsKeyFile"`
	ClientCACertFile string        `yaml:"clientCACertFile"` // For mTLS
	MetricsPort      int           `yaml:"metricsPort"`
}

type RouterConfig struct {
	Path           string            `yaml:"path"`
	Destination    string            `yaml:"destination"`
	Methods        []string          `yaml:"methods"`
	RequireAuth    bool              `yaml:"requireAuth"`
	RateLimit      *int              `yaml:"rateLimit"`
	Timeout        *time.Duration    `yaml:"timeout"`
	Headers        map[string]string `yaml:"headers"`
	StripPath      bool              `yaml:"stripPath"`
	ValidateSchema string            `yaml:"validateSchema"`
}

type PluginConfig struct {
	Name    string                 `yaml:"name"`
	Path    string                 `yaml:"path"`
	Enabled bool                   `yaml:"enabled"`
	Config  map[string]interface{} `yaml:"config"`
}

type SecurityConfig struct {
	EnableMTLS              bool              `yaml:"enableMTLS"`
	EnableCSRF              bool              `yaml:"enableCSRF"`
	CSRFTokenExpiry         time.Duration     `yaml:"csrfTokenExpiry"`
	RateLimitRequests       int               `yaml:"rateLimitRequests"`
	RateLimitInterval       time.Duration     `yaml:"rateLimitInterval"`
	EnableXSS               bool              `yaml:"enableXSS"`
	EnableHSTS              bool              `yaml:"enableHSTS"`
	HSTSMaxAge              int               `yaml:"hstsMaxAge"`
	EnableSecureCookies     bool              `yaml:"enableSecureCookies"`
	JWTSecret               string            `yaml:"jwtSecret"`
	JWTIssuer               string            `yaml:"jwtIssuer"`
	EnableIPWhitelisting    bool              `yaml:"enableIPWhitelisting"`
	WhitelistedIPs          []string          `yaml:"whitelistedIPs"`
	EnableRequestValidation bool              `yaml:"enableRequestValidation"`
	MaxRequestBodySize      int64             `yaml:"maxRequestBodySize"`
	EnableBasicAuth         bool              `yaml:"enableBasicAuth"`
	BasicAuthUsers          map[string]string `yaml:"basicAuthUsers"`
}
