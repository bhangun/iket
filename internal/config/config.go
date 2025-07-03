package config

import (
	"crypto/rsa"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"os"
	"sync"
	"time"

	"gopkg.in/yaml.v3"

	coreerrors "iket/internal/core/errors"
	"iket/internal/logging"

	"github.com/golang-jwt/jwt/v4"
)

// Config represents the main configuration structure
type Config struct {
	Server   ServerConfig                      `yaml:"server"`
	Security SecurityConfig                    `yaml:"security"`
	Routes   []RouterConfig                    `yaml:"routes"`
	Plugins  map[string]map[string]interface{} `yaml:"plugins"`
}

// ServerConfig represents server configuration
type ServerConfig struct {
	Port          int    `yaml:"port"`
	ReadTimeout   string `yaml:"readTimeout"`
	WriteTimeout  string `yaml:"writeTimeout"`
	IdleTimeout   string `yaml:"idleTimeout"`
	PluginsDir    string `yaml:"pluginsDir,omitempty"`
	EnableLogging bool   `yaml:"enableLogging"`
}

// SecurityConfig represents security configuration
type SecurityConfig struct {
	TLS             TLSConfig         `yaml:"tls"`
	EnableBasicAuth bool              `yaml:"enableBasicAuth"`
	BasicAuthUsers  map[string]string `yaml:"basicAuthUsers"`
	IPWhitelist     []string          `yaml:"ipWhitelist"`
	Headers         map[string]string `yaml:"headers"`
	Clients         map[string]string `yaml:"clients"` // clientID: clientSecret
	Jwt             JWTConfig         `yaml:"jwt"`
}

// TLSConfig represents TLS configuration
type TLSConfig struct {
	Enabled    bool     `yaml:"enabled"`
	CertFile   string   `yaml:"certFile"`
	KeyFile    string   `yaml:"keyFile"`
	MinVersion string   `yaml:"minVersion"`
	Ciphers    []string `yaml:"ciphers"`
}

// RouterConfig represents a route configuration
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
	WebSocket      *WebSocketOptions `yaml:"websocket,omitempty"`
	RequireJwt     bool              `yaml:"requireJwt"`
}

type WebSocketOptions struct {
	Timeout             string            `yaml:"timeout,omitempty"`
	BufferSize          int               `yaml:"bufferSize,omitempty"`
	DNSRoundRobin       bool              `yaml:"dnsRoundRobin,omitempty"`
	InjectHeaders       map[string]string `yaml:"injectHeaders,omitempty"`
	AllowedSubprotocols []string          `yaml:"allowedSubprotocols,omitempty"`
	MaxConnections      int               `yaml:"maxConnections,omitempty"`
	MaxConnectionsPerIP int               `yaml:"maxConnectionsPerIP,omitempty"`
	RateLimit           int               `yaml:"rateLimit,omitempty"`
	HandshakeTimeout    time.Duration     `json:"handshake_timeout"`
	ReadBufferSize      int               `json:"read_buffer_size"`
	WriteBufferSize     int               `json:"write_buffer_size"`
	EnableCompression   bool              `json:"enable_compression"`
	CheckOrigin         bool              `json:"check_origin"`
}

// JWTConfig holds JWT auth settings
type JWTConfig struct {
	Enabled       bool     `yaml:"enabled"`
	Secret        string   `yaml:"secret"`
	Algorithms    []string `yaml:"algorithms"`
	PublicKeyFile string   `yaml:"publicKeyFile"`
	Required      bool     `yaml:"required"`
}

// Provider defines the interface for configuration providers
type Provider interface {
	Load() (*Config, error)
	Save(*Config) error
	Watch(func(*Config) error) error
	Close() error
}

// FileProvider implements configuration loading from files
type FileProvider struct {
	configPath  string
	routesPath  string
	logger      *logging.Logger
	watchers    []func(*Config) error
	mu          sync.RWMutex
	stopWatcher chan struct{}
}

// NewFileProvider creates a new file-based configuration provider
func NewFileProvider(configPath, routesPath string, logger *logging.Logger) *FileProvider {
	return &FileProvider{
		configPath:  configPath,
		routesPath:  routesPath,
		logger:      logger,
		stopWatcher: make(chan struct{}),
	}
}

// Load loads configuration from files
func (p *FileProvider) Load() (*Config, error) {
	// Load main config
	configData, err := os.ReadFile(p.configPath)
	if err != nil {
		return nil, coreerrors.NewConfigError("failed to read config file", err)
	}

	var config Config
	if err := yaml.Unmarshal(configData, &config); err != nil {
		return nil, coreerrors.NewConfigError("failed to parse config file", err)
	}

	// Load routes config if separate file
	if p.routesPath != "" && p.routesPath != p.configPath {
		routesData, err := os.ReadFile(p.routesPath)
		if err != nil {
			return nil, coreerrors.NewConfigError("failed to read routes file", err)
		}

		var routesConfig Config
		if err := yaml.Unmarshal(routesData, &routesConfig); err != nil {
			return nil, coreerrors.NewConfigError("failed to parse routes file", err)
		}

		config.Routes = routesConfig.Routes
	}

	// Validate configuration
	validator := NewConfigValidator()
	if err := validator.Validate(&config); err != nil {
		return nil, err
	}

	p.logger.LogConfigLoad(p.configPath, nil)
	return &config, nil
}

// Save saves configuration to files
func (p *FileProvider) Save(cfg *Config) error {
	// Validate before saving
	validator := NewConfigValidator()
	if err := validator.Validate(cfg); err != nil {
		return err
	}

	// Save main config
	configData, err := yaml.Marshal(cfg)
	if err != nil {
		return coreerrors.NewConfigError("failed to marshal config", err)
	}

	if err := os.WriteFile(p.configPath, configData, 0644); err != nil {
		return coreerrors.NewConfigError("failed to write config file", err)
	}

	// Save routes to separate file if needed
	if p.routesPath != "" && p.routesPath != p.configPath {
		routesConfig := Config{Routes: cfg.Routes}
		routesData, err := yaml.Marshal(routesConfig)
		if err != nil {
			return coreerrors.NewConfigError("failed to marshal routes", err)
		}

		if err := os.WriteFile(p.routesPath, routesData, 0644); err != nil {
			return coreerrors.NewConfigError("failed to write routes file", err)
		}
	}

	p.logger.Info("Configuration saved successfully")
	return nil
}

// Watch sets up file watching for configuration changes
func (p *FileProvider) Watch(callback func(*Config) error) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.watchers = append(p.watchers, callback)

	// Start watching if not already started
	if len(p.watchers) == 1 {
		go p.watchFiles()
	}

	return nil
}

// watchFiles monitors configuration files for changes
func (p *FileProvider) watchFiles() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	var lastModTime time.Time

	for {
		select {
		case <-p.stopWatcher:
			return
		case <-ticker.C:
			// Check if files have been modified
			info, err := os.Stat(p.configPath)
			if err != nil {
				p.logger.Error("Failed to stat config file", err)
				continue
			}

			if info.ModTime().After(lastModTime) {
				lastModTime = info.ModTime()

				// Reload configuration
				cfg, err := p.Load()
				if err != nil {
					p.logger.Error("Failed to reload configuration", err)
					continue
				}

				// Notify all watchers
				p.mu.RLock()
				for _, watcher := range p.watchers {
					if err := watcher(cfg); err != nil {
						p.logger.Error("Configuration reload callback failed", err)
					}
				}
				p.mu.RUnlock()

				p.logger.Info("Configuration reloaded successfully")
			}
		}
	}
}

// Close stops the file watcher
func (p *FileProvider) Close() error {
	close(p.stopWatcher)
	return nil
}

// LoadConfig loads configuration from the specified path
func LoadConfig(configPath, routesPath string, logger *logging.Logger) (*Config, error) {
	provider := NewFileProvider(configPath, routesPath, logger)
	return provider.Load()
}

// LoadFromFile loads configuration from a single file
func LoadFromFile(configPath string) (*Config, error) {
	provider := NewFileProvider(configPath, "", nil)
	return provider.Load()
}

// SaveConfig saves configuration to the specified path
func SaveConfig(cfg *Config, configPath, routesPath string, logger *logging.Logger) error {
	provider := NewFileProvider(configPath, routesPath, logger)
	return provider.Save(cfg)
}

// Validate validates the configuration
func (c *Config) Validate() error {
	validator := NewConfigValidator()
	return validator.Validate(c)
}

// GetRouteByPath finds a route by its path
func (c *Config) GetRouteByPath(path string) (*RouterConfig, error) {
	for _, route := range c.Routes {
		if route.Path == path {
			return &route, nil
		}
	}
	return nil, coreerrors.ErrRouteNotFound
}

// AddRoute adds a new route to the configuration
func (c *Config) AddRoute(route RouterConfig) error {
	// Validate the route
	if route.Path == "" {
		return coreerrors.NewValidationError("path", "path is required")
	}

	// Check for duplicate paths
	for _, existingRoute := range c.Routes {
		if existingRoute.Path == route.Path {
			return coreerrors.NewValidationError("path", "duplicate path found")
		}
	}

	c.Routes = append(c.Routes, route)
	return nil
}

// RemoveRoute removes a route by path
func (c *Config) RemoveRoute(path string) error {
	for i, route := range c.Routes {
		if route.Path == path {
			c.Routes = append(c.Routes[:i], c.Routes[i+1:]...)
			return nil
		}
	}
	return coreerrors.ErrRouteNotFound
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

// loadRSAPublicKey loads an RSA public key from a PEM file
func LoadRSAPublicKey(path string) (*rsa.PublicKey, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, errors.New("invalid PEM public key")
	}
	pub, err := jwt.ParseRSAPublicKeyFromPEM(data)
	if err != nil {
		return nil, err
	}
	return pub, nil
}
