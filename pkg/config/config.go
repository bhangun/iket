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

	coreerrors "github.com/bhangun/iket/pkg/core/errors"
	"github.com/bhangun/iket/pkg/logging"

	"github.com/golang-jwt/jwt/v4"
)

// Config represents the main configuration structure
type Config struct {
	Server   ServerConfig                      `yaml:"server"`
	Security SecurityConfig                    `yaml:"security"`
	Services []ServiceConfig                   `yaml:"services,omitempty"` // New service-based configuration
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

// RouterConfig represents a route configuration
type RouterConfig struct {
	Path           string            `yaml:"path"`
	Methods        []string          `yaml:"methods"`
	Method         string            `yaml:"method"` // Single method for new format
	RequireAuth    bool              `yaml:"requireAuth"`
	RateLimit      *int              `yaml:"rateLimit"`
	Timeout        *time.Duration    `yaml:"timeout"`
	Headers        map[string]string `yaml:"headers"`
	StripPath      bool              `yaml:"stripPath"`
	ValidateSchema string            `yaml:"validateSchema"`
	WebSocket      *WebSocketOptions `yaml:"websocket,omitempty"`
	RequireJwt     bool              `yaml:"requireJwt"`
	Enabled        bool              `yaml:"enabled"`
	AuthPlugin     string            `yaml:"auth_plugin,omitempty" json:"auth_plugin,omitempty"`
	// New fields for enhanced configuration
	Name            string    `yaml:"name,omitempty" json:"name,omitempty"`
	Description     string    `yaml:"description,omitempty" json:"description,omitempty"`
	Tags            []string  `yaml:"tags,omitempty" json:"tags,omitempty"`
	Group           string    `yaml:"group,omitempty" json:"group,omitempty"`
	Priority        int       `yaml:"priority,omitempty" json:"priority,omitempty"`
	ConcurrentCalls string    `yaml:"concurrent_calls,omitempty" json:"concurrent_calls,omitempty"`
	MaxRate         string    `yaml:"max_rate,omitempty" json:"max_rate,omitempty"`
	Backends        []Backend `yaml:"backend" json:"backend"`
	Roles           []string  `yaml:"roles,omitempty" json:"roles,omitempty"`
}

// TLSConfig represents TLS configuration
type TLSConfig struct {
	Enabled    bool     `yaml:"enabled"`
	CertFile   string   `yaml:"certFile"`
	KeyFile    string   `yaml:"keyFile"`
	MinVersion string   `yaml:"minVersion"`
	Ciphers    []string `yaml:"ciphers"`
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

// ServiceConfig represents the new service-based configuration structure
type ServiceConfig struct {
	Version  int       `yaml:"version" json:"version"`
	Services []Service `yaml:"services" json:"services"`
	CacheTTL string    `yaml:"cache_ttl" json:"cache_ttl"`
	Timeout  string    `yaml:"timeout" json:"timeout"`
}

// Service represents a service in the new configuration format
type Service struct {
	Name        string         `yaml:"name,omitempty" json:"name,omitempty"`
	Description string         `yaml:"description,omitempty" json:"description,omitempty"`
	Host        string         `yaml:"host" json:"host"`
	BasePath    string         `yaml:"base_path,omitempty" json:"base_path,omitempty"`
	Tags        []string       `yaml:"tags,omitempty" json:"tags,omitempty"`
	Group       string         `yaml:"group,omitempty" json:"group,omitempty"`
	Routes      []RouterConfig `yaml:"routes" json:"routes"`
}

// Backend represents a backend configuration for routes
type Backend struct {
	URLPattern string `yaml:"url_pattern" json:"url_pattern"`
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
	configPath   string
	servicesPath string
	logger       *logging.Logger
	watchers     []func(*Config) error
	mu           sync.RWMutex
	stopWatcher  chan struct{}
}

// NewFileProvider creates a new file-based configuration provider
func NewFileProvider(configPath, servicesPath string, logger *logging.Logger) *FileProvider {
	return &FileProvider{
		configPath:   configPath,
		servicesPath: servicesPath,
		logger:       logger,
		stopWatcher:  make(chan struct{}),
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

	// Load service config if separate file (new format)
	if p.servicesPath != "" && p.servicesPath != p.configPath {
		// If a --services file is provided, load services from that file
		serviceData, err := os.ReadFile(p.servicesPath)
		if err != nil {
			return nil, coreerrors.NewConfigError("failed to read service config file", err)
		}
		var serviceConfig ServiceConfig
		if err := yaml.Unmarshal(serviceData, &serviceConfig); err != nil {
			return nil, coreerrors.NewConfigError("failed to parse service config file", err)
		}
		// Instead of merging into config.Services[0], append as a new ServiceConfig
		if len(serviceConfig.Services) > 0 {
			config.Services = append(config.Services, serviceConfig)
		}
	}

	// After merging serviceConfig into config.Services, set default backend if missing
	for si := range config.Services {
		for sj := range config.Services[si].Services {
			service := &config.Services[si].Services[sj]
			for rk := range service.Routes {
				route := &service.Routes[rk]
				// If no backends and not a plugin/internal route, set default backend
				if len(route.Backends) == 0 && !isPluginOrInternalRoute(route.Path) {
					route.Backends = []Backend{{URLPattern: route.Path}}
				}
				// Set default backend URLPattern if missing
				for bk := range route.Backends {
					if route.Backends[bk].URLPattern == "" {
						route.Backends[bk].URLPattern = route.Path
					}
				}
			}
		}
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

	// Save service config to separate file if needed
	if p.servicesPath != "" && p.servicesPath != p.configPath {
		if len(cfg.Services) > 0 {
			serviceData, err := yaml.Marshal(cfg.Services[0])
			if err != nil {
				return coreerrors.NewConfigError("failed to marshal service config", err)
			}
			if err := os.WriteFile(p.servicesPath, serviceData, 0644); err != nil {
				return coreerrors.NewConfigError("failed to write service config file", err)
			}
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
func LoadConfig(configPath, servicesPath string, logger *logging.Logger) (*Config, error) {
	provider := NewFileProvider(configPath, servicesPath, logger)
	return provider.Load()
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

// GetServiceByName finds a service by its name
func (c *Config) GetServiceByName(name string) (*Service, error) {
	for _, serviceConfig := range c.Services {
		for _, service := range serviceConfig.Services {
			if service.Name == name {
				return &service, nil
			}
		}
	}
	return nil, coreerrors.NewValidationError("service", "service not found")
}

// GetServiceByGroup finds all services in a specific group
func (c *Config) GetServiceByGroup(group string) []Service {
	var services []Service
	for _, serviceConfig := range c.Services {
		for _, service := range serviceConfig.Services {
			if service.Group == group {
				services = append(services, service)
			}
		}
	}
	return services
}

// GetServiceByTag finds all services with a specific tag
func (c *Config) GetServiceByTag(tag string) []Service {
	var services []Service
	for _, serviceConfig := range c.Services {
		for _, service := range serviceConfig.Services {
			for _, serviceTag := range service.Tags {
				if serviceTag == tag {
					services = append(services, service)
					break
				}
			}
		}
	}
	return services
}

// GetAllRoutesFromServices returns all routes from all services
func (c *Config) GetAllRoutesFromServices() []RouterConfig {
	var allRoutes []RouterConfig
	for _, serviceConfig := range c.Services {
		for _, service := range serviceConfig.Services {
			allRoutes = append(allRoutes, service.Routes...)
		}
	}
	return allRoutes
}

// GetRouteByPathFromServices finds a route by path from service configurations
func (c *Config) GetRouteByPathFromServices(path string) (*RouterConfig, error) {
	for _, serviceConfig := range c.Services {
		for _, service := range serviceConfig.Services {
			for _, route := range service.Routes {
				if route.Path == path {
					return &route, nil
				}
			}
		}
	}
	return nil, coreerrors.ErrRouteNotFound
}

// AddService adds a new service to the configuration
func (c *Config) AddService(service Service) error {
	if len(c.Services) == 0 {
		c.Services = []ServiceConfig{{
			Version:  1,
			Services: []Service{},
		}}
	}

	c.Services[0].Services = append(c.Services[0].Services, service)
	return nil
}

// RemoveService removes a service by name
func (c *Config) RemoveService(name string) error {
	for i, serviceConfig := range c.Services {
		for j, service := range serviceConfig.Services {
			if service.Name == name {
				c.Services[i].Services = append(c.Services[i].Services[:j], c.Services[i].Services[j+1:]...)
				return nil
			}
		}
	}
	return coreerrors.NewValidationError("service", "service not found")
}

// Add helper to find parent service for a route
func (c *Config) FindServiceForRoute(path string, method string) *Service {
	for _, serviceConfig := range c.Services {
		for _, service := range serviceConfig.Services {
			for _, route := range service.Routes {
				if route.Path == path {
					if route.Method != "" && route.Method == method {
						return &service
					}
					if len(route.Methods) > 0 {
						for _, m := range route.Methods {
							if m == method {
								return &service
							}
						}
					}
				}
			}
		}
	}
	return nil
}
