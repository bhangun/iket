package config

import (
	"os"
	"sync"
	"time"

	coreerrors "github.com/bhangun/iket/pkg/core/errors"
	"github.com/bhangun/iket/pkg/logging"
	"gopkg.in/yaml.v3"
)

// FileProvider implements configuration loading from files
type FileProvider struct {
	configPath   string
	servicesPath string
	logger       *logging.Logger
	watchers     []func(*Config) error
	mu           sync.RWMutex
	stopWatcher  chan struct{}
	closeOnce    sync.Once
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
	loadDotEnvFile(".env")

	// Load main config
	configData, err := os.ReadFile(p.configPath)
	if err != nil {
		return nil, coreerrors.NewConfigError("failed to read config file", err)
	}

	var config Config
	if err := yaml.Unmarshal(configData, &config); err != nil {
		return nil, coreerrors.NewConfigError("failed to parse config file", err)
	}
	normalizeLegacyConfig(&config)

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

	if err := prepareLoadedConfig(&config); err != nil {
		return nil, err
	}

	return &config, nil
}

// Save saves configuration to files atomically
func (p *FileProvider) Save(cfg *Config) error {
	if err := validateConfig(cfg); err != nil {
		return err
	}

	// Save main config
	if err := p.saveAtomic(p.configPath, cfg); err != nil {
		return err
	}

	// Save service config to separate file if needed
	if p.servicesPath != "" && p.servicesPath != p.configPath {
		if len(cfg.Services) > 0 {
			if err := p.saveServicesAtomic(p.servicesPath, &cfg.Services[0]); err != nil {
				return err
			}
		}
	}

	if p.logger != nil {
		p.logger.Info("Configuration saved successfully",
			logging.String("config_path", p.configPath),
			logging.String("services_path", p.servicesPath),
		)
	}
	return nil
}

func (p *FileProvider) saveAtomic(path string, cfg *Config) error {
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return coreerrors.NewConfigError("failed to marshal config", err)
	}

	tempFile := path + ".tmp"
	if err := os.WriteFile(tempFile, data, 0644); err != nil {
		return coreerrors.NewConfigError("failed to write temp config file", err)
	}

	if err := os.Rename(tempFile, path); err != nil {
		os.Remove(tempFile) // clean up
		return coreerrors.NewConfigError("failed to commit config file change", err)
	}

	return nil
}

func (p *FileProvider) saveServicesAtomic(path string, svcCfg *ServiceConfig) error {
	data, err := yaml.Marshal(svcCfg)
	if err != nil {
		return coreerrors.NewConfigError("failed to marshal service config", err)
	}

	tempFile := path + ".tmp"
	if err := os.WriteFile(tempFile, data, 0644); err != nil {
		return coreerrors.NewConfigError("failed to write temp service config file", err)
	}

	if err := os.Rename(tempFile, path); err != nil {
		os.Remove(tempFile) // clean up
		return coreerrors.NewConfigError("failed to commit service config file change", err)
	}

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
				if p.logger != nil {
					p.logger.Error("Failed to stat config file", err)
				}
				continue
			}

			if info.ModTime().After(lastModTime) {
				lastModTime = info.ModTime()

				// Reload configuration
				cfg, err := p.Load()
				if err != nil {
					if p.logger != nil {
						p.logger.Error("Failed to reload configuration", err)
					}
					continue
				}

				// Notify all watchers
				p.mu.RLock()
				for _, watcher := range p.watchers {
					if err := watcher(cfg); err != nil {
						if p.logger != nil {
							p.logger.Error("Configuration reload callback failed", err)
						}
					}
				}
				p.mu.RUnlock()

				if p.logger != nil {
					p.logger.Info("Configuration reloaded successfully")
				}
			}
		}
	}
}

// Close stops the file watcher
func (p *FileProvider) Close() error {
	p.closeOnce.Do(func() {
		close(p.stopWatcher)
	})
	return nil
}
