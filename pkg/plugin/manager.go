package plugin

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// PluginManager provides high-level plugin management functionality
type PluginManager struct {
	registry     *Registry
	configStore  PluginConfigStore
	hotReloader  *HotReloadManager
	mu           sync.RWMutex
	ctx          context.Context
	cancel       context.CancelFunc
}

// PluginConfigStore interface for storing and retrieving plugin configurations
type PluginConfigStore interface {
	GetPluginConfig(name string) (PluginConfig, error)
	SetPluginConfig(name string, config PluginConfig) error
	ListPluginConfigs() (map[string]PluginConfig, error)
	DeletePluginConfig(name string) error
}

// InMemoryConfigStore implements PluginConfigStore in memory
type InMemoryConfigStore struct {
	configs map[string]PluginConfig
	mu      sync.RWMutex
}

// NewInMemoryConfigStore creates a new in-memory config store
func NewInMemoryConfigStore() *InMemoryConfigStore {
	return &InMemoryConfigStore{
		configs: make(map[string]PluginConfig),
	}
}

func (s *InMemoryConfigStore) GetPluginConfig(name string) (PluginConfig, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	
	config, exists := s.configs[name]
	if !exists {
		return PluginConfig{}, fmt.Errorf("plugin config for %s not found", name)
	}
	
	return config, nil
}

func (s *InMemoryConfigStore) SetPluginConfig(name string, config PluginConfig) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	
	s.configs[name] = config
	return nil
}

func (s *InMemoryConfigStore) ListPluginConfigs() (map[string]PluginConfig, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	
	result := make(map[string]PluginConfig)
	for name, config := range s.configs {
		result[name] = config
	}
	
	return result, nil
}

func (s *InMemoryConfigStore) DeletePluginConfig(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	
	delete(s.configs, name)
	return nil
}

// NewPluginManager creates a new plugin manager
func NewPluginManager(registry *Registry) *PluginManager {
	ctx, cancel := context.WithCancel(context.Background())
	
	manager := &PluginManager{
		registry:    registry,
		configStore: NewInMemoryConfigStore(),
		ctx:         ctx,
		cancel:      cancel,
	}
	
	return manager
}

// InstallPlugin installs a plugin with the given configuration
func (pm *PluginManager) InstallPlugin(plugin Plugin, config PluginConfig) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	
	// Register the plugin
	if err := pm.registry.Register(plugin); err != nil {
		return fmt.Errorf("failed to register plugin: %w", err)
	}
	
	// Store the configuration
	if err := pm.configStore.SetPluginConfig(plugin.Name(), config); err != nil {
		// If config storage fails, try to unregister the plugin
		pm.registry.Unregister(plugin.Name())
		return fmt.Errorf("failed to store plugin config: %w", err)
	}
	
	// Initialize the plugin if it's enabled
	if config.Enabled {
		if err := plugin.Initialize(config.Config); err != nil {
			pm.configStore.DeletePluginConfig(plugin.Name())
			pm.registry.Unregister(plugin.Name())
			return fmt.Errorf("failed to initialize plugin: %w", err)
		}
		
		// Start the plugin if it supports start/stop
		if startable, ok := plugin.(interface{ Start(context.Context) error }); ok {
			if err := startable.Start(pm.ctx); err != nil {
				return fmt.Errorf("failed to start plugin: %w", err)
			}
		}
	}
	
	return nil
}

// UninstallPlugin uninstalls a plugin
func (pm *PluginManager) UninstallPlugin(name string) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	
	// Stop the plugin if it's running
	p, err := pm.registry.Get(name)
	if err != nil {
		return fmt.Errorf("plugin %s not found: %w", name, err)
	}
	
	if stoppable, ok := p.(interface{ Stop(context.Context) error }); ok {
		if err := stoppable.Stop(pm.ctx); err != nil {
			return fmt.Errorf("failed to stop plugin: %w", err)
		}
	}
	
	// Remove from registry
	if err := pm.registry.Unregister(name); err != nil {
		return fmt.Errorf("failed to unregister plugin: %w", err)
	}
	
	// Remove from config store
	if err := pm.configStore.DeletePluginConfig(name); err != nil {
		return fmt.Errorf("failed to delete plugin config: %w", err)
	}
	
	return nil
}

// EnablePlugin enables a plugin
func (pm *PluginManager) EnablePlugin(name string) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	
	p, err := pm.registry.Get(name)
	if err != nil {
		return fmt.Errorf("plugin %s not found: %w", name, err)
	}
	
	// Get stored config
	config, err := pm.configStore.GetPluginConfig(name)
	if err != nil {
		return fmt.Errorf("failed to get plugin config: %w", err)
	}
	
	// Initialize the plugin
	if err := p.Initialize(config.Config); err != nil {
		return fmt.Errorf("failed to initialize plugin: %w", err)
	}
	
	// Start the plugin if it supports start/stop
	if startable, ok := p.(interface{ Start(context.Context) error }); ok {
		if err := startable.Start(pm.ctx); err != nil {
			return fmt.Errorf("failed to start plugin: %w", err)
		}
	}
	
	// Update config to enabled
	config.Enabled = true
	if err := pm.configStore.SetPluginConfig(name, config); err != nil {
		return fmt.Errorf("failed to update plugin config: %w", err)
	}
	
	return nil
}

// DisablePlugin disables a plugin
func (pm *PluginManager) DisablePlugin(name string) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	
	p, err := pm.registry.Get(name)
	if err != nil {
		return fmt.Errorf("plugin %s not found: %w", name, err)
	}
	
	// Stop the plugin if it supports stop
	if stoppable, ok := p.(interface{ Stop(context.Context) error }); ok {
		if err := stoppable.Stop(pm.ctx); err != nil {
			return fmt.Errorf("failed to stop plugin: %w", err)
		}
	}
	
	// Get stored config
	config, err := pm.configStore.GetPluginConfig(name)
	if err != nil {
		return fmt.Errorf("failed to get plugin config: %w", err)
	}
	
	// Update config to disabled
	config.Enabled = false
	if err := pm.configStore.SetPluginConfig(name, config); err != nil {
		return fmt.Errorf("failed to update plugin config: %w", err)
	}
	
	return nil
}

// UpdatePluginConfig updates a plugin's configuration
func (pm *PluginManager) UpdatePluginConfig(name string, newConfig PluginConfig) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	
	// Get the plugin
	p, err := pm.registry.Get(name)
	if err != nil {
		return fmt.Errorf("plugin %s not found: %w", name, err)
	}
	
	// If plugin is currently enabled, we need to restart it with new config
	isEnabled := false
	oldConfig, err := pm.configStore.GetPluginConfig(name)
	if err == nil {
		isEnabled = oldConfig.Enabled
	}
	
	// Update the stored config
	if err := pm.configStore.SetPluginConfig(name, newConfig); err != nil {
		return fmt.Errorf("failed to update plugin config: %w", err)
	}
	
	// If the plugin was enabled, reload it with new config
	if isEnabled {
		// Stop the plugin if it supports stop
		if stoppable, ok := p.(interface{ Stop(context.Context) error }); ok {
			if err := stoppable.Stop(pm.ctx); err != nil {
				return fmt.Errorf("failed to stop plugin for config update: %w", err)
			}
		}
		
		// Initialize with new config
		if err := p.Initialize(newConfig.Config); err != nil {
			return fmt.Errorf("failed to initialize plugin with new config: %w", err)
		}
		
		// Start the plugin if it supports start
		if startable, ok := p.(interface{ Start(context.Context) error }); ok {
			if err := startable.Start(pm.ctx); err != nil {
				return fmt.Errorf("failed to start plugin with new config: %w", err)
			}
		}
	}
	
	return nil
}

// GetPluginInfo returns detailed information about a plugin
func (pm *PluginManager) GetPluginInfo(name string) (*PluginInfo, error) {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	
	p, err := pm.registry.Get(name)
	if err != nil {
		return nil, fmt.Errorf("plugin %s not found: %w", name, err)
	}
	
	config, err := pm.configStore.GetPluginConfig(name)
	if err != nil {
		return nil, fmt.Errorf("failed to get plugin config: %w", err)
	}
	
	info := &PluginInfo{
		Name:        p.Name(),
		Type:        p.Type(),
		Version:     p.Version(),
		Description: p.Description(),
		Enabled:     config.Enabled,
		Config:      config.Config,
		CreatedAt:   time.Now(), // In a real implementation, you'd store creation time
		UpdatedAt:   time.Now(),
	}
	
	return info, nil
}

// ListPluginInfos returns detailed information about all plugins
func (pm *PluginManager) ListPluginInfos() ([]*PluginInfo, error) {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	
	pluginNames := pm.registry.List()
	var infos []*PluginInfo
	
	for _, name := range pluginNames {
		info, err := pm.GetPluginInfo(name)
		if err != nil {
			continue // Skip plugins that have issues
		}
		infos = append(infos, info)
	}
	
	return infos, nil
}

// ValidatePluginConfig validates a plugin's configuration
func (pm *PluginManager) ValidatePluginConfig(pluginName string, config map[string]interface{}) error {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	
	p, err := pm.registry.Get(pluginName)
	if err != nil {
		return fmt.Errorf("plugin %s not found: %w", pluginName, err)
	}
	
	return p.Validate(config)
}

// GetPluginConfigSchema returns the configuration schema for a plugin
func (pm *PluginManager) GetPluginConfigSchema(pluginName string) (map[string]interface{}, error) {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	
	p, err := pm.registry.Get(pluginName)
	if err != nil {
		return nil, fmt.Errorf("plugin %s not found: %w", pluginName, err)
	}
	
	return p.GetConfigSchema(), nil
}

// ReloadPlugin reloads a plugin with its stored configuration
func (pm *PluginManager) ReloadPlugin(name string) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	
	p, err := pm.registry.Get(name)
	if err != nil {
		return fmt.Errorf("plugin %s not found: %w", name, err)
	}
	
	config, err := pm.configStore.GetPluginConfig(name)
	if err != nil {
		return fmt.Errorf("failed to get plugin config: %w", err)
	}
	
	// If the plugin supports reload, use it
	if reloadable, ok := p.(interface{ Reload(context.Context, map[string]interface{}) error }); ok {
		return reloadable.Reload(pm.ctx, config.Config)
	}
	
	// Otherwise, restart the plugin with current config
	if stoppable, ok := p.(interface{ Stop(context.Context) error }); ok {
		if err := stoppable.Stop(pm.ctx); err != nil {
			return fmt.Errorf("failed to stop plugin for reload: %w", err)
		}
	}
	
	if err := p.Initialize(config.Config); err != nil {
		return fmt.Errorf("failed to initialize plugin: %w", err)
	}
	
	if startable, ok := p.(interface{ Start(context.Context) error }); ok {
		if err := startable.Start(pm.ctx); err != nil {
			return fmt.Errorf("failed to start plugin: %w", err)
		}
	}
	
	return nil
}

// EnableHotReload enables hot reloading of plugin configurations
func (pm *PluginManager) EnableHotReload(configPath string) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	
	pm.hotReloader = NewHotReloadManager(pm.registry, configPath)
	
	go func() {
		if err := pm.hotReloader.WatchConfig(pm.ctx); err != nil {
			// Log error - in a real implementation you'd use a proper logger
			fmt.Printf("Hot reload error: %v\n", err)
		}
	}()
	
	return nil
}

// Shutdown gracefully shuts down the plugin manager
func (pm *PluginManager) Shutdown() error {
	pm.cancel() // Cancel the context to signal shutdown
	
	// Shutdown the registry which will stop all plugins
	return pm.registry.Shutdown()
}

// ToJSON serializes the plugin manager state to JSON
func (pm *PluginManager) ToJSON() ([]byte, error) {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	
	pluginInfos, err := pm.ListPluginInfos()
	if err != nil {
		return nil, fmt.Errorf("failed to get plugin infos: %w", err)
	}
	
	return json.Marshal(pluginInfos)
}