package plugin

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"plugin"
	"sync"
	"time"
)

// DynamicPluginLoader handles loading of dynamic plugins from .so files
type DynamicPluginLoader struct {
	pluginsDir string
	loaded     map[string]*plugin.Plugin
	mu         sync.RWMutex
}

// NewDynamicPluginLoader creates a new dynamic plugin loader
func NewDynamicPluginLoader(pluginsDir string) *DynamicPluginLoader {
	return &DynamicPluginLoader{
		pluginsDir: pluginsDir,
		loaded:     make(map[string]*plugin.Plugin),
	}
}

// LoadPlugin loads a dynamic plugin from a .so file
func (d *DynamicPluginLoader) LoadPlugin(pluginFile string) (Plugin, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	pluginPath := filepath.Join(d.pluginsDir, pluginFile)
	if _, err := os.Stat(pluginPath); err != nil {
		return nil, fmt.Errorf("plugin file does not exist: %s", pluginPath)
	}

	// Load the plugin
	p, err := plugin.Open(pluginPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open plugin %s: %w", pluginPath, err)
	}

	// Look for the Plugin symbol
	symbol, err := p.Lookup("Plugin")
	if err != nil {
		return nil, fmt.Errorf("plugin %s missing 'Plugin' symbol: %w", pluginFile, err)
	}

	// Type assert to our Plugin interface
	pluginInstance, ok := symbol.(Plugin)
	if !ok {
		return nil, fmt.Errorf("plugin %s symbol does not implement Plugin interface", pluginFile)
	}

	// Store the loaded plugin reference
	d.loaded[pluginFile] = p

	return pluginInstance, nil
}

// LoadAllPlugins loads all plugins from the plugins directory
func (d *DynamicPluginLoader) LoadAllPlugins(registry *Registry) error {
	entries, err := os.ReadDir(d.pluginsDir)
	if err != nil {
		return fmt.Errorf("failed to read plugins directory %s: %w", d.pluginsDir, err)
	}

	for _, entry := range entries {
		if !entry.IsDir() && filepath.Ext(entry.Name()) == ".so" {
			pluginInstance, err := d.LoadPlugin(entry.Name())
			if err != nil {
				return fmt.Errorf("failed to load plugin %s: %w", entry.Name(), err)
			}

			if err := registry.Register(pluginInstance); err != nil {
				return fmt.Errorf("failed to register plugin %s: %w", entry.Name(), err)
			}
		}
	}

	return nil
}

// ReloadPlugin reloads a dynamic plugin (not supported in Go's plugin system, so we return an error)
func (d *DynamicPluginLoader) ReloadPlugin(pluginFile string) error {
	return fmt.Errorf("dynamic plugin reloading is not supported in Go. Plugin %s must be restarted", pluginFile)
}

// UnloadPlugin unloads a dynamic plugin (not supported in Go's plugin system)
func (d *DynamicPluginLoader) UnloadPlugin(pluginFile string) error {
	return fmt.Errorf("dynamic plugin unloading is not supported in Go")
}

// HotReloadManager manages hot reloading of configuration for plugins
type HotReloadManager struct {
	registry    *Registry
	configPath  string
	lastModTime int64
	mu          sync.RWMutex
}

// NewHotReloadManager creates a new hot reload manager
func NewHotReloadManager(registry *Registry, configPath string) *HotReloadManager {
	return &HotReloadManager{
		registry:   registry,
		configPath: configPath,
	}
}

// WatchConfig watches for configuration changes and reloads plugins
func (h *HotReloadManager) WatchConfig(ctx context.Context) error {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if err := h.checkAndReload(); err != nil {
				// Log error but continue watching
				continue
			}
		}
	}
}

// checkAndReload checks if config has changed and reloads if necessary
func (h *HotReloadManager) checkAndReload() error {
	h.mu.Lock()
	defer h.mu.Unlock()

	info, err := os.Stat(h.configPath)
	if err != nil {
		return fmt.Errorf("failed to stat config file: %w", err)
	}

	modTime := info.ModTime().Unix()
	if modTime > h.lastModTime {
		// Config has changed, reload plugins
		newConfig, err := LoadConfigFromFile(h.configPath) // You'll need to implement this
		if err != nil {
			return fmt.Errorf("failed to load new config: %w", err)
		}

		// Reload enabled plugins with new config
		for name, pluginConfig := range newConfig.Plugins {
			if pluginConfig.Enabled {
				if err := h.registry.Reload(name, pluginConfig.Config); err != nil {
					return fmt.Errorf("failed to reload plugin %s: %w", name, err)
				}
			}
		}

		h.lastModTime = modTime
	}

	return nil
}

// LoadConfigFromFile is a placeholder function to load config from file
// You'll need to implement this based on your config structure
func LoadConfigFromFile(path string) (*Config, error) {
	// This is a placeholder - implement based on your config structure
	return nil, fmt.Errorf("LoadConfigFromFile not implemented")
}

// Config represents the configuration structure (placeholder)
type Config struct {
	Plugins map[string]PluginConfig `json:"plugins"`
}