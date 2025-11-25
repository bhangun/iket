package plugin

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// Registry manages all plugins
type Registry struct {
	plugins map[string]Plugin
	mu      sync.RWMutex
	ctx     context.Context
	cancel  context.CancelFunc
}

// NewRegistry creates a new plugin registry
func NewRegistry() *Registry {
	ctx, cancel := context.WithCancel(context.Background())
	return &Registry{
		plugins: make(map[string]Plugin),
		ctx:     ctx,
		cancel:  cancel,
	}
}

// Register adds a plugin to the registry
func (r *Registry) Register(p Plugin) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	name := p.Name()
	if _, exists := r.plugins[name]; exists {
		return fmt.Errorf("plugin %s already registered", name)
	}

	// Validate the plugin configuration schema if available
	if err := p.Validate(nil); err != nil {
		return fmt.Errorf("plugin %s validation failed: %w", name, err)
	}

	r.plugins[name] = p
	return nil
}

// Get returns a plugin by name
func (r *Registry) Get(name string) (Plugin, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	p, ok := r.plugins[name]
	if !ok {
		return nil, fmt.Errorf("plugin %s not found", name)
	}

	return p, nil
}

// GetByType returns plugins of a specific type
func (r *Registry) GetByType(pluginType PluginType) []Plugin {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var plugins []Plugin
	for _, p := range r.plugins {
		if p.Type() == pluginType {
			plugins = append(plugins, p)
		}
	}
	return plugins
}

// Initialize initializes all registered plugins with their configurations
func (r *Registry) Initialize(configs map[string]PluginConfig) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	for name, pluginConfig := range configs {
		p, ok := r.plugins[name]
		if !ok {
			return fmt.Errorf("plugin %s not found", name)
		}

		// Only initialize if enabled
		if !pluginConfig.Enabled {
			continue
		}

		if err := p.Initialize(pluginConfig.Config); err != nil {
			return fmt.Errorf("failed to initialize plugin %s: %w", name, err)
		}

		// Start the plugin if it implements start/stop
		if startable, ok := p.(interface{ Start(context.Context) error }); ok {
			if err := startable.Start(r.ctx); err != nil {
				return fmt.Errorf("failed to start plugin %s: %w", name, err)
			}
		}
	}

	return nil
}

// List returns a list of all registered plugin names
func (r *Registry) List() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var names []string
	for name := range r.plugins {
		names = append(names, name)
	}
	return names
}

// ListInfo returns detailed information about all registered plugins
func (r *Registry) ListInfo() []PluginInfo {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var infos []PluginInfo
	for name, p := range r.plugins {
		info := PluginInfo{
			Name:        name,
			Type:        p.Type(),
			Version:     p.Version(),
			Description: p.Description(),
			Enabled:     true, // This would be determined by actual state
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		}
		infos = append(infos, info)
	}
	return infos
}

// Reload reloads a specific plugin with new configuration
func (r *Registry) Reload(name string, config map[string]interface{}) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	p, ok := r.plugins[name]
	if !ok {
		return fmt.Errorf("plugin %s not found", name)
	}

	if reloadable, ok := p.(interface{ Reload(context.Context, map[string]interface{}) error }); ok {
		return reloadable.Reload(r.ctx, config)
	}

	return fmt.Errorf("plugin %s does not support reload", name)
}

// Unregister removes a plugin from the registry
func (r *Registry) Unregister(name string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	p, ok := r.plugins[name]
	if !ok {
		return fmt.Errorf("plugin %s not found", name)
	}

	// Stop the plugin if it implements start/stop
	if stoppable, ok := p.(interface{ Stop(context.Context) error }); ok {
		if err := stoppable.Stop(r.ctx); err != nil {
			return fmt.Errorf("failed to stop plugin %s: %w", name, err)
		}
	}

	delete(r.plugins, name)
	return nil
}

// Shutdown gracefully shuts down all plugins
func (r *Registry) Shutdown() error {
	r.cancel() // Cancel the context to signal shutdown
	
	r.mu.Lock()
	defer r.mu.Unlock()

	var lastErr error
	for name, p := range r.plugins {
		if stoppable, ok := p.(interface{ Stop(context.Context) error }); ok {
			if err := stoppable.Stop(r.ctx); err != nil {
				lastErr = fmt.Errorf("failed to stop plugin %s: %w", name, err)
			}
		}
	}

	return lastErr
}

// IsRegistered checks if a plugin is registered
func (r *Registry) IsRegistered(name string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()

	_, exists := r.plugins[name]
	return exists
}

// GetConfigSchema returns the configuration schema for a plugin
func (r *Registry) GetConfigSchema(name string) (map[string]interface{}, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	p, ok := r.plugins[name]
	if !ok {
		return nil, fmt.Errorf("plugin %s not found", name)
	}

	return p.GetConfigSchema(), nil
}
