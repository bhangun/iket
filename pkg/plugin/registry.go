package plugin

import (
	"fmt"
	"sync"
)

// Plugin interface that all plugins must implement
type Plugin interface {
	Name() string
	Initialize(config map[string]interface{}) error
}

// Registry manages all plugins
type Registry struct {
	plugins map[string]Plugin
	mu      sync.RWMutex
}

// NewRegistry creates a new plugin registry
func NewRegistry() *Registry {
	return &Registry{
		plugins: make(map[string]Plugin),
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

// Initialize initializes all registered plugins with their configurations
func (r *Registry) Initialize(configs map[string]map[string]interface{}) error {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for name, p := range r.plugins {
		config, ok := configs[name]
		if !ok {
			return fmt.Errorf("configuration for plugin %s not found", name)
		}

		if err := p.Initialize(config); err != nil {
			return fmt.Errorf("failed to initialize plugin %s: %w", name, err)
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
