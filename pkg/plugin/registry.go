package plugin

import (
	"fmt"
	"net/http"
	"sync"
)

// Plugin interface that all plugins must implement
type Plugin interface {
	Name() string
	Initialize(config map[string]interface{}) error
}

type PluginType string

const (
	AuthPlugin      PluginType = "auth"
	RateLimitPlugin PluginType = "ratelimit"
	TransformPlugin PluginType = "transform"
	Observability   PluginType = "observability"
)

type TypedPlugin interface {
	Plugin
	Type() PluginType
}

type ReloadablePlugin interface {
	Plugin
	Reload(config map[string]interface{}) error
}

// To be support hooks
type LifecyclePlugin interface {
	Plugin
	OnStart() error
	OnShutdown() error
}

// To let plugins declare tags/types
type TaggedPlugin interface {
	Plugin
	Tags() map[string]string
}

// MiddlewarePlugin extends Plugin to support HTTP middleware functionality
type MiddlewarePlugin interface {
	Plugin
	Middleware(next http.Handler) http.Handler
}

// Registry manages all plugins
type Registry struct {
	plugins map[string]Plugin
	mu      sync.RWMutex
}

type HealthChecker interface {
	Health() error
}

type StatusReporter interface {
	Status() string
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

// GetMiddlewarePlugin returns a plugin as MiddlewarePlugin if it implements the interface
func (r *Registry) GetMiddlewarePlugin(name string) (MiddlewarePlugin, error) {
	p, err := r.Get(name)
	if err != nil {
		return nil, err
	}

	if mp, ok := p.(MiddlewarePlugin); ok {
		return mp, nil
	}

	return nil, fmt.Errorf("plugin %s does not implement MiddlewarePlugin interface", name)
}

// IsMiddlewarePlugin checks if a plugin implements the MiddlewarePlugin interface
func (r *Registry) IsMiddlewarePlugin(name string) bool {
	_, err := r.GetMiddlewarePlugin(name)
	return err == nil
}

// GetMiddlewarePlugins returns all plugins that implement MiddlewarePlugin
func (r *Registry) GetMiddlewarePlugins() map[string]MiddlewarePlugin {
	r.mu.RLock()
	defer r.mu.RUnlock()

	middlewarePlugins := make(map[string]MiddlewarePlugin)
	for name, p := range r.plugins {
		if mp, ok := p.(MiddlewarePlugin); ok {
			middlewarePlugins[name] = mp
		}
	}
	return middlewarePlugins
}

// BuildMiddlewareChain creates a middleware chain from a list of plugin names
// The middleware will be applied in the order specified
func (r *Registry) BuildMiddlewareChain(pluginNames []string, finalHandler http.Handler) (http.Handler, error) {
	handler := finalHandler

	// Apply middleware in reverse order (last to first) to maintain correct execution order
	for i := len(pluginNames) - 1; i >= 0; i-- {
		name := pluginNames[i]
		mp, err := r.GetMiddlewarePlugin(name)
		if err != nil {
			return nil, fmt.Errorf("failed to get middleware plugin %s: %w", name, err)
		}

		handler = mp.Middleware(handler)
	}

	return handler, nil
}

// BuildMiddlewareChainFromTags creates a middleware chain using reflection to detect
// plugins with specific tags or annotations
func (r *Registry) BuildMiddlewareChainFromTags(tagKey, tagValue string, finalHandler http.Handler) (http.Handler, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	handler := finalHandler
	var middlewarePlugins []MiddlewarePlugin

	for _, p := range r.plugins {
		// Check if it’s both a middleware and a tagged plugin
		mp, isMiddleware := p.(MiddlewarePlugin)
		tp, isTagged := p.(TaggedPlugin)

		if isMiddleware && isTagged {
			if tagVal, ok := tp.Tags()[tagKey]; ok && tagVal == tagValue {
				middlewarePlugins = append(middlewarePlugins, mp)
			}
		}
	}

	// Apply middleware in reverse
	for i := len(middlewarePlugins) - 1; i >= 0; i-- {
		handler = middlewarePlugins[i].Middleware(handler)
	}

	return handler, nil
}

// Initialize initializes all registered plugins with their configurations
func (r *Registry) Initialize(configs map[string]map[string]interface{}) error {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for name, p := range r.plugins {
		//config, ok := configs[name]

		config := configs[name]
		if config == nil {
			config = make(map[string]interface{}) // default empty config
		}

		if err := p.Initialize(config); err != nil {
			return fmt.Errorf("failed to initialize plugin %s: %w", name, err)
		}
	}

	return nil
}

// StartAll invokes OnStart for all plugins that implement LifecyclePlugin
func (r *Registry) StartAll() error {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for name, p := range r.plugins {
		if lp, ok := p.(LifecyclePlugin); ok {
			if err := lp.OnStart(); err != nil {
				return fmt.Errorf("plugin %s failed to start: %w", name, err)
			}
		}
	}
	return nil
}

// ShutdownAll invokes OnShutdown for all plugins that implement LifecyclePlugin
func (r *Registry) ShutdownAll() error {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for name, p := range r.plugins {
		if lp, ok := p.(LifecyclePlugin); ok {
			if err := lp.OnShutdown(); err != nil {
				return fmt.Errorf("plugin %s failed to shutdown: %w", name, err)
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

// ListMiddlewarePlugins returns a list of all registered middleware plugin names
func (r *Registry) ListMiddlewarePlugins() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var names []string
	for name, p := range r.plugins {
		if _, ok := p.(MiddlewarePlugin); ok {
			names = append(names, name)
		}
	}
	return names
}

// To filter plugins by type
func (r *Registry) GetByType(pType PluginType) []Plugin {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var result []Plugin
	for _, p := range r.plugins {
		if tp, ok := p.(TypedPlugin); ok && tp.Type() == pType {
			result = append(result, p)
		}
	}
	return result
}

// For hot-reloading plugins
func (r *Registry) ReloadAll(configs map[string]map[string]interface{}) error {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for name, p := range r.plugins {
		if rp, ok := p.(ReloadablePlugin); ok {
			if config, ok := configs[name]; ok {
				if err := rp.Reload(config); err != nil {
					return fmt.Errorf("reload failed for plugin %s: %w", name, err)
				}
			}
		}
	}
	return nil
}

// HealthCheck runs Health() on all plugins that support it
func (r *Registry) HealthCheck() map[string]error {
	r.mu.RLock()
	defer r.mu.RUnlock()

	results := make(map[string]error)
	for name, p := range r.plugins {
		if hc, ok := p.(HealthChecker); ok {
			results[name] = hc.Health()
		}
	}
	return results
}

// PluginStatuses returns human-readable status strings
func (r *Registry) PluginStatuses() map[string]string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	statuses := make(map[string]string)
	for name, p := range r.plugins {
		if sr, ok := p.(StatusReporter); ok {
			statuses[name] = sr.Status()
		}
	}
	return statuses
}
