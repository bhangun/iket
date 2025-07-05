package plugin

import (
	"fmt"
	"net/http"

	internalplugin "iket/internal/core/plugin"
)

// Adapter bridges between the existing internal/core/plugin system and the new pkg/plugin system
type Adapter struct {
	internalPlugin internalplugin.Plugin
}

// NewAdapter creates a new adapter for an internal plugin
func NewAdapter(p internalplugin.Plugin) *Adapter {
	return &Adapter{
		internalPlugin: p,
	}
}

// Name returns the plugin name
func (a *Adapter) Name() string {
	return a.internalPlugin.Name()
}

// Initialize adapts the internal plugin's Init method
func (a *Adapter) Initialize(config map[string]interface{}) error {
	return a.internalPlugin.Init(config)
}

// Middleware adapts the internal plugin's Middleware method
func (a *Adapter) Middleware(next http.Handler) http.Handler {
	return a.internalPlugin.Middleware()(next)
}

// RegistryAdapter provides methods to work with both plugin systems
type RegistryAdapter struct {
	internalRegistry map[string]internalplugin.Plugin
	newRegistry      *Registry
}

// NewRegistryAdapter creates a new registry adapter
func NewRegistryAdapter() *RegistryAdapter {
	return &RegistryAdapter{
		internalRegistry: internalplugin.All(),
		newRegistry:      NewRegistry(),
	}
}

// RegisterInternalPlugin registers an internal plugin with the new registry system
func (ra *RegistryAdapter) RegisterInternalPlugin(name string) error {
	if plugin, exists := ra.internalRegistry[name]; exists {
		adapter := NewAdapter(plugin)
		return ra.newRegistry.Register(adapter)
	}
	return fmt.Errorf("internal plugin %s not found", name)
}

// RegisterAllInternalPlugins registers all internal plugins with the new registry system
func (ra *RegistryAdapter) RegisterAllInternalPlugins() error {
	for name := range ra.internalRegistry {
		if err := ra.RegisterInternalPlugin(name); err != nil {
			return err
		}
	}
	return nil
}

// GetRegistry returns the new registry with all plugins
func (ra *RegistryAdapter) GetRegistry() *Registry {
	return ra.newRegistry
}

// BuildMiddlewareChainFromInternal builds a middleware chain using internal plugins
func (ra *RegistryAdapter) BuildMiddlewareChainFromInternal(pluginNames []string, finalHandler http.Handler) (http.Handler, error) {
	handler := finalHandler

	// Apply middleware in reverse order (last to first) to maintain correct execution order
	for i := len(pluginNames) - 1; i >= 0; i-- {
		name := pluginNames[i]
		plugin, exists := ra.internalRegistry[name]
		if !exists {
			return nil, fmt.Errorf("internal plugin %s not found", name)
		}

		handler = plugin.Middleware()(handler)
	}

	return handler, nil
}
