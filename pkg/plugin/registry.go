package plugin

import (
	"fmt"
	"net/http"
	"reflect"
	"sort"
	"sync"

	coreerrors "github.com/bhangun/iket/pkg/core/errors"
	"github.com/bhangun/iket/pkg/logging"
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

type Factory func(config map[string]interface{}) (Plugin, error)

// Registry manages all plugins
type Registry struct {
	plugins                  map[string]Plugin
	factories                map[string]Factory
	factoryLoads             map[string]*factoryLoad
	clientUsageObserverWires map[string]map[string]struct{}
	mu                       sync.RWMutex
}

type factoryLoad struct {
	done   chan struct{}
	plugin Plugin
	err    error
}

type registeredPlugin struct {
	name   string
	plugin Plugin
}

type HealthChecker interface {
	Health() error
}

type StatusReporter interface {
	Status() string
}

type DiagnosticsReporter interface {
	Diagnostics() map[string]interface{}
}

var globalPlugins = make(map[string]Plugin)
var globalPluginsMu sync.RWMutex

// RegisterGlobal allows plugins to self-register globally (for auto-discovery)
func RegisterGlobal(p Plugin) {
	if pluginIsNil(p) {
		panic("plugin: cannot globally register nil plugin")
	}
	name := p.Name()
	if name == "" {
		panic("plugin: cannot globally register plugin with empty name")
	}

	globalPluginsMu.Lock()
	defer globalPluginsMu.Unlock()
	globalPlugins[name] = p
}

// RegisterAllGlobal registers all globally registered plugins to the given registry
func (r *Registry) RegisterAllGlobal() {
	// Initialize logger
	logger := logging.NewLoggerFromEnv()
	defer logger.Sync()
	plugins := globalRegisteredPluginsSnapshot()
	logger.Info(
		"Registering plugins to registry",
		logging.String("count", fmt.Sprintf("%d", len(plugins))),
	)
	for _, registered := range plugins {
		_ = r.Register(registered.plugin)
	}
}

// NewRegistry creates a new plugin registry
func NewRegistry() *Registry {
	return &Registry{
		plugins:                  make(map[string]Plugin),
		factories:                make(map[string]Factory),
		factoryLoads:             make(map[string]*factoryLoad),
		clientUsageObserverWires: make(map[string]map[string]struct{}),
	}
}

// RegisterFactory registers a plugin factory for a given name
func (r *Registry) RegisterFactory(name string, factory Factory) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.factories == nil {
		r.factories = make(map[string]Factory)
	}
	if r.factoryLoads == nil {
		r.factoryLoads = make(map[string]*factoryLoad)
	}
	r.factories[name] = factory
}

// Register adds a plugin to the registry
func (r *Registry) Register(p Plugin) error {
	name, err := pluginRegistrationName(p)
	if err != nil {
		return err
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.plugins[name]; exists {
		return coreerrors.NewPluginError(name, "already registered", nil)
	}

	r.plugins[name] = p
	return nil
}

// Get returns a plugin by name, using a factory if available
func (r *Registry) Get(name string) (Plugin, error) {
	r.mu.Lock()
	if p, ok := r.plugins[name]; ok {
		r.mu.Unlock()
		return p, nil
	}
	factory, ok := r.factories[name]
	if !ok {
		r.mu.Unlock()
		return nil, coreerrors.NewCodeError(coreerrors.CodePluginNotFound, fmt.Sprintf("plugin %s not found", name), nil)
	}
	if r.factoryLoads == nil {
		r.factoryLoads = make(map[string]*factoryLoad)
	}
	if load, ok := r.factoryLoads[name]; ok {
		r.mu.Unlock()
		<-load.done
		return load.plugin, load.err
	}
	load := &factoryLoad{done: make(chan struct{})}
	r.factoryLoads[name] = load
	r.mu.Unlock()

	plugin, err := loadPluginFromFactory(name, factory)

	r.mu.Lock()
	if err == nil {
		if existing, ok := r.plugins[name]; ok {
			plugin = existing
		} else {
			r.plugins[name] = plugin
		}
	}
	load.plugin = plugin
	load.err = err
	close(load.done)
	delete(r.factoryLoads, name)
	r.mu.Unlock()

	return plugin, err
}

func loadPluginFromFactory(name string, factory Factory) (plugin Plugin, err error) {
	if factory == nil {
		return nil, coreerrors.NewPluginError(name, "factory is nil", nil)
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			plugin = nil
			err = coreerrors.NewPluginError(name, "factory panicked", fmt.Errorf("%v", recovered))
			return
		}
		if err != nil {
			plugin = nil
			return
		}
		if err == nil && pluginIsNil(plugin) {
			err = coreerrors.NewPluginError(name, "factory returned nil plugin", nil)
			return
		}
		if _, nameErr := pluginName(plugin, name); nameErr != nil {
			plugin = nil
			err = nameErr
			return
		}
	}()
	return factory(nil)
}

func pluginRegistrationName(p Plugin) (string, error) {
	if pluginIsNil(p) {
		return "", coreerrors.NewPluginError("<invalid>", "plugin is nil", nil)
	}
	return pluginName(p, "<invalid>")
}

func pluginName(p Plugin, errorName string) (name string, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			name = ""
			err = coreerrors.NewPluginError(errorName, "plugin name panicked", fmt.Errorf("%v", recovered))
			return
		}
		if name == "" {
			err = coreerrors.NewPluginError(errorName, "plugin name is empty", nil)
		}
	}()
	name = p.Name()
	return name, nil
}

func pluginIsNil(p Plugin) bool {
	if p == nil {
		return true
	}
	value := reflect.ValueOf(p)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
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

	return nil, coreerrors.NewCodeError(coreerrors.CodePluginUnsupported, fmt.Sprintf("plugin %s does not implement MiddlewarePlugin interface", name), nil)
}

// IsMiddlewarePlugin checks if a plugin implements the MiddlewarePlugin interface
func (r *Registry) IsMiddlewarePlugin(name string) bool {
	_, err := r.GetMiddlewarePlugin(name)
	return err == nil
}

// GetMiddlewarePlugins returns all plugins that implement MiddlewarePlugin
func (r *Registry) GetMiddlewarePlugins() map[string]MiddlewarePlugin {
	middlewarePlugins := make(map[string]MiddlewarePlugin)
	for _, registered := range r.registeredPluginsSnapshot() {
		if mp, ok := registered.plugin.(MiddlewarePlugin); ok {
			middlewarePlugins[registered.name] = mp
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
			return nil, coreerrors.NewPluginError(name, "failed to get middleware plugin", err)
		}

		handler = mp.Middleware(handler)
	}

	return handler, nil
}

// BuildMiddlewareChainFromTags creates a middleware chain using reflection to detect
// plugins with specific tags or annotations
func (r *Registry) BuildMiddlewareChainFromTags(tagKey, tagValue string, finalHandler http.Handler) (http.Handler, error) {
	handler := finalHandler
	var middlewarePlugins []MiddlewarePlugin

	for _, registered := range r.registeredPluginsSnapshot() {
		p := registered.plugin
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
	for _, registered := range r.registeredPluginsSnapshot() {
		name := registered.name
		//config, ok := configs[name]

		config := configs[name]
		if config == nil {
			config = make(map[string]interface{}) // default empty config
		}

		if err := registered.plugin.Initialize(config); err != nil {
			return coreerrors.NewPluginError(name, "failed to initialize", err)
		}
	}

	return nil
}

// StartAll invokes OnStart for all plugins that implement LifecyclePlugin
func (r *Registry) StartAll() error {
	for _, registered := range r.registeredPluginsSnapshot() {
		name := registered.name
		p := registered.plugin
		if lp, ok := p.(LifecyclePlugin); ok {
			if err := lp.OnStart(); err != nil {
				return coreerrors.NewPluginError(name, "failed to start", err)
			}
		}
	}
	return nil
}

// ShutdownAll invokes OnShutdown for all plugins that implement LifecyclePlugin
func (r *Registry) ShutdownAll() error {
	for _, registered := range r.registeredPluginsSnapshot() {
		name := registered.name
		p := registered.plugin
		if lp, ok := p.(LifecyclePlugin); ok {
			if err := lp.OnShutdown(); err != nil {
				return coreerrors.NewPluginError(name, "failed to shutdown", err)
			}
		}
	}
	return nil
}

// List returns a list of all registered plugin names
func (r *Registry) List() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	nameSet := make(map[string]struct{})
	for name := range r.plugins {
		nameSet[name] = struct{}{}
	}
	for name := range r.factories {
		nameSet[name] = struct{}{}
	}
	return sortedNameSet(nameSet)
}

// ListMiddlewarePlugins returns a list of all registered middleware plugin names
func (r *Registry) ListMiddlewarePlugins() []string {
	var names []string
	for _, registered := range r.registeredPluginsSnapshot() {
		if _, ok := registered.plugin.(MiddlewarePlugin); ok {
			names = append(names, registered.name)
		}
	}
	return names
}

// To filter plugins by type
func (r *Registry) GetByType(pType PluginType) []Plugin {
	result := make([]Plugin, 0)
	for _, registered := range r.registeredPluginsSnapshot() {
		if pluginMatchesType(registered.plugin, pType) {
			result = append(result, registered.plugin)
		}
	}
	return result
}

func pluginMatchesType(p Plugin, pType PluginType) bool {
	if typedPlugin, ok := p.(TypedPlugin); ok {
		return typedPlugin.Type() == pType
	}
	if typedPlugin, ok := p.(interface{ Type() string }); ok {
		return PluginType(typedPlugin.Type()) == pType
	}
	return false
}

// For hot-reloading plugins
func (r *Registry) ReloadAll(configs map[string]map[string]interface{}) error {
	for _, registered := range r.registeredPluginsSnapshot() {
		name := registered.name
		p := registered.plugin
		if rp, ok := p.(ReloadablePlugin); ok {
			if config, ok := configs[name]; ok {
				if err := rp.Reload(config); err != nil {
					return coreerrors.NewPluginError(name, "reload failed", err)
				}
			}
		}
	}
	return nil
}

// HealthCheck runs Health() on all plugins that support it
func (r *Registry) HealthCheck() map[string]error {
	results := make(map[string]error)
	for _, registered := range r.registeredPluginsSnapshot() {
		name := registered.name
		p := registered.plugin
		if hc, ok := p.(HealthChecker); ok {
			results[name] = hc.Health()
		}
	}
	return results
}

// PluginStatuses returns human-readable status strings
func (r *Registry) PluginStatuses() map[string]string {
	statuses := make(map[string]string)
	for _, registered := range r.registeredPluginsSnapshot() {
		name := registered.name
		p := registered.plugin
		if sr, ok := p.(StatusReporter); ok {
			statuses[name] = sr.Status()
		}
	}
	return statuses
}

func (r *Registry) registeredPluginsSnapshot() []registeredPlugin {
	r.mu.RLock()
	defer r.mu.RUnlock()

	names := sortedPluginNames(r.plugins)
	plugins := make([]registeredPlugin, 0, len(names))
	for _, name := range names {
		plugins = append(plugins, registeredPlugin{name: name, plugin: r.plugins[name]})
	}
	return plugins
}

func globalRegisteredPluginsSnapshot() []registeredPlugin {
	globalPluginsMu.RLock()
	defer globalPluginsMu.RUnlock()

	names := sortedPluginNames(globalPlugins)
	plugins := make([]registeredPlugin, 0, len(names))
	for _, name := range names {
		plugins = append(plugins, registeredPlugin{name: name, plugin: globalPlugins[name]})
	}
	return plugins
}

func sortedPluginNames(plugins map[string]Plugin) []string {
	names := make([]string, 0, len(plugins))
	for name := range plugins {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func sortedNameSet(nameSet map[string]struct{}) []string {
	names := make([]string, 0, len(nameSet))
	for name := range nameSet {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

var DefaultRegistry = NewRegistry()

func RegisterFactory(name string, factory Factory) {
	DefaultRegistry.RegisterFactory(name, factory)
}
