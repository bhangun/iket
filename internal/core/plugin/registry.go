package plugin

import (
	"fmt"
	"net/http"
)

// Plugin is the interface that all gateway plugins must implement
// Plugins can provide middleware or hooks for requests
type Plugin interface {
	Name() string
	Init(config map[string]interface{}) error
	Middleware() func(next http.Handler) http.Handler
}

// Registry holds all registered plugins
var registry = make(map[string]Plugin)

// Register registers a plugin by name
func Register(p Plugin) {
	name := p.Name()
	if _, exists := registry[name]; exists {
		panic(fmt.Sprintf("plugin %s already registered", name))
	}
	registry[name] = p
}

// Get returns a plugin by name
func Get(name string) (Plugin, bool) {
	p, ok := registry[name]
	return p, ok
}

// All returns all registered plugins
func All() map[string]Plugin {
	return registry
}
