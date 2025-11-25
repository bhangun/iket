package plugin

import (
	"context"
	"net/http"
	"time"
)

// PluginType represents the type of plugin
type PluginType string

const (
	MiddlewarePlugin PluginType = "middleware"
	AuthPlugin       PluginType = "auth"
	RoutePlugin      PluginType = "route"
	MetricPlugin     PluginType = "metric"
	LoggingPlugin    PluginType = "logging"
	StoragePlugin    PluginType = "storage"
)

// Plugin represents the base interface that all plugins must implement
type Plugin interface {
	// Name returns the unique name of the plugin
	Name() string
	
	// Type returns the type of plugin
	Type() PluginType
	
	// Version returns the plugin version
	Version() string
	
	// Description returns a brief description of the plugin
	Description() string
	
	// Initialize initializes the plugin with configuration
	Initialize(config map[string]interface{}) error
	
	// Validate validates the plugin configuration
	Validate(config map[string]interface{}) error
	
	// GetConfigSchema returns the JSON schema for plugin configuration
	GetConfigSchema() map[string]interface{}
	
	// Start starts the plugin (optional)
	Start(ctx context.Context) error
	
	// Stop stops the plugin (optional)
	Stop(ctx context.Context) error
	
	// Reload reloads the plugin configuration (optional)
	Reload(ctx context.Context, config map[string]interface{}) error
}

// MiddlewarePlugin interface for plugins that provide HTTP middleware
type MiddlewarePlugin interface {
	Plugin
	Middleware() func(http.Handler) http.Handler
}

// AuthPlugin interface for authentication plugins
type AuthPlugin interface {
	Plugin
	Authenticate(r *http.Request) (bool, string, error)
	Authorize(r *http.Request, userID string) (bool, error)
}

// RoutePlugin interface for routing plugins
type RoutePlugin interface {
	Plugin
	ModifyRoute(route *RouteConfig) error
}

// RouteConfig represents a route configuration
type RouteConfig struct {
	Path        string            `json:"path"`
	Destination string            `json:"destination"`
	Methods     []string          `json:"methods"`
	Headers     map[string]string `json:"headers"`
	Timeout     *time.Duration    `json:"timeout"`
	RequireAuth bool              `json:"requireAuth"`
	Middlewares []string          `json:"middlewares"`
	Plugins     []string          `json:"plugins"`
}

// PluginInfo contains information about a registered plugin
type PluginInfo struct {
	Name        string      `json:"name"`
	Type        PluginType  `json:"type"`
	Version     string      `json:"version"`
	Description string      `json:"description"`
	Enabled     bool        `json:"enabled"`
	Config      interface{} `json:"config,omitempty"`
	CreatedAt   time.Time   `json:"created_at"`
	UpdatedAt   time.Time   `json:"updated_at"`
}

// PluginConfig represents plugin configuration
type PluginConfig struct {
	Enabled bool                   `json:"enabled"`
	Type    PluginType             `json:"type"`
	Config  map[string]interface{} `json:"config"`
}