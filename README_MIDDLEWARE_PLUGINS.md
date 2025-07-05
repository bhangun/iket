# Middleware Plugin System

This document explains how to use the new middleware plugin system that extends the existing plugin architecture to support HTTP middleware functionality. The system provides backward compatibility with existing plugins while adding new capabilities.

## Overview

The middleware plugin system allows you to create plugins that can inject behavior into the HTTP request/response pipeline. This is useful for implementing cross-cutting concerns like:

- Authentication and authorization
- Rate limiting
- CORS handling
- Request logging
- Security headers
- Request/response transformation

## Core Interfaces

### Plugin Interface
```go
type Plugin interface {
    Name() string
    Initialize(config map[string]interface{}) error
}
```

### MiddlewarePlugin Interface
```go
type MiddlewarePlugin interface {
    Plugin
    Middleware(next http.Handler) http.Handler
}
```

The `MiddlewarePlugin` interface extends the base `Plugin` interface by adding a `Middleware` method that returns an HTTP middleware function.

### Extended Plugin Interfaces

#### TypedPlugin Interface
```go
type TypedPlugin interface {
    Plugin
    Type() PluginType
}
```

#### TaggedPlugin Interface
```go
type TaggedPlugin interface {
    Plugin
    Tags() map[string]string
}
```

#### ReloadablePlugin Interface
```go
type ReloadablePlugin interface {
    Plugin
    Reload(config map[string]interface{}) error
}
```

#### LifecyclePlugin Interface
```go
type LifecyclePlugin interface {
    Plugin
    OnStart() error
    OnShutdown() error
}
```

#### HealthChecker Interface
```go
type HealthChecker interface {
    Health() error
}
```

#### StatusReporter Interface
```go
type StatusReporter interface {
    Status() string
}
```

### Plugin Types
```go
type PluginType string

const (
    AuthPlugin      PluginType = "auth"
    RateLimitPlugin PluginType = "ratelimit"
    TransformPlugin PluginType = "transform"
    Observability   PluginType = "observability"
)
```

## Backward Compatibility

The system provides backward compatibility with existing plugins in `internal/core/plugin` through an adapter pattern. Existing plugins like `RateLimitPlugin`, `CORSPlugin`, etc., can be used with the new system without modification.

### Plugin Migration

Some plugins have been moved to external locations for better organization:

- **OpenAPI Plugin**: Moved from `internal/core/plugin/openapi.go` to `plugins/openapi/`
  - Import: `"iket/plugins/openapi"`
  - Usage: `openapi.NewOpenAPIPlugin()`
  - Same functionality, enhanced middleware integration

### Adapter System
```go
// Create an adapter to work with both plugin systems
adapter := plugin.NewRegistryAdapter()

// Register all existing internal plugins
adapter.RegisterAllInternalPlugins()

// Register new plugins
adapter.GetRegistry().Register(newPlugin)

// Use both old and new plugins together
chain, err := adapter.GetRegistry().BuildMiddlewareChain([]string{"cors", "rate_limit", "auth"}, finalHandler)
```

## Creating a Middleware Plugin

Here's an example of how to create a simple authentication middleware plugin with the new interfaces:

```go
package auth

import (
    "context"
    "fmt"
    "net/http"
    "strings"
    "time"
    
    "iket/pkg/plugin"
)

type AuthPlugin struct {
    apiKey string
    PluginName string `plugin:"type" plugin:"auth"`
    // Health tracking
    lastHealthCheck time.Time
    isHealthy       bool
}

func NewAuthPlugin() *AuthPlugin {
    return &AuthPlugin{
        PluginName:      "auth",
        lastHealthCheck: time.Now(),
        isHealthy:       true,
    }
}

func (a *AuthPlugin) Name() string {
    return a.PluginName
}

// Type implements TypedPlugin interface
func (a *AuthPlugin) Type() plugin.PluginType {
    return plugin.AuthPlugin
}

// Tags implements TaggedPlugin interface
func (a *AuthPlugin) Tags() map[string]string {
    return map[string]string{
        "security": "authentication",
        "priority": "high",
        "category": "auth",
    }
}

// Health implements HealthChecker interface
func (a *AuthPlugin) Health() error {
    a.lastHealthCheck = time.Now()
    
    if a.apiKey == "" {
        a.isHealthy = false
        return fmt.Errorf("auth plugin not properly configured: missing api_key")
    }
    
    a.isHealthy = true
    return nil
}

// Status implements StatusReporter interface
func (a *AuthPlugin) Status() string {
    if a.isHealthy {
        return "healthy"
    }
    return "unhealthy"
}

func (a *AuthPlugin) Initialize(config map[string]interface{}) error {
    if apiKey, ok := config["api_key"].(string); ok {
        a.apiKey = apiKey
        a.isHealthy = true
    } else {
        a.isHealthy = false
        return fmt.Errorf("api_key is required for auth plugin")
    }
    return nil
}

func (a *AuthPlugin) Middleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // Authentication logic here
        authHeader := r.Header.Get("Authorization")
        if authHeader == "" {
            http.Error(w, "Authorization header required", http.StatusUnauthorized)
            return
        }
        
        // Validate token
        token := strings.TrimPrefix(authHeader, "Bearer ")
        if token != a.apiKey {
            http.Error(w, "Invalid API key", http.StatusUnauthorized)
            return
        }
        
        // Add authentication info to context
        ctx := context.WithValue(r.Context(), "authenticated", true)
        ctx = context.WithValue(ctx, "api_key", token)
        
        next.ServeHTTP(w, r.WithContext(ctx))
    })
}
```

## Using the Plugin Registry

### Basic Usage

```go
// Create a new registry
registry := plugin.NewRegistry()

// Register your middleware plugin
authPlugin := auth.NewAuthPlugin()
registry.Register(authPlugin)

// Initialize with configuration
configs := map[string]map[string]interface{}{
    "auth": {
        "api_key": "your-secret-api-key-here",
    },
}
registry.Initialize(configs)

// Create your final handler
finalHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    w.Write([]byte("Hello, World!"))
})

// Build middleware chain
middlewareChain, err := registry.BuildMiddlewareChain([]string{"auth"}, finalHandler)
if err != nil {
    panic(err)
}

// Use the middleware chain
http.ListenAndServe(":8080", middlewareChain)
```

### Advanced Usage with New Features

```go
// Register multiple plugins
registry.Register(auth.NewAuthPlugin())
registry.Register(openapi.NewOpenAPIPlugin())

// Get plugins by type
authPlugins := registry.GetByType(plugin.AuthPlugin)
fmt.Printf("Found %d auth plugins\n", len(authPlugins))

// Get plugin tags
if authP, err := registry.Get("auth"); err == nil {
    if tagged, ok := authP.(plugin.TaggedPlugin); ok {
        fmt.Printf("Auth plugin tags: %v\n", tagged.Tags())
    }
}

// Build chain using tag-based discovery
chain, err := registry.BuildMiddlewareChainFromTags("security", "authentication", finalHandler)
```

### Health Checking and Status Reporting

```go
// Start lifecycle plugins
if err := registry.StartAll(); err != nil {
    panic(fmt.Sprintf("Failed to start plugins: %v", err))
}

// Check plugin health
healthResults := registry.HealthCheck()
for name, err := range healthResults {
    if err != nil {
        fmt.Printf("Plugin %s is unhealthy: %v\n", name, err)
    } else {
        fmt.Printf("Plugin %s is healthy\n", name)
    }
}

// Get plugin statuses
statuses := registry.PluginStatuses()
for name, status := range statuses {
    fmt.Printf("Plugin %s status: %s\n", name, status)
}

// Graceful shutdown
if err := registry.ShutdownAll(); err != nil {
    fmt.Printf("Error during shutdown: %v\n", err)
}
```

### Tag-Based Plugin Discovery

You can use tags to automatically discover and chain middleware plugins:

```go
// Build middleware chain using reflection to find plugins with specific tags
middlewareChain, err := registry.BuildMiddlewareChainFromTags("security", "authentication", finalHandler)
if err != nil {
    panic(err)
}
```

This will find all plugins that have the tag `security: "authentication"`.

## Registry Methods

### Plugin Management
- `Register(p Plugin) error` - Register a new plugin
- `Get(name string) (Plugin, error)` - Get a plugin by name
- `List() []string` - List all registered plugin names

### Middleware-Specific Methods
- `GetMiddlewarePlugin(name string) (MiddlewarePlugin, error)` - Get a plugin as MiddlewarePlugin
- `IsMiddlewarePlugin(name string) bool` - Check if a plugin implements MiddlewarePlugin
- `GetMiddlewarePlugins() map[string]MiddlewarePlugin` - Get all middleware plugins
- `ListMiddlewarePlugins() []string` - List all middleware plugin names

### New Advanced Methods
- `GetByType(pType PluginType) []Plugin` - Get plugins by type
- `BuildMiddlewareChainFromTags(tagKey, tagValue string, finalHandler http.Handler) (http.Handler, error)` - Build chain using tags
- `ReloadAll(configs map[string]map[string]interface{}) error` - Hot-reload plugins

### Lifecycle Methods
- `StartAll() error` - Start all lifecycle plugins
- `ShutdownAll() error` - Shutdown all lifecycle plugins

### Health and Status Methods
- `HealthCheck() map[string]error` - Check health of all plugins
- `PluginStatuses() map[string]string` - Get status of all plugins

### Middleware Chain Building
- `BuildMiddlewareChain(pluginNames []string, finalHandler http.Handler) (http.Handler, error)` - Build chain from explicit plugin names
- `BuildMiddlewareChainFromTags(tagKey, tagValue string, finalHandler http.Handler) (http.Handler, error)` - Build chain using tags

## Middleware Execution Order

When building middleware chains, the middleware is applied in the order specified in the plugin names array. For example:

```go
// This will apply middleware in order: cors -> auth -> rate_limit
chain, err := registry.BuildMiddlewareChain([]string{"cors", "auth", "rate_limit"}, finalHandler)
```

The execution order will be:
1. CORS middleware
2. Authentication middleware  
3. Rate limiting middleware
4. Final handler

## Plugin Types and Tags

### Plugin Types
- **AuthPlugin**: Authentication and authorization plugins
- **RateLimitPlugin**: Rate limiting and throttling plugins
- **TransformPlugin**: Request/response transformation plugins
- **Observability**: Logging, metrics, and monitoring plugins

### Common Tags
- `security`: "authentication", "authorization", "rate-limiting", "ip-filtering"
- `priority`: "high", "medium", "low"
- `category`: "auth", "cors", "documentation", "logging"
- `type`: "api-docs", "monitoring", "transformation"

## Health Checking and Monitoring

### Health Check Implementation

Plugins can implement the `HealthChecker` interface to provide health status:

```go
func (p *MyPlugin) Health() error {
    // Check if plugin is properly configured
    if p.config == nil {
        return fmt.Errorf("plugin not configured")
    }
    
    // Check external dependencies
    if err := p.checkDatabaseConnection(); err != nil {
        return fmt.Errorf("database connection failed: %w", err)
    }
    
    // Check internal state
    if p.isOverloaded() {
        return fmt.Errorf("plugin is overloaded")
    }
    
    return nil // Plugin is healthy
}
```

### Status Reporting Implementation

Plugins can implement the `StatusReporter` interface to provide human-readable status:

```go
func (p *MyPlugin) Status() string {
    if !p.enabled {
        return "disabled"
    }
    if p.isHealthy {
        return "healthy"
    }
    if p.isDegraded {
        return "degraded"
    }
    return "unhealthy"
}
```

### Health Check Endpoint Example

```go
http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
    healthResults := registry.HealthCheck()
    statuses := registry.PluginStatuses()
    
    w.Header().Set("Content-Type", "application/json")
    
    hasErrors := false
    response := map[string]interface{}{
        "timestamp": time.Now().Format(time.RFC3339),
        "overall":   "healthy",
        "plugins":   make(map[string]interface{}),
    }
    
    for name, err := range healthResults {
        pluginInfo := map[string]interface{}{
            "status": statuses[name],
        }
        if err != nil {
            pluginInfo["error"] = err.Error()
            hasErrors = true
        }
        response["plugins"].(map[string]interface{})[name] = pluginInfo
    }
    
    if hasErrors {
        response["overall"] = "unhealthy"
        w.WriteHeader(http.StatusServiceUnavailable)
    }
    
    json.NewEncoder(w).Encode(response)
})
```

## Best Practices

1. **Error Handling**: Always check for errors when registering and initializing plugins
2. **Configuration**: Use strongly-typed configuration maps for better type safety
3. **Context Usage**: Use request context to pass data between middleware
4. **Performance**: Keep middleware lightweight and avoid expensive operations
5. **Testing**: Test each middleware plugin in isolation and as part of a chain
6. **Tagging**: Use meaningful tags to categorize and discover plugins
7. **Type Safety**: Implement appropriate plugin types for better organization
8. **Health Monitoring**: Implement health checks for critical plugins
9. **Graceful Shutdown**: Use lifecycle hooks for proper cleanup
10. **Status Reporting**: Provide meaningful status information for monitoring

## Example: Multiple Middleware Chain

```go
// Register multiple middleware plugins
registry.Register(&CORSPlugin{})
registry.Register(&AuthPlugin{})
registry.Register(&RateLimitPlugin{})

// Initialize all plugins
configs := map[string]map[string]interface{}{
    "cors": {
        "allow_origin": "*",
        "allow_methods": "GET,POST,PUT,DELETE",
    },
    "auth": {
        "api_key": "secret-key",
    },
    "rate_limit": {
        "requests_per_second": 10,
        "burst": 20,
    },
}
registry.Initialize(configs)

// Start lifecycle plugins
registry.StartAll()

// Build chain with multiple middleware
chain, err := registry.BuildMiddlewareChain([]string{"cors", "auth", "rate_limit"}, finalHandler)

// Monitor health
go func() {
    ticker := time.NewTicker(30 * time.Second)
    for range ticker.C {
        healthResults := registry.HealthCheck()
        for name, err := range healthResults {
            if err != nil {
                log.Printf("Plugin %s health check failed: %v", name, err)
            }
        }
    }
}()
```

This creates a comprehensive middleware stack that handles CORS, authentication, and rate limiting for your HTTP server with health monitoring. 