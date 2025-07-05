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

Here's an example of how to create a simple authentication middleware plugin:

```go
package auth

import (
    "context"
    "fmt"
    "net/http"
    "strings"
    
    "iket/pkg/plugin"
)

type AuthPlugin struct {
    apiKey string
    PluginName string `plugin:"type" plugin:"auth"`
}

func NewAuthPlugin() *AuthPlugin {
    return &AuthPlugin{
        PluginName: "auth",
    }
}

func (a *AuthPlugin) Name() string {
    return a.PluginName
}

func (a *AuthPlugin) Initialize(config map[string]interface{}) error {
    if apiKey, ok := config["api_key"].(string); ok {
        a.apiKey = apiKey
    } else {
        return fmt.Errorf("api_key is required for auth plugin")
    }
    return nil
}

func (a *AuthPlugin) Middleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // Extract and validate API key from Authorization header
        authHeader := r.Header.Get("Authorization")
        if authHeader == "" {
            http.Error(w, "Authorization header required", http.StatusUnauthorized)
            return
        }
        
        if !strings.HasPrefix(authHeader, "Bearer ") {
            http.Error(w, "Invalid authorization format", http.StatusUnauthorized)
            return
        }
        
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

### Reflection-Based Plugin Discovery

You can also use reflection to automatically discover and chain middleware plugins based on struct tags:

```go
// Build middleware chain using reflection to find plugins with specific tags
middlewareChain, err := registry.BuildMiddlewareChainFromTags("plugin", "auth", finalHandler)
if err != nil {
    panic(err)
}
```

This will find all plugins that have a struct field with the tag `plugin:"auth"`.

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

### Middleware Chain Building
- `BuildMiddlewareChain(pluginNames []string, finalHandler http.Handler) (http.Handler, error)` - Build chain from explicit plugin names
- `BuildMiddlewareChainFromTags(tagKey, tagValue string, finalHandler http.Handler) (http.Handler, error)` - Build chain using reflection

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

## Best Practices

1. **Error Handling**: Always check for errors when registering and initializing plugins
2. **Configuration**: Use strongly-typed configuration maps for better type safety
3. **Context Usage**: Use request context to pass data between middleware
4. **Performance**: Keep middleware lightweight and avoid expensive operations
5. **Testing**: Test each middleware plugin in isolation and as part of a chain

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

// Build chain with multiple middleware
chain, err := registry.BuildMiddlewareChain([]string{"cors", "auth", "rate_limit"}, finalHandler)
```

This creates a comprehensive middleware stack that handles CORS, authentication, and rate limiting for your HTTP server. 