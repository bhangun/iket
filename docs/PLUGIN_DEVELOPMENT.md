# Plugin Development Guide

This guide explains how to create custom plugins for the Iket API Gateway. Plugins allow you to extend the gateway's functionality with custom middleware, authentication, validation, and more.

## Table of Contents

1. [Plugin Architecture](#plugin-architecture)
2. [Plugin Interfaces](#plugin-interfaces)
3. [Creating a Basic Plugin](#creating-a-basic-plugin)
4. [Plugin Lifecycle](#plugin-lifecycle)
5. [Configuration](#configuration)
6. [Middleware Implementation](#middleware-implementation)
7. [Health Checking](#health-checking)
8. [Status Reporting](#status-reporting)
9. [Plugin Registration](#plugin-registration)
10. [Testing Plugins](#testing-plugins)
11. [Best Practices](#best-practices)
12. [Examples](#examples)

## Plugin Architecture

Iket uses a plugin system that supports multiple interfaces:

- **Basic Plugin**: Core functionality (name, initialization)
- **Middleware Plugin**: HTTP middleware capabilities
- **Typed Plugin**: Categorization by type
- **Tagged Plugin**: Metadata and discovery
- **Lifecycle Plugin**: Startup/shutdown hooks
- **Health Checker**: Health monitoring
- **Status Reporter**: Status reporting
- **Reloadable Plugin**: Hot-reload support

## Plugin Interfaces

### Core Interfaces

```go
// Basic plugin interface
type Plugin interface {
    Name() string
    Initialize(config map[string]interface{}) error
}

// Middleware plugin interface
type MiddlewarePlugin interface {
    Plugin
    Middleware(next http.Handler) http.Handler
}

// Typed plugin interface
type TypedPlugin interface {
    Plugin
    Type() PluginType
}

// Tagged plugin interface
type TaggedPlugin interface {
    Plugin
    Tags() map[string]string
}

// Lifecycle plugin interface
type LifecyclePlugin interface {
    Plugin
    OnStart() error
    OnShutdown() error
}

// Health checker interface
type HealthChecker interface {
    Health() error
}

// Status reporter interface
type StatusReporter interface {
    Status() string
}

// Reloadable plugin interface
type ReloadablePlugin interface {
    Plugin
    Reload(config map[string]interface{}) error
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

## Creating a Basic Plugin

Here's a minimal plugin example:

```go
package myplugin

import (
    "net/http"
    "sync"
)

type MyPlugin struct {
    enabled bool
    mu      sync.RWMutex
}

func (p *MyPlugin) Name() string {
    return "my_plugin"
}

func (p *MyPlugin) Initialize(config map[string]interface{}) error {
    p.mu.Lock()
    defer p.mu.Unlock()
    
    // Set default values
    p.enabled = true
    
    // Load configuration
    if enabled, ok := config["enabled"].(bool); ok {
        p.enabled = enabled
    }
    
    return nil
}
```

## Plugin Lifecycle

### Initialization
- `Initialize()` is called when the plugin is first loaded
- Configuration is passed as a map[string]interface{}
- Set up resources, validate configuration

### Startup
- `OnStart()` is called when the gateway starts
- Initialize connections, start background processes
- Return error if startup fails

### Runtime
- `Middleware()` is called for each HTTP request
- Process requests, modify responses
- Handle errors gracefully

### Shutdown
- `OnShutdown()` is called when the gateway stops
- Clean up resources, close connections
- Return error if shutdown fails

## Configuration

Plugins receive configuration through the `Initialize()` method:

```go
func (p *MyPlugin) Initialize(config map[string]interface{}) error {
    // Access configuration values
    if enabled, ok := config["enabled"].(bool); ok {
        p.enabled = enabled
    }
    
    if timeout, ok := config["timeout"].(float64); ok {
        p.timeout = time.Duration(timeout) * time.Second
    }
    
    if paths, ok := config["skip_paths"].([]interface{}); ok {
        for _, path := range paths {
            if pathStr, ok := path.(string); ok {
                p.skipPaths = append(p.skipPaths, pathStr)
            }
        }
    }
    
    return nil
}
```

## Middleware Implementation

Here's how to implement HTTP middleware:

```go
func (p *MyPlugin) Middleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // Pre-processing
        if !p.enabled {
            next.ServeHTTP(w, r)
            return
        }
        
        // Skip processing for certain paths
        if p.shouldSkip(r.URL.Path) {
            next.ServeHTTP(w, r)
            return
        }
        
        // Process request
        if err := p.processRequest(r); err != nil {
            p.writeError(w, err.Error(), http.StatusBadRequest)
            return
        }
        
        // Call next handler
        next.ServeHTTP(w, r)
        
        // Post-processing
        p.processResponse(w, r)
    })
}
```

## Health Checking

Implement health checking for your plugin:

```go
func (p *MyPlugin) Health() error {
    p.mu.RLock()
    defer p.mu.RUnlock()
    
    if !p.enabled {
        return fmt.Errorf("plugin is disabled")
    }
    
    // Check if plugin is healthy
    if err := p.checkHealth(); err != nil {
        return fmt.Errorf("health check failed: %w", err)
    }
    
    return nil
}

func (p *MyPlugin) checkHealth() error {
    // Implement your health check logic
    // e.g., check database connections, external services, etc.
    return nil
}
```

## Status Reporting

Provide human-readable status information:

```go
func (p *MyPlugin) Status() string {
    p.mu.RLock()
    defer p.mu.RUnlock()
    
    if !p.enabled {
        return "MyPlugin: Disabled"
    }
    
    return fmt.Sprintf("MyPlugin: Enabled (processed: %d requests)", p.requestCount)
}
```

## Plugin Registration

### Method 1: Direct Registration

```go
package main

import (
    "iket/pkg/plugin"
    "myproject/myplugin"
)

func main() {
    registry := plugin.NewRegistry()
    
    // Register your plugin
    myPlugin := &myplugin.MyPlugin{}
    if err := registry.Register(myPlugin); err != nil {
        log.Fatal(err)
    }
    
    // Initialize with configuration
    config := map[string]map[string]interface{}{
        "my_plugin": {
            "enabled": true,
            "timeout": 30.0,
        },
    }
    
    if err := registry.Initialize(config); err != nil {
        log.Fatal(err)
    }
}
```

### Method 2: Dynamic Loading

Compile your plugin as a shared library:

```bash
go build -buildmode=plugin -o myplugin.so myplugin.go
```

Place the `.so` file in the gateway's plugins directory and it will be loaded automatically.

## Testing Plugins

Create unit tests for your plugin:

```go
package myplugin

import (
    "net/http"
    "net/http/httptest"
    "testing"
)

func TestMyPlugin_Initialize(t *testing.T) {
    plugin := &MyPlugin{}
    
    config := map[string]interface{}{
        "enabled": true,
        "timeout": 30.0,
    }
    
    err := plugin.Initialize(config)
    if err != nil {
        t.Errorf("Initialize failed: %v", err)
    }
    
    if !plugin.enabled {
        t.Error("Plugin should be enabled")
    }
}

func TestMyPlugin_Middleware(t *testing.T) {
    plugin := &MyPlugin{}
    plugin.Initialize(map[string]interface{}{"enabled": true})
    
    // Create test request
    req := httptest.NewRequest("GET", "/test", nil)
    w := httptest.NewRecorder()
    
    // Create test handler
    testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.WriteHeader(http.StatusOK)
        w.Write([]byte("OK"))
    })
    
    // Test middleware
    middleware := plugin.Middleware(testHandler)
    middleware.ServeHTTP(w, req)
    
    if w.Code != http.StatusOK {
        t.Errorf("Expected status 200, got %d", w.Code)
    }
}
```

## Best Practices

### 1. Thread Safety
- Use mutexes to protect shared state
- Avoid global variables
- Use atomic operations when possible

```go
type MyPlugin struct {
    enabled bool
    mu      sync.RWMutex
}

func (p *MyPlugin) Initialize(config map[string]interface{}) error {
    p.mu.Lock()
    defer p.mu.Unlock()
    // ... configuration logic
}
```

### 2. Error Handling
- Return meaningful errors
- Log errors appropriately
- Don't panic in middleware

```go
func (p *MyPlugin) processRequest(r *http.Request) error {
    if r.Body == nil {
        return fmt.Errorf("request body is required")
    }
    
    // Process request...
    return nil
}
```

### 3. Configuration Validation
- Validate configuration in Initialize()
- Provide sensible defaults
- Return errors for invalid config

```go
func (p *MyPlugin) Initialize(config map[string]interface{}) error {
    // Set defaults
    p.timeout = 30 * time.Second
    
    // Load config
    if timeout, ok := config["timeout"].(float64); ok {
        if timeout <= 0 {
            return fmt.Errorf("timeout must be positive")
        }
        p.timeout = time.Duration(timeout) * time.Second
    }
    
    return nil
}
```

### 4. Resource Management
- Clean up resources in OnShutdown()
- Use defer for cleanup
- Handle connection timeouts

```go
func (p *MyPlugin) OnShutdown() error {
    p.mu.Lock()
    defer p.mu.Unlock()
    
    // Close connections
    if p.client != nil {
        p.client.CloseIdleConnections()
    }
    
    return nil
}
```

### 5. Performance
- Minimize allocations in middleware
- Use sync.Pool for frequently allocated objects
- Avoid blocking operations in middleware

```go
var bufferPool = sync.Pool{
    New: func() interface{} {
        return make([]byte, 4096)
    },
}

func (p *MyPlugin) Middleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        buffer := bufferPool.Get().([]byte)
        defer bufferPool.Put(buffer)
        
        // Use buffer...
        next.ServeHTTP(w, r)
    })
}
```

## Examples

### Example 1: Request Logger Plugin

```go
package requestlogger

import (
    "net/http"
    "time"
    "sync"
)

type RequestLoggerPlugin struct {
    enabled bool
    logger  Logger
    mu      sync.RWMutex
}

type Logger interface {
    Log(level, message string, fields map[string]interface{})
}

func (p *RequestLoggerPlugin) Name() string {
    return "request_logger"
}

func (p *RequestLoggerPlugin) Type() string {
    return "observability"
}

func (p *RequestLoggerPlugin) Initialize(config map[string]interface{}) error {
    p.mu.Lock()
    defer p.mu.Unlock()
    
    p.enabled = true
    if enabled, ok := config["enabled"].(bool); ok {
        p.enabled = enabled
    }
    
    return nil
}

func (p *RequestLoggerPlugin) Middleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        if !p.enabled {
            next.ServeHTTP(w, r)
            return
        }
        
        start := time.Now()
        
        // Wrap response writer to capture status
        wrapped := &responseWriter{ResponseWriter: w, statusCode: 200}
        
        next.ServeHTTP(wrapped, r)
        
        duration := time.Since(start)
        
        p.logger.Log("info", "HTTP request", map[string]interface{}{
            "method":     r.Method,
            "path":       r.URL.Path,
            "status":     wrapped.statusCode,
            "duration":   duration.String(),
            "user_agent": r.UserAgent(),
        })
    })
}

type responseWriter struct {
    http.ResponseWriter
    statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
    rw.statusCode = code
    rw.ResponseWriter.WriteHeader(code)
}
```

### Example 2: Rate Limiting Plugin

```go
package ratelimiter

import (
    "net/http"
    "sync"
    "time"
    "golang.org/x/time/rate"
)

type RateLimiterPlugin struct {
    enabled bool
    limiters map[string]*rate.Limiter
    mu       sync.RWMutex
}

func (p *RateLimiterPlugin) Name() string {
    return "rate_limiter"
}

func (p *RateLimiterPlugin) Type() string {
    return "ratelimit"
}

func (p *RateLimiterPlugin) Initialize(config map[string]interface{}) error {
    p.mu.Lock()
    defer p.mu.Unlock()
    
    p.enabled = true
    p.limiters = make(map[string]*rate.Limiter)
    
    if enabled, ok := config["enabled"].(bool); ok {
        p.enabled = enabled
    }
    
    if rate, ok := config["requests_per_second"].(float64); ok {
        p.defaultRate = rate
    }
    
    return nil
}

func (p *RateLimiterPlugin) Middleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        if !p.enabled {
            next.ServeHTTP(w, r)
            return
        }
        
        // Get client identifier (IP, user ID, etc.)
        clientID := p.getClientID(r)
        
        // Get or create rate limiter for client
        limiter := p.getLimiter(clientID)
        
        // Check rate limit
        if !limiter.Allow() {
            w.Header().Set("Content-Type", "application/json")
            w.WriteHeader(http.StatusTooManyRequests)
            w.Write([]byte(`{"error":"Rate limit exceeded"}`))
            return
        }
        
        next.ServeHTTP(w, r)
    })
}

func (p *RateLimiterPlugin) getClientID(r *http.Request) string {
    // Use IP address as client identifier
    return r.RemoteAddr
}

func (p *RateLimiterPlugin) getLimiter(clientID string) *rate.Limiter {
    p.mu.Lock()
    defer p.mu.Unlock()
    
    if limiter, exists := p.limiters[clientID]; exists {
        return limiter
    }
    
    limiter := rate.NewLimiter(rate.Limit(p.defaultRate), int(p.defaultRate))
    p.limiters[clientID] = limiter
    return limiter
}
```

## Configuration Examples

### YAML Configuration

```yaml
plugins:
  my_plugin:
    enabled: true
    timeout: 30
    skip_paths:
      - "/health"
      - "/metrics"
  
  request_logger:
    enabled: true
    log_level: "info"
    include_headers: true
  
  rate_limiter:
    enabled: true
    requests_per_second: 100
    burst_size: 10
```

### JSON Configuration

```json
{
  "plugins": {
    "my_plugin": {
      "enabled": true,
      "timeout": 30,
      "skip_paths": ["/health", "/metrics"]
    },
    "request_logger": {
      "enabled": true,
      "log_level": "info",
      "include_headers": true
    },
    "rate_limiter": {
      "enabled": true,
      "requests_per_second": 100,
      "burst_size": 10
    }
  }
}
```

## Troubleshooting

### Common Issues

1. **Plugin not loading**
   - Check plugin name matches registration
   - Verify plugin implements required interfaces
   - Check for compilation errors

2. **Configuration not applied**
   - Verify configuration format
   - Check type assertions in Initialize()
   - Add logging to debug configuration loading

3. **Middleware not executing**
   - Ensure plugin is registered
   - Check if plugin is enabled
   - Verify middleware chain order

4. **Performance issues**
   - Profile middleware execution
   - Check for blocking operations
   - Use sync.Pool for frequent allocations

### Debugging Tips

1. Add logging to your plugin:
```go
func (p *MyPlugin) Initialize(config map[string]interface{}) error {
    log.Printf("Initializing plugin %s with config: %+v", p.Name(), config)
    // ... initialization logic
    return nil
}
```

2. Use health checks to verify plugin state:
```go
func (p *MyPlugin) Health() error {
    if !p.enabled {
        return fmt.Errorf("plugin is disabled")
    }
    // ... health check logic
    return nil
}
```

3. Monitor plugin status:
```go
func (p *MyPlugin) Status() string {
    return fmt.Sprintf("MyPlugin: enabled=%t, processed=%d", p.enabled, p.requestCount)
}
```

## Conclusion

This guide covers the essential aspects of plugin development for the Iket API Gateway. By following these patterns and best practices, you can create robust, maintainable plugins that extend the gateway's functionality effectively.

For more information, refer to the built-in plugins in `internal/plugin/` for additional examples and patterns. 