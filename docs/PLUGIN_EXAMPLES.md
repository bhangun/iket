# Plugin Examples

This document provides practical examples of custom plugins for the Iket API Gateway.

## Example 1: Simple Request Counter Plugin

```go
package requestcounter

import (
    "encoding/json"
    "fmt"
    "net/http"
    "sync"
    "sync/atomic"
)

type RequestCounterPlugin struct {
    enabled      bool
    requestCount int64
    mu           sync.RWMutex
}

func (p *RequestCounterPlugin) Name() string {
    return "request_counter"
}

func (p *RequestCounterPlugin) Type() string {
    return "observability"
}

func (p *RequestCounterPlugin) Initialize(config map[string]interface{}) error {
    p.mu.Lock()
    defer p.mu.Unlock()
    
    p.enabled = true
    if enabled, ok := config["enabled"].(bool); ok {
        p.enabled = enabled
    }
    
    return nil
}

func (p *RequestCounterPlugin) Middleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        if !p.enabled {
            next.ServeHTTP(w, r)
            return
        }
        
        // Increment counter
        atomic.AddInt64(&p.requestCount, 1)
        
        // Add header with current count
        w.Header().Set("X-Request-Count", fmt.Sprintf("%d", atomic.LoadInt64(&p.requestCount)))
        
        next.ServeHTTP(w, r)
    })
}

func (p *RequestCounterPlugin) Tags() map[string]string {
    return map[string]string{
        "type":       "request_counter",
        "category":   "observability",
        "middleware": "true",
    }
}

func (p *RequestCounterPlugin) Health() error {
    if !p.enabled {
        return fmt.Errorf("plugin is disabled")
    }
    return nil
}

func (p *RequestCounterPlugin) Status() string {
    return fmt.Sprintf("RequestCounter: enabled=%t, count=%d", p.enabled, atomic.LoadInt64(&p.requestCount))
}
```

## Example 2: API Key Authentication Plugin

```go
package apikey

import (
    "context"
    "encoding/json"
    "fmt"
    "net/http"
    "strings"
    "sync"
)

type APIKeyPlugin struct {
    enabled bool
    keys    map[string]string // key -> user mapping
    mu      sync.RWMutex
}

func (p *APIKeyPlugin) Name() string {
    return "api_key"
}

func (p *APIKeyPlugin) Type() string {
    return "auth"
}

func (p *APIKeyPlugin) Initialize(config map[string]interface{}) error {
    p.mu.Lock()
    defer p.mu.Unlock()
    
    p.enabled = true
    p.keys = make(map[string]string)
    
    if enabled, ok := config["enabled"].(bool); ok {
        p.enabled = enabled
    }
    
    // Load API keys from config
    if keys, ok := config["keys"].(map[string]interface{}); ok {
        for key, user := range keys {
            if userStr, ok := user.(string); ok {
                p.keys[key] = userStr
            }
        }
    }
    
    return nil
}

func (p *APIKeyPlugin) Middleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        if !p.enabled {
            next.ServeHTTP(w, r)
            return
        }
        
        // Extract API key from header
        apiKey := r.Header.Get("X-API-Key")
        if apiKey == "" {
            p.writeError(w, "Missing API key", http.StatusUnauthorized)
            return
        }
        
        // Validate API key
        user, valid := p.validateAPIKey(apiKey)
        if !valid {
            p.writeError(w, "Invalid API key", http.StatusUnauthorized)
            return
        }
        
        // Add user to context
        ctx := context.WithValue(r.Context(), "user", user)
        next.ServeHTTP(w, r.WithContext(ctx))
    })
}

func (p *APIKeyPlugin) validateAPIKey(key string) (string, bool) {
    p.mu.RLock()
    defer p.mu.RUnlock()
    
    user, exists := p.keys[key]
    return user, exists
}

func (p *APIKeyPlugin) writeError(w http.ResponseWriter, message string, statusCode int) {
    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(statusCode)
    response := map[string]interface{}{
        "error":   "API Key Error",
        "message": message,
    }
    json.NewEncoder(w).Encode(response)
}

func (p *APIKeyPlugin) Tags() map[string]string {
    return map[string]string{
        "type":       "api_key",
        "category":   "auth",
        "middleware": "true",
    }
}

func (p *APIKeyPlugin) Health() error {
    p.mu.RLock()
    defer p.mu.RUnlock()
    
    if !p.enabled {
        return fmt.Errorf("plugin is disabled")
    }
    
    if len(p.keys) == 0 {
        return fmt.Errorf("no API keys configured")
    }
    
    return nil
}

func (p *APIKeyPlugin) Status() string {
    p.mu.RLock()
    defer p.mu.RUnlock()
    
    if !p.enabled {
        return "APIKey: Disabled"
    }
    
    return fmt.Sprintf("APIKey: Enabled (%d keys configured)", len(p.keys))
}
```

## Example 3: Request/Response Transformation Plugin

```go
package transformer

import (
    "bytes"
    "encoding/json"
    "io"
    "net/http"
    "strings"
    "sync"
)

type TransformerPlugin struct {
    enabled     bool
    addHeaders  map[string]string
    removeHeaders []string
    mu          sync.RWMutex
}

func (p *TransformerPlugin) Name() string {
    return "transformer"
}

func (p *TransformerPlugin) Type() string {
    return "transform"
}

func (p *TransformerPlugin) Initialize(config map[string]interface{}) error {
    p.mu.Lock()
    defer p.mu.Unlock()
    
    p.enabled = true
    p.addHeaders = make(map[string]string)
    p.removeHeaders = make([]string, 0)
    
    if enabled, ok := config["enabled"].(bool); ok {
        p.enabled = enabled
    }
    
    // Load headers to add
    if headers, ok := config["add_headers"].(map[string]interface{}); ok {
        for key, value := range headers {
            if valueStr, ok := value.(string); ok {
                p.addHeaders[key] = valueStr
            }
        }
    }
    
    // Load headers to remove
    if headers, ok := config["remove_headers"].([]interface{}); ok {
        for _, header := range headers {
            if headerStr, ok := header.(string); ok {
                p.removeHeaders = append(p.removeHeaders, headerStr)
            }
        }
    }
    
    return nil
}

func (p *TransformerPlugin) Middleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        if !p.enabled {
            next.ServeHTTP(w, r)
            return
        }
        
        // Transform request
        p.transformRequest(r)
        
        // Create response writer wrapper
        wrapped := &responseWriterWrapper{
            ResponseWriter: w,
            body:          &bytes.Buffer{},
        }
        
        next.ServeHTTP(wrapped, r)
        
        // Transform response
        p.transformResponse(wrapped)
    })
}

func (p *TransformerPlugin) transformRequest(r *http.Request) {
    p.mu.RLock()
    defer p.mu.RUnlock()
    
    // Add headers
    for key, value := range p.addHeaders {
        r.Header.Set(key, value)
    }
    
    // Remove headers
    for _, header := range p.removeHeaders {
        r.Header.Del(header)
    }
}

func (p *TransformerPlugin) transformResponse(w *responseWriterWrapper) {
    p.mu.RLock()
    defer p.mu.RUnlock()
    
    // Add headers to response
    for key, value := range p.addHeaders {
        w.Header().Set(key, value)
    }
    
    // Remove headers from response
    for _, header := range p.removeHeaders {
        w.Header().Del(header)
    }
    
    // Write transformed body
    w.ResponseWriter.WriteHeader(w.statusCode)
    w.ResponseWriter.Write(w.body.Bytes())
}

type responseWriterWrapper struct {
    http.ResponseWriter
    statusCode int
    body       *bytes.Buffer
}

func (rw *responseWriterWrapper) WriteHeader(code int) {
    rw.statusCode = code
}

func (rw *responseWriterWrapper) Write(b []byte) (int, error) {
    return rw.body.Write(b)
}

func (p *TransformerPlugin) Tags() map[string]string {
    return map[string]string{
        "type":       "transformer",
        "category":   "transform",
        "middleware": "true",
    }
}

func (p *TransformerPlugin) Health() error {
    if !p.enabled {
        return fmt.Errorf("plugin is disabled")
    }
    return nil
}

func (p *TransformerPlugin) Status() string {
    p.mu.RLock()
    defer p.mu.RUnlock()
    
    if !p.enabled {
        return "Transformer: Disabled"
    }
    
    return fmt.Sprintf("Transformer: Enabled (add: %d headers, remove: %d headers)", 
        len(p.addHeaders), len(p.removeHeaders))
}
```

## Example 4: Circuit Breaker Plugin

```go
package circuitbreaker

import (
    "context"
    "encoding/json"
    "fmt"
    "net/http"
    "sync"
    "time"
)

type CircuitState string

const (
    StateClosed   CircuitState = "closed"
    StateOpen     CircuitState = "open"
    StateHalfOpen CircuitState = "half-open"
)

type CircuitBreakerPlugin struct {
    enabled         bool
    threshold       int
    windowSize      time.Duration
    timeout         time.Duration
    state           CircuitState
    failureCount    int
    lastFailureTime time.Time
    mu              sync.RWMutex
}

func (p *CircuitBreakerPlugin) Name() string {
    return "circuit_breaker"
}

func (p *CircuitBreakerPlugin) Type() string {
    return "resilience"
}

func (p *CircuitBreakerPlugin) Initialize(config map[string]interface{}) error {
    p.mu.Lock()
    defer p.mu.Unlock()
    
    p.enabled = true
    p.threshold = 5
    p.windowSize = 60 * time.Second
    p.timeout = 30 * time.Second
    p.state = StateClosed
    
    if enabled, ok := config["enabled"].(bool); ok {
        p.enabled = enabled
    }
    
    if threshold, ok := config["threshold"].(float64); ok {
        p.threshold = int(threshold)
    }
    
    if windowSize, ok := config["window_size"].(float64); ok {
        p.windowSize = time.Duration(windowSize) * time.Second
    }
    
    if timeout, ok := config["timeout"].(float64); ok {
        p.timeout = time.Duration(timeout) * time.Second
    }
    
    return nil
}

func (p *CircuitBreakerPlugin) Middleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        if !p.enabled {
            next.ServeHTTP(w, r)
            return
        }
        
        // Check circuit state
        if !p.canExecute() {
            p.writeError(w, "Circuit breaker is open", http.StatusServiceUnavailable)
            return
        }
        
        // Execute with timeout
        success := p.executeWithTimeout(w, r, next)
        
        // Update circuit state
        p.updateState(success)
    })
}

func (p *CircuitBreakerPlugin) canExecute() bool {
    p.mu.RLock()
    defer p.mu.RUnlock()
    
    switch p.state {
    case StateClosed:
        return true
    case StateHalfOpen:
        return true
    case StateOpen:
        if time.Since(p.lastFailureTime) > p.windowSize {
            p.mu.RUnlock()
            p.mu.Lock()
            p.state = StateHalfOpen
            p.mu.Unlock()
            p.mu.RLock()
            return true
        }
        return false
    default:
        return false
    }
}

func (p *CircuitBreakerPlugin) executeWithTimeout(w http.ResponseWriter, r *http.Request, next http.Handler) bool {
    ctx, cancel := context.WithTimeout(r.Context(), p.timeout)
    defer cancel()
    
    done := make(chan bool, 1)
    go func() {
        next.ServeHTTP(w, r.WithContext(ctx))
        done <- true
    }()
    
    select {
    case <-done:
        return true
    case <-ctx.Done():
        return false
    }
}

func (p *CircuitBreakerPlugin) updateState(success bool) {
    p.mu.Lock()
    defer p.mu.Unlock()
    
    if success {
        p.onSuccess()
    } else {
        p.onFailure()
    }
}

func (p *CircuitBreakerPlugin) onSuccess() {
    switch p.state {
    case StateClosed:
        p.failureCount = 0
    case StateHalfOpen:
        p.state = StateClosed
        p.failureCount = 0
    }
}

func (p *CircuitBreakerPlugin) onFailure() {
    p.failureCount++
    p.lastFailureTime = time.Now()
    
    switch p.state {
    case StateClosed:
        if p.failureCount >= p.threshold {
            p.state = StateOpen
        }
    case StateHalfOpen:
        p.state = StateOpen
    }
}

func (p *CircuitBreakerPlugin) writeError(w http.ResponseWriter, message string, statusCode int) {
    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(statusCode)
    response := map[string]interface{}{
        "error":   "Circuit Breaker Error",
        "message": message,
    }
    json.NewEncoder(w).Encode(response)
}

func (p *CircuitBreakerPlugin) Tags() map[string]string {
    return map[string]string{
        "type":        "circuit_breaker",
        "category":    "resilience",
        "middleware":  "true",
        "lifecycle":   "true",
    }
}

func (p *CircuitBreakerPlugin) Health() error {
    p.mu.RLock()
    defer p.mu.RUnlock()
    
    if !p.enabled {
        return fmt.Errorf("plugin is disabled")
    }
    
    if p.state == StateOpen && time.Since(p.lastFailureTime) > p.windowSize*2 {
        return fmt.Errorf("circuit breaker stuck in open state")
    }
    
    return nil
}

func (p *CircuitBreakerPlugin) Status() string {
    p.mu.RLock()
    defer p.mu.RUnlock()
    
    if !p.enabled {
        return "CircuitBreaker: Disabled"
    }
    
    return fmt.Sprintf("CircuitBreaker: %s (failures: %d)", p.state, p.failureCount)
}

func (p *CircuitBreakerPlugin) OnStart() error {
    p.mu.Lock()
    defer p.mu.Unlock()
    
    p.state = StateClosed
    p.failureCount = 0
    return nil
}

func (p *CircuitBreakerPlugin) OnShutdown() error {
    p.mu.Lock()
    defer p.mu.Unlock()
    
    p.state = StateClosed
    p.failureCount = 0
    return nil
}
```

## Configuration Examples

### Request Counter Plugin
```yaml
plugins:
  request_counter:
    enabled: true
```

### API Key Plugin
```yaml
plugins:
  api_key:
    enabled: true
    keys:
      "key1": "user1"
      "key2": "user2"
      "key3": "user3"
```

### Transformer Plugin
```yaml
plugins:
  transformer:
    enabled: true
    add_headers:
      "X-Custom-Header": "value"
      "X-Plugin": "transformer"
    remove_headers:
      - "X-Sensitive-Header"
      - "X-Debug-Header"
```

### Circuit Breaker Plugin
```yaml
plugins:
  circuit_breaker:
    enabled: true
    threshold: 5
    window_size: 60
    timeout: 30
```

## Building and Loading

### 1. Create a Go module for your plugin

```bash
mkdir my-plugin
cd my-plugin
go mod init my-plugin
```

### 2. Create your plugin file

```go
// main.go
package main

import (
    "iket/pkg/plugin"
    "my-plugin/counter"
)

func main() {
    // This is required for dynamic loading
    // The gateway will look for this symbol
    Plugin = &counter.RequestCounterPlugin{}
}

var Plugin plugin.Plugin
```

### 3. Build as shared library

```bash
go build -buildmode=plugin -o my-plugin.so main.go
```

### 4. Place in plugins directory

```bash
cp my-plugin.so /path/to/iket/plugins/
```

### 5. Configure in gateway

```yaml
server:
  plugins_dir: "/path/to/iket/plugins"

plugins:
  request_counter:
    enabled: true
```

## Testing Your Plugin

### Unit Tests

```go
package counter

import (
    "net/http"
    "net/http/httptest"
    "testing"
)

func TestRequestCounterPlugin_Initialize(t *testing.T) {
    plugin := &RequestCounterPlugin{}
    
    config := map[string]interface{}{
        "enabled": true,
    }
    
    err := plugin.Initialize(config)
    if err != nil {
        t.Errorf("Initialize failed: %v", err)
    }
    
    if !plugin.enabled {
        t.Error("Plugin should be enabled")
    }
}

func TestRequestCounterPlugin_Middleware(t *testing.T) {
    plugin := &RequestCounterPlugin{}
    plugin.Initialize(map[string]interface{}{"enabled": true})
    
    req := httptest.NewRequest("GET", "/test", nil)
    w := httptest.NewRecorder()
    
    testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.WriteHeader(http.StatusOK)
    })
    
    middleware := plugin.Middleware(testHandler)
    middleware.ServeHTTP(w, req)
    
    if w.Code != http.StatusOK {
        t.Errorf("Expected status 200, got %d", w.Code)
    }
    
    if w.Header().Get("X-Request-Count") == "" {
        t.Error("Expected X-Request-Count header")
    }
}
```

### Integration Tests

```go
func TestPluginIntegration(t *testing.T) {
    // Create registry
    registry := plugin.NewRegistry()
    
    // Register plugin
    counterPlugin := &RequestCounterPlugin{}
    err := registry.Register(counterPlugin)
    if err != nil {
        t.Fatal(err)
    }
    
    // Initialize
    config := map[string]map[string]interface{}{
        "request_counter": {
            "enabled": true,
        },
    }
    
    err = registry.Initialize(config)
    if err != nil {
        t.Fatal(err)
    }
    
    // Test health
    health := registry.HealthCheck()
    if health["request_counter"] != nil {
        t.Errorf("Plugin should be healthy: %v", health["request_counter"])
    }
    
    // Test status
    statuses := registry.PluginStatuses()
    if statuses["request_counter"] == "" {
        t.Error("Plugin should have status")
    }
}
```

These examples provide a solid foundation for creating custom plugins. Use them as templates and adapt them to your specific requirements. 