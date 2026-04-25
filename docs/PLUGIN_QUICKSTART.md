# Plugin Quick Start Guide

This guide will help you create your first plugin for the Iket API Gateway in under 10 minutes.

## Prerequisites

- Go 1.23 or later
- Basic understanding of Go and HTTP middleware
- Iket API Gateway installed

## Step 1: Create Plugin Directory

```bash
mkdir my-first-plugin
cd my-first-plugin
go mod init my-first-plugin
```

## Step 2: Create Your Plugin

Create a file called `plugin.go`:

```go
package main

import (
    "fmt"
    "net/http"
    "sync"
)

// MyFirstPlugin implements a simple request logger
type MyFirstPlugin struct {
    enabled bool
    mu      sync.RWMutex
}

func (p *MyFirstPlugin) Name() string { return "my_first_plugin" }

func (p *MyFirstPlugin) Initialize(config map[string]interface{}) error {
    p.mu.Lock()
    defer p.mu.Unlock()
    p.enabled = true
    if enabled, ok := config["enabled"].(bool); ok {
        p.enabled = enabled
    }
    return nil
}

func (p *MyFirstPlugin) Middleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        if !p.enabled {
            next.ServeHTTP(w, r)
            return
        }
        fmt.Printf("Request: %s %s\n", r.Method, r.URL.Path)
        w.Header().Set("X-My-Plugin", "Hello from Iket!")
        next.ServeHTTP(w, r)
    })
}

var Plugin = &MyFirstPlugin{}
```

## Step 3: Build the Plugin

```bash
go build -buildmode=plugin -o my-first-plugin.so plugin.go
```

## Step 4: Configure the Gateway

Update your `config/config.yaml`:

```yaml
server:
  port: 8080
  pluginsDir: "./plugins"  # Directory for .so files

plugins:
  my_first_plugin:
    enabled: true
```

## Step 5: Load the Plugin

1. Create the plugins directory:
```bash
mkdir plugins
```

2. Copy your plugin:
```bash
cp my-first-plugin.so plugins/
```

3. Start the gateway:
```bash
iket-server --config config/config.yaml
```

## Step 6: Verify with `iket`

Use the CLI to verify that your plugin is loaded and active:

```bash
# List all plugins
iket plugin list
```

## Step 7: Test Your Plugin

Make a request through your gateway:

```bash
curl -i http://localhost:8080/some-route
```

You should see:
- The request logged in the gateway console.
- A custom header `X-My-Plugin: Hello from Iket!` in the response.

---

## 🛠️ Managing Plugins via CLI

Iket allows you to manage plugins in real-time using `iket`.

### Enable a Plugin
```bash
iket plugin enable my_first_plugin
```

### Disable a Plugin
```bash
iket plugin disable my_first_plugin
```

---

## Resources

- [Plugin Development Guide](PLUGIN_DEVELOPMENT.md) - Comprehensive guide.
- [Plugin Examples](PLUGIN_EXAMPLES.md) - More examples and patterns.
- [Secure Administration](README-PRODUCTION.md) - Learn how to secure your management API.
