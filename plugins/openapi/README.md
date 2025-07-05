# OpenAPI Plugin

This is an external plugin that provides OpenAPI specification serving and Swagger UI integration for the Iket gateway.

## Features

- **OpenAPI Specification Serving**: Serve OpenAPI specs in YAML or JSON format
- **Swagger UI Integration**: Embedded Swagger UI for interactive API documentation
- **Flexible Configuration**: Configurable paths, formats, and features
- **Middleware Integration**: Works seamlessly with the new middleware plugin system

## Configuration

The OpenAPI plugin supports the following configuration options:

```yaml
openapi:
  spec_path: "openapi.yaml"    # Path to your OpenAPI specification file (required)
  enabled: true                # Enable/disable the plugin (default: true)
  path: "/openapi"             # Path where the spec will be served (default: "/openapi")
  format: "yaml"               # Output format: "yaml" or "json" (default: "yaml")
  swagger_ui: true             # Enable Swagger UI (default: false)
```

### Configuration Options

| Option | Type | Required | Default | Description |
|--------|------|----------|---------|-------------|
| `spec_path` | string | Yes | - | Path to the OpenAPI specification file |
| `enabled` | boolean | No | `true` | Enable or disable the plugin |
| `path` | string | No | `"/openapi"` | URL path where the spec will be served |
| `format` | string | No | `"yaml"` | Output format: `"yaml"` or `"json"` |
| `swagger_ui` | boolean | No | `false` | Enable Swagger UI interface |

## Usage

### Basic Usage

```go
package main

import (
    "net/http"
    "iket/pkg/plugin"
    "iket/plugins/openapi"
)

func main() {
    // Create registry
    registry := plugin.NewRegistry()
    
    // Register OpenAPI plugin
    openAPIPlugin := openapi.NewOpenAPIPlugin()
    registry.Register(openAPIPlugin)
    
    // Initialize with configuration
    configs := map[string]map[string]interface{}{
        "openapi": {
            "spec_path":  "api/openapi.yaml",
            "enabled":    true,
            "swagger_ui": true,
        },
    }
    registry.Initialize(configs)
    
    // Build middleware chain
    finalHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.Write([]byte("Your API"))
    })
    
    chain, _ := registry.BuildMiddlewareChain([]string{"openapi"}, finalHandler)
    http.ListenAndServe(":8080", chain)
}
```

### With Other Plugins

```go
// Register multiple plugins
registry.Register(openapi.NewOpenAPIPlugin())
registry.Register(auth.NewAuthPlugin())

// Build chain with multiple middleware
chain, _ := registry.BuildMiddlewareChain([]string{"cors", "openapi", "auth"}, finalHandler)
```

## Endpoints

When enabled, the plugin creates the following endpoints:

- **`/openapi`** (or configured path) - Serves the OpenAPI specification
- **`/swagger-ui/`** - Swagger UI interface (if enabled)
- **`/swagger-ui/*`** - Static assets for Swagger UI

## Examples

### YAML Specification

```yaml
# config.yaml
openapi:
  spec_path: "api/openapi.yaml"
  format: "yaml"
  swagger_ui: true
```

### JSON Specification

```yaml
# config.yaml
openapi:
  spec_path: "api/openapi.json"
  format: "json"
  swagger_ui: true
```

### Custom Path

```yaml
# config.yaml
openapi:
  spec_path: "docs/api.yaml"
  path: "/api/docs"
  format: "yaml"
  swagger_ui: true
```

## Integration with Existing System

The OpenAPI plugin can be used alongside existing internal plugins through the adapter system:

```go
// Create adapter for backward compatibility
adapter := plugin.NewRegistryAdapter()
adapter.RegisterAllInternalPlugins()  // Register existing plugins

// Register external OpenAPI plugin
adapter.GetRegistry().Register(openapi.NewOpenAPIPlugin())

// Use both old and new plugins
chain, _ := adapter.GetRegistry().BuildMiddlewareChain(
    []string{"cors", "rate_limit", "openapi", "auth"}, finalHandler)
```

## Migration from Internal Plugin

If you were using the internal OpenAPI plugin, you can migrate by:

1. **Remove internal plugin registration** (if any)
2. **Import the external plugin**: `"iket/plugins/openapi"`
3. **Register the plugin**: `registry.Register(openapi.NewOpenAPIPlugin())`
4. **Use the same configuration** - the external plugin is compatible

The external plugin provides the same functionality as the internal one but with enhanced middleware integration capabilities. 