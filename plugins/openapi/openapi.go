package openapi

import (
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"strings"
	"time"

	"iket/pkg/plugin"

	"gopkg.in/yaml.v3"
)

//go:embed swaggerui/*
var swaggerUIFS embed.FS

type OpenAPIPlugin struct {
	specPath  string
	specData  []byte
	enabled   bool
	servePath string
	format    string // "yaml" or "json"
	swaggerUI bool
	// Tag for reflection-based discovery
	PluginName string `plugin:"type" plugin:"openapi"`
	// Health tracking
	lastHealthCheck time.Time
	isHealthy       bool
	loadTime        time.Time
}

func NewOpenAPIPlugin() *OpenAPIPlugin {
	return &OpenAPIPlugin{
		PluginName:      "openapi",
		lastHealthCheck: time.Now(),
		isHealthy:       true,
		loadTime:        time.Now(),
	}
}

func (p *OpenAPIPlugin) Name() string { return "openapi" }

// Type implements TypedPlugin interface
func (p *OpenAPIPlugin) Type() plugin.PluginType {
	return plugin.TransformPlugin // OpenAPI transforms requests/responses
}

// Tags implements TaggedPlugin interface
func (p *OpenAPIPlugin) Tags() map[string]string {
	return map[string]string{
		"category": "documentation",
		"type":     "api-docs",
		"priority": "low",
	}
}

// Health implements HealthChecker interface
func (p *OpenAPIPlugin) Health() error {
	p.lastHealthCheck = time.Now()

	if !p.enabled {
		return nil // Disabled plugins are considered healthy
	}

	if p.specPath == "" {
		p.isHealthy = false
		return fmt.Errorf("openapi plugin not properly configured: missing spec_path")
	}

	// Check if spec file still exists and is readable
	if _, err := os.Stat(p.specPath); err != nil {
		p.isHealthy = false
		return fmt.Errorf("openapi spec file not accessible: %w", err)
	}

	// Check if spec data is valid
	if len(p.specData) == 0 {
		p.isHealthy = false
		return fmt.Errorf("openapi spec data is empty")
	}

	p.isHealthy = true
	return nil
}

// Status implements StatusReporter interface
func (p *OpenAPIPlugin) Status() string {
	if !p.enabled {
		return "disabled"
	}
	if p.isHealthy {
		return "healthy"
	}
	return "unhealthy"
}

// Config options:
//
//	spec_path: string (required)
//	enabled: bool (optional, default true)
//	path: string (optional, default "/openapi")
//	format: string ("yaml" or "json", default "yaml")
//	swagger_ui: bool (optional, default false)
func (p *OpenAPIPlugin) Initialize(config map[string]interface{}) error {
	enabled := true
	if v, ok := config["enabled"].(bool); ok {
		enabled = v
	}
	p.enabled = enabled
	if !enabled {
		p.isHealthy = true // Disabled plugins are healthy
		return nil         // plugin is disabled
	}
	pathVal, ok := config["spec_path"].(string)
	if !ok || pathVal == "" {
		p.isHealthy = false
		return nil // no spec path, plugin is a no-op
	}
	p.specPath = pathVal
	data, err := os.ReadFile(pathVal)
	if err != nil {
		p.isHealthy = false
		return err
	}
	p.specData = data
	p.servePath = "/openapi"
	if v, ok := config["path"].(string); ok && v != "" {
		p.servePath = v
	}
	p.format = "yaml"
	if v, ok := config["format"].(string); ok && (v == "yaml" || v == "json") {
		p.format = v
	}
	p.swaggerUI = false
	if v, ok := config["swagger_ui"].(bool); ok {
		p.swaggerUI = v
	}
	p.isHealthy = true
	p.loadTime = time.Now()
	return nil
}

// Middleware implements the pkg/plugin.MiddlewarePlugin interface
func (p *OpenAPIPlugin) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !p.enabled {
			next.ServeHTTP(w, r)
			return
		}
		if r.URL.Path == p.servePath {
			if p.format == "json" {
				var y interface{}
				err := yaml.Unmarshal(p.specData, &y)
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					w.Write([]byte("Failed to parse OpenAPI YAML"))
					return
				}
				j, err := json.MarshalIndent(y, "", "  ")
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					w.Write([]byte("Failed to convert OpenAPI to JSON"))
					return
				}
				w.Header().Set("Content-Type", "application/json; charset=UTF-8")
				w.WriteHeader(http.StatusOK)
				w.Write(j)
				return
			}
			w.Header().Set("Content-Type", "application/yaml; charset=UTF-8")
			w.WriteHeader(http.StatusOK)
			w.Write(p.specData)
			return
		}
		if p.swaggerUI && (r.URL.Path == "/swagger-ui/" || strings.HasPrefix(r.URL.Path, "/swagger-ui/") || r.URL.Path == "/swagger-ui") {
			if r.URL.Path == "/swagger-ui/" || r.URL.Path == "/swagger-ui" {
				w.Header().Set("Content-Type", "text/html; charset=UTF-8")
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(swaggerUIHTML(p.servePath, p.format)))
				return
			}
			// Serve static assets from embedded FS
			assetPath := strings.TrimPrefix(r.URL.Path, "/swagger-ui/")
			if assetPath == "" {
				assetPath = "index.html"
			}
			f, err := swaggerUIFS.Open(path.Join("swaggerui", assetPath))
			if err != nil {
				w.WriteHeader(http.StatusNotFound)
				w.Write([]byte("Swagger UI asset not found"))
				return
			}
			defer f.Close()
			stat, _ := f.Stat()
			http.ServeContent(w, r, assetPath, stat.ModTime(), f.(io.ReadSeeker))
			return
		}
		next.ServeHTTP(w, r)
	})
}

func swaggerUIHTML(specPath, format string) string {
	return `<!DOCTYPE html>
<html>
<head>
  <title>Swagger UI</title>
  <link rel="stylesheet" href="/swagger-ui/swagger-ui.css" />
</head>
<body>
  <div id="swagger-ui"></div>
  <script src="/swagger-ui/swagger-ui-bundle.js"></script>
  <script src="/swagger-ui/swagger-ui-standalone-preset.js"></script>
  <script>
    window.onload = function() {
      window.ui = SwaggerUIBundle({
        url: '` + specPath + `?format=` + format + `',
        dom_id: '#swagger-ui',
        presets: [
          SwaggerUIBundle.presets.apis,
          SwaggerUIStandalonePreset
        ],
        layout: "StandaloneLayout"
      });
    };
  </script>
</body>
</html>`
}
