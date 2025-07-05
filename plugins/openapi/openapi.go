package openapi

import (
	"embed"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path"
	"strings"

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
}

func NewOpenAPIPlugin() *OpenAPIPlugin {
	return &OpenAPIPlugin{
		PluginName: "openapi",
	}
}

func (p *OpenAPIPlugin) Name() string { return "openapi" }

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
		return nil // plugin is disabled
	}
	pathVal, ok := config["spec_path"].(string)
	if !ok || pathVal == "" {
		return nil // no spec path, plugin is a no-op
	}
	p.specPath = pathVal
	data, err := os.ReadFile(pathVal)
	if err != nil {
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
