package plugin

import (
	"embed"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path"
	"strings"

	"iket/internal/logging"

	"gopkg.in/yaml.v3"
)

//go:embed swaggerui/*
var swaggerUIFS embed.FS

var logger *logging.Logger = logging.NewLoggerFromEnv() // default fallback

// SetLogger allows the gateway to inject the main logger
func SetLogger(l *logging.Logger) {
	logger = l
}

type OpenAPIPlugin struct {
	specPath  string
	specData  []byte
	enabled   bool
	servePath string
	format    string // "yaml" or "json"
	swaggerUI bool
}

func (p *OpenAPIPlugin) Name() string { return "openapi" }

// Config options:
//
//	spec_path: string (required)
//	enabled: bool (optional, default true)
//	path: string (optional, default "/openapi")
//	format: string ("yaml" or "json", default "yaml")
//	swagger_ui: bool (optional, default false)
func (p *OpenAPIPlugin) Init(config map[string]interface{}) error {
	logger.Debug("OpenAPIPlugin.Init called", logging.Any("config", config))
	enabled := true
	if v, ok := config["enabled"].(bool); ok {
		enabled = v
	}
	p.enabled = enabled
	if !enabled {
		logger.Info("OpenAPIPlugin is disabled")
		return nil // plugin is disabled
	}
	pathVal, ok := config["spec_path"].(string)
	if !ok || pathVal == "" {
		logger.Warn("OpenAPIPlugin: no spec_path provided, plugin is a no-op")
		return nil // no spec path, plugin is a no-op
	}
	p.specPath = pathVal
	data, err := os.ReadFile(pathVal)
	if err != nil {
		logger.Error("OpenAPIPlugin: failed to read spec file", err, logging.String("spec_path", pathVal))
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
	logger.Info("OpenAPIPlugin initialized", logging.String("servePath", p.servePath), logging.String("format", p.format), logging.Bool("swaggerUI", p.swaggerUI))
	return nil
}

func (p *OpenAPIPlugin) Middleware() func(next http.Handler) http.Handler {
	logger.Debug("OpenAPIPlugin.Middleware registered", logging.String("servePath", p.servePath))
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !p.enabled {
				next.ServeHTTP(w, r)
				return
			}
			if r.URL.Path == p.servePath {
				logger.Info("OpenAPIPlugin: serving OpenAPI spec", logging.String("path", r.URL.Path), logging.String("format", p.format))
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
				logger.Info("OpenAPIPlugin: serving Swagger UI", logging.String("path", r.URL.Path))
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

func init() {
	Register(&OpenAPIPlugin{})
}
