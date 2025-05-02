// openapi_plugin.go
package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync"

	"github.com/gorilla/mux"
)

// OpenAPIPlugin implements the GatewayPlugin interface for OpenAPI documentation
type OpenAPIPlugin struct {
	config   map[string]interface{}
	spec     map[string]interface{}
	specLock sync.RWMutex
	router   *mux.Router
}

// NewOpenAPIPlugin creates a new OpenAPIPlugin instance
func NewOpenAPIPlugin() *OpenAPIPlugin {
	return &OpenAPIPlugin{
		spec: make(map[string]any),
	}
}

// Name returns the plugin name
func (p *OpenAPIPlugin) Name() string {
	return "openapi"
}

// Initialize initializes the plugin with configuration
func (p *OpenAPIPlugin) Initialize(config map[string]interface{}) error {
	p.config = config
	p.router = mux.NewRouter()
	p.setupRoutes()
	return nil
}

// Middleware returns the plugin middleware
func (p *OpenAPIPlugin) Middleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Let the OpenAPI router handle requests to its paths
			if strings.HasPrefix(r.URL.Path, "/docs") || strings.HasPrefix(r.URL.Path, "/openapi.json") {
				p.router.ServeHTTP(w, r)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// Shutdown cleans up the plugin
func (p *OpenAPIPlugin) Shutdown() error {
	return nil
}

// UpdateSpec updates the OpenAPI specification
func (p *OpenAPIPlugin) UpdateSpec(spec map[string]interface{}) {
	p.specLock.Lock()
	defer p.specLock.Unlock()
	p.spec = spec
}

// setupRoutes configures the OpenAPI endpoints
func (p *OpenAPIPlugin) setupRoutes() {
	// OpenAPI JSON specification
	p.router.HandleFunc("/openapi.json", func(w http.ResponseWriter, r *http.Request) {
		p.specLock.RLock()
		defer p.specLock.RUnlock()

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(p.spec)
	})

	// Swagger UI
	p.router.PathPrefix("/docs").Handler(http.StripPrefix("/docs",
		http.FileServer(http.Dir("./swagger-ui"))))
}

// GetOpenAPISpec returns the current OpenAPI specification
func (p *OpenAPIPlugin) GetOpenAPISpec() map[string]interface{} {
	p.specLock.RLock()
	defer p.specLock.RUnlock()
	return p.spec
}
