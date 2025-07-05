package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"iket/internal/config"
	"iket/internal/core/errors"
	"iket/internal/core/plugin"
	"iket/internal/logging"
	"iket/internal/metrics"

	pluginlib "plugin"

	"github.com/gorilla/mux"
)

// Gateway represents the main API gateway instance.
// It handles request routing, middleware execution, and plugin management.
type Gateway struct {
	config  *config.Config
	router  *mux.Router
	metrics *metrics.Collector
	logger  *logging.Logger
	server  *http.Server

	// State management
	mu       sync.RWMutex
	shutdown chan struct{}

	version string // Add version field
}

// Dependencies contains all the dependencies required to create a Gateway
type Dependencies struct {
	Config  *config.Config
	Logger  *logging.Logger
	Metrics *metrics.Collector
}

// NewGateway creates a new Gateway instance with the provided dependencies
func NewGateway(deps Dependencies, version string) (*Gateway, error) {
	if deps.Config == nil {
		return nil, errors.NewConfigError("config is required", nil)
	}

	if deps.Logger == nil {
		return nil, errors.NewConfigError("logger is required", nil)
	}

	// Validate configuration
	if err := deps.Config.Validate(); err != nil {
		return nil, errors.NewConfigError("invalid configuration", err)
	}

	gateway := &Gateway{
		config:   deps.Config,
		router:   mux.NewRouter(),
		metrics:  deps.Metrics,
		logger:   deps.Logger,
		shutdown: make(chan struct{}),
		version:  version,
	}

	// Setup routes and middleware
	if err := gateway.setupRoutes(); err != nil {
		return nil, fmt.Errorf("failed to setup routes: %w", err)
	}

	if err := gateway.setupMiddleware(); err != nil {
		return nil, fmt.Errorf("failed to setup middleware: %w", err)
	}

	// Load built-in and external plugins
	if err := gateway.loadPlugins(); err != nil {
		return nil, fmt.Errorf("failed to load plugins: %w", err)
	}

	gateway.logger.Info("Gateway initialized successfully")
	return gateway, nil
}

// setupRoutes configures all the routes for the gateway
func (g *Gateway) setupRoutes() error {
	// Add health check endpoint
	g.router.HandleFunc("/health", g.healthHandler).Methods(http.MethodGet)

	// Add metrics endpoint
	g.router.HandleFunc("/metrics", g.metricsHandler).Methods(http.MethodGet)

	// Add config endpoint (protected by admin auth)
	g.router.Handle("/admin/config", g.adminAuthMiddleware(http.HandlerFunc(g.configHandler))).Methods(http.MethodGet)

	// Add version endpoint (protected by admin auth)
	g.router.Handle("/admin/version", g.adminAuthMiddleware(http.HandlerFunc(g.versionHandler))).Methods(http.MethodGet)

	// Setup proxy routes
	for _, route := range g.config.Routes {
		if err := g.addProxyRoute(route); err != nil {
			return fmt.Errorf("failed to add route %s: %w", route.Path, err)
		}
	}

	// Register dummy handlers for plugin endpoints so middleware is invoked
	for pluginName, pluginConfig := range g.config.Plugins {
		if pluginName == "openapi" {
			servePath := "/openapi"
			swaggerUI := false
			if v, ok := pluginConfig["path"].(string); ok && v != "" {
				servePath = v
			}
			if v, ok := pluginConfig["swagger_ui"].(bool); ok {
				swaggerUI = v
			}
			g.router.HandleFunc(servePath, func(w http.ResponseWriter, r *http.Request) {}).Methods("GET")
			if swaggerUI {
				g.router.PathPrefix("/swagger-ui/").HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
				g.router.HandleFunc("/swagger-ui", func(w http.ResponseWriter, r *http.Request) {}).Methods("GET")
			}
		}
	}

	// Add catch-all route for 404s
	g.router.NotFoundHandler = http.HandlerFunc(g.notFoundHandler)

	return nil
}

// setupMiddleware configures the middleware chain
func (g *Gateway) setupMiddleware() error {
	// Add client credential auth middleware if enabled
	if len(g.config.Security.Clients) > 0 {
		g.router.Use(g.clientCredentialAuthMiddleware())
	}
	// Add global middleware
	g.router.Use(g.loggingMiddleware())
	g.router.Use(g.metricsMiddleware())
	g.router.Use(g.securityHeadersMiddleware())

	// Add JWT middleware if enabled
	if g.config.Security.Jwt.Enabled {
		jwtCfg := config.JWTConfig{
			Enabled:       g.config.Security.Jwt.Enabled,
			Secret:        g.config.Security.Jwt.Secret,
			Algorithms:    g.config.Security.Jwt.Algorithms,
			PublicKeyFile: g.config.Security.Jwt.PublicKeyFile,
			Required:      g.config.Security.Jwt.Required,
		}
		g.router.Use(g.jwtAuthMiddleware(jwtCfg))
	}

	// Add global plugin middleware (OpenAPI, Swagger UI, etc.)
	for pluginName, pluginConfig := range g.config.Plugins {
		if p, ok := plugin.Get(pluginName); ok {
			if err := p.Init(pluginConfig); err != nil {
				g.logger.Warn("Failed to initialize global plugin", logging.String("plugin", pluginName), logging.Error(err))
				continue
			}
			g.router.Use(p.Middleware())
		}
	}

	// Add error logging middleware last to catch all 4xx/5xx
	g.router.Use(g.errorLoggingMiddleware())

	return nil
}

// clientCredentialAuthMiddleware enforces HTTP Basic Auth using security.clients
func (g *Gateway) clientCredentialAuthMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Find route config for this path
			matched := false
			var requireAuth bool = true
			for _, route := range g.config.Routes {
				if r.Method != "" && len(route.Methods) > 0 {
					found := false
					for _, m := range route.Methods {
						if m == r.Method {
							found = true
							break
						}
					}
					if !found {
						continue
					}
				}
				if route.Path == r.URL.Path || containsRestWildcard(route.Path) {
					matched = true
					requireAuth = route.RequireAuth
					break
				}
			}
			if matched && !requireAuth {
				next.ServeHTTP(w, r)
				return
			}
			// Check HTTP Basic Auth
			user, pass, ok := r.BasicAuth()
			if !ok || user == "" || pass == "" {
				w.Header().Set("WWW-Authenticate", "Basic realm=\"Iket Gateway\"")
				w.WriteHeader(http.StatusUnauthorized)
				w.Write([]byte("Missing or invalid client credentials"))
				return
			}
			if secret, ok := g.config.Security.Clients[user]; !ok || secret != pass {
				w.Header().Set("WWW-Authenticate", "Basic realm=\"Iket Gateway\"")
				w.WriteHeader(http.StatusUnauthorized)
				w.Write([]byte("Invalid client credentials"))
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// loadPlugins loads built-in and external plugins
func (g *Gateway) loadPlugins() error {
	// Dynamically load plugins from plugins directory
	pluginsDir := g.config.Server.PluginsDir
	if pluginsDir == "" {
		return nil
	}
	files, err := os.ReadDir(pluginsDir)
	if err != nil {
		return err
	}
	for _, file := range files {
		if filepath.Ext(file.Name()) != ".so" {
			continue
		}
		plug, err := pluginlib.Open(filepath.Join(pluginsDir, file.Name()))
		if err != nil {
			g.logger.Warn("Failed to open plugin", logging.String("file", file.Name()), logging.Error(err))
			continue
		}
		sym, err := plug.Lookup("Plugin")
		if err != nil {
			g.logger.Warn("Plugin missing 'Plugin' symbol", logging.String("file", file.Name()), logging.Error(err))
			continue
		}
		p, ok := sym.(plugin.Plugin)
		if !ok {
			g.logger.Warn("Plugin symbol does not implement Plugin interface", logging.String("file", file.Name()))
			continue
		}
		plugin.Register(p)
		g.logger.Info("Dynamically loaded plugin", logging.String("name", p.Name()), logging.String("file", file.Name()))
	}
	return nil
}

// addProxyRoute adds a proxy route to the router
func (g *Gateway) addProxyRoute(route config.RouterConfig) error {
	var handler http.Handler = http.HandlerFunc(g.proxyHandler(route))

	// (Optional: per-route plugin middleware can be added here if you want per-route plugins)
	// for pluginName, pluginConfig := range g.config.Plugins {
	// 	if p, ok := plugin.Get(pluginName); ok {
	// 		if err := p.Init(pluginConfig); err != nil {
	// 			g.logger.Warn("Failed to initialize plugin for route", logging.String("plugin", pluginName), logging.Error(err))
	// 			continue
	// 		}
	// 		handler = p.Middleware()(handler)
	// 	}
	// }

	// Apply route-specific middleware
	if route.RequireAuth {
		handler = g.authMiddleware(handler)
	}

	// Apply route-specific timeout if configured
	if route.Timeout != nil {
		handler = g.timeoutMiddleware(*route.Timeout)(handler)
	}

	// Wildcard support: if path contains {rest:.*} or ends with /*, use PathPrefix or regex
	if route.Path == "/{rest:.*}" || route.Path == "/*" {
		g.router.PathPrefix("/").Handler(handler).Methods(route.Methods...)
		g.logger.Info("Added wildcard route (PathPrefix)", logging.String("path", route.Path), logging.String("destination", route.Destination))
	} else if len(route.Path) > 0 && route.Path[len(route.Path)-2:] == "/*" {
		prefix := route.Path[:len(route.Path)-1] // remove the *
		g.router.PathPrefix(prefix).Handler(handler).Methods(route.Methods...)
		g.logger.Info("Added wildcard route (PathPrefix)", logging.String("path", route.Path), logging.String("destination", route.Destination))
	} else if route.Path == "/" {
		g.router.Handle(route.Path, handler).Methods(route.Methods...)
		g.logger.Info("Added root route", logging.String("path", route.Path), logging.String("destination", route.Destination))
	} else if containsRestWildcard(route.Path) {
		// Use regex for {rest:.*}
		g.router.HandleFunc(route.Path, g.proxyHandler(route)).Methods(route.Methods...)
		g.logger.Info("Added regex wildcard route", logging.String("path", route.Path), logging.String("destination", route.Destination))
	} else {
		g.router.Handle(route.Path, handler).Methods(route.Methods...)
		g.logger.Info("Added route", logging.String("path", route.Path), logging.String("destination", route.Destination))
	}

	return nil
}

// containsRestWildcard checks if the path contains a {rest:.*} wildcard
func containsRestWildcard(path string) bool {
	return path == "/{rest:.*}" || (len(path) >= 9 && path[len(path)-9:] == "{rest:.*}")
}

// Serve starts the gateway server
func (g *Gateway) Serve(ctx context.Context) error {
	g.logger.Info("Starting gateway server", logging.Int("port", g.config.Server.Port))

	server := &http.Server{
		Addr:    fmt.Sprintf(":%d", g.config.Server.Port),
		Handler: g.router,
	}

	g.server = server

	// Start server in goroutine
	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			g.logger.Error("Server error", err)
		}
	}()

	// Wait for shutdown signal
	<-g.shutdown

	g.logger.Info("Shutting down gateway server")
	return server.Shutdown(ctx)
}

// Shutdown gracefully shuts down the gateway
func (g *Gateway) Shutdown() {
	g.mu.Lock()
	defer g.mu.Unlock()

	select {
	case <-g.shutdown:
		// Already shutting down
		return
	default:
		close(g.shutdown)
	}

	g.logger.Info("Gateway shutdown complete")
}

// GetConfig returns the current configuration
func (g *Gateway) GetConfig() *config.Config {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.config
}

// GetRouter returns the router for external route registration
func (g *Gateway) GetRouter() *mux.Router {
	return g.router
}

// UpdateConfig updates the gateway configuration
func (g *Gateway) UpdateConfig(cfg *config.Config) error {
	g.mu.Lock()
	defer g.mu.Unlock()

	if err := cfg.Validate(); err != nil {
		return errors.NewConfigError("invalid configuration", err)
	}

	g.config = cfg

	// Rebuild routes
	if err := g.setupRoutes(); err != nil {
		return fmt.Errorf("failed to rebuild routes: %w", err)
	}

	g.logger.Info("Configuration updated successfully")
	return nil
}

// healthHandler handles health check requests
func (g *Gateway) healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"UP","timestamp":"` + time.Now().Format(time.RFC3339) + `"}`))
}

// metricsHandler handles metrics requests
func (g *Gateway) metricsHandler(w http.ResponseWriter, r *http.Request) {
	if g.metrics != nil {
		g.metrics.ServeHTTP(w, r)
	} else {
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte(`{"error":"Metrics not available"}`))
	}
}

// notFoundHandler handles 404 requests
func (g *Gateway) notFoundHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Printf("notFoundHandler called for path: %s\n", r.URL.Path)
	g.logger.Warn("404 Not Found",
		logging.String("method", r.Method),
		logging.String("path", r.URL.Path),
		logging.String("remote_addr", r.RemoteAddr),
	)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotFound)
	w.Write([]byte(`{"error":"Not Found","message":"The requested resource does not exist"}`))
}

// configHandler returns the current configuration as JSON, with secrets redacted
func (g *Gateway) configHandler(w http.ResponseWriter, r *http.Request) {
	cfg := *g.GetConfig()
	// Redact secrets
	if cfg.Security.Jwt.Secret != "" {
		cfg.Security.Jwt.Secret = "REDACTED"
	}
	cfg.Security.BasicAuthUsers = nil // Hide BasicAuthUsers
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(cfg)
}

// adminAuthMiddleware enforces Basic Auth for admin endpoints
func (g *Gateway) adminAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || user == "" || pass == "" {
			g.logger.Warn("401 Unauthorized (admin endpoint)",
				logging.String("reason", "Missing or invalid admin credentials"),
				logging.String("method", r.Method),
				logging.String("path", r.URL.Path),
				logging.String("remote_addr", r.RemoteAddr),
			)
			w.Header().Set("WWW-Authenticate", "Basic realm=\"Iket Admin\"")
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("Missing or invalid admin credentials"))
			return
		}
		if expected, ok := g.config.Security.BasicAuthUsers[user]; !ok || expected != pass {
			g.logger.Warn("401 Unauthorized (admin endpoint)",
				logging.String("reason", "Invalid admin credentials"),
				logging.String("method", r.Method),
				logging.String("path", r.URL.Path),
				logging.String("remote_addr", r.RemoteAddr),
			)
			w.Header().Set("WWW-Authenticate", "Basic realm=\"Iket Admin\"")
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("Invalid admin credentials"))
			return
		}
		next.ServeHTTP(w, r)
	})
}

// versionHandler returns the current version as JSON
func (g *Gateway) versionHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"version": g.version})
}
