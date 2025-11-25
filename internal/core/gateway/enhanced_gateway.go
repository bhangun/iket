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
	"iket/internal/logging"
	"iket/internal/metrics"
	"iket/pkg/plugin"

	"github.com/gorilla/mux"
)

// EnhancedGateway represents the enhanced API gateway instance with improved plugin system.
// It handles request routing, middleware execution, and the enhanced plugin management.
type EnhancedGateway struct {
	config    *config.Config
	router    *mux.Router
	metrics   *metrics.Collector
	logger    *logging.Logger
	server    *http.Server
	pluginReg *plugin.Registry
	pluginDir string

	// State management
	mu       sync.RWMutex
	shutdown chan struct{}
	version  string
}

// EnhancedDependencies contains all the dependencies required to create an EnhancedGateway
type EnhancedDependencies struct {
	Config  *config.Config
	Logger  *logging.Logger
	Metrics *metrics.Collector
}

// NewEnhancedGateway creates a new EnhancedGateway instance with the provided dependencies
func NewEnhancedGateway(deps EnhancedDependencies, version string) (*EnhancedGateway, error) {
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

	gateway := &EnhancedGateway{
		config:    deps.Config,
		router:    mux.NewRouter(),
		metrics:   deps.Metrics,
		logger:    deps.Logger,
		shutdown:  make(chan struct{}),
		version:   version,
		pluginReg: plugin.NewRegistry(),
		pluginDir: deps.Config.Server.PluginsDir,
	}

	// Setup routes and middleware
	if err := gateway.setupRoutes(); err != nil {
		return nil, fmt.Errorf("failed to setup routes: %w", err)
	}

	if err := gateway.setupMiddleware(); err != nil {
		return nil, fmt.Errorf("failed to setup middleware: %w", err)
	}

	// Load enhanced plugins
	if err := gateway.loadEnhancedPlugins(); err != nil {
		return nil, fmt.Errorf("failed to load enhanced plugins: %w", err)
	}

	gateway.logger.Info("Enhanced Gateway initialized successfully")
	return gateway, nil
}

// setupRoutes configures all the routes for the gateway
func (g *EnhancedGateway) setupRoutes() error {
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

	// Add catch-all route for 404s
	g.router.NotFoundHandler = http.HandlerFunc(g.notFoundHandler)

	return nil
}

// setupMiddleware configures the middleware chain
func (g *EnhancedGateway) setupMiddleware() error {
	// Add client credential auth middleware if enabled
	if g.config.Security.Clients != nil && len(g.config.Security.Clients) > 0 {
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

	// Add global plugin middleware
	if err := g.setupPluginMiddleware(); err != nil {
		g.logger.Warn("Failed to setup plugin middleware", logging.Error(err))
	}

	// Add error logging middleware last to catch all 4xx/5xx
	g.router.Use(g.errorLoggingMiddleware())

	return nil
}

// setupPluginMiddleware sets up middleware from registered plugins
func (g *EnhancedGateway) setupPluginMiddleware() error {
	// Get all middleware plugins
	middlewarePlugins := g.pluginReg.GetByType(plugin.MiddlewarePlugin)
	
	for _, p := range middlewarePlugins {
		if middlewarePlugin, ok := p.(plugin.MiddlewarePlugin); ok {
			g.router.Use(middlewarePlugin.Middleware())
			g.logger.Info("Applied middleware plugin", logging.String("plugin", p.Name()))
		}
	}
	
	return nil
}

// loadEnhancedPlugins loads plugins using the enhanced plugin system
func (g *EnhancedGateway) loadEnhancedPlugins() error {
	// Register built-in plugins
	g.registerBuiltInPlugins()

	// Load dynamic plugins from directory if specified
	if g.pluginDir != "" {
		if err := g.loadDynamicPlugins(); err != nil {
			return fmt.Errorf("failed to load dynamic plugins: %w", err)
		}
	}

	// Initialize all registered plugins with their configurations
	pluginConfigs := make(map[string]plugin.PluginConfig)
	for name, config := range g.config.Plugins {
		// Extract the 'enabled' field from the config map
		enabled := true // default to true
		if enabledVal, exists := config["enabled"]; exists {
			if enabledBool, ok := enabledVal.(bool); ok {
				enabled = enabledBool
			}
		}
		
		pluginConfigs[name] = plugin.PluginConfig{
			Enabled: enabled,
			Type:    plugin.MiddlewarePlugin, // Default type, will be determined by plugin
			Config:  config,
		}
	}

	if err := g.pluginReg.Initialize(pluginConfigs); err != nil {
		return fmt.Errorf("failed to initialize plugins: %w", err)
	}

	g.logger.Info("Enhanced plugins loaded successfully", logging.Int("count", len(g.pluginReg.List())))
	return nil
}

// registerBuiltInPlugins registers built-in plugins
func (g *EnhancedGateway) registerBuiltInPlugins() {
	// For now, we'll just log that this is where built-in plugins would be registered
	// In a real implementation, you would create instances of built-in plugins and register them
	g.logger.Info("Registering built-in plugins")
}

// loadDynamicPlugins loads dynamic plugins from the plugins directory
func (g *EnhancedGateway) loadDynamicPlugins() error {
	loader := plugin.NewDynamicPluginLoader(g.pluginDir)
	
	if err := loader.LoadAllPlugins(g.pluginReg); err != nil {
		return fmt.Errorf("failed to load all plugins: %w", err)
	}
	
	return nil
}

// addProxyRoute adds a proxy route to the router
func (g *EnhancedGateway) addProxyRoute(route config.RouterConfig) error {
	var handler http.Handler = http.HandlerFunc(g.proxyHandler(route))

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
func (g *EnhancedGateway) Serve(ctx context.Context) error {
	g.logger.Info("Starting enhanced gateway server", logging.Int("port", g.config.Server.Port))

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

	g.logger.Info("Shutting down enhanced gateway server")
	return server.Shutdown(ctx)
}

// Shutdown gracefully shuts down the gateway
func (g *EnhancedGateway) Shutdown() {
	g.mu.Lock()
	defer g.mu.Unlock()

	select {
	case <-g.shutdown:
		// Already shutting down
		return
	default:
		close(g.shutdown)
	}

	// Shutdown plugins
	if err := g.pluginReg.Shutdown(); err != nil {
		g.logger.Error("Error shutting down plugins", err)
	}

	g.logger.Info("Enhanced Gateway shutdown complete")
}

// GetConfig returns the current configuration
func (g *EnhancedGateway) GetConfig() *config.Config {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.config
}

// UpdateConfig updates the gateway configuration
func (g *EnhancedGateway) UpdateConfig(cfg *config.Config) error {
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
func (g *EnhancedGateway) healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"UP","timestamp":"` + time.Now().Format(time.RFC3339) + `"}`))
}

// metricsHandler handles metrics requests
func (g *EnhancedGateway) metricsHandler(w http.ResponseWriter, r *http.Request) {
	if g.metrics != nil {
		g.metrics.ServeHTTP(w, r)
	} else {
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte(`{"error":"Metrics not available"}`))
	}
}

// notFoundHandler handles 404 requests
func (g *EnhancedGateway) notFoundHandler(w http.ResponseWriter, r *http.Request) {
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
func (g *EnhancedGateway) configHandler(w http.ResponseWriter, r *http.Request) {
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
func (g *EnhancedGateway) adminAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || user == "" || pass == "" {
			g.logger.Warn("401 Unauthorized (admin endpoint)",
				logging.String("reason", "Missing or invalid admin credentials"),
				logging.String("method", r.Method),
				logging.String("path", r.URL.Path),
				logging.String("remote_addr", r.RemoteAddr),
			)
			w.Header().Set("WWW-Authenticate", `Basic realm="Iket Admin"`)
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
			w.Header().Set("WWW-Authenticate", `Basic realm="Iket Admin"`)
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("Invalid admin credentials"))
			return
		}
		next.ServeHTTP(w, r)
	})
}

// versionHandler returns the current version as JSON
func (g *EnhancedGateway) versionHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"version": g.version})
}