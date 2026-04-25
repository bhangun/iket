package gateway

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/bhangun/iket/pkg/config"
	"github.com/bhangun/iket/pkg/core/errors"
	"github.com/bhangun/iket/pkg/logging"
	"github.com/bhangun/iket/pkg/metrics"
	"github.com/bhangun/iket/pkg/plugin"
	_ "github.com/bhangun/iket/pkg/plugin/apikey"
	_ "github.com/bhangun/iket/pkg/plugin/jwt"

	pluginlib "plugin"

	"github.com/gorilla/mux"
)

// Gateway represents the main API gateway instance.
// It handles request routing, middleware execution, and plugin management.
type Gateway struct {
	config         *config.Config
	configProvider config.Provider
	router         *mux.Router
	metrics        *metrics.Collector
	logger         *logging.Logger
	server         *http.Server
	tlsServer      *http.Server

	// State management
	mu       sync.RWMutex
	shutdown chan struct{}

	version string // Add version field
	// Add a field to Gateway struct for the plugin registry
	pluginRegistry *plugin.Registry
}

// Dependencies contains all the dependencies required to create a Gateway
type Dependencies struct {
	Config         *config.Config
	ConfigProvider config.Provider
	Logger         *logging.Logger
	Metrics        *metrics.Collector
	Registry       *plugin.Registry // <-- Added Registry field
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
		config:         deps.Config,
		configProvider: deps.ConfigProvider,
		router:         mux.NewRouter(),
		metrics:        deps.Metrics,
		logger:         deps.Logger,
		shutdown:       make(chan struct{}),
		version:        version,
		pluginRegistry: deps.Registry, // <-- Use provided registry
	}
	if gateway.pluginRegistry == nil {
		gateway.pluginRegistry = plugin.NewRegistry()
	}

	return gateway, nil
}

// Initialize performs the actual setup of routes, middleware and plugins.
// This should be called after external handlers (like Management API) have been registered
// to the router, ensuring they are not shadowed by wildcard proxy routes.
func (g *Gateway) Initialize() error {
	// Setup routes and middleware
	if err := g.setupRoutes(); err != nil {
		return fmt.Errorf("failed to setup routes: %w", err)
	}

	if err := g.setupMiddleware(); err != nil {
		return fmt.Errorf("failed to setup middleware: %w", err)
	}

	// Load built-in and external plugins
	if err := g.loadPlugins(); err != nil {
		return fmt.Errorf("failed to load plugins: %w", err)
	}

	g.logger.Info("Gateway initialized successfully")
	return nil
}

// setupRoutes configures all the routes for the gateway
func (g *Gateway) setupRoutes() error {
	// DEBUG: Print all loaded routes
	allRoutes := g.config.GetAllRoutesFromServices(g.logger)
	g.logger.Info("Loaded routes from config", logging.Int("count", len(allRoutes)))

	// Add health check endpoint
	g.router.HandleFunc("/health", g.healthHandler).Methods(http.MethodGet)

	// Add metrics endpoint
	g.router.HandleFunc("/metrics", g.metricsHandler).Methods(http.MethodGet)

	// Add config endpoint (protected by admin auth)
	g.router.Handle("/admin/config", g.adminAuthMiddleware(http.HandlerFunc(g.configHandler))).Methods(http.MethodGet)

	// Add version endpoint (protected by admin auth)
	g.router.Handle("/admin/version", g.adminAuthMiddleware(http.HandlerFunc(g.versionHandler))).Methods(http.MethodGet)

	// Setup proxy routes
	for _, route := range g.config.GetAllRoutesFromServices(g.logger) {
		if !route.IsEnabled() {
			continue
		}
		if err := g.addProxyRoute(route); err != nil {
			return fmt.Errorf("failed to add route %s: %w", route.Path, err)
		}
	}

	// Mount billing plugin HTTP handler if available
	if p, err := g.pluginRegistry.Get("billing"); err == nil {
		if handlerProvider, ok := p.(interface{ Routes() http.Handler }); ok {
			g.router.PathPrefix("/plugin/billing/").Handler(
				http.StripPrefix("/plugin/billing", handlerProvider.Routes()),
			)
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
	g.router.Use(g.routeContextMiddleware())
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
		p, err := g.pluginRegistry.Get(pluginName)
		if err != nil {
			g.logger.Warn("Plugin not found", logging.String("plugin", pluginName), logging.Error(err))
			continue
		}
		if err := p.Initialize(pluginConfig); err != nil {
			g.logger.Warn("Failed to initialize global plugin", logging.String("plugin", pluginName), logging.Error(err))
			continue
		}
		if mp, ok := p.(plugin.MiddlewarePlugin); ok {
			g.router.Use(mp.Middleware)
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
			for _, route := range g.config.GetAllRoutesFromServices(g.logger) {
				if !route.IsEnabled() {
					continue
				}
				if !route.SupportsMethod(r.Method) {
					continue
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
		if err := g.pluginRegistry.Register(p); err != nil {
			g.logger.Warn("Failed to register plugin", logging.String("name", p.Name()), logging.Error(err))
			continue
		}
		g.logger.Info("Dynamically loaded plugin", logging.String("name", p.Name()), logging.String("file", file.Name()))
	}
	return nil
}

// addProxyRoute adds a proxy route to the router
func (g *Gateway) addProxyRoute(route config.RouterConfig) error {
	var handler http.Handler = http.HandlerFunc(g.proxyHandler(route))

	// Hybrid global/local plugin auth
	if route.RequireAuth {
		if route.AuthPlugin != "" {
			// Use only the specified plugin for this route
			p, err := g.pluginRegistry.Get(route.AuthPlugin)
			if err == nil {
				if mp, ok := p.(plugin.MiddlewarePlugin); ok {
					handler = mp.Middleware(handler)
				}
			}
		} else {
			// Use all global plugins as fallback
			for pluginName, pluginConfig := range g.config.Plugins {
				p, err := g.pluginRegistry.Get(pluginName)
				if err == nil {
					if err := p.Initialize(pluginConfig); err == nil {
						if mp, ok := p.(plugin.MiddlewarePlugin); ok {
							handler = mp.Middleware(handler)
						}
					}
				}
			}
		}
		// Per-route roles enforcement
		if len(route.Roles) > 0 {
			handler = requireRolesMiddleware(route.Roles)(handler)
		}

		// Scope and Group enforcement
		service := g.config.FindServiceForRoute(route.Path, "")
		if service != nil {
			// Enforce service-level grouping
			if service.Group != "" {
				handler = requireGroupMiddleware(service.Group)(handler)
			}

			// Enforce scopes (merge service and route level)
			allRequiredScopes := append([]string{}, service.Scopes...)
			allRequiredScopes = append(allRequiredScopes, route.Scopes...)
			if len(allRequiredScopes) > 0 {
				handler = requireScopesMiddleware(allRequiredScopes)(handler)
			}
		} else if len(route.Scopes) > 0 {
			// Only route-level scopes if no parent service found
			handler = requireScopesMiddleware(route.Scopes)(handler)
		}
	}

	// Apply route-specific timeout if configured
	if route.Timeout != nil {
		handler = g.timeoutMiddleware(*route.Timeout)(handler)
	}

	// Wildcard support: if path contains {rest:.*} or ends with /*, use PathPrefix or regex
	if route.Path == "/{rest:.*}" || route.Path == "/*" {
		g.router.PathPrefix("/").Handler(handler).Methods(route.EffectiveMethods()...)
		service := g.config.FindServiceForRoute(route.Path, "")
		backend := ""
		if service != nil {
			backend = service.Host
		}
		g.logger.Info("Added wildcard route (PathPrefix)", logging.String("path", route.Path), logging.String("backend", backend))
	} else if len(route.Path) > 0 && route.Path[len(route.Path)-2:] == "/*" {
		prefix := route.Path[:len(route.Path)-1] // remove the *
		g.router.PathPrefix(prefix).Handler(handler).Methods(route.EffectiveMethods()...)
		service := g.config.FindServiceForRoute(route.Path, "")
		backend := ""
		if service != nil {
			backend = service.Host
		}
		g.logger.Info("Added wildcard route (PathPrefix)", logging.String("path", route.Path), logging.String("backend", backend))
	} else if route.Path == "/" {
		g.router.Handle(route.Path, handler).Methods(route.EffectiveMethods()...)
		service := g.config.FindServiceForRoute(route.Path, "")
		backend := ""
		if service != nil {
			backend = service.Host
		}
		g.logger.Info("Added root route", logging.String("path", route.Path), logging.String("backend", backend))
	} else if containsRestWildcard(route.Path) {
		// Use regex for {rest:.*}
		g.router.HandleFunc(route.Path, g.proxyHandler(route)).Methods(route.EffectiveMethods()...)
		service := g.config.FindServiceForRoute(route.Path, "")
		backend := ""
		if service != nil {
			backend = service.Host
		}
		g.logger.Info("Added regex wildcard route", logging.String("path", route.Path), logging.String("backend", backend))
	} else {
		g.router.Handle(route.Path, handler).Methods(route.EffectiveMethods()...)
		service := g.config.FindServiceForRoute(route.Path, "")
		backend := ""
		if service != nil {
			backend = service.Host
		}
		g.logger.Info("Added route", logging.String("path", route.Path), logging.String("backend", backend))
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
		Handler: AccessLogMiddleware(g, g.router),
	}

	g.server = server
	tlsPort := g.config.Security.TLS.EffectivePort(g.config.Server.Port)

	if !g.config.Security.TLS.Enabled || tlsPort != g.config.Server.Port {
		go func() {
			if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				g.logger.Error("Server error", err)
			}
		}()
	}

	// Setup TLS if enabled on a dedicated or shared port
	if g.config.Security.TLS.Enabled {
		if err := config.EnsureTLSAssets(g.config.Security.TLS); err != nil {
			return fmt.Errorf("failed to prepare TLS assets: %w", err)
		}

		tlsConfig := &tls.Config{
			MinVersion: tls.VersionTLS12,
		}

		// Set minimum TLS version if configured
		switch g.config.Security.TLS.MinVersion {
		case "TLS1.0":
			tlsConfig.MinVersion = tls.VersionTLS10
		case "TLS1.1":
			tlsConfig.MinVersion = tls.VersionTLS11
		case "TLS1.2":
			tlsConfig.MinVersion = tls.VersionTLS12
		case "TLS1.3":
			tlsConfig.MinVersion = tls.VersionTLS13
		}

		// Setup mTLS if configured
		if g.config.Security.TLS.ClientCAFile != "" {
			caCert, err := os.ReadFile(g.config.Security.TLS.ClientCAFile)
			if err != nil {
				return fmt.Errorf("failed to read client CA file: %w", err)
			}

			caPool := x509.NewCertPool()
			if !caPool.AppendCertsFromPEM(caCert) {
				return fmt.Errorf("failed to append client CA certificate to pool")
			}

			tlsConfig.ClientCAs = caPool

			// Set client auth type
			switch g.config.Security.TLS.ClientAuthType {
			case "RequestClientCert":
				tlsConfig.ClientAuth = tls.RequestClientCert
			case "RequireAnyClientCert":
				tlsConfig.ClientAuth = tls.RequireAnyClientCert
			case "VerifyClientCertIfGiven":
				tlsConfig.ClientAuth = tls.VerifyClientCertIfGiven
			case "RequireAndVerifyClientCert":
				tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
			default:
				tlsConfig.ClientAuth = tls.NoClientCert
			}
		}

		if tlsPort == g.config.Server.Port {
			go func() {
				g.logger.Info("Starting TLS server", logging.Int("port", tlsPort), logging.String("cert", g.config.Security.TLS.CertFile))
				if err := server.ListenAndServeTLS(g.config.Security.TLS.CertFile, g.config.Security.TLS.KeyFile); err != nil && err != http.ErrServerClosed {
					g.logger.Error("TLS Server error", err)
				}
			}()
			g.tlsServer = server
		} else {
			tlsServer := &http.Server{
				Addr:      fmt.Sprintf(":%d", tlsPort),
				Handler:   AccessLogMiddleware(g, g.router),
				TLSConfig: tlsConfig,
			}
			g.tlsServer = tlsServer

			go func() {
				g.logger.Info("Starting TLS server", logging.Int("port", tlsPort), logging.String("cert", g.config.Security.TLS.CertFile))
				if err := tlsServer.ListenAndServeTLS(g.config.Security.TLS.CertFile, g.config.Security.TLS.KeyFile); err != nil && err != http.ErrServerClosed {
					g.logger.Error("TLS Server error", err)
				}
			}()
		}
	}

	// Wait for shutdown signal
	<-g.shutdown

	g.logger.Info("Shutting down gateway server")
	if g.tlsServer != nil && g.tlsServer != server {
		if err := g.tlsServer.Shutdown(ctx); err != nil {
			g.logger.Error("TLS shutdown error", err)
		}
	}
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

func (g *Gateway) ReloadConfig() error {
	if g.configProvider == nil {
		return fmt.Errorf("config provider not available")
	}

	cfg, err := g.configProvider.Load()
	if err != nil {
		return fmt.Errorf("failed to reload configuration: %w", err)
	}

	g.mu.Lock()
	defer g.mu.Unlock()
	g.config = cfg
	g.logger.Info("Configuration reloaded from provider")
	return nil
}

func (g *Gateway) Version() string {
	return g.version
}

// UpdateConfig updates the gateway configuration
func (g *Gateway) UpdateConfig(cfg *config.Config) error {
	g.mu.Lock()
	defer g.mu.Unlock()

	if err := cfg.Validate(); err != nil {
		return errors.NewConfigError("invalid configuration", err)
	}

	// Persist configuration if provider is available
	if g.configProvider != nil {
		if err := g.configProvider.Save(cfg); err != nil {
			g.logger.Error("Failed to persist configuration changes", err)
			return fmt.Errorf("failed to persist configuration: %w", err)
		}
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
	clientIP := GetClientIP(r)
	g.logger.Warn("404 Not Found",
		logging.String("method", r.Method),
		logging.String("path", r.URL.Path),
		logging.String("remote_addr", r.RemoteAddr),
		logging.String("client_ip", clientIP),
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
		// Get client IP
		clientIP := GetClientIP(r)
		g.logger.Debug("Admin request", logging.String("client_ip", clientIP))
		user, pass, ok := r.BasicAuth()
		if !ok || user == "" || pass == "" {
			g.logger.Warn("401 Unauthorized (admin endpoint)",
				logging.String("reason", "Missing or invalid admin credentials"),
				logging.String("method", r.Method),
				logging.String("path", r.URL.Path),
				logging.String("remote_addr", r.RemoteAddr),
				logging.String("client_ip", clientIP),
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
				logging.String("client_ip", clientIP),
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

// requireRolesMiddleware returns a middleware that enforces at least one required role
func requireRolesMiddleware(requiredRoles []string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			roles, ok := r.Context().Value("roles").([]string)
			if !ok || len(roles) == 0 {
				w.WriteHeader(http.StatusForbidden)
				w.Write([]byte(`{"error":"Forbidden","message":"No roles found in token"}`))
				return
			}
			for _, required := range requiredRoles {
				for _, actual := range roles {
					if required == actual {
						next.ServeHTTP(w, r)
						return
					}
				}
			}
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte(`{"error":"Forbidden","message":"Insufficient roles"}`))
		})
	}
}

// requireScopesMiddleware returns a middleware that enforces at least one required scope
func requireScopesMiddleware(requiredScopes []string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			scopes, ok := r.Context().Value("apikey_scopes").([]string)
			if !ok || len(scopes) == 0 {
				w.WriteHeader(http.StatusForbidden)
				w.Write([]byte(`{"error":"Forbidden","message":"No scopes found for client"}`))
				return
			}
			for _, required := range requiredScopes {
				for _, actual := range scopes {
					if required == actual {
						next.ServeHTTP(w, r)
						return
					}
				}
			}
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte(`{"error":"Forbidden","message":"Insufficient scopes"}`))
		})
	}
}

// requireGroupMiddleware returns a middleware that enforces the required client group
func requireGroupMiddleware(requiredGroup string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			clientGroup, ok := r.Context().Value("apikey_group").(string)
			if !ok || clientGroup != requiredGroup {
				w.WriteHeader(http.StatusForbidden)
				w.Write([]byte(`{"error":"Forbidden","message":"Client group mismatch"}`))
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
