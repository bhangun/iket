package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
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
	http3Server    http3Transport

	// State management
	mu       sync.RWMutex
	shutdown chan struct{}

	backendStateMu sync.RWMutex
	backendState   map[string]backendRuntimeState

	policyStateMu sync.RWMutex
	policyState   policyHitRuntimeState

	version string // Add version field
	// Add a field to Gateway struct for the plugin registry
	pluginRegistry *plugin.Registry
}

type backendRuntimeState struct {
	ConsecutiveFailures      int
	ConsecutiveSuccesses     int
	ConsecutiveSlowResponses int
	LatencyEWMA              time.Duration
	ShadowRequests           int
	ShadowFailures           int
	ShadowLatencyEWMA        time.Duration
	UnhealthyUntil           time.Time
	ProbeInFlight            bool
	HalfOpenInFlight         int
	LastChecked              time.Time
	LastSuccess              time.Time
	LastFailure              time.Time
	LastStatusCode           int
	LastObservedLatency      time.Duration
	LastShadowStatusCode     int
	LastShadowLatency        time.Duration
	LastShadowError          string
	LastError                string
}

type policyHitRuntimeState struct {
	Total     int
	ByReason  map[string]int
	ByRoute   map[string]policyHitRouteRuntimeState
	Events    []policyHitEvent
	UpdatedAt time.Time
}

type policyHitRouteRuntimeState struct {
	ServiceName string
	RoutePath   string
	Total       int
	ByReason    map[string]int
}

type policyHitEvent struct {
	ServiceName string
	RoutePath   string
	Reason      string
	OccurredAt  time.Time
}

type BackendStatus struct {
	ServiceName                     string    `json:"service_name"`
	RoutePath                       string    `json:"route_path"`
	Destination                     string    `json:"destination"`
	URLPattern                      string    `json:"url_pattern"`
	Weight                          int       `json:"weight"`
	CircuitState                    string    `json:"circuit_state"`
	Available                       bool      `json:"available"`
	ProbeInFlight                   bool      `json:"probe_in_flight"`
	HalfOpenInFlight                int       `json:"half_open_in_flight"`
	HalfOpenMaxRequests             int       `json:"half_open_max_requests"`
	ConsecutiveSuccesses            int       `json:"consecutive_successes"`
	RecoverySuccessThreshold        int       `json:"recovery_success_threshold"`
	ConsecutiveSlowResponses        int       `json:"consecutive_slow_responses"`
	OutlierLatencyThreshold         string    `json:"outlier_latency_threshold,omitempty"`
	OutlierConsecutiveSlowResponses int       `json:"outlier_consecutive_slow_responses"`
	LastObservedLatencyMs           int64     `json:"last_observed_latency_ms,omitempty"`
	LatencyEWMAMs                   int64     `json:"latency_ewma_ms,omitempty"`
	ShadowRequests                  int       `json:"shadow_requests"`
	ShadowFailures                  int       `json:"shadow_failures"`
	ShadowFailureRate               float64   `json:"shadow_failure_rate,omitempty"`
	ShadowLatencyEWMAMs             int64     `json:"shadow_latency_ewma_ms,omitempty"`
	LastShadowStatusCode            int       `json:"last_shadow_status_code,omitempty"`
	LastShadowLatencyMs             int64     `json:"last_shadow_latency_ms,omitempty"`
	LastShadowError                 string    `json:"last_shadow_error,omitempty"`
	ShadowVsLiveLatencyDeltaMs      int64     `json:"shadow_vs_live_latency_delta_ms,omitempty"`
	ConsecutiveFailures             int       `json:"consecutive_failures"`
	UnhealthyUntil                  time.Time `json:"unhealthy_until,omitempty"`
	LastChecked                     time.Time `json:"last_checked,omitempty"`
	LastSuccess                     time.Time `json:"last_success,omitempty"`
	LastFailure                     time.Time `json:"last_failure,omitempty"`
	LastStatusCode                  int       `json:"last_status_code,omitempty"`
	LastError                       string    `json:"last_error,omitempty"`
	HealthCheckPath                 string    `json:"health_check_path,omitempty"`
	HealthInterval                  string    `json:"health_interval,omitempty"`
	HealthTimeout                   string    `json:"health_timeout,omitempty"`
}

type ShadowRouteSummary struct {
	ServiceName                string   `json:"service_name"`
	RoutePath                  string   `json:"route_path"`
	ShadowRequests             int      `json:"shadow_requests"`
	ShadowFailures             int      `json:"shadow_failures"`
	ShadowFailureRate          float64  `json:"shadow_failure_rate,omitempty"`
	LiveLatencyEWMAMs          int64    `json:"live_latency_ewma_ms,omitempty"`
	ShadowLatencyEWMAMs        int64    `json:"shadow_latency_ewma_ms,omitempty"`
	ShadowVsLiveLatencyDeltaMs int64    `json:"shadow_vs_live_latency_delta_ms,omitempty"`
	Backends                   []string `json:"backends,omitempty"`
	HealthyBackends            int      `json:"healthy_backends"`
}

type ShadowRouteEvaluation struct {
	ShadowRouteSummary
	PolicyConfigured      bool     `json:"policy_configured"`
	Healthy               bool     `json:"healthy"`
	Reasons               []string `json:"reasons,omitempty"`
	MinRequests           int      `json:"min_requests,omitempty"`
	MaxErrorRate          float64  `json:"max_error_rate,omitempty"`
	MaxLatencyDeltaMs     int64    `json:"max_latency_delta_ms,omitempty"`
	MaxLatencyDeltaSource string   `json:"max_latency_delta,omitempty"`
}

type PolicyHitReasonSummary struct {
	Reason string `json:"reason"`
	Count  int    `json:"count"`
}

type PolicyHitRouteSummary struct {
	ServiceName string         `json:"service_name,omitempty"`
	RoutePath   string         `json:"route_path"`
	Total       int            `json:"total"`
	ByReason    map[string]int `json:"by_reason,omitempty"`
}

type PolicyHitSummary struct {
	Total     int                      `json:"total"`
	Reasons   []PolicyHitReasonSummary `json:"reasons,omitempty"`
	Routes    []PolicyHitRouteSummary  `json:"routes,omitempty"`
	UpdatedAt time.Time                `json:"updated_at,omitempty"`
}

type PolicyHitWindowSummary struct {
	Window         string                   `json:"window"`
	WindowSeconds  int64                    `json:"window_seconds"`
	Total          int                      `json:"total"`
	Reasons        []PolicyHitReasonSummary `json:"reasons,omitempty"`
	Routes         []PolicyHitRouteSummary  `json:"routes,omitempty"`
	Since          time.Time                `json:"since,omitempty"`
	TopReason      string                   `json:"top_reason,omitempty"`
	TopRoutePath   string                   `json:"top_route_path,omitempty"`
	TopServiceName string                   `json:"top_service_name,omitempty"`
}

type PolicyAlert struct {
	Severity    string    `json:"severity"`
	ServiceName string    `json:"service_name,omitempty"`
	RoutePath   string    `json:"route_path"`
	Reason      string    `json:"reason"`
	Count       int       `json:"count"`
	Since       time.Time `json:"since,omitempty"`
}

type PolicyAlertSummary struct {
	Window        string         `json:"window"`
	WindowSeconds int64          `json:"window_seconds"`
	MinCount      int            `json:"min_count"`
	TotalAlerts   int            `json:"total_alerts"`
	BySeverity    map[string]int `json:"by_severity,omitempty"`
	Alerts        []PolicyAlert  `json:"alerts,omitempty"`
}

type shadowRouteAggregate struct {
	ShadowRouteSummary
	backends      map[string]struct{}
	liveSamples   int64
	shadowSamples int64
	deltaSamples  int64
}

const (
	defaultBackendHealthInterval = 15 * time.Second
	defaultBackendHealthTimeout  = 2 * time.Second
)

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
		backendState:   make(map[string]backendRuntimeState),
		policyState: policyHitRuntimeState{
			ByReason: make(map[string]int),
			ByRoute:  make(map[string]policyHitRouteRuntimeState),
		},
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

	go g.activeBackendProbeLoop()

	g.logger.Info("Gateway initialized successfully")
	return nil
}

// setupRoutes configures all the routes for the gateway
func (g *Gateway) setupRoutes() error {
	// DEBUG: Print all loaded routes
	allRoutes := g.config.GetAllRoutesFromServices(g.logger)
	sort.SliceStable(allRoutes, func(i, j int) bool {
		return routeSpecificityScore(allRoutes[i]) > routeSpecificityScore(allRoutes[j])
	})
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
	for _, route := range allRoutes {
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
		service := g.config.FindServiceForRoute(route.Path, "", route.MatchHeaders)
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
	if route.CORS != nil {
		handler = corsMiddleware(route)(handler)
	}

	// Wildcard support: if path contains {rest:.*} or ends with /*, use PathPrefix or regex
	if route.Path == "/{rest:.*}" || route.Path == "/*" {
		registered := g.router.PathPrefix("/").Handler(handler).Methods(route.EffectiveMethodsForRegistration()...)
		applyRouteHeaderMatchers(registered, route.MatchHeaders)
		service := g.config.FindServiceForRoute(route.Path, "", route.MatchHeaders)
		backend := ""
		if service != nil {
			backend = service.Host
		}
		g.logger.Info("Added wildcard route (PathPrefix)", logging.String("path", route.Path), logging.String("backend", backend))
	} else if len(route.Path) > 0 && route.Path[len(route.Path)-2:] == "/*" {
		prefix := route.Path[:len(route.Path)-1] // remove the *
		registered := g.router.PathPrefix(prefix).Handler(handler).Methods(route.EffectiveMethodsForRegistration()...)
		applyRouteHeaderMatchers(registered, route.MatchHeaders)
		service := g.config.FindServiceForRoute(route.Path, "", route.MatchHeaders)
		backend := ""
		if service != nil {
			backend = service.Host
		}
		g.logger.Info("Added wildcard route (PathPrefix)", logging.String("path", route.Path), logging.String("backend", backend))
	} else if route.Path == "/" {
		registered := g.router.Handle(route.Path, handler).Methods(route.EffectiveMethodsForRegistration()...)
		applyRouteHeaderMatchers(registered, route.MatchHeaders)
		service := g.config.FindServiceForRoute(route.Path, "", route.MatchHeaders)
		backend := ""
		if service != nil {
			backend = service.Host
		}
		g.logger.Info("Added root route", logging.String("path", route.Path), logging.String("backend", backend))
	} else if containsRestWildcard(route.Path) {
		// Use regex for {rest:.*}
		registered := g.router.Handle(route.Path, handler).Methods(route.EffectiveMethodsForRegistration()...)
		applyRouteHeaderMatchers(registered, route.MatchHeaders)
		service := g.config.FindServiceForRoute(route.Path, "", route.MatchHeaders)
		backend := ""
		if service != nil {
			backend = service.Host
		}
		g.logger.Info("Added regex wildcard route", logging.String("path", route.Path), logging.String("backend", backend))
	} else {
		registered := g.router.Handle(route.Path, handler).Methods(route.EffectiveMethodsForRegistration()...)
		applyRouteHeaderMatchers(registered, route.MatchHeaders)
		service := g.config.FindServiceForRoute(route.Path, "", route.MatchHeaders)
		backend := ""
		if service != nil {
			backend = service.Host
		}
		g.logger.Info("Added route", logging.String("path", route.Path), logging.String("backend", backend))
	}

	return nil
}

func applyRouteHeaderMatchers(route *mux.Route, headers map[string]string) {
	if route == nil || len(headers) == 0 {
		return
	}
	headerPairs := make([]string, 0, len(headers)*2)
	for key, value := range headers {
		headerPairs = append(headerPairs, key, value)
	}
	route.Headers(headerPairs...)
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
	http3Transport, err := buildHTTP3Transport(g.config.Security.TLS, AccessLogMiddleware(g, g.router))
	if err != nil {
		return fmt.Errorf("failed to prepare HTTP/3 transport: %w", err)
	}
	g.http3Server = http3Transport

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

		tlsConfig, err := buildServerTLSConfig(g.config.Security.TLS)
		if err != nil {
			return err
		}

		if http3Transport != nil {
			go func() {
				http3Port := g.config.Security.TLS.EffectiveHTTP3Port(tlsPort)
				g.logger.Info("Starting HTTP/3 server", logging.Int("port", http3Port), logging.String("cert", g.config.Security.TLS.CertFile))
				if err := http3Transport.ListenAndServe(); err != nil && err != http.ErrServerClosed {
					g.logger.Error("HTTP/3 server error", err)
				}
			}()
		}

		if tlsPort == g.config.Server.Port {
			server.Handler = wrapHandlerWithHTTP3Advertisement(AccessLogMiddleware(g, g.router), http3Transport)
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
				Handler:   wrapHandlerWithHTTP3Advertisement(AccessLogMiddleware(g, g.router), http3Transport),
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
	if g.http3Server != nil {
		if err := g.http3Server.Shutdown(ctx); err != nil {
			g.logger.Error("HTTP/3 shutdown error", err)
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

func (g *Gateway) BackendStatuses() []BackendStatus {
	g.mu.RLock()
	cfg := g.config
	g.mu.RUnlock()
	if cfg == nil {
		return nil
	}
	now := time.Now().UTC()
	statuses := make([]BackendStatus, 0)
	for _, route := range cfg.GetAllRoutesFromServices(g.logger) {
		if len(route.Backends) == 0 {
			continue
		}
		for _, backend := range route.Backends {
			destination := strings.TrimSpace(backend.Host)
			if destination == "" {
				destination = strings.TrimSpace(route.ServiceHost)
			}
			key := g.backendStateKey(route, backend, destination)
			g.backendStateMu.RLock()
			state := g.backendState[key]
			g.backendStateMu.RUnlock()
			circuitState := backendCircuitState(state, now)
			shadowFailureRate := float64(0)
			if state.ShadowRequests > 0 {
				shadowFailureRate = float64(state.ShadowFailures) / float64(state.ShadowRequests)
			}
			shadowVsLiveDelta := int64(0)
			if state.ShadowLatencyEWMA > 0 && state.LatencyEWMA > 0 {
				shadowVsLiveDelta = (state.ShadowLatencyEWMA - state.LatencyEWMA).Milliseconds()
			}
			statuses = append(statuses, BackendStatus{
				ServiceName:                     route.ServiceName,
				RoutePath:                       route.Path,
				Destination:                     destination,
				URLPattern:                      backend.URLPattern,
				Weight:                          effectiveBackendWeight(backend),
				CircuitState:                    circuitState,
				Available:                       circuitState != "open" && state.HalfOpenInFlight < backendHalfOpenMaxRequests(backend),
				ProbeInFlight:                   state.ProbeInFlight,
				HalfOpenInFlight:                state.HalfOpenInFlight,
				HalfOpenMaxRequests:             backendHalfOpenMaxRequests(backend),
				ConsecutiveSuccesses:            state.ConsecutiveSuccesses,
				RecoverySuccessThreshold:        backendRecoverySuccessThreshold(backend),
				ConsecutiveSlowResponses:        state.ConsecutiveSlowResponses,
				OutlierLatencyThreshold:         strings.TrimSpace(backend.OutlierLatencyThreshold),
				OutlierConsecutiveSlowResponses: backendOutlierSlowResponseThreshold(backend),
				LastObservedLatencyMs:           state.LastObservedLatency.Milliseconds(),
				LatencyEWMAMs:                   state.LatencyEWMA.Milliseconds(),
				ShadowRequests:                  state.ShadowRequests,
				ShadowFailures:                  state.ShadowFailures,
				ShadowFailureRate:               shadowFailureRate,
				ShadowLatencyEWMAMs:             state.ShadowLatencyEWMA.Milliseconds(),
				LastShadowStatusCode:            state.LastShadowStatusCode,
				LastShadowLatencyMs:             state.LastShadowLatency.Milliseconds(),
				LastShadowError:                 state.LastShadowError,
				ShadowVsLiveLatencyDeltaMs:      shadowVsLiveDelta,
				ConsecutiveFailures:             state.ConsecutiveFailures,
				UnhealthyUntil:                  state.UnhealthyUntil,
				LastChecked:                     state.LastChecked,
				LastSuccess:                     state.LastSuccess,
				LastFailure:                     state.LastFailure,
				LastStatusCode:                  state.LastStatusCode,
				LastError:                       state.LastError,
				HealthCheckPath:                 strings.TrimSpace(backend.HealthCheckPath),
				HealthInterval:                  strings.TrimSpace(backend.HealthInterval),
				HealthTimeout:                   strings.TrimSpace(backend.HealthTimeout),
			})
		}
	}
	sort.SliceStable(statuses, func(i, j int) bool {
		if statuses[i].ServiceName == statuses[j].ServiceName {
			if statuses[i].RoutePath == statuses[j].RoutePath {
				return statuses[i].Destination < statuses[j].Destination
			}
			return statuses[i].RoutePath < statuses[j].RoutePath
		}
		return statuses[i].ServiceName < statuses[j].ServiceName
	})
	return statuses
}

func (g *Gateway) ShadowRouteSummaries() []ShadowRouteSummary {
	statuses := g.BackendStatuses()
	aggregates := make(map[string]*shadowRouteAggregate)
	for _, status := range statuses {
		if status.ShadowRequests == 0 {
			continue
		}
		key := status.ServiceName + "|" + status.RoutePath
		entry := aggregates[key]
		if entry == nil {
			entry = &shadowRouteAggregate{
				ShadowRouteSummary: ShadowRouteSummary{
					ServiceName: status.ServiceName,
					RoutePath:   status.RoutePath,
				},
				backends: make(map[string]struct{}),
			}
			aggregates[key] = entry
		}
		entry.ShadowRequests += status.ShadowRequests
		entry.ShadowFailures += status.ShadowFailures
		if status.LatencyEWMAMs > 0 {
			entry.LiveLatencyEWMAMs += status.LatencyEWMAMs
			entry.liveSamples++
		}
		if status.ShadowLatencyEWMAMs > 0 {
			entry.ShadowLatencyEWMAMs += status.ShadowLatencyEWMAMs
			entry.shadowSamples++
		}
		if status.ShadowVsLiveLatencyDeltaMs != 0 {
			entry.ShadowVsLiveLatencyDeltaMs += status.ShadowVsLiveLatencyDeltaMs
			entry.deltaSamples++
		}
		if status.Available {
			entry.HealthyBackends++
		}
		if status.Destination != "" {
			entry.backends[status.Destination] = struct{}{}
		}
	}
	summaries := make([]ShadowRouteSummary, 0, len(aggregates))
	for _, entry := range aggregates {
		if entry.ShadowRequests > 0 {
			entry.ShadowFailureRate = float64(entry.ShadowFailures) / float64(entry.ShadowRequests)
		}
		if entry.liveSamples > 0 {
			entry.LiveLatencyEWMAMs /= entry.liveSamples
		}
		if entry.shadowSamples > 0 {
			entry.ShadowLatencyEWMAMs /= entry.shadowSamples
		}
		if entry.deltaSamples > 0 {
			entry.ShadowVsLiveLatencyDeltaMs /= entry.deltaSamples
		}
		if len(entry.backends) > 0 {
			entry.Backends = make([]string, 0, len(entry.backends))
			for backend := range entry.backends {
				entry.Backends = append(entry.Backends, backend)
			}
			sort.Strings(entry.Backends)
		}
		summaries = append(summaries, entry.ShadowRouteSummary)
	}
	sort.SliceStable(summaries, func(i, j int) bool {
		if summaries[i].ServiceName == summaries[j].ServiceName {
			return summaries[i].RoutePath < summaries[j].RoutePath
		}
		return summaries[i].ServiceName < summaries[j].ServiceName
	})
	return summaries
}

func (g *Gateway) ShadowRouteEvaluations() []ShadowRouteEvaluation {
	summaries := g.ShadowRouteSummaries()
	summaryIndex := make(map[string]ShadowRouteSummary, len(summaries))
	for _, summary := range summaries {
		summaryIndex[summary.ServiceName+"|"+summary.RoutePath] = summary
	}
	g.mu.RLock()
	cfg := g.config
	g.mu.RUnlock()
	if cfg == nil {
		return nil
	}
	routeIndex := make(map[string]config.RouterConfig)
	for _, route := range cfg.GetAllRoutesFromServices(g.logger) {
		if route.ShadowTrafficPercent <= 0 && !shadowPolicyConfigured(route) {
			continue
		}
		routeIndex[route.ServiceName+"|"+route.Path] = route
	}
	evaluations := make([]ShadowRouteEvaluation, 0, len(routeIndex))
	keys := make([]string, 0, len(routeIndex))
	for key := range routeIndex {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		route := routeIndex[key]
		summary := summaryIndex[key]
		evaluation := ShadowRouteEvaluation{
			ShadowRouteSummary: ShadowRouteSummary{
				ServiceName:                route.ServiceName,
				RoutePath:                  route.Path,
				ShadowRequests:             summary.ShadowRequests,
				ShadowFailures:             summary.ShadowFailures,
				ShadowFailureRate:          summary.ShadowFailureRate,
				LiveLatencyEWMAMs:          summary.LiveLatencyEWMAMs,
				ShadowLatencyEWMAMs:        summary.ShadowLatencyEWMAMs,
				ShadowVsLiveLatencyDeltaMs: summary.ShadowVsLiveLatencyDeltaMs,
				Backends:                   append([]string(nil), summary.Backends...),
				HealthyBackends:            summary.HealthyBackends,
			},
			Healthy: true,
		}
		evaluation.MinRequests = route.ShadowMinRequests
		evaluation.MaxErrorRate = route.ShadowMaxErrorRate
		evaluation.MaxLatencyDeltaSource = strings.TrimSpace(route.ShadowMaxLatencyDelta)
		if evaluation.MinRequests > 0 || evaluation.MaxErrorRate > 0 || evaluation.MaxLatencyDeltaSource != "" {
			evaluation.PolicyConfigured = true
		}
		if evaluation.MinRequests > 0 && summary.ShadowRequests < evaluation.MinRequests {
			evaluation.Healthy = false
			evaluation.Reasons = append(evaluation.Reasons, fmt.Sprintf("shadow requests %d below required minimum %d", summary.ShadowRequests, evaluation.MinRequests))
		}
		if evaluation.MaxErrorRate > 0 && summary.ShadowFailureRate > evaluation.MaxErrorRate {
			evaluation.Healthy = false
			evaluation.Reasons = append(evaluation.Reasons, fmt.Sprintf("shadow failure rate %.3f exceeds max %.3f", summary.ShadowFailureRate, evaluation.MaxErrorRate))
		}
		if evaluation.MaxLatencyDeltaSource != "" {
			if maxDelta, err := time.ParseDuration(evaluation.MaxLatencyDeltaSource); err == nil {
				evaluation.MaxLatencyDeltaMs = maxDelta.Milliseconds()
				if summary.ShadowVsLiveLatencyDeltaMs > evaluation.MaxLatencyDeltaMs {
					evaluation.Healthy = false
					evaluation.Reasons = append(evaluation.Reasons, fmt.Sprintf("shadow latency delta %dms exceeds max %dms", summary.ShadowVsLiveLatencyDeltaMs, evaluation.MaxLatencyDeltaMs))
				}
			}
		}
		evaluations = append(evaluations, evaluation)
	}
	return evaluations
}

func (g *Gateway) RecordPolicyHit(route config.RouterConfig, reason string) {
	g.recordPolicyHitAt(route, reason, time.Now().UTC())
}

func (g *Gateway) recordPolicyHitAt(route config.RouterConfig, reason string, occurredAt time.Time) {
	reason = strings.TrimSpace(reason)
	if reason == "" {
		return
	}
	serviceName := strings.TrimSpace(route.ServiceName)
	routePath := strings.TrimSpace(route.Path)
	if routePath == "" {
		routePath = "/"
	}
	routeKey := serviceName + "|" + routePath

	g.policyStateMu.Lock()
	defer g.policyStateMu.Unlock()

	if g.policyState.ByReason == nil {
		g.policyState.ByReason = make(map[string]int)
	}
	if g.policyState.ByRoute == nil {
		g.policyState.ByRoute = make(map[string]policyHitRouteRuntimeState)
	}
	g.policyState.Total++
	g.policyState.ByReason[reason]++
	entry := g.policyState.ByRoute[routeKey]
	if entry.ByReason == nil {
		entry.ByReason = make(map[string]int)
	}
	entry.ServiceName = serviceName
	entry.RoutePath = routePath
	entry.Total++
	entry.ByReason[reason]++
	g.policyState.ByRoute[routeKey] = entry
	g.policyState.Events = append(g.policyState.Events, policyHitEvent{
		ServiceName: serviceName,
		RoutePath:   routePath,
		Reason:      reason,
		OccurredAt:  occurredAt,
	})
	g.trimPolicyHitEventsLocked(occurredAt)
	g.policyState.UpdatedAt = occurredAt
}

func (g *Gateway) PolicyHitSummary() PolicyHitSummary {
	g.policyStateMu.RLock()
	defer g.policyStateMu.RUnlock()

	summary := PolicyHitSummary{
		Total:     g.policyState.Total,
		UpdatedAt: g.policyState.UpdatedAt,
	}
	for reason, count := range g.policyState.ByReason {
		summary.Reasons = append(summary.Reasons, PolicyHitReasonSummary{
			Reason: reason,
			Count:  count,
		})
	}
	sort.Slice(summary.Reasons, func(i, j int) bool {
		if summary.Reasons[i].Count == summary.Reasons[j].Count {
			return summary.Reasons[i].Reason < summary.Reasons[j].Reason
		}
		return summary.Reasons[i].Count > summary.Reasons[j].Count
	})
	for _, entry := range g.policyState.ByRoute {
		copyReasons := make(map[string]int, len(entry.ByReason))
		for reason, count := range entry.ByReason {
			copyReasons[reason] = count
		}
		summary.Routes = append(summary.Routes, PolicyHitRouteSummary{
			ServiceName: entry.ServiceName,
			RoutePath:   entry.RoutePath,
			Total:       entry.Total,
			ByReason:    copyReasons,
		})
	}
	sort.Slice(summary.Routes, func(i, j int) bool {
		if summary.Routes[i].Total == summary.Routes[j].Total {
			if summary.Routes[i].ServiceName == summary.Routes[j].ServiceName {
				return summary.Routes[i].RoutePath < summary.Routes[j].RoutePath
			}
			return summary.Routes[i].ServiceName < summary.Routes[j].ServiceName
		}
		return summary.Routes[i].Total > summary.Routes[j].Total
	})
	return summary
}

func (g *Gateway) PolicyHitWindowSummary(window time.Duration) PolicyHitWindowSummary {
	g.policyStateMu.RLock()
	defer g.policyStateMu.RUnlock()

	if window <= 0 {
		window = 5 * time.Minute
	}
	now := time.Now().UTC()
	since := now.Add(-window)
	summary := PolicyHitWindowSummary{
		Window:        window.String(),
		WindowSeconds: int64(window.Seconds()),
		Since:         since,
	}
	reasons := make(map[string]int)
	routes := make(map[string]PolicyHitRouteSummary)
	for _, event := range g.policyState.Events {
		if event.OccurredAt.Before(since) {
			continue
		}
		summary.Total++
		reasons[event.Reason]++
		key := event.ServiceName + "|" + event.RoutePath
		entry := routes[key]
		if entry.ByReason == nil {
			entry.ByReason = make(map[string]int)
		}
		entry.ServiceName = event.ServiceName
		entry.RoutePath = event.RoutePath
		entry.Total++
		entry.ByReason[event.Reason]++
		routes[key] = entry
	}
	for reason, count := range reasons {
		summary.Reasons = append(summary.Reasons, PolicyHitReasonSummary{Reason: reason, Count: count})
	}
	sort.Slice(summary.Reasons, func(i, j int) bool {
		if summary.Reasons[i].Count == summary.Reasons[j].Count {
			return summary.Reasons[i].Reason < summary.Reasons[j].Reason
		}
		return summary.Reasons[i].Count > summary.Reasons[j].Count
	})
	if len(summary.Reasons) > 0 {
		summary.TopReason = summary.Reasons[0].Reason
	}
	for _, entry := range routes {
		summary.Routes = append(summary.Routes, entry)
	}
	sort.Slice(summary.Routes, func(i, j int) bool {
		if summary.Routes[i].Total == summary.Routes[j].Total {
			if summary.Routes[i].ServiceName == summary.Routes[j].ServiceName {
				return summary.Routes[i].RoutePath < summary.Routes[j].RoutePath
			}
			return summary.Routes[i].ServiceName < summary.Routes[j].ServiceName
		}
		return summary.Routes[i].Total > summary.Routes[j].Total
	})
	if len(summary.Routes) > 0 {
		summary.TopRoutePath = summary.Routes[0].RoutePath
		summary.TopServiceName = summary.Routes[0].ServiceName
	}
	return summary
}

func (g *Gateway) PolicyAlertSummary(window time.Duration, minCount int) PolicyAlertSummary {
	return g.PolicyAlertSummaryAt(time.Now().UTC(), window, minCount)
}

func (g *Gateway) PolicyAlertSummaryAt(now time.Time, window time.Duration, minCount int) PolicyAlertSummary {
	g.policyStateMu.RLock()
	defer g.policyStateMu.RUnlock()

	if window <= 0 {
		window = 5 * time.Minute
	}
	if minCount <= 0 {
		minCount = 3
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	since := now.Add(-window)
	type counter struct {
		serviceName string
		routePath   string
		reason      string
		count       int
	}
	grouped := make(map[string]*counter)
	for _, event := range g.policyState.Events {
		if event.OccurredAt.Before(since) {
			continue
		}
		key := event.ServiceName + "|" + event.RoutePath + "|" + event.Reason
		entry := grouped[key]
		if entry == nil {
			entry = &counter{
				serviceName: event.ServiceName,
				routePath:   event.RoutePath,
				reason:      event.Reason,
			}
			grouped[key] = entry
		}
		entry.count++
	}
	summary := PolicyAlertSummary{
		Window:        window.String(),
		WindowSeconds: int64(window.Seconds()),
		MinCount:      minCount,
		BySeverity:    map[string]int{"warning": 0, "elevated": 0, "critical": 0},
	}
	for _, entry := range grouped {
		if entry.count < minCount {
			continue
		}
		severity := "warning"
		if entry.count >= maxInt(minCount*4, 12) {
			severity = "critical"
		} else if entry.count >= maxInt(minCount*2, 6) {
			severity = "elevated"
		}
		summary.Alerts = append(summary.Alerts, PolicyAlert{
			Severity:    severity,
			ServiceName: entry.serviceName,
			RoutePath:   entry.routePath,
			Reason:      entry.reason,
			Count:       entry.count,
			Since:       since,
		})
		summary.BySeverity[severity]++
	}
	sort.Slice(summary.Alerts, func(i, j int) bool {
		if summary.Alerts[i].Count == summary.Alerts[j].Count {
			if summary.Alerts[i].Severity == summary.Alerts[j].Severity {
				if summary.Alerts[i].ServiceName == summary.Alerts[j].ServiceName {
					if summary.Alerts[i].RoutePath == summary.Alerts[j].RoutePath {
						return summary.Alerts[i].Reason < summary.Alerts[j].Reason
					}
					return summary.Alerts[i].RoutePath < summary.Alerts[j].RoutePath
				}
				return summary.Alerts[i].ServiceName < summary.Alerts[j].ServiceName
			}
			return summary.Alerts[i].Severity > summary.Alerts[j].Severity
		}
		return summary.Alerts[i].Count > summary.Alerts[j].Count
	})
	summary.TotalAlerts = len(summary.Alerts)
	return summary
}

func (g *Gateway) trimPolicyHitEventsLocked(now time.Time) {
	const maxPolicyHitRetention = 24 * time.Hour
	if len(g.policyState.Events) == 0 {
		return
	}
	cutoff := now.Add(-maxPolicyHitRetention)
	trim := 0
	for trim < len(g.policyState.Events) && g.policyState.Events[trim].OccurredAt.Before(cutoff) {
		trim++
	}
	if trim > 0 {
		g.policyState.Events = append([]policyHitEvent(nil), g.policyState.Events[trim:]...)
	}
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func shadowPolicyConfigured(route config.RouterConfig) bool {
	return route.ShadowMinRequests > 0 || route.ShadowMaxErrorRate > 0 || strings.TrimSpace(route.ShadowMaxLatencyDelta) != ""
}

func (g *Gateway) RecordBackendSuccessForTest(route config.RouterConfig, backend config.Backend, destination string, statusCode int, latency time.Duration, now time.Time) {
	g.recordBackendSuccessWithStatus(route, backend, destination, statusCode, latency, now)
}

func (g *Gateway) RecordShadowResultForTest(route config.RouterConfig, backend config.Backend, destination string, statusCode int, latency time.Duration, shadowErr error) {
	g.recordShadowResult(route, backend, destination, statusCode, latency, shadowErr)
}

func (g *Gateway) RecordPolicyHitForTest(route config.RouterConfig, reason string, occurredAt time.Time) {
	g.recordPolicyHitAt(route, reason, occurredAt)
}

func (g *Gateway) activeBackendProbeLoop() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-g.shutdown:
			return
		case <-ticker.C:
			g.probeConfiguredBackends(time.Now().UTC())
		}
	}
}

func (g *Gateway) probeConfiguredBackends(now time.Time) {
	g.mu.RLock()
	cfg := g.config
	g.mu.RUnlock()
	if cfg == nil {
		return
	}
	for _, route := range cfg.GetAllRoutesFromServices(g.logger) {
		for _, backend := range route.Backends {
			if strings.TrimSpace(backend.HealthCheckPath) == "" {
				continue
			}
			destination := strings.TrimSpace(backend.Host)
			if destination == "" {
				destination = strings.TrimSpace(route.ServiceHost)
			}
			if destination == "" || !g.backendProbeDue(route, backend, destination, now) {
				continue
			}
			g.probeBackend(route, backend, destination, now)
		}
	}
}

func (g *Gateway) backendProbeDue(route config.RouterConfig, backend config.Backend, destination string, now time.Time) bool {
	key := g.backendStateKey(route, backend, destination)
	g.backendStateMu.RLock()
	state := g.backendState[key]
	g.backendStateMu.RUnlock()
	if state.LastChecked.IsZero() {
		return true
	}
	return now.Sub(state.LastChecked) >= backendHealthInterval(backend)
}

func (g *Gateway) probeBackend(route config.RouterConfig, backend config.Backend, destination string, now time.Time) {
	target, err := urlJoinPath(destination, backend.HealthCheckPath)
	if err != nil {
		g.recordBackendFailureWithStatus(route, backend, destination, 0, fmt.Errorf("failed to build backend health check url: %w", err), now)
		return
	}
	client := &http.Client{Timeout: backendHealthTimeout(backend)}
	req, err := http.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		g.recordBackendFailureWithStatus(route, backend, destination, 0, err, now)
		return
	}
	resp, err := client.Do(req)
	if err != nil {
		g.recordBackendFailureWithStatus(route, backend, destination, 0, err, now)
		return
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode >= 200 && resp.StatusCode < 400 {
		g.recordBackendSuccessWithStatus(route, backend, destination, resp.StatusCode, 0, now)
		return
	}
	g.recordBackendFailureWithStatus(route, backend, destination, resp.StatusCode, fmt.Errorf("health check responded with status %d", resp.StatusCode), now)
}

func urlJoinPath(rawBase, probePath string) (string, error) {
	base, err := url.Parse(strings.TrimSpace(rawBase))
	if err != nil {
		return "", err
	}
	base.Path = joinURLPath(base.Path, probePath)
	return base.String(), nil
}

func backendHealthInterval(backend config.Backend) time.Duration {
	if raw := strings.TrimSpace(backend.HealthInterval); raw != "" {
		if parsed, err := time.ParseDuration(raw); err == nil && parsed > 0 {
			return parsed
		}
	}
	return defaultBackendHealthInterval
}

func backendHealthTimeout(backend config.Backend) time.Duration {
	if raw := strings.TrimSpace(backend.HealthTimeout); raw != "" {
		if parsed, err := time.ParseDuration(raw); err == nil && parsed > 0 {
			return parsed
		}
	}
	return defaultBackendHealthTimeout
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
