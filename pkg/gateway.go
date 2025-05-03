package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"plugin"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// NewGateway creates a new API gateway instance
func NewGateway(path string, routes string) (*Gateway, error) {
	logger := NewLogger(false) // Start with logging disabled until we load config

	configPath := path
	routesPath := routes

	// First try to load config from storage
	storage := NewStorageManager(logger)
	storedConfig, err := storage.LoadConfig()
	if err != nil {
		logger.Error("Failed to load config from storage: %v", err)
	}

	var config *Config
	var routesConfig *Config

	if storedConfig != nil {
		config = storedConfig
		logger.Info("Loaded configuration from storage")
	} else {
		// Fall back to file-based config
		config, err = loadConfig(configPath)

		if err != nil {
			return nil, fmt.Errorf("failed to load config: %w", err)
		}

		routesConfig, err = loadConfig(routesPath)

		config.Routes = routesConfig.Routes

		if err != nil {
			return nil, fmt.Errorf("failed to load config: %w", err)
		}
		logger.Info("Loaded configuration from file")
	}

	// Apply the loaded config to the logger
	logger.enableLogging = config.Server.EnableLogging

	// Load basic auth from storage if available
	if config.Security.EnableBasicAuth {
		storedUsers, err := storage.LoadBasicAuth()
		if err != nil {
			logger.Error("Failed to load basic auth from storage: %v", err)
		}
		if storedUsers != nil {
			config.Security.BasicAuthUsers = storedUsers
			logger.Info("Loaded basic auth users from storage")
		}
	}

	metrics := NewMetrics()

	gateway := &Gateway{
		config:      config,
		router:      mux.NewRouter(),
		openAPISpec: make(map[string]interface{}),
		plugins:     make([]GatewayPlugin, 0),
		middlewares: make([]func(http.Handler) http.Handler, 0),
		metrics:     metrics,
		logger:      logger,
		storage:     storage,
	}

	gateway.openAPISpec = gateway.adminAPI.OpenAPISpec()

	// Save the initial config to storage
	if err := gateway.storage.SaveConfig(config); err != nil {
		logger.Error("Failed to save initial config to storage: %v", err)
	}

	// Save basic auth if enabled
	if config.Security.EnableBasicAuth {
		if err := gateway.storage.SaveBasicAuth(config.Security.BasicAuthUsers); err != nil {
			logger.Error("Failed to save basic auth to storage: %v", err)
		}
	}

	// Load the OpenAPI plugin
	openapiPlugin := NewOpenAPIPlugin()
	if err := openapiPlugin.Initialize(map[string]any{
		"uiPath":   "/docs",
		"specPath": "/openapi.json",
	}); err != nil {
		return nil, fmt.Errorf("failed to initialize OpenAPI plugin: %w", err)
	}

	///
	// Initialize admin API
	gateway.adminAPI = NewAdminAPI(gateway, openapiPlugin)

	gateway.plugins = append(gateway.plugins, openapiPlugin)
	gateway.middlewares = append(gateway.middlewares, openapiPlugin.Middleware())
	//

	gateway.setupRoutes()

	if err := gateway.loadPlugins(); err != nil {
		return nil, fmt.Errorf("failed to load plugins: %w", err)
	}

	return gateway, nil
}

// GatewayPlugin interface that all plugins must implement
type GatewayPlugin interface {
	Name() string
	Initialize(config map[string]interface{}) error
	Middleware() func(http.Handler) http.Handler
	Shutdown() error
}

// Gateway is the main API gateway struct
type Gateway struct {
	config      *Config
	router      *mux.Router
	adminAPI    *AdminAPI
	openAPISpec map[string]interface{}
	plugins     []GatewayPlugin
	pluginsMu   sync.RWMutex
	middlewares []func(http.Handler) http.Handler
	metrics     *Metrics
	logger      *Logger
	storage     *StorageManager
	configPath  string
}

// setupRoutes configures the routes from the config
func (g *Gateway) setupRoutes() {
	// Add health check endpoint
	g.router.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"UP"}`))
	}).Methods(http.MethodGet)

	// Configure routes from the config
	for _, route := range g.config.Routes {

		// Print routes list
		g.logger.Info(route.Path)

		handler := g.proxyHandler(route)

		// Apply route-specific middleware
		if route.RequireAuth {
			handler = http.HandlerFunc(g.authMiddleware(handler).ServeHTTP)
		}

		// Apply route-specific timeout if configured
		if route.Timeout != nil {
			handler = http.HandlerFunc(g.timeoutMiddleware(*route.Timeout)(handler).ServeHTTP)
		}

		// Apply schema validation if configured
		if route.ValidateSchema != "" {
			handler = http.HandlerFunc(g.validateRequestMiddleware(route.ValidateSchema)(handler).ServeHTTP)
		}

		g.router.HandleFunc(route.Path, handler).
			Methods(route.Methods...)

	}

	// Add catch-all route for 404s
	g.router.NotFoundHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"error":"Not Found","message":"The requested resource does not exist"}`))
	})
}

// proxyHandler returns a handler function that proxies requests to the destination
func (g *Gateway) proxyHandler(route RouterConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		g.logger.Info(route.Destination)
		// Parse the destination URL
		target, err := url.Parse(route.Destination)
		g.logger.Info(target.Path)
		if err != nil {
			g.logger.Error("Failed to parse destination URL: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`{"error":"Internal Server Error"}`))
			return
		}

		// Create the reverse proxy
		proxy := httputil.NewSingleHostReverseProxy(target)

		// Customize the director function to modify the request
		originalDirector := proxy.Director
		proxy.Director = func(req *http.Request) {
			originalDirector(req)

			// Strip the path prefix if configured
			if route.StripPath {
				req.URL.Path = strings.TrimPrefix(req.URL.Path, route.Path)
				if req.URL.Path == "" {
					req.URL.Path = "/"
				}
			}

			// Add custom headers
			for key, value := range route.Headers {
				req.Header.Set(key, value)
			}

			// Add X-Forwarded headers
			req.Header.Set("X-Forwarded-Host", req.Host)
			req.Header.Set("X-Forwarded-For", getClientIP(req))

			// Add X-Request-ID for tracking
			if reqID := r.Header.Get("X-Request-ID"); reqID == "" {
				req.Header.Set("X-Request-ID", generateRequestID())
			} else {
				req.Header.Set("X-Request-ID", reqID)
			}
		}

		// Customize the error handler
		proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
			g.logger.Error("Proxy error: %v", err)
			w.WriteHeader(http.StatusBadGateway)
			w.Write([]byte(`{"error":"Bad Gateway","message":"Unable to reach the upstream service"}`))
		}

		// Customize the response writer to log and collect metrics
		lrw := newLoggingResponseWriter(w)

		// Execute the proxy
		proxy.ServeHTTP(lrw, r)

		// Record metrics
		duration := time.Since(start).Seconds()
		g.metrics.requestDuration.WithLabelValues(r.Method, route.Path).Observe(duration)
		g.metrics.requestCount.WithLabelValues(r.Method, route.Path, fmt.Sprintf("%d", lrw.statusCode)).Inc()
		g.metrics.responseSize.WithLabelValues(r.Method, route.Path).Observe(float64(lrw.bytesWritten))

		// Log the request
		g.logger.Info("%s %s %d %s %dB", r.Method, r.URL.Path, lrw.statusCode, time.Since(start), lrw.bytesWritten)
	}
}

// loadPlugins loads and initializes all enabled plugins
func (g *Gateway) loadPlugins() error {
	for _, pluginConfig := range g.config.Plugins {
		if !pluginConfig.Enabled {
			g.logger.Info("Plugin %s is disabled, skipping", pluginConfig.Name)
			continue
		}

		g.logger.Info("Loading plugin: %s from %s", pluginConfig.Name, pluginConfig.Path)

		// Load the plugin
		plug, err := plugin.Open(pluginConfig.Path)
		if err != nil {
			return fmt.Errorf("failed to open plugin %s: %w", pluginConfig.Name, err)
		}

		// Look up the plugin's constructor
		symPlugin, err := plug.Lookup("Plugin")
		if err != nil {
			return fmt.Errorf("failed to lookup 'Plugin' symbol in %s: %w", pluginConfig.Name, err)
		}

		// Check if it's a storage plugin
		if storagePlugin, ok := symPlugin.(StoragePlugin); ok {
			// Initialize the storage plugin
			if err := storagePlugin.Initialize(pluginConfig.Config); err != nil {
				return fmt.Errorf("failed to initialize storage plugin %s: %w", pluginConfig.Name, err)
			}

			// Set it as the active storage
			g.storage.SetStorage(storagePlugin)
			g.logger.Info("Storage plugin %s loaded and activated", pluginConfig.Name)
			continue
		}

		// Cast to the GatewayPlugin interface
		gatewayPlugin, ok := symPlugin.(GatewayPlugin)
		if !ok {
			return fmt.Errorf("plugin %s does not implement GatewayPlugin interface", pluginConfig.Name)
		}

		// Initialize the plugin with its configuration
		if err := gatewayPlugin.Initialize(pluginConfig.Config); err != nil {
			return fmt.Errorf("failed to initialize plugin %s: %w", pluginConfig.Name, err)
		}

		// Add the plugin to the list
		g.pluginsMu.Lock()
		g.plugins = append(g.plugins, gatewayPlugin)

		// Register the plugin's middleware
		middleware := gatewayPlugin.Middleware()
		if middleware != nil {
			g.middlewares = append(g.middlewares, middleware)
		}
		g.pluginsMu.Unlock()

		g.logger.Info("Plugin %s loaded successfully", pluginConfig.Name)
	}

	return nil
}

// basicAuthMiddleware implements HTTP Basic Authentication
func (g *Gateway) basicAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip if basic auth is disabled
		if !g.config.Security.EnableBasicAuth {
			next.ServeHTTP(w, r)
			return
		}

		// Get the Basic Auth credentials
		username, password, ok := r.BasicAuth()
		if !ok {
			w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"error":"Unauthorized","message":"Basic authentication required"}`))
			return
		}

		// Check if credentials are valid
		expectedPassword, userExists := g.config.Security.BasicAuthUsers[username]
		if !userExists || expectedPassword != password {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"error":"Unauthorized","message":"Invalid username or password"}`))
			return
		}

		// If credentials are valid, continue to the next handler
		next.ServeHTTP(w, r)
	})
}

// Serve starts the gateway server
func (g *Gateway) Serve() error {
	// Apply core security middlewares first
	var handler http.Handler = g.router

	// Apply security middlewares
	handler = g.basicAuthMiddleware(handler)
	handler = g.rateLimitMiddleware(handler)
	handler = g.ipWhitelistMiddleware(handler)
	handler = g.securityHeadersMiddleware(handler)
	handler = g.csrfMiddleware(handler)
	handler = g.requestSizeMiddleware(handler)

	// Apply plugin middlewares in reverse order (last added, first executed)
	for i := len(g.middlewares) - 1; i >= 0; i-- {
		handler = g.middlewares[i](handler)
	}

	// Add logging middleware if enabled
	if g.config.Server.EnableLogging {
		handler = g.loggingMiddleware(handler)
	}

	// Add metrics middleware
	handler = g.metricsMiddleware(handler)

	// Configure the server
	addr := fmt.Sprintf(":%d", g.config.Server.Port)
	server := &http.Server{
		Addr:         addr,
		Handler:      handler,
		ReadTimeout:  g.config.Server.ReadTimeout * time.Second,
		WriteTimeout: g.config.Server.WriteTimeout * time.Second,
		IdleTimeout:  g.config.Server.IdleTimeout * time.Second,
	}

	// Configure TLS if cert and key files are provided
	var tlsConfig *tls.Config
	if g.config.Server.TLSCertFile != "" && g.config.Server.TLSKeyFile != "" {
		tlsConfig = &tls.Config{
			MinVersion: tls.VersionTLS12,
			CipherSuites: []uint16{
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			},
			PreferServerCipherSuites: true,
		}

		// Configure mTLS if enabled and client CA cert is provided
		if g.config.Security.EnableMTLS && g.config.Server.ClientCACertFile != "" {
			caCert, err := os.ReadFile(g.config.Server.ClientCACertFile)
			if err != nil {
				return fmt.Errorf("failed to read client CA cert file: %w", err)
			}

			caCertPool := x509.NewCertPool()
			if !caCertPool.AppendCertsFromPEM(caCert) {
				return fmt.Errorf("failed to parse client CA cert file")
			}

			tlsConfig.ClientCAs = caCertPool
			tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
		}

		server.TLSConfig = tlsConfig
	}

	// Start metrics server on a separate port
	if g.config.Server.MetricsPort > 0 {
		metricsServer := &http.Server{
			Addr:    fmt.Sprintf(":%d", g.config.Server.MetricsPort),
			Handler: promhttp.Handler(),
		}

		go func() {
			g.logger.Info("Starting metrics server on :%d", g.config.Server.MetricsPort)
			if err := metricsServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				g.logger.Error("Failed to start metrics server: %v", err)
			}
		}()
	}

	// Handle graceful shutdown
	done := make(chan os.Signal, 1)
	signal.Notify(done, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		g.logger.Info("Starting gateway server on %s", addr)
		var err error
		if server.TLSConfig != nil {
			err = server.ListenAndServeTLS(g.config.Server.TLSCertFile, g.config.Server.TLSKeyFile)
		} else {
			err = server.ListenAndServe()
		}

		if err != nil && err != http.ErrServerClosed {
			g.logger.Error("Failed to start server: %v", err)
			os.Exit(1)
		}
	}()

	<-done
	g.logger.Info("Server is shutting down...")

	// Shutdown plugins
	g.shutdownPlugins()

	// Create a deadline to wait for
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		return fmt.Errorf("server forced to shutdown: %w", err)
	}

	g.logger.Info("Server gracefully stopped")
	return nil
}

// metricsMiddleware collects metrics for requests
func (g *Gateway) metricsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Increment active connections
		activeConnections.Inc()
		defer activeConnections.Dec()

		// Create custom response writer to capture status code
		rw := newLoggingResponseWriter(w)

		// Start timer for request duration
		start := time.Now()

		// Call next handler
		next.ServeHTTP(rw, r)

		// Calculate duration
		duration := time.Since(start).Seconds()

		// Normalize the request path to avoid high cardinality in metrics
		route := mux.CurrentRoute(r)
		path := "unknown"
		if route != nil {
			// Try to get the route name, fall back to the template
			path = route.GetName()
			if path == "" {
				pathTemplate, err := route.GetPathTemplate()
				if err == nil {
					path = pathTemplate
				}
			}
		}

		// Record metrics
		statusCode := fmt.Sprintf("%d", rw.statusCode)
		httpRequestsTotal.WithLabelValues(statusCode, r.Method, path).Inc()
		httpRequestDuration.WithLabelValues(statusCode, r.Method, path).Observe(duration)
		httpResponseSize.WithLabelValues(statusCode, r.Method, path).Observe(float64(rw.bytesWritten))
	})
}

// shutdownPlugins gracefully shuts down all plugins
func (g *Gateway) shutdownPlugins() {
	g.pluginsMu.RLock()
	defer g.pluginsMu.RUnlock()

	for _, p := range g.plugins {
		if err := p.Shutdown(); err != nil {
			g.logger.Error("Error shutting down plugin %s: %v", p.Name(), err)
		} else {
			g.logger.Info("Plugin %s shutdown successfully", p.Name())
		}
	}
}

// timeoutMiddleware adds a timeout to the request context
func (g *Gateway) timeoutMiddleware(timeout time.Duration) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Create a context with timeout
			ctx, cancel := context.WithTimeout(r.Context(), timeout)
			defer cancel()

			// Create a channel to signal when the request has completed
			done := make(chan struct{})

			// Create a response writer that can detect when the response is complete
			lrw := newLoggingResponseWriter(w)

			// Process the request in a goroutine
			go func() {
				next.ServeHTTP(lrw, r.WithContext(ctx))
				close(done)
			}()

			// Wait for the request to complete or timeout
			select {
			case <-done:
				// Request completed normally
				return
			case <-ctx.Done():
				// Request timed out
				if ctx.Err() == context.DeadlineExceeded {
					w.WriteHeader(http.StatusGatewayTimeout)
					w.Write([]byte(`{"error":"Gateway Timeout","message":"Request processing timed out"}`))
				}
				return
			}
		})
	}
}

// validateRequestMiddleware validates request bodies against a JSON schema
func (g *Gateway) validateRequestMiddleware(schemaPath string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Only validate POST, PUT, and PATCH requests with a Content-Type of application/json
			if (r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodPatch) &&
				r.Header.Get("Content-Type") == "application/json" {

				// Read the request body
				body, err := io.ReadAll(r.Body)
				if err != nil {
					w.WriteHeader(http.StatusBadRequest)
					w.Write([]byte(`{"error":"Bad Request","message":"Unable to read request body"}`))
					return
				}

				// Close the original body
				r.Body.Close()

				// Create a new reader with the same body data
				r.Body = io.NopCloser(strings.NewReader(string(body)))

				// Check if the body is valid JSON
				var jsonData interface{}
				if err := json.Unmarshal(body, &jsonData); err != nil {
					w.WriteHeader(http.StatusBadRequest)
					w.Write([]byte(`{"error":"Bad Request","message":"Invalid JSON format"}`))
					return
				}

				// TODO: Add actual schema validation using a library like gojsonschema
				// This is a placeholder for now, as implementing full schema validation
				// would require adding a dependency

				// For now, let's just check if the schema file exists
				if _, err := os.Stat(schemaPath); os.IsNotExist(err) {
					g.logger.Error("Schema file not found: %s", schemaPath)
					// Continue processing even if schema file is missing
				}
			}

			next.ServeHTTP(w, r)
		})
	}
}

// authMiddleware handles authentication for protected routes
func (g *Gateway) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check for Authorization header
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"error":"Unauthorized","message":"Missing authorization header"}`))
			return
		}

		// Simple token validation for now
		// In a real implementation, this would validate JWT tokens
		if !strings.HasPrefix(authHeader, "Bearer ") {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"error":"Unauthorized","message":"Invalid authorization format"}`))
			return
		}

		// Extract the token
		token := strings.TrimPrefix(authHeader, "Bearer ")

		// TODO: Implement JWT token validation using the JWT secret from config
		// This is a placeholder for now
		if token == "" {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"error":"Unauthorized","message":"Invalid token"}`))
			return
		}

		// For now, we'll just continue the request
		next.ServeHTTP(w, r)
	})
}

// rateLimitMiddleware implements rate limiting
func (g *Gateway) rateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip rate limiting if disabled
		if g.config.Security.RateLimitRequests <= 0 {
			next.ServeHTTP(w, r)
			return
		}

		// Find rate limiter plugin
		g.pluginsMu.RLock()
		var rateLimiterPlugin GatewayPlugin
		for _, plugin := range g.plugins {
			if plugin.Name() == "rate-limiter" {
				rateLimiterPlugin = plugin
				break
			}
		}
		g.pluginsMu.RUnlock()

		if rateLimiterPlugin == nil {
			g.logger.Error("Rate limiter plugin not found")
			next.ServeHTTP(w, r)
			return
		}

		// Use plugin's middleware
		rateLimiterPlugin.Middleware()(next).ServeHTTP(w, r)
	})
}

// ipWhitelistMiddleware implements IP whitelisting
func (g *Gateway) ipWhitelistMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip IP whitelisting if disabled
		if !g.config.Security.EnableIPWhitelisting {
			next.ServeHTTP(w, r)
			return
		}

		// Get client IP
		clientIP := getClientIP(r)

		// Create whitelist checker
		whitelist := NewIPWhitelist(true, g.config.Security.WhitelistedIPs)

		// Check if IP is allowed
		if !whitelist.IsAllowed(clientIP) {
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte(`{"error":"Forbidden","message":"IP address not allowed"}`))
			return
		}

		next.ServeHTTP(w, r)
	})
}

// securityHeadersMiddleware adds security headers to responses
func (g *Gateway) securityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Add security headers
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")

		// Add XSS protection header if enabled
		if g.config.Security.EnableXSS {
			w.Header().Set("X-XSS-Protection", "1; mode=block")
		}

		// Add HSTS header if enabled
		if g.config.Security.EnableHSTS {
			maxAge := g.config.Security.HSTSMaxAge
			if maxAge <= 0 {
				maxAge = 31536000 // Default to 1 year
			}
			w.Header().Set("Strict-Transport-Security", fmt.Sprintf("max-age=%d; includeSubDomains", maxAge))
		}

		// Set content security policy
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; object-src 'none'; img-src 'self'; style-src 'self';")

		next.ServeHTTP(w, r)
	})
}

// csrfMiddleware implements CSRF protection
func (g *Gateway) csrfMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip CSRF protection if disabled or for non-mutating methods
		if !g.config.Security.EnableCSRF || (r.Method != http.MethodPost && r.Method != http.MethodPut && r.Method != http.MethodPatch && r.Method != http.MethodDelete) {
			next.ServeHTTP(w, r)
			return
		}

		// Check for CSRF token in header
		csrfToken := r.Header.Get("X-CSRF-Token")
		if csrfToken == "" {
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte(`{"error":"Forbidden","message":"Missing CSRF token"}`))
			return
		}

		// TODO: Implement proper CSRF token validation
		// This is a placeholder for now

		next.ServeHTTP(w, r)
	})
}

// requestSizeMiddleware limits the size of request bodies
func (g *Gateway) requestSizeMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip if request size validation is disabled or if there's no request body
		if !g.config.Security.EnableRequestValidation || r.ContentLength == 0 {
			next.ServeHTTP(w, r)
			return
		}

		// Check if request body is too large
		maxSize := g.config.Security.MaxRequestBodySize
		if maxSize > 0 && r.ContentLength > maxSize {
			w.WriteHeader(http.StatusRequestEntityTooLarge)
			w.Write([]byte(`{"error":"Request Entity Too Large","message":"Request body exceeds maximum size"}`))
			return
		}

		next.ServeHTTP(w, r)
	})
}

// loggingMiddleware logs requests
func (g *Gateway) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Create a custom response writer to capture the status code
		lrw := newLoggingResponseWriter(w)

		// Call the next handler
		next.ServeHTTP(lrw, r)

		// Log the request
		g.logger.Info("%s %s %d %s %dB", r.Method, r.URL.Path, lrw.statusCode, time.Since(start), lrw.bytesWritten)
	})
}
