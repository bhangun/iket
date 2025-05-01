package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"plugin"
	"sync"
	"syscall"
	"time"

	"github.com/gorilla/mux"
	"gopkg.in/yaml.v3"
)

// Config represents the gateway configuration
type Config struct {
	Server struct {
		Port          int           `yaml:"port"`
		ReadTimeout   time.Duration `yaml:"readTimeout"`
		WriteTimeout  time.Duration `yaml:"writeTimeout"`
		IdleTimeout   time.Duration `yaml:"idleTimeout"`
		PluginsDir    string        `yaml:"pluginsDir"`
		EnableLogging bool          `yaml:"enableLogging"`
	} `yaml:"server"`

	Routes []struct {
		Path        string   `yaml:"path"`
		Destination string   `yaml:"destination"`
		Methods     []string `yaml:"methods"`
	} `yaml:"routes"`

	Plugins []struct {
		Name    string                 `yaml:"name"`
		Path    string                 `yaml:"path"`
		Enabled bool                   `yaml:"enabled"`
		Config  map[string]interface{} `yaml:"config"`
	} `yaml:"plugins"`
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
	plugins     []GatewayPlugin
	pluginsMu   sync.RWMutex
	middlewares []func(http.Handler) http.Handler
}

// NewGateway creates a new API gateway instance
func NewGateway(configPath string) (*Gateway, error) {
	config, err := loadConfig(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load config: %w", err)
	}

	gateway := &Gateway{
		config:      config,
		router:      mux.NewRouter(),
		plugins:     make([]GatewayPlugin, 0),
		middlewares: make([]func(http.Handler) http.Handler, 0),
	}

	// Set up the router
	gateway.setupRoutes()

	// Load plugins
	if err := gateway.loadPlugins(); err != nil {
		return nil, fmt.Errorf("failed to load plugins: %w", err)
	}

	return gateway, nil
}

// loadConfig loads the gateway configuration from a YAML file
func loadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, err
	}

	return &config, nil
}

// setupRoutes configures the routes from the config
func (g *Gateway) setupRoutes() {
	for _, route := range g.config.Routes {
		g.router.HandleFunc(route.Path, g.proxyHandler(route.Destination)).
			Methods(route.Methods...)
	}

	// Add catch-all route for 404s
	g.router.NotFoundHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("404 - Route not found"))
	})
}

// proxyHandler returns a handler function that proxies requests to the destination
func (g *Gateway) proxyHandler(destination string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// In a real implementation, this would proxy the request to the destination
		// For simplicity, we'll just return a placeholder response
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(fmt.Sprintf("Request would be proxied to %s", destination)))
	}
}

// loadPlugins loads and initializes all enabled plugins
func (g *Gateway) loadPlugins() error {
	for _, pluginConfig := range g.config.Plugins {
		if !pluginConfig.Enabled {
			log.Printf("Plugin %s is disabled, skipping", pluginConfig.Name)
			continue
		}

		log.Printf("Loading plugin: %s from %s", pluginConfig.Name, pluginConfig.Path)

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

		log.Printf("Plugin %s loaded successfully", pluginConfig.Name)
	}

	return nil
}

// Serve starts the gateway server
func (g *Gateway) Serve() error {
	var handler http.Handler = g.router

	// Apply all middlewares in reverse order (last added, first executed)
	for i := len(g.middlewares) - 1; i >= 0; i-- {
		handler = g.middlewares[i](handler)
	}

	// Add logging middleware if enabled
	if g.config.Server.EnableLogging {
		handler = loggingMiddleware(handler)
	}

	// Configure the server
	addr := fmt.Sprintf(":%d", g.config.Server.Port)
	server := &http.Server{
		Addr:         addr,
		Handler:      handler,
		ReadTimeout:  g.config.Server.ReadTimeout * time.Second,
		WriteTimeout: g.config.Server.WriteTimeout * time.Second,
		IdleTimeout:  g.config.Server.IdleTimeout * time.Second,
	}

	// Handle graceful shutdown
	done := make(chan os.Signal, 1)
	signal.Notify(done, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		log.Printf("Starting gateway server on %s", addr)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Failed to start server: %v", err)
		}
	}()

	<-done
	log.Println("Server is shutting down...")

	// Shutdown plugins
	g.shutdownPlugins()

	// Create a deadline to wait for
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		return fmt.Errorf("server forced to shutdown: %w", err)
	}

	log.Println("Server gracefully stopped")
	return nil
}

// shutdownPlugins gracefully shuts down all plugins
func (g *Gateway) shutdownPlugins() {
	g.pluginsMu.RLock()
	defer g.pluginsMu.RUnlock()

	for _, p := range g.plugins {
		if err := p.Shutdown(); err != nil {
			log.Printf("Error shutting down plugin %s: %v", p.Name(), err)
		} else {
			log.Printf("Plugin %s shutdown successfully", p.Name())
		}
	}
}

// loggingMiddleware logs incoming requests
func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		lw := newLoggingResponseWriter(w)
		next.ServeHTTP(lw, r)

		duration := time.Since(start)

		log.Printf("%s %s %d %s", r.Method, r.URL.Path, lw.statusCode, duration)
	})
}

// loggingResponseWriter is a custom ResponseWriter that captures the status code
type loggingResponseWriter struct {
	http.ResponseWriter
	statusCode int
}

func newLoggingResponseWriter(w http.ResponseWriter) *loggingResponseWriter {
	return &loggingResponseWriter{w, http.StatusOK}
}

func (lw *loggingResponseWriter) WriteHeader(code int) {
	lw.statusCode = code
	lw.ResponseWriter.WriteHeader(code)
}

func main() {
	configPath := flag.String("config", "config.yaml", "Path to the configuration file")
	flag.Parse()

	gateway, err := NewGateway(*configPath)
	if err != nil {
		log.Fatalf("Failed to create gateway: %v", err)
	}

	if err := gateway.Serve(); err != nil {
		log.Fatalf("Gateway error: %v", err)
	}
}
