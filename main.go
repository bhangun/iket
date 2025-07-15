package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/bhangun/iket/pkg/api"
	"github.com/bhangun/iket/pkg/app"
	"github.com/bhangun/iket/pkg/config"
	"github.com/bhangun/iket/pkg/core/gateway"
	"github.com/bhangun/iket/pkg/logging"
	"github.com/bhangun/iket/pkg/metrics"
	"github.com/bhangun/iket/pkg/plugin"
)

var (
	defaultConfigPath = "config/config.yaml"
	// defaultServicePath = "config/service.yaml"
	version = app.Version // use version from app package
)

var defaultConfig = `
server:
  port: 8080
  readTimeout: "10s"
  writeTimeout: "10s"
  idleTimeout: "60s"
  enableLogging: true

security:
  enableBasicAuth: true
  basicAuthUsers:
    admin: admin123
  clients:
    my-client-id: my-secret
  jwt:
    enabled: false
    secret: "changeme"
    algorithms: ["HS256"]
    publicKeyFile: ""
    required: false
	
plugins:
  auth:
    api_key: "your-secret-api-key-here"
  openapi:
    spec_path: "openapi.yaml"
    enabled: true
    swagger_ui: true
`

var defaultService = `
services:
  - name: "Example Service"
    host: "http://localhost:9000"
    base_path: "/example"
    routes:
      - path: "/hello"
        method: GET
        requireAuth: false
        backend:
          - url_pattern: /hello
`

func ensureDefaultConfig(configPath, servicesPath string) bool {
	created := false
	configDir := filepath.Dir(configPath)
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		os.MkdirAll(configDir, 0755)
		os.WriteFile(configPath, []byte(defaultConfig), 0644)
		created = true
	}
	if servicesPath != "" {
		routesDir := filepath.Dir(servicesPath)
		if _, err := os.Stat(servicesPath); os.IsNotExist(err) {
			os.MkdirAll(routesDir, 0755)
			os.WriteFile(servicesPath, []byte(defaultService), 0644)
			created = true
		}
	}
	return created
}

func printBanner() {
	blue := "\033[34m"
	red := "\033[31m"
	reset := "\033[0m"
	fmt.Print(blue + `
 _ _                 
(_) |            _   
 _| |  _ _____ _| |_ 
| | |_/ ) ___ (_   _)
| |  _ (| ____| | |_ 
|_|_| \_)_____)  \__)` + red + " G a t e w a y \n\n" + reset)
}

func printFileIfExists(path string, label string) {
	if data, err := os.ReadFile(path); err == nil {
		fmt.Printf("\n===== %s (%s) =====\n%s\n", label, path, string(data))
	}
}

func main() {
	startTime := time.Now()

	configPath := flag.String("config", defaultConfigPath, "Path to config.yaml")
	servicesPath := flag.String("services", "", "Path to service-based config (service.yaml), optional")
	portFlag := flag.Int("port", 0, "Port to run the gateway on (overrides config and IKET_PORT env var)")
	printConfig := flag.Bool("print-config", false, "Print the loaded configuration and exit")
	printVersion := flag.Bool("version", false, "Print version and exit")
	flag.Parse()

	if *printVersion {
		yellow := "\033[33m"
		reset := "\033[0m"
		fmt.Printf(yellow+"Iket Gateway version: %s\n\n"+reset, version)
		os.Exit(0)
	}

	if ensureDefaultConfig(*configPath, *servicesPath) {
		fmt.Printf("\nDefault config created at %s and/or %s. Please review and run again.\n", *configPath, *servicesPath)
		os.Exit(0)
	}

	// Initialize logger
	logger := logging.NewLoggerFromEnv()
	defer logger.Sync()

	printBanner()
	yellow := "\033[33m"
	reset := "\033[0m"
	fmt.Printf(yellow+"Version: %s\n\n"+reset, version)

	printFileIfExists("config/config.yaml", "Default Config")
	printFileIfExists("config/service.yaml", "Default Service Config")

	logger.Info("Iket Gateway version", logging.String("version", version))
	logger.Info("Starting Iket Gateway")

	// Load configuration
	cfg, err := config.LoadConfig(*configPath, *servicesPath, logger)
	if err != nil {
		logger.Fatal("Failed to load configuration", logging.Error(err))
	}

	if *printConfig {
		if cfg.Security.Jwt.Secret != "" {
			cfg.Security.Jwt.Secret = "REDACTED"
		}
		cfg.Security.BasicAuthUsers = nil
		b, _ := json.MarshalIndent(cfg, "", "  ")
		fmt.Println(string(b))
		os.Exit(0)
	}

	// Allow port override: --port > IKET_PORT env > config file
	if *portFlag > 0 {
		cfg.Server.Port = *portFlag
		logger.Info("Overriding port from --port flag", logging.Int("port", cfg.Server.Port))
	} else if portEnv := os.Getenv("IKET_PORT"); portEnv != "" {
		var port int
		_, err := fmt.Sscanf(portEnv, "%d", &port)
		if err == nil && port > 0 {
			cfg.Server.Port = port
			logger.Info("Overriding port from IKET_PORT env var", logging.Int("port", cfg.Server.Port))
		} else if err != nil {
			logger.Warn("Invalid IKET_PORT env var, using config file port", logging.String("value", portEnv), logging.Error(err))
		}
	}

	// Initialize metrics collector
	metricsCollector := metrics.NewCollector()

	// Create plugin registry
	registry := plugin.NewRegistry()

	// Create gateway with dependencies
	gw, err := gateway.NewGateway(gateway.Dependencies{
		Config:  cfg,
		Logger:  logger,
		Metrics: metricsCollector,
	}, version)
	if err != nil {
		logger.Fatal("Failed to create gateway", logging.Error(err))
	}

	// Create and register management API
	managementAPI := api.NewManagementAPI(gw, logger, registry)
	managementAPI.RegisterRoutes(gw.GetRouter())

	logger.Info("Management API registered", logging.String("base_path", "/api/v1"))

	startupDuration := time.Since(startTime)

	logger.Info("Gateway startup complete", logging.Duration("startup_time", startupDuration))

	// Setup graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle shutdown signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigChan
		logger.Info("Received shutdown signal", logging.String("signal", sig.String()))
		gw.Shutdown()
		cancel()
	}()

	// Start the gateway
	if err := gw.Serve(ctx); err != nil {
		logger.Error("Gateway server error", err)
		os.Exit(1)
	}

	logger.Info("Gateway shutdown complete")
}
