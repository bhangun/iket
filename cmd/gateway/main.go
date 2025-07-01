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

	"iket/internal/config"
	"iket/internal/core/gateway"
	"iket/internal/logging"
	"iket/internal/metrics"
)

var (
	defaultConfigPath = "config/config.yaml"
	defaultRoutesPath = "config/routes.yaml"
	version           = "dev" // can be set at build time with -ldflags
)

var defaultConfig = `server:
  port: 8080
  readTimeout: "10s"
  writeTimeout: "10s"
  idleTimeout: "60s"
  enableLogging: true
routes: []
plugins: {}
`

var defaultRoutes = `routes:
  - path: "/hello"
    destination: "http://localhost:9000"
    methods: ["GET"]
    requireAuth: false
`

func ensureDefaultConfig(configPath, routesPath string) bool {
	created := false
	configDir := filepath.Dir(configPath)
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		os.MkdirAll(configDir, 0755)
		os.WriteFile(configPath, []byte(defaultConfig), 0644)
		created = true
	}
	routesDir := filepath.Dir(routesPath)
	if _, err := os.Stat(routesPath); os.IsNotExist(err) {
		os.MkdirAll(routesDir, 0755)
		os.WriteFile(routesPath, []byte(defaultRoutes), 0644)
		created = true
	}
	return created
}

func main() {
	startTime := time.Now()

	configPath := flag.String("config", defaultConfigPath, "Path to config.yaml")
	routesPath := flag.String("routes", defaultRoutesPath, "Path to routes.yaml")
	portFlag := flag.Int("port", 0, "Port to run the gateway on (overrides config and IKET_PORT env var)")
	printConfig := flag.Bool("print-config", false, "Print the loaded configuration and exit")
	flag.Parse()

	fmt.Printf("Iket Gateway version: %s\n", version)

	if ensureDefaultConfig(*configPath, *routesPath) {
		fmt.Printf("\nDefault config created at %s and/or %s. Please review and run again.\n", *configPath, *routesPath)
		os.Exit(0)
	}

	// Initialize logger
	logger := logging.NewLoggerFromEnv()
	defer logger.Sync()

	logger.Info("Iket Gateway version", logging.String("version", version))
	logger.Info("Starting Iket Gateway")

	// Load configuration
	cfg, err := config.LoadConfig(*configPath, *routesPath, logger)
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

	// Create gateway with dependencies
	gw, err := gateway.NewGateway(gateway.Dependencies{
		Config:  cfg,
		Logger:  logger,
		Metrics: metricsCollector,
	}, version)
	if err != nil {
		logger.Fatal("Failed to create gateway", logging.Error(err))
	}

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
