package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/bhangun/iket/pkg/api"
	"github.com/bhangun/iket/pkg/app"
	"github.com/bhangun/iket/pkg/config"
	"github.com/bhangun/iket/pkg/core/gateway"
	"github.com/bhangun/iket/pkg/helper"
	"github.com/bhangun/iket/pkg/logging"
	"github.com/bhangun/iket/pkg/metrics"
	"github.com/bhangun/iket/pkg/plugin"
	_ "github.com/bhangun/iket/pkg/plugin/apikey"
	_ "github.com/bhangun/iket/pkg/plugin/circuitbreaker"
	_ "github.com/bhangun/iket/pkg/plugin/cors"
	_ "github.com/bhangun/iket/pkg/plugin/ipwhitelist"
	_ "github.com/bhangun/iket/pkg/plugin/jwt"
	_ "github.com/bhangun/iket/pkg/plugin/mtls"
	_ "github.com/bhangun/iket/pkg/plugin/oauth2"
	_ "github.com/bhangun/iket/pkg/plugin/ratelimit"
	_ "github.com/bhangun/iket/pkg/plugin/tls"
	_ "github.com/bhangun/iket/pkg/plugin/validation"
	_ "github.com/bhangun/iket/pkg/plugin/websocket"
	"github.com/gorilla/mux"
	"gopkg.in/yaml.v3"
)

var (
	defaultConfigPath  = "config/config.yaml"
	defaultSQLitePath  = ".iket-admin/sqlite/iket.db"
	defaultPostgresURL = "postgres://iket:iket@127.0.0.1:55432/iket?sslmode=disable"
	// defaultServicePath = "config/service.yaml"
	version = app.Version // use version from app package
)

var storageEnvVarPattern = regexp.MustCompile(`\$\{([A-Za-z0-9_]+)(:-([^}]*))?\}`)

var defaultConfig = `
server:
  port: 8080
  readTimeout: "10s"
  writeTimeout: "10s"
  idleTimeout: "60s"
  enableLogging: true

security:
  tls:
    enabled: true
    port: 8443
    enrollmentPort: 9443
    enrollmentMaxActive: 10
    certFile: "${IKET_CERTS_DIR:-./certs}/server.crt"
    keyFile: "${IKET_CERTS_DIR:-./certs}/server.key"
    clientCAFile: "${IKET_CERTS_DIR:-./certs}/ca.crt"
    clientAuthType: "RequireAndVerifyClientCert"
    minVersion: "TLS1.2"
    autoGenerate: true
    generateSharedClient: false
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

storage:
  mode: "postgres"
  postgres_url: "${IKET_POSTGRES_URL:-postgres://iket:iket@127.0.0.1:55432/iket?sslmode=disable}"
  mirror_files: true

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

func printFileIfExists(path string, label string) {
	if data, err := os.ReadFile(path); err == nil {
		fmt.Printf("\n===== %s (%s) =====\n%s\n", label, path, string(data))
	}
}

func main() {
	startTime := time.Now()

	configPath := flag.String("config", defaultConfigPath, "Path to config.yaml")
	servicesPath := flag.String("services", "", "Path to service-based config (service.yaml), optional")
	storageMode := flag.String("storage", "", "Configuration storage backend override: postgres, sqlite, or file")
	sqlitePath := flag.String("sqlite-path", "", "SQLite database path override")
	postgresURL := flag.String("postgres-url", "", "PostgreSQL connection URL override")
	portFlag := flag.Int("port", 0, "Port to run the gateway on (overrides config and IKET_PORT env var)")
	printConfig := flag.Bool("print-config", false, "Print the loaded configuration and exit")
	printVersion := flag.Bool("version", false, "Print version and exit")
	flag.Parse()

	if *printVersion {
		helper.PrintBannerWithEdition(version, app.CurrentEdition().DisplayName)
		os.Exit(0)
	}

	if ensureDefaultConfig(*configPath, *servicesPath) {
		fmt.Printf("\nDefault config created at %s and/or %s. Please review and run again.\n", *configPath, *servicesPath)
		os.Exit(0)
	}

	bootstrapTLS, err := config.ReadBootstrapTLSConfig(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to read bootstrap TLS settings from %s: %v\n", *configPath, err)
		os.Exit(1)
	}
	if err := config.EnsureTLSAssets(bootstrapTLS); err != nil {
		fmt.Fprintf(os.Stderr, "failed to prepare bootstrap TLS assets from %s: %v\n", *configPath, err)
		os.Exit(1)
	}

	storageSettings := readStorageSettings(*configPath)
	if *storageMode != "" {
		storageSettings.Mode = *storageMode
	}
	if *sqlitePath != "" {
		storageSettings.SQLitePath = *sqlitePath
	}
	if *postgresURL != "" {
		storageSettings.PostgresURL = *postgresURL
	}
	if strings.TrimSpace(storageSettings.SQLitePath) == "" {
		storageSettings.SQLitePath = defaultSQLitePath
	}
	if strings.TrimSpace(storageSettings.PostgresURL) == "" {
		storageSettings.PostgresURL = defaultPostgresURL
	}

	// Initialize logger
	logger := logging.NewLoggerFromEnv()
	defer logger.Sync()

	edition := app.CurrentEdition()
	helper.PrintBannerWithEdition(version, edition.DisplayName)

	printFileIfExists("config/config.yaml", "Default Config")
	printFileIfExists("config/service.yaml", "Default Service Config")

	logger.Info("Iket Gateway version", logging.String("version", version), logging.String("edition", edition.Edition))
	logger.Info("Starting Iket Gateway")
	logger.Info("Bootstrap TLS settings",
		logging.String("cert_file", bootstrapTLS.CertFile),
		logging.String("key_file", bootstrapTLS.KeyFile),
		logging.String("client_ca_file", bootstrapTLS.ClientCAFile),
		logging.Any("server_names", config.EffectiveServerNames(bootstrapTLS)),
		logging.Any("server_ips", config.EffectiveServerIPs(bootstrapTLS)),
		logging.Bool("auto_generate", bootstrapTLS.ShouldAutoGenerate()),
		logging.Bool("generate_shared_client", bootstrapTLS.ShouldGenerateSharedClient()),
	)

	fileProvider := config.NewFileProvider(*configPath, *servicesPath, logger)
	var provider config.Provider
	switch storageSettings.EffectiveMode() {
	case "file":
		provider = fileProvider
	case "sqlite":
		sqliteProvider := config.NewSQLiteProvider(storageSettings.SQLitePath, fileProvider, logger)
		if storageSettings.EffectiveMirrorFiles() {
			provider = config.NewMirroringProvider(sqliteProvider, fileProvider)
		} else {
			provider = sqliteProvider
		}
	case "postgres":
		postgresProvider := config.NewPostgresProvider(storageSettings.PostgresURL, fileProvider, logger)
		if storageSettings.EffectiveMirrorFiles() {
			provider = config.NewMirroringProvider(postgresProvider, fileProvider)
		} else {
			provider = postgresProvider
		}
	default:
		logger.Fatal("Unsupported storage backend", logging.String("storage", storageSettings.EffectiveMode()))
	}

	// Load configuration
	cfg, err := provider.Load()
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

	// Use the global plugin registry
	// registry := plugin.NewRegistry()
	// registry.RegisterAllGlobal()

	// Create gateway with dependencies
	if err := config.EnsureTLSAssets(cfg.Security.TLS); err != nil {
		logger.Fatal("Failed to prepare TLS assets", logging.Error(err))
	}

	gw, err := gateway.NewGateway(gateway.Dependencies{
		Config:         cfg,
		ConfigProvider: provider,
		Logger:         logger,
		Metrics:        metricsCollector,
		Registry:       plugin.DefaultRegistry,
	}, version)
	if err != nil {
		logger.Fatal("Failed to create gateway", logging.Error(err))
	}

	// Create and register management API
	managementAPI := api.NewManagementAPI(gw, logger, plugin.DefaultRegistry)
	managementAPI.RegisterRoutes(gw.GetRouter())
	enrollmentServer := startEnrollmentServer(cfg, logger, managementAPI)

	// Initialize the gateway (sets up proxy routes, middleware, etc.)
	// Calling this AFTER RegisterRoutes ensures management API routes are registered first
	// in the router and thus take precedence over wildcard proxy routes.
	if err := gw.Initialize(); err != nil {
		logger.Fatal("Failed to initialize gateway", logging.Error(err))
	}

	logger.Info("Registered plugins", logging.Any("plugins", managementAPI.ListPlugins()))
	logger.Info("Management API registered", logging.String("base_path", "/api/v1"))
	startupDuration := time.Since(startTime)

	logger.Info("Gateway startup complete", logging.Duration("startup_time", startupDuration))
	logger.Info("Configuration storage ready",
		logging.String("storage", storageSettings.EffectiveMode()),
		logging.String("sqlite_path", storageSettings.SQLitePath),
		logging.String("postgres_url", configRedactedPostgresURL(storageSettings.PostgresURL)),
		logging.Bool("mirror_files", storageSettings.EffectiveMirrorFiles()),
	)

	// Setup graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle shutdown signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigChan
		logger.Info("Received shutdown signal", logging.String("signal", sig.String()))
		if enrollmentServer != nil {
			shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer shutdownCancel()
			if err := enrollmentServer.Shutdown(shutdownCtx); err != nil {
				logger.Error("Enrollment server shutdown error", err)
			}
		}
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

func readStorageSettings(configPath string) config.StorageConfig {
	settings := config.StorageConfig{
		Mode:        "postgres",
		SQLitePath:  defaultSQLitePath,
		PostgresURL: defaultPostgresURL,
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		return settings
	}

	var raw struct {
		Storage config.StorageConfig `yaml:"storage"`
	}
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return settings
	}
	if raw.Storage.Mode != "" {
		settings.Mode = expandStorageEnvVars(raw.Storage.Mode)
	}
	if raw.Storage.SQLitePath != "" {
		settings.SQLitePath = expandStorageEnvVars(raw.Storage.SQLitePath)
	}
	if raw.Storage.PostgresURL != "" {
		settings.PostgresURL = expandStorageEnvVars(raw.Storage.PostgresURL)
	}
	if raw.Storage.MirrorFiles != nil {
		settings.MirrorFiles = raw.Storage.MirrorFiles
	}
	return settings
}

func expandStorageEnvVars(input string) string {
	return storageEnvVarPattern.ReplaceAllStringFunc(input, func(match string) string {
		parts := storageEnvVarPattern.FindStringSubmatch(match)
		if len(parts) < 2 {
			return match
		}
		if value, ok := os.LookupEnv(parts[1]); ok && value != "" {
			return value
		}
		if len(parts) >= 4 {
			return parts[3]
		}
		return ""
	})
}

func configRedactedPostgresURL(raw string) string {
	if raw == "" {
		return raw
	}
	start := strings.Index(raw, "://")
	if start == -1 {
		return raw
	}
	start += 3
	at := strings.Index(raw[start:], "@")
	if at == -1 {
		return raw
	}
	at += start
	colon := strings.Index(raw[start:at], ":")
	if colon == -1 {
		return raw
	}
	colon += start
	return raw[:colon+1] + "****" + raw[at:]
}

func startEnrollmentServer(cfg *config.Config, logger *logging.Logger, managementAPI *api.ManagementAPI) *http.Server {
	if cfg == nil || !cfg.Security.TLS.Enabled {
		return nil
	}
	port := cfg.Security.TLS.EffectiveEnrollmentPort()
	if port <= 0 {
		return nil
	}

	router := mux.NewRouter()
	managementAPI.RegisterEnrollmentRoutes(router)

	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}
	switch cfg.Security.TLS.MinVersion {
	case "TLS1.0":
		tlsConfig.MinVersion = tls.VersionTLS10
	case "TLS1.1":
		tlsConfig.MinVersion = tls.VersionTLS11
	case "TLS1.2":
		tlsConfig.MinVersion = tls.VersionTLS12
	case "TLS1.3":
		tlsConfig.MinVersion = tls.VersionTLS13
	}

	server := &http.Server{
		Addr:      fmt.Sprintf(":%d", port),
		Handler:   router,
		TLSConfig: tlsConfig,
	}

	go func() {
		logger.Info("Starting enrollment TLS server", logging.Int("port", port))
		if err := server.ListenAndServeTLS(cfg.Security.TLS.CertFile, cfg.Security.TLS.KeyFile); err != nil && err != http.ErrServerClosed {
			logger.Error("Enrollment TLS server error", err)
		}
	}()

	return server
}
