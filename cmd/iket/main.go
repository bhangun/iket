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
	defaultServicePath = "config/service.yaml"
	defaultSQLitePath  = ".iket-admin/sqlite/iket.db"
	defaultPostgresURL = "postgres://iket:iket@127.0.0.1:55432/iket?sslmode=disable"
	version            = app.Version // use version from app package
)

var storageEnvVarPattern = regexp.MustCompile(`\$\{([A-Za-z0-9_]+)(:-([^}]*))?\}`)

const defaultFileConfig = `
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
  mode: "file"

plugins:
  auth:
    api_key: "your-secret-api-key-here"
  openapi:
    spec_path: "openapi.yaml"
    enabled: true
    swagger_ui: true
`

const defaultPostgresConfigTemplate = `
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
  postgres_url: "%s"
  mirror_files: true

plugins:
  auth:
    api_key: "your-secret-api-key-here"
  openapi:
    spec_path: "openapi.yaml"
    enabled: true
    swagger_ui: true
`

const legacyDefaultService = `
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

const defaultService = `
version: 1
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

const defaultDockerComposeFile = `version: "3.8"

services:
  iket:
    image: ${IKET_IMAGE:-bhangun/iket:latest}
    container_name: iket
    restart: unless-stopped
    ports:
      - "${IKET_HTTP_PORT:-7100}:8080"
      - "${IKET_HTTPS_PORT:-8443}:8443"
      - "${IKET_ENROLLMENT_PORT:-9443}:9443"
    environment:
      - TZ=${TZ:-UTC}
      - IKET_CERTS_DIR=/app/certs
    command: ["--config", "/app/config/config.yaml", "--services", "/app/config/service.yaml"]
    volumes:
      - ./config:/app/config:ro
      - ./certs:/app/certs:rw
      - ./logs:/app/logs:rw
`

var backupTimestampNow = func() time.Time {
	return time.Now()
}

func buildDefaultConfig(storage config.StorageConfig) string {
	if storage.EffectiveMode() == "postgres" {
		return fmt.Sprintf(defaultPostgresConfigTemplate, storage.PostgresURL)
	}
	return defaultFileConfig
}

func inferComposePath(configPath string) string {
	configDir := filepath.Dir(configPath)
	if filepath.Base(configDir) == "config" {
		return filepath.Join(filepath.Dir(configDir), "docker-compose.yaml")
	}
	return filepath.Join(configDir, "docker-compose.yaml")
}

func ensureDefaultScaffold(configPath, servicesPath string, storage config.StorageConfig, overwrite bool) ([]string, error) {
	created := make([]string, 0, 3)
	configDir := filepath.Dir(configPath)
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return nil, err
	}
	configContent := buildDefaultConfig(storage)
	if overwrite || fileMissing(configPath) || shouldAutoRefreshLegacyConfig(configPath, storage) {
		if (overwrite || !fileMissing(configPath)) && !sameFileContents(configPath, configContent) {
			if err := backupFileIfExists(configPath); err != nil {
				return nil, err
			}
		}
		if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
			return nil, err
		}
		created = append(created, configPath)
	}
	if servicesPath != "" {
		routesDir := filepath.Dir(servicesPath)
		if err := os.MkdirAll(routesDir, 0755); err != nil {
			return nil, err
		}
		if overwrite || fileMissing(servicesPath) || shouldAutoRefreshLegacyService(servicesPath) {
			if (overwrite || !fileMissing(servicesPath)) && !sameFileContents(servicesPath, defaultService) {
				if err := backupFileIfExists(servicesPath); err != nil {
					return nil, err
				}
			}
			if err := os.WriteFile(servicesPath, []byte(defaultService), 0644); err != nil {
				return nil, err
			}
			created = append(created, servicesPath)
		}
	}
	composePath := inferComposePath(configPath)
	composeDir := filepath.Dir(composePath)
	if err := os.MkdirAll(composeDir, 0755); err != nil {
		return nil, err
	}
	if overwrite || fileMissing(composePath) {
		if overwrite && !sameFileContents(composePath, defaultDockerComposeFile) {
			if err := backupFileIfExists(composePath); err != nil {
				return nil, err
			}
		}
		if err := os.WriteFile(composePath, []byte(defaultDockerComposeFile), 0644); err != nil {
			return nil, err
		}
		created = append(created, composePath)
	}
	return created, nil
}

func fileMissing(path string) bool {
	_, err := os.Stat(path)
	return os.IsNotExist(err)
}

func sameFileContents(path string, content string) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	return normalizeScaffoldContent(string(data)) == normalizeScaffoldContent(content)
}

func normalizeScaffoldContent(content string) string {
	return strings.TrimSpace(strings.ReplaceAll(content, "\r\n", "\n"))
}

func shouldAutoRefreshLegacyConfig(path string, storage config.StorageConfig) bool {
	if storage.EffectiveMode() != "file" {
		return false
	}
	legacyPostgresConfig := fmt.Sprintf(defaultPostgresConfigTemplate, defaultPostgresURL)
	return sameFileContents(path, legacyPostgresConfig)
}

func shouldAutoRefreshLegacyService(path string) bool {
	return sameFileContents(path, legacyDefaultService)
}

func legacyScaffoldRefreshPaths(configPath, servicesPath string, storage config.StorageConfig) []string {
	refreshed := make([]string, 0, 2)
	if shouldAutoRefreshLegacyConfig(configPath, storage) {
		refreshed = append(refreshed, configPath)
	}
	if servicesPath != "" && shouldAutoRefreshLegacyService(servicesPath) {
		refreshed = append(refreshed, servicesPath)
	}
	return refreshed
}

func backupFileIfExists(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	timestamp := backupTimestampNow().Format("20060102-150405")
	return os.WriteFile(path+"."+timestamp+".bak", data, 0644)
}

func printFileIfExists(path string, label string) {
	if data, err := os.ReadFile(path); err == nil {
		fmt.Printf("\n===== %s (%s) =====\n%s\n", label, path, string(data))
	}
}

func main() {
	startTime := time.Now()

	configPath := flag.String("config", defaultConfigPath, "Path to config.yaml")
	servicesPath := flag.String("services", defaultServicePath, "Path to service-based config (service.yaml)")
	storageMode := flag.String("storage", "", "Configuration storage backend override: postgres, sqlite, or file")
	sqlitePath := flag.String("sqlite-path", "", "SQLite database path override")
	postgresURL := flag.String("postgres-url", "", "PostgreSQL connection URL override")
	useDatabase := flag.Bool("database", false, "Use PostgreSQL for configuration storage instead of file-based config")
	databaseUsername := flag.String("username", "", "Database username used when --database is enabled")
	databasePassword := flag.String("password", "", "Database password used when --database is enabled")
	databaseName := flag.String("database-name", "", "Database name used when --database is enabled")
	databaseHost := flag.String("database-host", "", "Database host used when --database is enabled")
	databasePort := flag.String("database-port", "", "Database port used when --database is enabled")
	resetDefaults := flag.Bool("reset-defaults", false, "Rewrite config, service, and docker-compose defaults before starting")
	initOnly := flag.Bool("init-only", false, "Generate or refresh default scaffold files and exit without starting")
	portFlag := flag.Int("port", 0, "Port to run the gateway on (overrides config and IKET_PORT env var)")
	printConfig := flag.Bool("print-config", false, "Print the loaded configuration and exit")
	printVersion := flag.Bool("version", false, "Print version and exit")
	flag.Parse()

	if *printVersion {
		helper.PrintBannerWithEdition(version, app.CurrentEdition().DisplayName)
		os.Exit(0)
	}

	storageSettings := readStorageSettings(*configPath)
	storageSettings = resolveServerStorageSettings(
		storageSettings,
		*storageMode,
		*sqlitePath,
		*postgresURL,
		*useDatabase,
		*databaseUsername,
		*databasePassword,
		*databaseName,
		*databaseHost,
		*databasePort,
		os.Getenv("IKET_DB_PASSWORD"),
	)
	legacyRefreshedPaths := legacyScaffoldRefreshPaths(*configPath, *servicesPath, storageSettings)
	createdPaths, err := ensureDefaultScaffold(*configPath, *servicesPath, storageSettings, *resetDefaults)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to prepare default scaffold: %v\n", err)
		os.Exit(1)
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

	// Initialize logger
	logger := logging.NewLoggerFromEnv()
	defer logger.Sync()

	edition := app.CurrentEdition()
	helper.PrintBannerWithEdition(version, edition.DisplayName)

	if len(createdPaths) > 0 {
		if *resetDefaults {
			fmt.Println("\nReset default scaffold:")
		} else {
			fmt.Println("\nGenerated default scaffold:")
		}
		for _, path := range createdPaths {
			fmt.Printf("  - %s\n", path)
		}
		fmt.Println()
	}

	printFileIfExists(*configPath, "Default Config")
	printFileIfExists(*servicesPath, "Default Service Config")
	printFileIfExists(inferComposePath(*configPath), "Default Docker Compose")
	if len(legacyRefreshedPaths) > 0 && !*resetDefaults {
		fmt.Println("Refreshed legacy scaffold defaults:")
		for _, path := range legacyRefreshedPaths {
			fmt.Printf("  - %s\n", path)
		}
		fmt.Println("Previous starter copies were preserved with timestamped .bak suffixes.")
		fmt.Println()
	}
	if *initOnly {
		fmt.Println("Initialization complete.")
		os.Exit(0)
	}

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
		Mode:        "file",
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

func coalesceString(value string, fallback string) string {
	if strings.TrimSpace(value) != "" {
		return strings.TrimSpace(value)
	}
	return fallback
}

func buildDatabaseURL(username, password, host, port, databaseName string) string {
	return fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=disable", username, password, host, port, databaseName)
}

func resolveServerStorageSettings(
	settings config.StorageConfig,
	storageMode string,
	sqlitePath string,
	postgresURL string,
	useDatabase bool,
	databaseUsername string,
	databasePassword string,
	databaseName string,
	databaseHost string,
	databasePort string,
	envDatabasePassword string,
) config.StorageConfig {
	explicitDatabase := useDatabase ||
		strings.TrimSpace(databaseUsername) != "" ||
		strings.TrimSpace(databasePassword) != "" ||
		strings.TrimSpace(databaseName) != "" ||
		strings.TrimSpace(databaseHost) != "" ||
		strings.TrimSpace(databasePort) != "" ||
		strings.TrimSpace(postgresURL) != ""

	if explicitDatabase {
		settings.Mode = "postgres"
		if strings.TrimSpace(postgresURL) == "" {
			settings.PostgresURL = buildDatabaseURL(
				coalesceString(databaseUsername, "iket"),
				coalesceString(databasePassword, coalesceString(envDatabasePassword, "iket")),
				coalesceString(databaseHost, "127.0.0.1"),
				coalesceString(databasePort, "55432"),
				coalesceString(databaseName, "iket"),
			)
		}
	} else if strings.TrimSpace(storageMode) == "" && strings.TrimSpace(sqlitePath) == "" {
		settings.Mode = "file"
	}

	if strings.TrimSpace(storageMode) != "" {
		settings.Mode = storageMode
	}
	if strings.TrimSpace(sqlitePath) != "" {
		settings.SQLitePath = sqlitePath
	}
	if strings.TrimSpace(postgresURL) != "" {
		settings.PostgresURL = postgresURL
	}
	if strings.TrimSpace(settings.SQLitePath) == "" {
		settings.SQLitePath = defaultSQLitePath
	}
	if strings.TrimSpace(settings.PostgresURL) == "" {
		settings.PostgresURL = defaultPostgresURL
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
