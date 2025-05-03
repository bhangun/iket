package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"gopkg.in/yaml.v3"

	"iket/pkg/plugin"
	"iket/plugins/auth"
	"iket/plugins/storage"
)

type Config struct {
	Plugins  map[string]map[string]interface{} `yaml:"plugins"`
	Server   ServerConfig                      `yaml:"server"`
	Security SecurityConfig                    `yaml:"security"`
}

type ServerConfig struct {
	Port          int    `yaml:"port"`
	ReadTimeout   string `yaml:"readTimeout"`
	WriteTimeout  string `yaml:"writeTimeout"`
	IdleTimeout   string `yaml:"idleTimeout"`
	PluginsDir    string `yaml:"pluginsDir"`
	EnableLogging bool   `yaml:"enableLogging"`
}

type SecurityConfig struct {
	TLS TLSConfig `yaml:"tls"`
}

type TLSConfig struct {
	Enabled    bool     `yaml:"enabled"`
	CertFile   string   `yaml:"cert_file"`
	KeyFile    string   `yaml:"key_file"`
	MinVersion string   `yaml:"min_version"`
	Ciphers    []string `yaml:"ciphers"`
}

func loadConfig(path string) (*Config, error) {
	configData, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var config Config
	if err := yaml.Unmarshal(configData, &config); err != nil {
		return nil, err
	}

	return &config, nil
}

func main() {
	// Load configuration
	config, err := loadConfig("/app/config/config.yaml")
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Create plugin registry
	registry := plugin.NewRegistry()

	// Register plugins
	registry.Register(storage.NewEtcdPlugin())
	registry.Register(auth.NewSAMLPlugin())

	// Initialize plugins
	if err := registry.Initialize(config.Plugins); err != nil {
		log.Fatalf("Failed to initialize plugins: %v", err)
	}

	// Setup signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Get SAML plugin
	plugin, err := registry.Get("auth")
	if err != nil {
		log.Fatalf("Failed to get SAML plugin: %v", err)
	}

	samlPlugin, ok := plugin.(*auth.SAMLPlugin)
	if !ok {
		log.Fatal("Failed to cast to SAML plugin")
	}

	// Create router
	router := http.NewServeMux()

	// Add SAML routes
	router.Handle("/saml/", samlPlugin.Routes())

	// Add SAML middleware
	samlMiddleware := samlPlugin.Middleware()
	
	// Create HTTP server
	httpSrv := &http.Server{
		Addr:    fmt.Sprintf(":%d", config.Server.Port),
		Handler: samlMiddleware(router),
	}

	// Create HTTPS server if TLS is enabled
	var httpsSrv *http.Server
	if config.Security.TLS.Enabled {
		httpsSrv = &http.Server{
			Addr:    ":8443",
			Handler: samlMiddleware(router),
			TLSConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
			},
		}
	}

	// Start HTTP server
	go func() {
		log.Printf("Starting HTTP server on port %d", config.Server.Port)
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("HTTP server error: %v", err)
			sigChan <- syscall.SIGTERM
		}
	}()

	// Start HTTPS server if enabled
	if httpsSrv != nil {
		go func() {
			log.Printf("Starting HTTPS server on port 8443")
			if err := httpsSrv.ListenAndServeTLS(
				config.Security.TLS.CertFile,
				config.Security.TLS.KeyFile,
			); err != nil && err != http.ErrServerClosed {
				log.Printf("HTTPS server error: %v", err)
				sigChan <- syscall.SIGTERM
			}
		}()
	}

	// Wait for shutdown signal
	sig := <-sigChan
	log.Printf("Received signal %v, shutting down", sig)

	// Graceful shutdown
	if err := httpSrv.Shutdown(context.Background()); err != nil {
		log.Printf("Error during HTTP server shutdown: %v", err)
	}

	if httpsSrv != nil {
		if err := httpsSrv.Shutdown(context.Background()); err != nil {
			log.Printf("Error during HTTPS server shutdown: %v", err)
		}
	}
}
