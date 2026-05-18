package tls

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"sync"

	coreerrors "github.com/bhangun/iket/pkg/core/errors"
	"github.com/bhangun/iket/pkg/plugin"
)

type TLSPlugin struct {
	enabled      bool
	certFile     string
	keyFile      string
	caFile       string
	clientAuth   bool
	minVersion   uint16
	maxVersion   uint16
	cipherSuites []uint16
	config       *tls.Config
	mu           sync.RWMutex
}

func (t *TLSPlugin) Name() string {
	return "tls"
}

func (t *TLSPlugin) Type() string {
	return "tls"
}

func (t *TLSPlugin) Initialize(config map[string]interface{}) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	// Default values
	t.enabled = false
	t.clientAuth = false
	t.minVersion = tls.VersionTLS12
	t.maxVersion = tls.VersionTLS13

	// Load configuration
	if enabled, ok := config["enabled"].(bool); ok {
		t.enabled = enabled
	}

	if !t.enabled {
		return nil
	}

	if certFile, ok := config["cert_file"].(string); ok {
		t.certFile = certFile
	}

	if keyFile, ok := config["key_file"].(string); ok {
		t.keyFile = keyFile
	}

	if caFile, ok := config["ca_file"].(string); ok {
		t.caFile = caFile
	}

	if clientAuth, ok := config["client_auth"].(bool); ok {
		t.clientAuth = clientAuth
	}

	// Validate required files
	if t.certFile == "" || t.keyFile == "" {
		return coreerrors.NewRequiredFieldError("cert_file and key_file are required for TLS")
	}

	// Build TLS config
	if err := t.buildTLSConfig(); err != nil {
		return coreerrors.NewConfigError("failed to build TLS config", err)
	}

	return nil
}

func (t *TLSPlugin) buildTLSConfig() error {
	// Load certificate
	cert, err := tls.LoadX509KeyPair(t.certFile, t.keyFile)
	if err != nil {
		return coreerrors.NewConfigError("failed to load certificate", err)
	}

	// Load CA certificate if provided
	var caCertPool *x509.CertPool
	if t.caFile != "" {
		caCert, err := os.ReadFile(t.caFile)
		if err != nil {
			return coreerrors.NewConfigError("failed to read CA certificate", err)
		}

		caCertPool = x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			return coreerrors.NewCodeError(coreerrors.CodeCertificatePEMInvalid, "failed to append CA certificate", nil)
		}
	}

	// Configure TLS
	t.config = &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   t.minVersion,
		MaxVersion:   t.maxVersion,
	}

	if t.clientAuth {
		t.config.ClientAuth = tls.RequireAndVerifyClientCert
		if caCertPool != nil {
			t.config.ClientCAs = caCertPool
		}
	}

	return nil
}

func (t *TLSPlugin) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !t.enabled {
			next.ServeHTTP(w, r)
			return
		}

		// Add TLS info to request context
		if r.TLS != nil {
			// TLS connection info is already available
			// You can add custom headers or context values here
		}

		next.ServeHTTP(w, r)
	})
}

// GetTLSConfig returns the TLS configuration for the server
func (t *TLSPlugin) GetTLSConfig() *tls.Config {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.config
}

// Reload reloads the TLS configuration
func (t *TLSPlugin) Reload(config map[string]interface{}) error {
	return t.Initialize(config)
}

// Tags returns plugin tags for discovery
func (t *TLSPlugin) Tags() map[string]string {
	return map[string]string{
		"type":        "tls",
		"category":    "security",
		"middleware":  "true",
		"client_auth": fmt.Sprintf("%t", t.clientAuth),
	}
}

// Health checks if the TLS plugin is healthy
func (t *TLSPlugin) Health() error {
	t.mu.RLock()
	defer t.mu.RUnlock()

	if !t.enabled {
		return coreerrors.NewCodeError(coreerrors.CodePluginUnsupported, "TLS plugin is disabled", nil)
	}

	// Check if certificate files exist
	if _, err := os.Stat(t.certFile); os.IsNotExist(err) {
		return coreerrors.NewCodeError(coreerrors.CodeCertificateNotFound, fmt.Sprintf("certificate file not found: %s", t.certFile), nil)
	}

	if _, err := os.Stat(t.keyFile); os.IsNotExist(err) {
		return coreerrors.NewConfigError(fmt.Sprintf("key file not found: %s", t.keyFile), nil)
	}

	if t.caFile != "" {
		if _, err := os.Stat(t.caFile); os.IsNotExist(err) {
			return coreerrors.NewConfigError(fmt.Sprintf("CA file not found: %s", t.caFile), nil)
		}
	}

	return nil
}

// Status returns human-readable status
func (t *TLSPlugin) Status() string {
	t.mu.RLock()
	defer t.mu.RUnlock()

	if !t.enabled {
		return "TLS Plugin: Disabled"
	}

	status := fmt.Sprintf("TLS Plugin: Enabled (cert: %s, key: %s", t.certFile, t.keyFile)
	if t.caFile != "" {
		status += fmt.Sprintf(", ca: %s", t.caFile)
	}
	if t.clientAuth {
		status += ", client auth enabled"
	}
	status += ")"

	return status
}

// OnStart lifecycle hook
func (t *TLSPlugin) OnStart() error {
	// Validate TLS config on startup
	return t.Health()
}

// OnShutdown lifecycle hook
func (t *TLSPlugin) OnShutdown() error {
	// Clean up any TLS-related resources if needed
	return nil
}

func init() {
	plugin.RegisterFactory("tls", func(config map[string]interface{}) (plugin.Plugin, error) {
		p := &TLSPlugin{}
		if err := p.Initialize(config); err != nil {
			return nil, err
		}
		return p, nil
	})
}
