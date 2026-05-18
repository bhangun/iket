package mtls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	coreerrors "github.com/bhangun/iket/pkg/core/errors"
	"github.com/bhangun/iket/pkg/plugin"
)

type MTLSPlugin struct {
	enabled       bool
	caFile        string
	caPool        *x509.CertPool
	allowedCNs    []string
	allowedOUs    []string
	skipPaths     []string
	claimsContext string
	mu            sync.RWMutex
}

type ClientCertInfo struct {
	Subject   string   `json:"subject"`
	Issuer    string   `json:"issuer"`
	CN        string   `json:"cn"`
	OU        []string `json:"ou"`
	O         []string `json:"o"`
	Serial    string   `json:"serial"`
	NotBefore string   `json:"not_before"`
	NotAfter  string   `json:"not_after"`
}

func init() {
	plugin.RegisterFactory("mtls", func(config map[string]interface{}) (plugin.Plugin, error) {
		p := &MTLSPlugin{}
		if err := p.Initialize(config); err != nil {
			return nil, err
		}
		return p, nil
	})
}

func (m *MTLSPlugin) Name() string {
	return "mtls"
}

func (m *MTLSPlugin) Type() string {
	return "mtls"
}

func (m *MTLSPlugin) Initialize(config map[string]interface{}) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Default values
	m.enabled = false
	m.claimsContext = "mtls_claims"

	// Load configuration
	if enabled, ok := config["enabled"].(bool); ok {
		m.enabled = enabled
	}

	if !m.enabled {
		return nil
	}

	if caFile, ok := config["ca_file"].(string); ok {
		m.caFile = caFile
	}

	if allowedCNs, ok := config["allowed_cns"].([]interface{}); ok {
		for _, cn := range allowedCNs {
			if cnStr, ok := cn.(string); ok {
				m.allowedCNs = append(m.allowedCNs, cnStr)
			}
		}
	}

	if allowedOUs, ok := config["allowed_ous"].([]interface{}); ok {
		for _, ou := range allowedOUs {
			if ouStr, ok := ou.(string); ok {
				m.allowedOUs = append(m.allowedOUs, ouStr)
			}
		}
	}

	if skipPaths, ok := config["skip_paths"].([]interface{}); ok {
		for _, path := range skipPaths {
			if pathStr, ok := path.(string); ok {
				m.skipPaths = append(m.skipPaths, pathStr)
			}
		}
	}

	if claimsContext, ok := config["claims_context"].(string); ok {
		m.claimsContext = claimsContext
	}

	// Load CA certificate pool
	if err := m.loadCACertPool(); err != nil {
		return coreerrors.NewConfigError("failed to load CA certificate pool", err)
	}

	return nil
}

func (m *MTLSPlugin) loadCACertPool() error {
	if m.caFile == "" {
		return coreerrors.NewRequiredFieldError("ca_file is required for mTLS plugin")
	}

	caCert, err := os.ReadFile(m.caFile)
	if err != nil {
		return coreerrors.NewConfigError("failed to read CA certificate", err)
	}

	m.caPool = x509.NewCertPool()
	if !m.caPool.AppendCertsFromPEM(caCert) {
		return coreerrors.NewCodeError(coreerrors.CodeCertificatePEMInvalid, "failed to append CA certificate to pool", nil)
	}

	return nil
}

func (m *MTLSPlugin) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !m.enabled {
			next.ServeHTTP(w, r)
			return
		}

		// Skip mTLS validation for certain paths
		if m.shouldSkipValidation(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}

		// Validate client certificate
		certInfo, err := m.validateClientCert(r)
		if err != nil {
			m.writeError(w, "Invalid client certificate", http.StatusUnauthorized)
			return
		}

		// Add certificate info to request context
		ctx := context.WithValue(r.Context(), m.claimsContext, certInfo)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (m *MTLSPlugin) shouldSkipValidation(path string) bool {
	for _, skipPath := range m.skipPaths {
		if strings.HasPrefix(path, skipPath) {
			return true
		}
	}
	return false
}

func (m *MTLSPlugin) validateClientCert(r *http.Request) (*ClientCertInfo, error) {
	// Check if TLS connection exists
	if r.TLS == nil {
		return nil, coreerrors.NewCodeError(coreerrors.CodeUnauthorized, "no TLS connection", nil)
	}

	// Check if client certificate is present
	if len(r.TLS.PeerCertificates) == 0 {
		return nil, coreerrors.NewCodeError(coreerrors.CodeUnauthorized, "no client certificate provided", nil)
	}

	clientCert := r.TLS.PeerCertificates[0]

	// Verify certificate against CA pool
	opts := x509.VerifyOptions{
		Roots:         m.caPool,
		CurrentTime:   time.Now(),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		Intermediates: x509.NewCertPool(),
	}

	// Add intermediate certificates to the pool
	for _, cert := range r.TLS.PeerCertificates[1:] {
		opts.Intermediates.AddCert(cert)
	}

	// Verify the certificate chain
	if _, err := clientCert.Verify(opts); err != nil {
		return nil, coreerrors.NewCodeError(coreerrors.CodeUnauthorized, "certificate verification failed", err)
	}

	// Check allowed Common Names
	if len(m.allowedCNs) > 0 {
		cnAllowed := false
		for _, allowedCN := range m.allowedCNs {
			if clientCert.Subject.CommonName == allowedCN {
				cnAllowed = true
				break
			}
		}
		if !cnAllowed {
			return nil, coreerrors.NewCodeError(coreerrors.CodePermissionDenied, fmt.Sprintf("common name not allowed: %s", clientCert.Subject.CommonName), nil)
		}
	}

	// Check allowed Organizational Units
	if len(m.allowedOUs) > 0 {
		ouAllowed := false
		for _, allowedOU := range m.allowedOUs {
			for _, ou := range clientCert.Subject.OrganizationalUnit {
				if ou == allowedOU {
					ouAllowed = true
					break
				}
			}
			if ouAllowed {
				break
			}
		}
		if !ouAllowed {
			return nil, coreerrors.NewCodeError(coreerrors.CodePermissionDenied, "organizational unit not allowed", nil)
		}
	}

	// Create certificate info
	certInfo := &ClientCertInfo{
		Subject:   clientCert.Subject.String(),
		Issuer:    clientCert.Issuer.String(),
		CN:        clientCert.Subject.CommonName,
		OU:        clientCert.Subject.OrganizationalUnit,
		O:         clientCert.Subject.Organization,
		Serial:    clientCert.SerialNumber.String(),
		NotBefore: clientCert.NotBefore.Format("2006-01-02T15:04:05Z"),
		NotAfter:  clientCert.NotAfter.Format("2006-01-02T15:04:05Z"),
	}

	return certInfo, nil
}

func (m *MTLSPlugin) writeError(w http.ResponseWriter, message string, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	response := map[string]interface{}{
		"error":   "mTLS Error",
		"message": message,
	}
	json.NewEncoder(w).Encode(response)
}

// GetClientCertFromContext extracts client certificate info from request context
func (m *MTLSPlugin) GetClientCertFromContext(ctx context.Context) (*ClientCertInfo, bool) {
	certInfo, ok := ctx.Value(m.claimsContext).(*ClientCertInfo)
	return certInfo, ok
}

// GetTLSConfig returns the TLS configuration for the server
func (m *MTLSPlugin) GetTLSConfig() *tls.Config {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if !m.enabled || m.caPool == nil {
		return nil
	}

	return &tls.Config{
		ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs:  m.caPool,
	}
}

// Tags returns plugin tags for discovery
func (m *MTLSPlugin) Tags() map[string]string {
	return map[string]string{
		"type":        "mtls",
		"category":    "security",
		"middleware":  "true",
		"client_auth": "true",
	}
}

// Health checks if the mTLS plugin is healthy
func (m *MTLSPlugin) Health() error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if !m.enabled {
		return coreerrors.NewCodeError(coreerrors.CodePluginUnsupported, "mTLS plugin is disabled", nil)
	}

	// Check if CA file exists
	if m.caFile != "" {
		if _, err := os.Stat(m.caFile); os.IsNotExist(err) {
			return coreerrors.NewConfigError(fmt.Sprintf("CA file not found: %s", m.caFile), nil)
		}
	}

	// Check if CA pool is loaded
	if m.caPool == nil {
		return coreerrors.NewConfigError("CA certificate pool not loaded", nil)
	}

	return nil
}

// Status returns human-readable status
func (m *MTLSPlugin) Status() string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if !m.enabled {
		return "mTLS Plugin: Disabled"
	}

	status := fmt.Sprintf("mTLS Plugin: Enabled (ca: %s", m.caFile)
	if len(m.allowedCNs) > 0 {
		status += fmt.Sprintf(", allowed CNs: %s", strings.Join(m.allowedCNs, ","))
	}
	if len(m.allowedOUs) > 0 {
		status += fmt.Sprintf(", allowed OUs: %s", strings.Join(m.allowedOUs, ","))
	}
	status += ")"

	return status
}

// OnStart lifecycle hook
func (m *MTLSPlugin) OnStart() error {
	// Validate mTLS config on startup
	return m.Health()
}

// OnShutdown lifecycle hook
func (m *MTLSPlugin) OnShutdown() error {
	// Clean up any mTLS-related resources if needed
	return nil
}
