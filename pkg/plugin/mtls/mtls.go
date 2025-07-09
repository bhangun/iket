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
)

type mTLSPlugin struct {
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

func (m *mTLSPlugin) Name() string {
	return "mtls"
}

func (m *mTLSPlugin) Type() string {
	return "mtls"
}

func (m *mTLSPlugin) Initialize(config map[string]interface{}) error {
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
		return fmt.Errorf("failed to load CA certificate pool: %w", err)
	}

	return nil
}

func (m *mTLSPlugin) loadCACertPool() error {
	if m.caFile == "" {
		return fmt.Errorf("ca_file is required for mTLS plugin")
	}

	caCert, err := os.ReadFile(m.caFile)
	if err != nil {
		return fmt.Errorf("failed to read CA certificate: %w", err)
	}

	m.caPool = x509.NewCertPool()
	if !m.caPool.AppendCertsFromPEM(caCert) {
		return fmt.Errorf("failed to append CA certificate to pool")
	}

	return nil
}

func (m *mTLSPlugin) Middleware(next http.Handler) http.Handler {
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

func (m *mTLSPlugin) shouldSkipValidation(path string) bool {
	for _, skipPath := range m.skipPaths {
		if strings.HasPrefix(path, skipPath) {
			return true
		}
	}
	return false
}

func (m *mTLSPlugin) validateClientCert(r *http.Request) (*ClientCertInfo, error) {
	// Check if TLS connection exists
	if r.TLS == nil {
		return nil, fmt.Errorf("no TLS connection")
	}

	// Check if client certificate is present
	if len(r.TLS.PeerCertificates) == 0 {
		return nil, fmt.Errorf("no client certificate provided")
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
		return nil, fmt.Errorf("certificate verification failed: %w", err)
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
			return nil, fmt.Errorf("common name not allowed: %s", clientCert.Subject.CommonName)
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
			return nil, fmt.Errorf("organizational unit not allowed")
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

func (m *mTLSPlugin) writeError(w http.ResponseWriter, message string, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	response := map[string]interface{}{
		"error":   "mTLS Error",
		"message": message,
	}
	json.NewEncoder(w).Encode(response)
}

// GetClientCertFromContext extracts client certificate info from request context
func (m *mTLSPlugin) GetClientCertFromContext(ctx context.Context) (*ClientCertInfo, bool) {
	certInfo, ok := ctx.Value(m.claimsContext).(*ClientCertInfo)
	return certInfo, ok
}

// GetTLSConfig returns the TLS configuration for the server
func (m *mTLSPlugin) GetTLSConfig() *tls.Config {
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
func (m *mTLSPlugin) Tags() map[string]string {
	return map[string]string{
		"type":        "mtls",
		"category":    "security",
		"middleware":  "true",
		"client_auth": "true",
	}
}

// Health checks if the mTLS plugin is healthy
func (m *mTLSPlugin) Health() error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if !m.enabled {
		return fmt.Errorf("mTLS plugin is disabled")
	}

	// Check if CA file exists
	if m.caFile != "" {
		if _, err := os.Stat(m.caFile); os.IsNotExist(err) {
			return fmt.Errorf("CA file not found: %s", m.caFile)
		}
	}

	// Check if CA pool is loaded
	if m.caPool == nil {
		return fmt.Errorf("CA certificate pool not loaded")
	}

	return nil
}

// Status returns human-readable status
func (m *mTLSPlugin) Status() string {
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
func (m *mTLSPlugin) OnStart() error {
	// Validate mTLS config on startup
	return m.Health()
}

// OnShutdown lifecycle hook
func (m *mTLSPlugin) OnShutdown() error {
	// Clean up any mTLS-related resources if needed
	return nil
}
