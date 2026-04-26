package config

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func TestReadBootstrapTLSConfigReadsSecurityTLS(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "config.yaml")
	if err := os.WriteFile(cfgPath, []byte(`
security:
  tls:
    enabled: true
    port: 8443
    certFile: "/tmp/server.crt"
    keyFile: "/tmp/server.key"
    clientCAFile: "/tmp/ca.crt"
    clientAuthType: "RequireAndVerifyClientCert"
    minVersion: "TLS1.2"
    autoGenerate: true
    generateSharedClient: true
`), 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	tlsCfg, err := ReadBootstrapTLSConfig(cfgPath)
	if err != nil {
		t.Fatalf("ReadBootstrapTLSConfig returned error: %v", err)
	}
	if !tlsCfg.Enabled {
		t.Fatalf("expected tls enabled")
	}
	if tlsCfg.CertFile != "/tmp/server.crt" {
		t.Fatalf("unexpected cert file: %s", tlsCfg.CertFile)
	}
	if !tlsCfg.ShouldAutoGenerate() {
		t.Fatalf("expected autoGenerate true")
	}
	if !tlsCfg.ShouldGenerateSharedClient() {
		t.Fatalf("expected generateSharedClient true")
	}
}

func TestNormalizeLegacyConfigMovesServerTLS(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{
			Port: 8080,
			TLS: TLSConfig{
				Enabled:        true,
				Port:           8443,
				CertFile:       "legacy-server.crt",
				KeyFile:        "legacy-server.key",
				ClientCAFile:   "legacy-ca.crt",
				ClientAuthType: "RequireAndVerifyClientCert",
			},
		},
	}

	normalizeLegacyConfig(cfg)

	if !cfg.Security.TLS.Enabled {
		t.Fatalf("expected legacy TLS to be copied into security.tls")
	}
	if cfg.Security.TLS.Port != 8443 {
		t.Fatalf("expected TLS port 8443, got %d", cfg.Security.TLS.Port)
	}
	if cfg.Security.TLS.CertFile != "legacy-server.crt" {
		t.Fatalf("unexpected cert file: %s", cfg.Security.TLS.CertFile)
	}
}

func TestEnsureTLSAssetsGeneratesServerBundleOnlyByDefault(t *testing.T) {
	tmpDir := t.TempDir()
	auto := true

	tlsCfg := TLSConfig{
		Enabled:      true,
		Port:         8443,
		CertFile:     filepath.Join(tmpDir, "server.crt"),
		KeyFile:      filepath.Join(tmpDir, "server.key"),
		ClientCAFile: filepath.Join(tmpDir, "ca.crt"),
		AutoGenerate: &auto,
	}

	if err := EnsureTLSAssets(tlsCfg); err != nil {
		t.Fatalf("EnsureTLSAssets returned error: %v", err)
	}

	for _, path := range []string{
		filepath.Join(tmpDir, "server.crt"),
		filepath.Join(tmpDir, "server.key"),
		filepath.Join(tmpDir, "ca.crt"),
		filepath.Join(tmpDir, "ca.key"),
	} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("expected generated file %s: %v", path, err)
		}
	}
	for _, path := range []string{
		filepath.Join(tmpDir, "client.crt"),
		filepath.Join(tmpDir, "client.key"),
	} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("expected shared client file to be absent by default: %s", path)
		}
	}
}

func TestEnsureTLSAssetsCanGenerateSharedClientWhenEnabled(t *testing.T) {
	tmpDir := t.TempDir()
	auto := true
	generateSharedClient := true

	tlsCfg := TLSConfig{
		Enabled:              true,
		Port:                 8443,
		CertFile:             filepath.Join(tmpDir, "server.crt"),
		KeyFile:              filepath.Join(tmpDir, "server.key"),
		ClientCAFile:         filepath.Join(tmpDir, "ca.crt"),
		AutoGenerate:         &auto,
		GenerateSharedClient: &generateSharedClient,
	}

	if err := EnsureTLSAssets(tlsCfg); err != nil {
		t.Fatalf("EnsureTLSAssets returned error: %v", err)
	}

	for _, path := range []string{
		filepath.Join(tmpDir, "client.crt"),
		filepath.Join(tmpDir, "client.key"),
	} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("expected generated shared client file %s: %v", path, err)
		}
	}
}

func TestEnsureTLSAssetsCanAddSharedClientAfterInitialBootstrap(t *testing.T) {
	tmpDir := t.TempDir()
	auto := true

	initial := TLSConfig{
		Enabled:      true,
		Port:         8443,
		CertFile:     filepath.Join(tmpDir, "server.crt"),
		KeyFile:      filepath.Join(tmpDir, "server.key"),
		ClientCAFile: filepath.Join(tmpDir, "ca.crt"),
		AutoGenerate: &auto,
	}

	if err := EnsureTLSAssets(initial); err != nil {
		t.Fatalf("initial EnsureTLSAssets returned error: %v", err)
	}

	for _, path := range []string{
		filepath.Join(tmpDir, "client.crt"),
		filepath.Join(tmpDir, "client.key"),
	} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("expected shared client file to be absent before enablement: %s", path)
		}
	}

	generateSharedClient := true
	updated := initial
	updated.GenerateSharedClient = &generateSharedClient

	if err := EnsureTLSAssets(updated); err != nil {
		t.Fatalf("updated EnsureTLSAssets returned error: %v", err)
	}

	for _, path := range []string{
		filepath.Join(tmpDir, "client.crt"),
		filepath.Join(tmpDir, "client.key"),
	} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("expected generated shared client file %s after enablement: %v", path, err)
		}
	}
}

func TestEnsureTLSAssetsGeneratesConfiguredServerSANs(t *testing.T) {
	tmpDir := t.TempDir()
	auto := true

	tlsCfg := TLSConfig{
		Enabled:      true,
		Port:         8443,
		CertFile:     filepath.Join(tmpDir, "server.crt"),
		KeyFile:      filepath.Join(tmpDir, "server.key"),
		ClientCAFile: filepath.Join(tmpDir, "ca.crt"),
		ServerNames:  []string{"localhost", "iket", "gateway.example.com"},
		ServerIPs:    []string{"127.0.0.1", "103.16.199.4"},
		AutoGenerate: &auto,
	}

	if err := EnsureTLSAssets(tlsCfg); err != nil {
		t.Fatalf("EnsureTLSAssets returned error: %v", err)
	}

	certPEM, err := os.ReadFile(tlsCfg.CertFile)
	if err != nil {
		t.Fatalf("read server cert: %v", err)
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatalf("decode server cert pem")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse server cert: %v", err)
	}

	if err := cert.VerifyHostname("gateway.example.com"); err != nil {
		t.Fatalf("expected hostname SAN to verify: %v", err)
	}
	if err := cert.VerifyHostname("103.16.199.4"); err != nil {
		t.Fatalf("expected IP SAN to verify: %v", err)
	}
}

func TestEnsureTLSAssetsRegeneratesServerCertWhenSANsChange(t *testing.T) {
	tmpDir := t.TempDir()
	auto := true

	initial := TLSConfig{
		Enabled:      true,
		Port:         8443,
		CertFile:     filepath.Join(tmpDir, "server.crt"),
		KeyFile:      filepath.Join(tmpDir, "server.key"),
		ClientCAFile: filepath.Join(tmpDir, "ca.crt"),
		ServerNames:  []string{"localhost"},
		ServerIPs:    []string{"127.0.0.1"},
		AutoGenerate: &auto,
	}

	if err := EnsureTLSAssets(initial); err != nil {
		t.Fatalf("initial EnsureTLSAssets returned error: %v", err)
	}

	updated := initial
	updated.ServerNames = []string{"localhost", "gateway.example.com"}
	updated.ServerIPs = []string{"127.0.0.1", "103.16.199.4"}

	if err := EnsureTLSAssets(updated); err != nil {
		t.Fatalf("updated EnsureTLSAssets returned error: %v", err)
	}

	certPEM, err := os.ReadFile(updated.CertFile)
	if err != nil {
		t.Fatalf("read server cert: %v", err)
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatalf("decode server cert pem")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse server cert: %v", err)
	}

	if err := cert.VerifyHostname("gateway.example.com"); err != nil {
		t.Fatalf("expected regenerated hostname SAN to verify: %v", err)
	}
	if err := cert.VerifyHostname("103.16.199.4"); err != nil {
		t.Fatalf("expected regenerated IP SAN to verify: %v", err)
	}
}
