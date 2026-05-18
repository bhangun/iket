package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolveServerSANsFromConfig(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")
	content := `
security:
  tls:
    enabled: true
    certFile: "/tmp/server.crt"
    keyFile: "/tmp/server.key"
    clientCAFile: "/tmp/ca.crt"
    serverNames: ["localhost", "gateway.example.com"]
    serverIPs: ["127.0.0.1", "103.16.199.4"]
    autoGenerate: true
`
	if err := os.WriteFile(configPath, []byte(content), 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	names, ips, err := resolveServerSANsFromInput(configPath)
	if err != nil {
		t.Fatalf("resolveServerSANsFromInput: %v", err)
	}
	if len(names) != 2 || names[1] != "gateway.example.com" {
		t.Fatalf("unexpected names: %v", names)
	}
	if len(ips) != 2 || ips[1] != "103.16.199.4" {
		t.Fatalf("unexpected ips: %v", ips)
	}
}
