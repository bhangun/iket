package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInferEnrollURL(t *testing.T) {
	got := inferEnrollURL("https://gateway.example.com:8443")
	want := "https://gateway.example.com:9443/api/v1/enroll"
	if got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
}

func TestLoadEnrollmentBundleFromWrapperFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "token.json")
	data := `{"data":{"token":"abc.def","server_url":"https://example.com:8443","enroll_url":"http://example.com:8080/api/v1/enroll","ca_pem":"PEM"}}`
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatalf("write token file: %v", err)
	}

	bundle, err := loadEnrollmentBundle("", path)
	if err != nil {
		t.Fatalf("loadEnrollmentBundle returned error: %v", err)
	}
	if bundle.Token != "abc.def" {
		t.Fatalf("expected token abc.def, got %q", bundle.Token)
	}
	if bundle.ServerURL != "https://example.com:8443" {
		t.Fatalf("unexpected server URL: %q", bundle.ServerURL)
	}
}

func TestGenerateClientCSR(t *testing.T) {
	keyPEM, csrPEM, err := generateClientCSR("laptop-admin")
	if err != nil {
		t.Fatalf("generateClientCSR returned error: %v", err)
	}
	if !strings.Contains(keyPEM, "RSA PRIVATE KEY") {
		t.Fatalf("expected RSA private key PEM")
	}
	if !strings.Contains(csrPEM, "CERTIFICATE REQUEST") {
		t.Fatalf("expected CSR PEM")
	}
}

func TestFirstNonEmptyString(t *testing.T) {
	got := firstNonEmptyString("", " ", "hello", "world")
	if got != "hello" {
		t.Fatalf("expected hello, got %q", got)
	}
}
