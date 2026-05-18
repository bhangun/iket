package main

import "testing"

func TestHostnameFromURL(t *testing.T) {
	host, err := hostnameFromURL("https://103.16.199.4:8443")
	if err != nil {
		t.Fatalf("hostnameFromURL returned error: %v", err)
	}
	if host != "103.16.199.4" {
		t.Fatalf("expected hostname 103.16.199.4, got %q", host)
	}
}

func TestHostnameFromURLRejectsMissingHost(t *testing.T) {
	if _, err := hostnameFromURL("https://:8443"); err == nil {
		t.Fatalf("expected error for missing hostname")
	}
}
