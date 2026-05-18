package gateway

import (
	"net/url"
	"testing"
)

func TestBuildBackendWebSocketURLUsesProxiedPath(t *testing.T) {
	destURL, err := url.Parse("http://notification:7110/api/notifications/ws/testclient")
	if err != nil {
		t.Fatalf("failed to parse dest url: %v", err)
	}
	reqURL, err := url.Parse("https://gateway.local/jahsy/notifications/ws/testclient?token=abc")
	if err != nil {
		t.Fatalf("failed to parse request url: %v", err)
	}

	got := buildBackendWebSocketURL(destURL, reqURL)

	if got.Scheme != "ws" {
		t.Fatalf("expected ws scheme, got %q", got.Scheme)
	}
	if got.Host != "notification:7110" {
		t.Fatalf("expected host notification:7110, got %q", got.Host)
	}
	if got.Path != "/api/notifications/ws/testclient" {
		t.Fatalf("expected proxied path /api/notifications/ws/testclient, got %q", got.Path)
	}
	if got.RawQuery != "token=abc" {
		t.Fatalf("expected token query to be preserved, got %q", got.RawQuery)
	}
}
