package gateway

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bhangun/iket/pkg/config"
	"github.com/bhangun/iket/pkg/logging"
)

func TestCORSPreflightReturnsConfiguredHeaders(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Services: []config.ServiceConfig{{
			Version: 1,
			Services: []config.Service{{
				Name: "identity",
				Host: "http://identity.internal",
				Routes: []config.RouterConfig{{
					Path:    "/auth/profile",
					Methods: []string{"GET"},
					CORS: &config.CORSConfig{
						AllowedOrigins: []string{"https://app.example.com"},
						AllowedMethods: []string{"GET", "POST"},
						AllowedHeaders: []string{"Authorization", "Content-Type"},
						ExposedHeaders: []string{"X-Trace-Id"},
						MaxAge:         600,
					},
					Backends: []config.Backend{
						{URLPattern: "/profile"},
					},
				}},
			}},
		}},
	}
	gw, err := NewGateway(Dependencies{Config: cfg, Logger: logging.NewLogger(false)}, "test")
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}
	if err := gw.Initialize(); err != nil {
		t.Fatalf("failed to initialize gateway: %v", err)
	}

	req := httptest.NewRequest(http.MethodOptions, "http://gateway.local/auth/profile", nil)
	req.Header.Set("Origin", "https://app.example.com")
	req.Header.Set("Access-Control-Request-Method", "GET")
	req.Header.Set("Access-Control-Request-Headers", "Authorization, Content-Type")
	rec := httptest.NewRecorder()

	gw.GetRouter().ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected 204 preflight response, got %d", rec.Code)
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "https://app.example.com" {
		t.Fatalf("expected allow origin header, got %q", got)
	}
	if got := rec.Header().Get("Access-Control-Allow-Methods"); !strings.Contains(got, "GET") || !strings.Contains(got, "POST") {
		t.Fatalf("expected allow methods to include GET and POST, got %q", got)
	}
	if got := rec.Header().Get("Access-Control-Allow-Headers"); !strings.Contains(got, "Authorization") || !strings.Contains(got, "Content-Type") {
		t.Fatalf("expected allow headers to include Authorization and Content-Type, got %q", got)
	}
	if got := rec.Header().Get("Access-Control-Max-Age"); got != "600" {
		t.Fatalf("expected max age 600, got %q", got)
	}
}

func TestCORSActualRequestAddsExposeHeaders(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Trace-Id", "abc123")
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Services: []config.ServiceConfig{{
			Version: 1,
			Services: []config.Service{{
				Name: "identity",
				Host: upstream.URL,
				Routes: []config.RouterConfig{{
					Path:    "/auth/profile",
					Methods: []string{"GET"},
					CORS: &config.CORSConfig{
						AllowedOrigins:   []string{"https://app.example.com"},
						AllowedHeaders:   []string{"Authorization"},
						ExposedHeaders:   []string{"X-Trace-Id"},
						AllowCredentials: true,
					},
					Backends: []config.Backend{
						{URLPattern: "/"},
					},
				}},
			}},
		}},
	}
	gw, err := NewGateway(Dependencies{Config: cfg, Logger: logging.NewLogger(false)}, "test")
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}
	if err := gw.Initialize(); err != nil {
		t.Fatalf("failed to initialize gateway: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://gateway.local/auth/profile", nil)
	req.Header.Set("Origin", "https://app.example.com")
	rec := httptest.NewRecorder()

	gw.GetRouter().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 actual CORS response, got %d", rec.Code)
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "https://app.example.com" {
		t.Fatalf("expected allow origin header, got %q", got)
	}
	if got := rec.Header().Get("Access-Control-Allow-Credentials"); got != "true" {
		t.Fatalf("expected allow credentials header, got %q", got)
	}
	if got := rec.Header().Get("Access-Control-Expose-Headers"); !strings.Contains(got, "X-Trace-Id") {
		t.Fatalf("expected expose headers to include X-Trace-Id, got %q", got)
	}
	if body := rec.Body.String(); body != "ok" {
		t.Fatalf("expected upstream body ok, got %q", body)
	}
}
