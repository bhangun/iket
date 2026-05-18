package gateway

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bhangun/iket/pkg/config"
	"github.com/bhangun/iket/pkg/logging"
)

func TestGRPCRouteRejectsNonGRPCContentType(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Services: []config.ServiceConfig{{
			Version: 1,
			Services: []config.Service{{
				Name: "agent",
				Host: upstream.URL,
				Routes: []config.RouterConfig{{
					Path:     "/grpc.Service/Call",
					Methods:  []string{"POST"},
					Protocol: "grpc",
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

	req := httptest.NewRequest(http.MethodPost, "http://gateway.local/grpc.Service/Call", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	gw.GetRouter().ServeHTTP(rec, req)

	if rec.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("expected 415 response, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "application/grpc") {
		t.Fatalf("expected gRPC content-type validation message, got %q", rec.Body.String())
	}
}

func TestSSEProtocolRejectsNonEventStreamAccept(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("data: ok\n\n"))
	}))
	defer upstream.Close()

	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Services: []config.ServiceConfig{{
			Version: 1,
			Services: []config.Service{{
				Name: "agent",
				Host: upstream.URL,
				Routes: []config.RouterConfig{{
					Path:     "/stream",
					Methods:  []string{"GET"},
					Protocol: "sse",
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

	req := httptest.NewRequest(http.MethodGet, "http://gateway.local/stream", nil)
	req.Header.Set("Accept", "application/json")
	rec := httptest.NewRecorder()
	gw.GetRouter().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 response, got %d", rec.Code)
	}
	if got := rec.Header().Get("X-Iket-Policy-Hit"); got != "protocol" {
		t.Fatalf("expected protocol policy hit header, got %q", got)
	}
}

func TestSSEProtocolStreamsEventResponses(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-store")
		flusher, _ := w.(http.Flusher)
		_, _ = io.WriteString(w, "data: hello\n\n")
		if flusher != nil {
			flusher.Flush()
		}
	}))
	defer upstream.Close()

	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Services: []config.ServiceConfig{{
			Version: 1,
			Services: []config.Service{{
				Name: "agent",
				Host: upstream.URL,
				Routes: []config.RouterConfig{{
					Path:     "/stream",
					Methods:  []string{"GET"},
					Protocol: "sse",
					ResponseHeaders: map[string]string{
						"X-Stream-Policy": "edge",
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

	req := httptest.NewRequest(http.MethodGet, "http://gateway.local/stream", nil)
	req.Header.Set("Accept", "text/event-stream")
	rec := httptest.NewRecorder()
	gw.GetRouter().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 response, got %d", rec.Code)
	}
	if got := rec.Header().Get("Content-Type"); !strings.Contains(got, "text/event-stream") {
		t.Fatalf("expected text/event-stream response, got %q", got)
	}
	if got := rec.Header().Get("X-Stream-Policy"); got != "edge" {
		t.Fatalf("expected response header transform on sse route, got %q", got)
	}
	if body := rec.Body.String(); !strings.Contains(body, "data: hello\n\n") {
		t.Fatalf("expected streamed event body to pass through, got %q", body)
	}
}

func TestGRPCWebProtocolRejectsNonGRPCWebContentType(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Services: []config.ServiceConfig{{
			Version: 1,
			Services: []config.Service{{
				Name: "agent",
				Host: upstream.URL,
				Routes: []config.RouterConfig{{
					Path:     "/rpc.AgentService/Chat",
					Methods:  []string{"POST"},
					Protocol: "grpc-web",
					Backends: []config.Backend{
						{URLPattern: "/rpc.AgentService/Chat"},
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

	req := httptest.NewRequest(http.MethodPost, "http://gateway.local/rpc.AgentService/Chat", strings.NewReader("hello"))
	req.Header.Set("Content-Type", "application/grpc")
	rec := httptest.NewRecorder()
	gw.GetRouter().ServeHTTP(rec, req)

	if rec.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("expected 415 response, got %d", rec.Code)
	}
	if got := rec.Header().Get("X-Iket-Policy-Hit"); got != "protocol" {
		t.Fatalf("expected protocol policy hit header, got %q", got)
	}
}

func TestGRPCWebProtocolAllowsBrowserStyleGRPCRequests(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Content-Type"); !strings.Contains(strings.ToLower(got), "application/grpc-web") {
			t.Fatalf("expected grpc-web content-type upstream, got %q", got)
		}
		if got := r.Header.Get("X-Grpc-Web"); got != "1" {
			t.Fatalf("expected X-Grpc-Web=1 upstream, got %q", got)
		}
		w.Header().Set("Content-Type", "application/grpc-web+proto")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte{0x00, 0x00, 0x00, 0x00, 0x00})
	}))
	defer upstream.Close()

	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Services: []config.ServiceConfig{{
			Version: 1,
			Services: []config.Service{{
				Name: "agent",
				Host: upstream.URL,
				Routes: []config.RouterConfig{{
					Path:     "/rpc.AgentService/Chat",
					Methods:  []string{"POST"},
					Protocol: "grpc-web",
					Backends: []config.Backend{
						{URLPattern: "/rpc.AgentService/Chat"},
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

	req := httptest.NewRequest(http.MethodPost, "http://gateway.local/rpc.AgentService/Chat", strings.NewReader("hello"))
	req.Header.Set("Content-Type", "application/grpc-web+proto")
	req.Header.Set("X-Grpc-Web", "1")
	rec := httptest.NewRecorder()
	gw.GetRouter().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 response, got %d", rec.Code)
	}
	if got := rec.Header().Get("Content-Type"); !strings.Contains(strings.ToLower(got), "application/grpc-web") {
		t.Fatalf("expected grpc-web response content-type, got %q", got)
	}
}
