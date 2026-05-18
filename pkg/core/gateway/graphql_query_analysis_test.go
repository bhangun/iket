package gateway

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bhangun/iket/pkg/config"
	"github.com/bhangun/iket/pkg/logging"
)

func TestGraphQLRouteCanEnforceDepthLimit(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
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
					Path:            "/graphql",
					Methods:         []string{"POST"},
					Protocol:        "graphql",
					GraphQLMaxDepth: 1,
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

	req := httptest.NewRequest(http.MethodPost, "http://gateway.local/graphql", strings.NewReader(`{"query":"query ChatQuery { viewer { profile { id } } }","operationName":"ChatQuery"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	gw.GetRouter().ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 response, got %d", rec.Code)
	}
	if got := rec.Header().Get("X-Iket-Policy-Hit"); got != "graphql_depth_limit" {
		t.Fatalf("expected graphql_depth_limit hit, got %q", got)
	}
}

func TestGraphQLRouteCanEnforceFieldLimit(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
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
					Path:             "/graphql",
					Methods:          []string{"POST"},
					Protocol:         "graphql",
					GraphQLMaxFields: 2,
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

	req := httptest.NewRequest(http.MethodPost, "http://gateway.local/graphql", strings.NewReader(`{"query":"query ChatQuery { viewer { id name } ping }","operationName":"ChatQuery"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	gw.GetRouter().ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 response, got %d", rec.Code)
	}
	if got := rec.Header().Get("X-Iket-Policy-Hit"); got != "graphql_field_limit" {
		t.Fatalf("expected graphql_field_limit hit, got %q", got)
	}
}
