package gateway

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bhangun/iket/pkg/config"
	"github.com/bhangun/iket/pkg/logging"
)

func TestGraphQLRouteCanRequireVariables(t *testing.T) {
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
					Path:                     "/graphql",
					Methods:                  []string{"POST"},
					Protocol:                 "graphql",
					GraphQLRequiredVariables: []string{"tenantId"},
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

	req := httptest.NewRequest(http.MethodPost, "http://gateway.local/graphql", strings.NewReader(`{"query":"query ChatQuery($tenantId: String!) { ping }","operationName":"ChatQuery","variables":{"workspaceId":"wk_123"}}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	gw.GetRouter().ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 response, got %d", rec.Code)
	}
	if got := rec.Header().Get("X-Iket-Policy-Hit"); got != "graphql_variable_policy" {
		t.Fatalf("expected graphql_variable_policy hit, got %q", got)
	}
}

func TestGraphQLRouteCanAllowlistVariables(t *testing.T) {
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
					Path:                    "/graphql",
					Methods:                 []string{"POST"},
					Protocol:                "graphql",
					GraphQLAllowedVariables: []string{"tenantId"},
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

	req := httptest.NewRequest(http.MethodPost, "http://gateway.local/graphql", strings.NewReader(`{"query":"query ChatQuery($tenantId: String!, $workspaceId: String!) { ping }","operationName":"ChatQuery","variables":{"tenantId":"tenant_123","workspaceId":"wk_123"}}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	gw.GetRouter().ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 response, got %d", rec.Code)
	}
	if got := rec.Header().Get("X-Iket-Policy-Hit"); got != "graphql_variable_policy" {
		t.Fatalf("expected graphql_variable_policy hit, got %q", got)
	}
}

func TestGraphQLRouteAllowsApprovedVariables(t *testing.T) {
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
					Path:                     "/graphql",
					Methods:                  []string{"POST"},
					Protocol:                 "graphql",
					GraphQLAllowedVariables:  []string{"tenantId", "workspaceId"},
					GraphQLRequiredVariables: []string{"tenantId"},
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

	req := httptest.NewRequest(http.MethodPost, "http://gateway.local/graphql", strings.NewReader(`{"query":"query ChatQuery($tenantId: String!, $workspaceId: String) { ping }","operationName":"ChatQuery","variables":{"tenantId":"tenant_123","workspaceId":"wk_123"}}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	gw.GetRouter().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 response, got %d body=%q", rec.Code, rec.Body.String())
	}
}

func TestGraphQLRouteCanEnforceVariableRegex(t *testing.T) {
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
					Path:                 "/graphql",
					Methods:              []string{"POST"},
					Protocol:             "graphql",
					GraphQLVariableRegex: map[string]string{"tenantId": "^tenant_[0-9]+$"},
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

	req := httptest.NewRequest(http.MethodPost, "http://gateway.local/graphql", strings.NewReader(`{"query":"query ChatQuery($tenantId: String!) { ping }","operationName":"ChatQuery","variables":{"tenantId":"bad-tenant"}}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	gw.GetRouter().ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 response, got %d", rec.Code)
	}
	if got := rec.Header().Get("X-Iket-Policy-Hit"); got != "graphql_variable_policy" {
		t.Fatalf("expected graphql_variable_policy hit, got %q", got)
	}
}

func TestGraphQLRouteCanEnforceVariableAllowedValues(t *testing.T) {
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
					Path:                         "/graphql",
					Methods:                      []string{"POST"},
					Protocol:                     "graphql",
					GraphQLVariableAllowedValues: map[string][]string{"mode": {"safe", "preview"}},
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

	req := httptest.NewRequest(http.MethodPost, "http://gateway.local/graphql", strings.NewReader(`{"query":"query ChatQuery($mode: String!) { ping }","operationName":"ChatQuery","variables":{"mode":"unsafe"}}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	gw.GetRouter().ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 response, got %d", rec.Code)
	}
	if got := rec.Header().Get("X-Iket-Policy-Hit"); got != "graphql_variable_policy" {
		t.Fatalf("expected graphql_variable_policy hit, got %q", got)
	}
}

func TestGraphQLRouteAllowsApprovedVariableValues(t *testing.T) {
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
					Path:                         "/graphql",
					Methods:                      []string{"POST"},
					Protocol:                     "graphql",
					GraphQLVariableRegex:         map[string]string{"tenantId": "^tenant_[0-9]+$"},
					GraphQLVariableAllowedValues: map[string][]string{"mode": {"safe", "preview"}},
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

	req := httptest.NewRequest(http.MethodPost, "http://gateway.local/graphql", strings.NewReader(`{"query":"query ChatQuery($tenantId: String!, $mode: String!) { ping }","operationName":"ChatQuery","variables":{"tenantId":"tenant_123","mode":"safe"}}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	gw.GetRouter().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 response, got %d body=%q", rec.Code, rec.Body.String())
	}
}
