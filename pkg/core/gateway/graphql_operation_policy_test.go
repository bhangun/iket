package gateway

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bhangun/iket/pkg/config"
	"github.com/bhangun/iket/pkg/logging"
)

func TestGraphQLRouteOperationPolicyOverridesRouteVariablePolicy(t *testing.T) {
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
					GraphQLOperationPolicies: map[string]config.GraphQLOperationPolicy{
						"ChatQuery": {
							AllowedVariables: []string{"tenantId", "workspaceId"},
						},
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

	req := httptest.NewRequest(http.MethodPost, "http://gateway.local/graphql", strings.NewReader(`{"query":"query ChatQuery($tenantId: String!, $workspaceId: String!) { ping }","operationName":"ChatQuery","variables":{"tenantId":"tenant_123","workspaceId":"wk_123"}}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	gw.GetRouter().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 response, got %d body=%q", rec.Code, rec.Body.String())
	}
}

func TestGraphQLRouteOperationPolicyCanRequireDifferentVariables(t *testing.T) {
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
					GraphQLOperationPolicies: map[string]config.GraphQLOperationPolicy{
						"SearchQuery": {
							RequiredVariables: []string{"mode"},
						},
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

	req := httptest.NewRequest(http.MethodPost, "http://gateway.local/graphql", strings.NewReader(`{"query":"query SearchQuery($tenantId: String!, $mode: String!) { ping }","operationName":"SearchQuery","variables":{"tenantId":"tenant_123"}}`))
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

func TestGraphQLRouteOperationPolicyCanOverrideVariableRegex(t *testing.T) {
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
					GraphQLOperationPolicies: map[string]config.GraphQLOperationPolicy{
						"SearchQuery": {
							VariableRegex: map[string]string{"tenantId": "^search_[0-9]+$"},
						},
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

	req := httptest.NewRequest(http.MethodPost, "http://gateway.local/graphql", strings.NewReader(`{"query":"query SearchQuery($tenantId: String!) { ping }","operationName":"SearchQuery","variables":{"tenantId":"tenant_123"}}`))
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

func TestGraphQLRouteOperationPolicyCanOverridePersistedQueryAllowlist(t *testing.T) {
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
					Path:                           "/graphql",
					Methods:                        []string{"POST"},
					Protocol:                       "graphql",
					GraphQLRequirePersistedQuery:   true,
					GraphQLAllowedPersistedQueries: []string{"route-hash"},
					GraphQLOperationPolicies: map[string]config.GraphQLOperationPolicy{
						"ChatQuery": {AllowedPersistedQueries: []string{"chat-hash"}},
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

	req := httptest.NewRequest(http.MethodPost, "http://gateway.local/graphql", strings.NewReader(`{"query":"query ChatQuery { ping }","operationName":"ChatQuery","extensions":{"persistedQuery":{"sha256Hash":"route-hash"}}}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	gw.GetRouter().ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 response, got %d", rec.Code)
	}

	req2 := httptest.NewRequest(http.MethodPost, "http://gateway.local/graphql", strings.NewReader(`{"query":"query ChatQuery { ping }","operationName":"ChatQuery","extensions":{"persistedQuery":{"sha256Hash":"chat-hash"}}}`))
	req2.Header.Set("Content-Type", "application/json")
	rec2 := httptest.NewRecorder()
	gw.GetRouter().ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("expected 200 response, got %d body=%q", rec2.Code, rec2.Body.String())
	}
}

func TestGraphQLRouteOperationPolicyCanOverrideDepthLimit(t *testing.T) {
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
					GraphQLOperationPolicies: map[string]config.GraphQLOperationPolicy{
						"ChatQuery": {MaxDepth: 3},
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

	req := httptest.NewRequest(http.MethodPost, "http://gateway.local/graphql", strings.NewReader(`{"query":"query ChatQuery { viewer { profile { id } } }","operationName":"ChatQuery"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	gw.GetRouter().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 response, got %d body=%q", rec.Code, rec.Body.String())
	}
}

func TestGraphQLRouteOperationPolicyCanOverrideFieldLimit(t *testing.T) {
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
					GraphQLMaxFields: 1,
					GraphQLOperationPolicies: map[string]config.GraphQLOperationPolicy{
						"SearchQuery": {MaxFields: 3},
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

	req := httptest.NewRequest(http.MethodPost, "http://gateway.local/graphql", strings.NewReader(`{"query":"query SearchQuery { a b c }","operationName":"SearchQuery"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	gw.GetRouter().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 response, got %d body=%q", rec.Code, rec.Body.String())
	}
}
