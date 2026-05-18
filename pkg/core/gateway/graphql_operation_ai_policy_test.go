package gateway

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/bhangun/iket/pkg/config"
	"github.com/bhangun/iket/pkg/logging"
)

func TestGraphQLRouteOperationPolicyCanOverrideAllowedModels(t *testing.T) {
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
					Path:          "/graphql",
					Methods:       []string{"POST"},
					Protocol:      "graphql",
					AllowedModels: []string{"gpt-4.1-mini"},
					GraphQLOperationPolicies: map[string]config.GraphQLOperationPolicy{
						"ChatQuery": {AllowedModels: []string{"gpt-4.1"}},
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

	req := httptest.NewRequest(http.MethodPost, "http://gateway.local/graphql", strings.NewReader(`{"query":"query ChatQuery { ping }","operationName":"ChatQuery","model":"gpt-4.1"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	gw.GetRouter().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 response, got %d body=%q", rec.Code, rec.Body.String())
	}
}

func TestGraphQLRouteOperationPolicyCanOverrideAllowedTools(t *testing.T) {
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
					AllowedToolNames: []string{"file_lookup"},
					GraphQLOperationPolicies: map[string]config.GraphQLOperationPolicy{
						"ChatQuery": {AllowedToolNames: []string{"web_search"}},
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

	req := httptest.NewRequest(http.MethodPost, "http://gateway.local/graphql", strings.NewReader(`{"query":"query ChatQuery { ping }","operationName":"ChatQuery","tools":[{"name":"web_search"}]}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	gw.GetRouter().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 response, got %d body=%q", rec.Code, rec.Body.String())
	}
}

func TestGraphQLRouteOperationPolicyCanOverrideTokenBudgets(t *testing.T) {
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
					Path:              "/graphql",
					Methods:           []string{"POST"},
					Protocol:          "graphql",
					MaxInputTokens:    1024,
					InputTokensField:  "max_prompt_tokens",
					MaxOutputTokens:   128,
					OutputTokensField: "max_tokens",
					GraphQLOperationPolicies: map[string]config.GraphQLOperationPolicy{
						"ChatQuery": {
							MaxInputTokens:    4096,
							InputTokensField:  "max_prompt_tokens",
							MaxOutputTokens:   512,
							OutputTokensField: "max_tokens",
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

	req := httptest.NewRequest(http.MethodPost, "http://gateway.local/graphql", strings.NewReader(`{"query":"query ChatQuery { ping }","operationName":"ChatQuery","max_prompt_tokens":2048,"max_tokens":256}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	gw.GetRouter().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 response, got %d body=%q", rec.Code, rec.Body.String())
	}
}

func TestGraphQLRouteOperationPolicyCanOverrideConversationBudgets(t *testing.T) {
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
					Path:           "/graphql",
					Methods:        []string{"POST"},
					Protocol:       "graphql",
					MaxMessages:    2,
					MessagesField:  "messages",
					MaxToolCalls:   1,
					ToolCallsField: "tools",
					GraphQLOperationPolicies: map[string]config.GraphQLOperationPolicy{
						"ChatQuery": {
							MaxMessages:    4,
							MessagesField:  "messages",
							MaxToolCalls:   2,
							ToolCallsField: "tools",
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

	req := httptest.NewRequest(http.MethodPost, "http://gateway.local/graphql", strings.NewReader(`{"query":"query ChatQuery { ping }","operationName":"ChatQuery","messages":[{"role":"system"},{"role":"user"},{"role":"assistant"}],"tools":[{"name":"web_search"},{"name":"file_lookup"}]}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	gw.GetRouter().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 response, got %d body=%q", rec.Code, rec.Body.String())
	}
}

func TestGraphQLRouteOperationPolicyCanOverrideRequestBodyBlockRegex(t *testing.T) {
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
					Path:                  "/graphql",
					Methods:               []string{"POST"},
					Protocol:              "graphql",
					RequestBodyBlockRegex: []string{"ROUTE_BLOCKED"},
					GraphQLOperationPolicies: map[string]config.GraphQLOperationPolicy{
						"ChatQuery": {RequestBodyBlockRegex: []string{"OP_BLOCKED"}},
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

	req := httptest.NewRequest(http.MethodPost, "http://gateway.local/graphql", strings.NewReader(`{"query":"query ChatQuery { ping }","operationName":"ChatQuery","prompt":"ROUTE_BLOCKED only"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	gw.GetRouter().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 response, got %d body=%q", rec.Code, rec.Body.String())
	}
}

func TestGraphQLRouteOperationPolicyCanOverrideRequestPIIPolicy(t *testing.T) {
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
					RequestPIIBlockTypes: []string{"email"},
					GraphQLOperationPolicies: map[string]config.GraphQLOperationPolicy{
						"ChatQuery": {RequestPIIBlockTypes: []string{"api_key"}},
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

	req := httptest.NewRequest(http.MethodPost, "http://gateway.local/graphql", strings.NewReader(`{"query":"query ChatQuery { ping }","operationName":"ChatQuery","prompt":"contact me at dev@example.com"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	gw.GetRouter().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 response, got %d body=%q", rec.Code, rec.Body.String())
	}
}

func TestGraphQLRouteOperationPolicyCanOverrideRequiredRequestHeaders(t *testing.T) {
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
					Path:                   "/graphql",
					Methods:                []string{"POST"},
					Protocol:               "graphql",
					RequiredRequestHeaders: []string{"Authorization"},
					GraphQLOperationPolicies: map[string]config.GraphQLOperationPolicy{
						"ChatQuery": {RequiredRequestHeaders: []string{"X-Agent-Session"}},
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

	req := httptest.NewRequest(http.MethodPost, "http://gateway.local/graphql", strings.NewReader(`{"query":"query ChatQuery { ping }","operationName":"ChatQuery"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Agent-Session", "sess-123")
	rec := httptest.NewRecorder()
	gw.GetRouter().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 response, got %d body=%q", rec.Code, rec.Body.String())
	}
}

func TestGraphQLRouteOperationPolicyCanOverrideRequiredRequestHeaderRegex(t *testing.T) {
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
					Path:     "/graphql",
					Methods:  []string{"POST"},
					Protocol: "graphql",
					RequiredRequestHeaderRegex: map[string]string{
						"Authorization": "^Bearer .+$",
					},
					GraphQLOperationPolicies: map[string]config.GraphQLOperationPolicy{
						"ChatQuery": {RequiredRequestHeaderRegex: map[string]string{"X-Agent-Session": "^sess-[a-z0-9]+$"}},
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

	req := httptest.NewRequest(http.MethodPost, "http://gateway.local/graphql", strings.NewReader(`{"query":"query ChatQuery { ping }","operationName":"ChatQuery"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Agent-Session", "sess-abc123")
	rec := httptest.NewRecorder()
	gw.GetRouter().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 response, got %d body=%q", rec.Code, rec.Body.String())
	}
}

func TestGraphQLRouteOperationPolicyCanOverrideAllowedUpstreamHosts(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer upstream.Close()

	upstreamURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("failed to parse upstream URL: %v", err)
	}

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
					AllowedUpstreamHosts: []string{"api.openai.com"},
					GraphQLOperationPolicies: map[string]config.GraphQLOperationPolicy{
						"ChatQuery": {AllowedUpstreamHosts: []string{upstreamURL.Hostname()}},
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

	req := httptest.NewRequest(http.MethodPost, "http://gateway.local/graphql", strings.NewReader(`{"query":"query ChatQuery { ping }","operationName":"ChatQuery"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	gw.GetRouter().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 response, got %d body=%q", rec.Code, rec.Body.String())
	}
}

func TestGraphQLRouteOperationPolicyPresetCanApplyAndOverrideAllowedUpstreamHosts(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer upstream.Close()

	upstreamURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("failed to parse upstream URL: %v", err)
	}

	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Services: []config.ServiceConfig{{
			Version: 1,
			Services: []config.Service{{
				Name: "agent",
				Host: upstream.URL,
				Routes: []config.RouterConfig{{
					Path:     "/graphql",
					Methods:  []string{"POST"},
					Protocol: "graphql",
					GraphQLOperationPresets: map[string]config.GraphQLOperationPolicy{
						"safe-chat": {
							RequiredRequestHeaders: []string{"X-Agent-Session"},
							AllowedUpstreamHosts:   []string{"api.openai.com"},
						},
					},
					GraphQLOperationPolicies: map[string]config.GraphQLOperationPolicy{
						"ChatQuery": {
							Preset:               "safe-chat",
							AllowedUpstreamHosts: []string{upstreamURL.Hostname()},
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

	req := httptest.NewRequest(http.MethodPost, "http://gateway.local/graphql", strings.NewReader(`{"query":"query ChatQuery { ping }","operationName":"ChatQuery"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Agent-Session", "sess-abc123")
	rec := httptest.NewRecorder()
	gw.GetRouter().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 response, got %d body=%q", rec.Code, rec.Body.String())
	}
}
