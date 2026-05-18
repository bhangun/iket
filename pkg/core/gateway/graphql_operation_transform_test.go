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

func TestGraphQLRouteOperationPolicyCanBlockResponseContent(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"message":"unsafe output"}`))
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
					GraphQLOperationPolicies: map[string]config.GraphQLOperationPolicy{
						"ChatQuery": {ResponseBodyBlockRegex: []string{"unsafe"}},
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

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("expected 502 response, got %d body=%q", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("X-Iket-Policy-Hit"); got != "response_content_policy" {
		t.Fatalf("expected response_content_policy hit, got %q", got)
	}
}

func TestGraphQLRouteOperationPolicyCanRequireResponseMarker(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"message":"plain output"}`))
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
					GraphQLOperationPolicies: map[string]config.GraphQLOperationPolicy{
						"SearchQuery": {ResponseBodyRequireRegex: []string{"SAFE_OUTPUT"}},
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

	req := httptest.NewRequest(http.MethodPost, "http://gateway.local/graphql", strings.NewReader(`{"query":"query SearchQuery { ping }","operationName":"SearchQuery"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	gw.GetRouter().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("expected 502 response, got %d body=%q", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("X-Iket-Policy-Hit"); got != "response_content_policy" {
		t.Fatalf("expected response_content_policy hit, got %q", got)
	}
}

func TestGraphQLRouteOperationPolicyCanOverrideSuccessEnvelope(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"message":"hello"}`))
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
					SuccessResponseFields: map[string]string{
						"route_level": "true",
					},
					GraphQLOperationPolicies: map[string]config.GraphQLOperationPolicy{
						"ChatQuery": {
							SuccessResponseFields: map[string]string{
								"operation": "chat",
								"status":    "ok",
							},
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
	rec := httptest.NewRecorder()
	gw.GetRouter().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 response, got %d body=%q", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"operation":"chat"`) {
		t.Fatalf("expected operation-specific success envelope, got %q", rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "route_level") {
		t.Fatalf("expected operation envelope to override route envelope, got %q", rec.Body.String())
	}
}

func TestGraphQLRouteOperationPolicyCanOverrideErrorEnvelope(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"bad request"}`))
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
					ErrorResponseFields: map[string]string{
						"route_error": "fallback",
					},
					GraphQLOperationPolicies: map[string]config.GraphQLOperationPolicy{
						"SearchQuery": {
							ErrorResponseFields: map[string]string{
								"operation": "search",
								"status":    "blocked",
							},
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

	req := httptest.NewRequest(http.MethodPost, "http://gateway.local/graphql", strings.NewReader(`{"query":"query SearchQuery { ping }","operationName":"SearchQuery"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	gw.GetRouter().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 response, got %d body=%q", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"operation":"search"`) {
		t.Fatalf("expected operation-specific error envelope, got %q", rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "route_error") {
		t.Fatalf("expected operation envelope to override route envelope, got %q", rec.Body.String())
	}
}

func TestGraphQLRouteOperationPolicyCanOverrideResponseJSONTransforms(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"message":"hello","legacy":"remove-me"}`))
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
					ResponseJSONFields: map[string]string{
						"route_level": "true",
					},
					GraphQLOperationPolicies: map[string]config.GraphQLOperationPolicy{
						"ChatQuery": {
							ResponseJSONFields: map[string]string{
								"meta.operation": "chat",
							},
							RemoveResponseJSONFields: []string{"legacy"},
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
	rec := httptest.NewRecorder()
	gw.GetRouter().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 response, got %d body=%q", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"operation":"chat"`) {
		t.Fatalf("expected operation-specific response json transform, got %q", rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "legacy") {
		t.Fatalf("expected operation-specific response json removal, got %q", rec.Body.String())
	}
}

func TestGraphQLRouteOperationPolicyCanOverrideResponseJSONRedaction(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"token":"secret-token","message":"hello"}`))
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
					GraphQLOperationPolicies: map[string]config.GraphQLOperationPolicy{
						"SearchQuery": {
							ResponseRedactJSONFields: []string{"token"},
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

	req := httptest.NewRequest(http.MethodPost, "http://gateway.local/graphql", strings.NewReader(`{"query":"query SearchQuery { ping }","operationName":"SearchQuery"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	gw.GetRouter().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 response, got %d body=%q", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"token":"[REDACTED]"`) {
		t.Fatalf("expected operation-specific response json redaction, got %q", rec.Body.String())
	}
}

func TestGraphQLRouteOperationPolicyCanOverrideResponseHeaders(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Upstream-Legacy", "legacy")
		w.Header().Set("Authorization", "Bearer secret")
		_, _ = w.Write([]byte(`{"message":"hello"}`))
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
					ResponseHeaders: map[string]string{
						"X-Route-Level": "default",
					},
					GraphQLOperationPolicies: map[string]config.GraphQLOperationPolicy{
						"ChatQuery": {
							ResponseHeaders: map[string]string{
								"X-Operation": "chat",
							},
							RemoveResponseHeaders: []string{"X-Upstream-Legacy"},
							ResponseRedactHeaders: []string{"Authorization"},
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
	rec := httptest.NewRecorder()
	gw.GetRouter().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 response, got %d body=%q", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("X-Operation"); got != "chat" {
		t.Fatalf("expected operation-specific response header, got %q", got)
	}
	if got := rec.Header().Get("X-Upstream-Legacy"); got != "" {
		t.Fatalf("expected operation-specific response header removal, got %q", got)
	}
	if got := rec.Header().Get("Authorization"); got != "[REDACTED]" {
		t.Fatalf("expected operation-specific response header redaction, got %q", got)
	}
}

func TestGraphQLRouteOperationPolicyCanGateResponseHeadersByStatusClass(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"bad request"}`))
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
					GraphQLOperationPolicies: map[string]config.GraphQLOperationPolicy{
						"SearchQuery": {
							ResponseHeaders:                map[string]string{"X-Operation-Error": "search"},
							ResponseTransformStatusClasses: []string{"4xx"},
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

	req := httptest.NewRequest(http.MethodPost, "http://gateway.local/graphql", strings.NewReader(`{"query":"query SearchQuery { ping }","operationName":"SearchQuery"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	gw.GetRouter().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 response, got %d body=%q", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("X-Operation-Error"); got != "search" {
		t.Fatalf("expected operation-specific gated response header, got %q", got)
	}
}

func TestGraphQLRouteOperationPolicyCanGateResponseJSONByUpstreamHeader(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/problem+json")
		_, _ = w.Write([]byte(`{"message":"hello"}`))
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
					GraphQLOperationPolicies: map[string]config.GraphQLOperationPolicy{
						"ChatQuery": {
							ResponseJSONFields:           map[string]string{"meta.problem": "true"},
							ResponseTransformWhenHeaders: map[string]string{"Content-Type": "application/problem+json"},
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
	rec := httptest.NewRecorder()
	gw.GetRouter().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 response, got %d body=%q", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"problem":"true"`) {
		t.Fatalf("expected operation-specific gated response json transform, got %q", rec.Body.String())
	}
}

func TestGraphQLRouteOperationPolicyCanOverrideRequestHeaders(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(r.Header.Get("X-Operation")))
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
					RequestHeaders: map[string]string{
						"X-Route-Level": "default",
					},
					GraphQLOperationPolicies: map[string]config.GraphQLOperationPolicy{
						"ChatQuery": {
							RequestHeaders: map[string]string{
								"X-Operation": "chat",
							},
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
	rec := httptest.NewRecorder()
	gw.GetRouter().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 response, got %d body=%q", rec.Code, rec.Body.String())
	}
	if rec.Body.String() != "chat" {
		t.Fatalf("expected operation-specific request header, got %q", rec.Body.String())
	}
}

func TestGraphQLRouteOperationPolicyCanOverrideQueryParams(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(r.URL.Query().Get("mode")))
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
					GraphQLOperationPolicies: map[string]config.GraphQLOperationPolicy{
						"SearchQuery": {
							QueryParams: map[string]string{
								"mode": "safe",
							},
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

	req := httptest.NewRequest(http.MethodPost, "http://gateway.local/graphql", strings.NewReader(`{"query":"query SearchQuery { ping }","operationName":"SearchQuery"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	gw.GetRouter().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 response, got %d body=%q", rec.Code, rec.Body.String())
	}
	if rec.Body.String() != "safe" {
		t.Fatalf("expected operation-specific query param transform, got %q", rec.Body.String())
	}
}

func TestGraphQLRouteOperationPolicyCanOverrideRequestJSONTransforms(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_, _ = w.Write(body)
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
					GraphQLOperationPolicies: map[string]config.GraphQLOperationPolicy{
						"ChatQuery": {
							RequestJSONFields: map[string]string{
								"meta.operation": "chat",
							},
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
	rec := httptest.NewRecorder()
	gw.GetRouter().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 response, got %d body=%q", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"operation":"chat"`) {
		t.Fatalf("expected operation-specific request json transform, got %q", rec.Body.String())
	}
}

func TestGraphQLRouteOperationPolicyCanGateRequestTransformsByHeader(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(r.URL.Query().Get("mode")))
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
					GraphQLOperationPolicies: map[string]config.GraphQLOperationPolicy{
						"SearchQuery": {
							QueryParams: map[string]string{
								"mode": "safe",
							},
							TransformWhenHeaders: map[string]string{
								"X-Transform-Mode": "beta",
							},
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

	req := httptest.NewRequest(http.MethodPost, "http://gateway.local/graphql", strings.NewReader(`{"query":"query SearchQuery { ping }","operationName":"SearchQuery"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	gw.GetRouter().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 response, got %d body=%q", rec.Code, rec.Body.String())
	}
	if rec.Body.String() != "" {
		t.Fatalf("expected gated transform to stay disabled, got %q", rec.Body.String())
	}

	req2 := httptest.NewRequest(http.MethodPost, "http://gateway.local/graphql", strings.NewReader(`{"query":"query SearchQuery { ping }","operationName":"SearchQuery"}`))
	req2.Header.Set("Content-Type", "application/json")
	req2.Header.Set("X-Transform-Mode", "beta")
	rec2 := httptest.NewRecorder()
	gw.GetRouter().ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("expected 200 response, got %d body=%q", rec2.Code, rec2.Body.String())
	}
	if rec2.Body.String() != "safe" {
		t.Fatalf("expected gated transform to activate, got %q", rec2.Body.String())
	}
}
