package gateway

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/bhangun/iket/pkg/config"
	"github.com/bhangun/iket/pkg/logging"
)

func TestApplyUpstreamHeadersInjectsRealmAndRouteHeaders(t *testing.T) {
	req := httptest.NewRequest("GET", "http://gateway.local/jahsy/chat/ws/events?token=abc", nil)
	req.RemoteAddr = "10.0.0.8:1234"
	req.Host = "gateway.example"
	ctx := context.WithValue(req.Context(), tenantRealmKey, "jahsy")
	ctx = context.WithValue(ctx, routeVarsKey, map[string]string{"client_id": "test-client"})
	ctx = context.WithValue(ctx, requestIDKey, "req-123")
	req = req.WithContext(ctx)
	req.Header.Set("X-Client-Version", "ios")

	headers := make(http.Header)
	route := config.RouterConfig{
		Headers: map[string]string{
			"X-Service": "chat",
		},
		RequestHeaders: map[string]string{
			"X-Request-Transform": "{{realm}}/{{query.token}}/{{var.client_id}}/{{header.X-Client-Version}}/{{request_id}}",
		},
		RemoveRequestHeaders: []string{"X-Remove-Me"},
	}
	wsOpts := &config.WebSocketOptions{
		InjectHeaders: map[string]string{
			"X-WS-Proxy": "iket",
		},
	}
	headers.Set("X-Remove-Me", "legacy")

	applyUpstreamHeaders(req, headers, route, wsOpts)

	if got := headers.Get("X-Realm"); got != "jahsy" {
		t.Fatalf("expected X-Realm jahsy, got %q", got)
	}
	if got := headers.Get("X-Service"); got != "chat" {
		t.Fatalf("expected X-Service chat, got %q", got)
	}
	if got := headers.Get("X-Request-Transform"); got != "jahsy/abc/test-client/ios/req-123" {
		t.Fatalf("expected templated X-Request-Transform, got %q", got)
	}
	if got := headers.Get("X-Remove-Me"); got != "" {
		t.Fatalf("expected X-Remove-Me to be removed, got %q", got)
	}
	if got := headers.Get("X-WS-Proxy"); got != "iket" {
		t.Fatalf("expected X-WS-Proxy iket, got %q", got)
	}
	if got := headers.Get("X-Forwarded-Host"); got != "gateway.example" {
		t.Fatalf("expected forwarded host gateway.example, got %q", got)
	}
}

func TestResponseHeaderTransformsAreApplied(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Upstream-Legacy", "old")
		w.Header().Set("X-Upstream-Trace", "trace-1")
		w.Header().Set("Authorization", "Bearer secret-token")
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
					ResponseHeaders: map[string]string{
						"X-Edge-Policy":   "{{query.mode}}-{{request_id}}",
						"X-Upstream-Seen": "{{response_header.X-Upstream-Trace}}",
					},
					RemoveResponseHeaders: []string{"X-Upstream-Legacy"},
					ResponseRedactHeaders: []string{"Authorization"},
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

	req := httptest.NewRequest(http.MethodGet, "http://gateway.local/auth/profile?mode=preview", nil)
	req.Header.Set("X-Request-Id", "req-456")
	rec := httptest.NewRecorder()

	gw.GetRouter().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 transformed response, got %d", rec.Code)
	}
	if got := rec.Header().Get("X-Edge-Policy"); got != "preview-req-456" {
		t.Fatalf("expected templated X-Edge-Policy, got %q", got)
	}
	if got := rec.Header().Get("X-Upstream-Seen"); got != "trace-1" {
		t.Fatalf("expected templated X-Upstream-Seen from upstream response header, got %q", got)
	}
	if got := rec.Header().Get("X-Upstream-Legacy"); got != "" {
		t.Fatalf("expected X-Upstream-Legacy to be removed, got %q", got)
	}
	if got := rec.Header().Get("Authorization"); got != "[REDACTED]" {
		t.Fatalf("expected Authorization header to be redacted, got %q", got)
	}
	if got := rec.Header().Get("X-Upstream-Trace"); got != "trace-1" {
		t.Fatalf("expected X-Upstream-Trace to remain, got %q", got)
	}
}

func TestResponseHeaderTransformsCanBeScopedToSuccessStatuses(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Upstream-Legacy", "old")
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte("nope"))
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
					Path:                           "/auth/profile",
					Methods:                        []string{"GET"},
					ResponseTransformStatusClasses: []string{"2xx"},
					ResponseHeaders: map[string]string{
						"X-Edge-Policy": "success-only",
					},
					RemoveResponseHeaders: []string{"X-Upstream-Legacy"},
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
	rec := httptest.NewRecorder()
	gw.GetRouter().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("expected 502 response, got %d", rec.Code)
	}
	if got := rec.Header().Get("X-Edge-Policy"); got != "" {
		t.Fatalf("expected success-only response header transform to be skipped on 502, got %q", got)
	}
	if got := rec.Header().Get("X-Upstream-Legacy"); got != "old" {
		t.Fatalf("expected upstream legacy header to remain on skipped transform, got %q", got)
	}
}

func TestResponseHeaderTransformsCanBeScopedToMatchingUpstreamHeaders(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/problem+json")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
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
					ResponseTransformWhenHeaders: map[string]string{
						"Content-Type": "application/problem+json",
					},
					ResponseHeaders: map[string]string{
						"X-Edge-Problem": "true",
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
	rec := httptest.NewRecorder()
	gw.GetRouter().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 response, got %d", rec.Code)
	}
	if got := rec.Header().Get("X-Edge-Problem"); got != "true" {
		t.Fatalf("expected response header transform to apply on matching upstream header, got %q", got)
	}
}

func TestQueryParamTransformsAreApplied(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(r.URL.RawQuery))
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
					Path:    "/{realm}/auth/profile/{client_id}",
					Methods: []string{"GET"},
					QueryParams: map[string]string{
						"realm":      "{{realm}}",
						"client_id":  "{{var.client_id}}",
						"token_copy": "{{query.token}}",
					},
					RemoveQueryParams: []string{"legacy"},
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

	req := httptest.NewRequest(http.MethodGet, "http://gateway.local/jahsy/auth/profile/test-client?token=abc&legacy=1", nil)
	rec := httptest.NewRecorder()

	gw.GetRouter().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 transformed response, got %d", rec.Code)
	}
	values, err := url.ParseQuery(rec.Body.String())
	if err != nil {
		t.Fatalf("expected valid encoded query string, got %q: %v", rec.Body.String(), err)
	}
	if got := values.Get("token"); got != "abc" {
		t.Fatalf("expected token query param abc, got %q", got)
	}
	if got := values.Get("realm"); got != "jahsy" {
		t.Fatalf("expected realm query param jahsy, got %q", got)
	}
	if got := values.Get("client_id"); got != "test-client" {
		t.Fatalf("expected client_id query param test-client, got %q", got)
	}
	if got := values.Get("token_copy"); got != "abc" {
		t.Fatalf("expected token_copy query param abc, got %q", got)
	}
	if got := values.Get("legacy"); got != "" {
		t.Fatalf("expected legacy query param to be removed, got %q", got)
	}
}

func TestRequestJSONTransformsAreApplied(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("failed to read upstream request body: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
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
					Path:    "/{realm}/auth/profile/{client_id}",
					Methods: []string{"POST"},
					RequestJSONFields: map[string]string{
						"meta.realm":             "{{realm}}",
						"meta.client_id":         "{{var.client_id}}",
						"meta.request_id":        "{{request_id}}",
						"meta.mode":              "{{query.mode}}",
						"meta.tags[]":            "{{realm}}",
						"meta.enabled":           "json:true",
						"meta.count":             "json:123",
						"meta.roles":             `json:["reader","writer"]`,
						"meta.subject":           `json:{"realm":"{{realm}}","client":"{{var.client_id}}"}`,
						"user.profile.realm":     "{{realm}}",
						"user.profile.client_id": "{{var.client_id}}",
						"users[0].profile.realm": "{{realm}}",
					},
					RemoveRequestJSONFields: []string{"legacy", "user.profile.legacy"},
					TransformWhenHeaders: map[string]string{
						"X-Transform-Mode": "beta",
					},
					TransformWhenQueryParams: map[string]string{
						"transform": "1",
					},
					TransformWhenHeaderRegex: map[string]string{
						"X-Env": "^prod-[a-z]+$",
					},
					TransformWhenQueryRegex: map[string]string{
						"mode": "^(preview|staging)$",
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

	req := httptest.NewRequest(http.MethodPost, "http://gateway.local/jahsy/auth/profile/test-client?mode=preview", strings.NewReader(`{"status":"ok","legacy":"drop-me","user":{"profile":{"legacy":"drop-me-too"}},"users":[{"profile":{}}]}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Request-Id", "req-321")
	req.Header.Set("X-Transform-Mode", "beta")
	req.Header.Set("X-Env", "prod-blue")
	req.URL.RawQuery = "mode=preview&transform=1"
	rec := httptest.NewRecorder()

	gw.GetRouter().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 transformed response, got %d", rec.Code)
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("expected JSON response, got %q: %v", rec.Body.String(), err)
	}
	if got := payload["status"]; got != "ok" {
		t.Fatalf("expected status ok, got %v", got)
	}
	meta, ok := payload["meta"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected meta object, got %v", payload["meta"])
	}
	if got := meta["realm"]; got != "jahsy" {
		t.Fatalf("expected meta.realm jahsy, got %v", got)
	}
	if got := meta["client_id"]; got != "test-client" {
		t.Fatalf("expected meta.client_id test-client, got %v", got)
	}
	if got := meta["request_id"]; got != "req-321" {
		t.Fatalf("expected meta.request_id req-321, got %v", got)
	}
	if got := meta["mode"]; got != "preview" {
		t.Fatalf("expected meta.mode preview, got %v", got)
	}
	tags, ok := meta["tags"].([]interface{})
	if !ok || len(tags) != 1 || tags[0] != "jahsy" {
		t.Fatalf("expected meta.tags append to contain jahsy, got %v", meta["tags"])
	}
	if got, ok := meta["enabled"].(bool); !ok || !got {
		t.Fatalf("expected meta.enabled true bool, got %v", meta["enabled"])
	}
	if got, ok := meta["count"].(float64); !ok || got != 123 {
		t.Fatalf("expected meta.count 123 number, got %v", meta["count"])
	}
	roles, ok := meta["roles"].([]interface{})
	if !ok || len(roles) != 2 || roles[0] != "reader" || roles[1] != "writer" {
		t.Fatalf("expected meta.roles typed array, got %v", meta["roles"])
	}
	subject, ok := meta["subject"].(map[string]interface{})
	if !ok || subject["realm"] != "jahsy" || subject["client"] != "test-client" {
		t.Fatalf("expected meta.subject typed object, got %v", meta["subject"])
	}
	if _, exists := payload["legacy"]; exists {
		t.Fatalf("expected legacy field to be removed, got payload %v", payload)
	}
	user, ok := payload["user"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected user object, got %v", payload["user"])
	}
	profile, ok := user["profile"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected user.profile object, got %v", user["profile"])
	}
	if got := profile["realm"]; got != "jahsy" {
		t.Fatalf("expected user.profile.realm jahsy, got %v", got)
	}
	if got := profile["client_id"]; got != "test-client" {
		t.Fatalf("expected user.profile.client_id test-client, got %v", got)
	}
	if _, exists := profile["legacy"]; exists {
		t.Fatalf("expected user.profile.legacy to be removed, got profile %v", profile)
	}
	users, ok := payload["users"].([]interface{})
	if !ok || len(users) != 1 {
		t.Fatalf("expected users array with one entry, got %v", payload["users"])
	}
	user0, ok := users[0].(map[string]interface{})
	if !ok {
		t.Fatalf("expected users[0] object, got %v", users[0])
	}
	user0Profile, ok := user0["profile"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected users[0].profile object, got %v", user0["profile"])
	}
	if got := user0Profile["realm"]; got != "jahsy" {
		t.Fatalf("expected users[0].profile.realm jahsy, got %v", got)
	}
}

func TestResponseJSONTransformsAreApplied(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok","legacy":"drop-me","user":{"profile":{"legacy":"drop-me-too"}},"users":[{"profile":{}}]}`))
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
					Path:    "/{realm}/auth/profile/{client_id}",
					Methods: []string{"GET"},
					ResponseJSONFields: map[string]string{
						"meta.realm":             "{{realm}}",
						"meta.client_id":         "{{var.client_id}}",
						"meta.request_id":        "{{request_id}}",
						"meta.mode":              "{{query.mode}}",
						"meta.tags[]":            "{{realm}}",
						"meta.enabled":           "json:true",
						"meta.count":             "json:123",
						"meta.roles":             `json:["reader","writer"]`,
						"meta.subject":           `json:{"realm":"{{realm}}","client":"{{var.client_id}}"}`,
						"user.profile.realm":     "{{realm}}",
						"user.profile.client_id": "{{var.client_id}}",
						"users[0].profile.realm": "{{realm}}",
					},
					RemoveResponseJSONFields: []string{"legacy", "user.profile.legacy"},
					TransformWhenHeaders: map[string]string{
						"X-Transform-Mode": "beta",
					},
					TransformWhenQueryParams: map[string]string{
						"transform": "1",
					},
					TransformWhenHeaderRegex: map[string]string{
						"X-Env": "^prod-[a-z]+$",
					},
					TransformWhenQueryRegex: map[string]string{
						"mode": "^(preview|staging)$",
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

	req := httptest.NewRequest(http.MethodGet, "http://gateway.local/jahsy/auth/profile/test-client?mode=preview&transform=1", nil)
	req.Header.Set("X-Request-Id", "req-789")
	req.Header.Set("X-Transform-Mode", "beta")
	req.Header.Set("X-Env", "prod-blue")
	rec := httptest.NewRecorder()

	gw.GetRouter().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 transformed response, got %d", rec.Code)
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("expected JSON response, got %q: %v", rec.Body.String(), err)
	}
	if got := payload["status"]; got != "ok" {
		t.Fatalf("expected status ok, got %v", got)
	}
	meta, ok := payload["meta"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected meta object, got %v", payload["meta"])
	}
	if got := meta["realm"]; got != "jahsy" {
		t.Fatalf("expected meta.realm jahsy, got %v", got)
	}
	if got := meta["client_id"]; got != "test-client" {
		t.Fatalf("expected meta.client_id test-client, got %v", got)
	}
	if got := meta["request_id"]; got != "req-789" {
		t.Fatalf("expected meta.request_id req-789, got %v", got)
	}
	if got := meta["mode"]; got != "preview" {
		t.Fatalf("expected meta.mode preview, got %v", got)
	}
	tags, ok := meta["tags"].([]interface{})
	if !ok || len(tags) != 1 || tags[0] != "jahsy" {
		t.Fatalf("expected meta.tags append to contain jahsy, got %v", meta["tags"])
	}
	if got, ok := meta["enabled"].(bool); !ok || !got {
		t.Fatalf("expected meta.enabled true bool, got %v", meta["enabled"])
	}
	if got, ok := meta["count"].(float64); !ok || got != 123 {
		t.Fatalf("expected meta.count 123 number, got %v", meta["count"])
	}
	roles, ok := meta["roles"].([]interface{})
	if !ok || len(roles) != 2 || roles[0] != "reader" || roles[1] != "writer" {
		t.Fatalf("expected meta.roles typed array, got %v", meta["roles"])
	}
	subject, ok := meta["subject"].(map[string]interface{})
	if !ok || subject["realm"] != "jahsy" || subject["client"] != "test-client" {
		t.Fatalf("expected meta.subject typed object, got %v", meta["subject"])
	}
	if _, exists := payload["legacy"]; exists {
		t.Fatalf("expected legacy field to be removed, got payload %v", payload)
	}
	user, ok := payload["user"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected user object, got %v", payload["user"])
	}
	profile, ok := user["profile"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected user.profile object, got %v", user["profile"])
	}
	if got := profile["realm"]; got != "jahsy" {
		t.Fatalf("expected user.profile.realm jahsy, got %v", got)
	}
	if got := profile["client_id"]; got != "test-client" {
		t.Fatalf("expected user.profile.client_id test-client, got %v", got)
	}
	if _, exists := profile["legacy"]; exists {
		t.Fatalf("expected user.profile.legacy to be removed, got profile %v", profile)
	}
	users, ok := payload["users"].([]interface{})
	if !ok || len(users) != 1 {
		t.Fatalf("expected users array with one entry, got %v", payload["users"])
	}
	user0, ok := users[0].(map[string]interface{})
	if !ok {
		t.Fatalf("expected users[0] object, got %v", users[0])
	}
	user0Profile, ok := user0["profile"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected users[0].profile object, got %v", user0["profile"])
	}
	if got := user0Profile["realm"]; got != "jahsy" {
		t.Fatalf("expected users[0].profile.realm jahsy, got %v", got)
	}
}

func TestResponseJSONTransformsCanBeScopedToErrorStatuses(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte(`{"status":"error"}`))
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
					Path:                           "/{realm}/auth/profile/{client_id}",
					Methods:                        []string{"GET"},
					ResponseTransformStatusClasses: []string{"5xx"},
					ResponseJSONFields: map[string]string{
						"error.realm": "{{realm}}",
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

	req := httptest.NewRequest(http.MethodGet, "http://gateway.local/jahsy/auth/profile/test-client", nil)
	rec := httptest.NewRecorder()
	gw.GetRouter().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("expected 502 response, got %d", rec.Code)
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("expected JSON response, got %q: %v", rec.Body.String(), err)
	}
	errorFields, ok := payload["error"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected error object from error-scoped response_json transform, got %v", payload["error"])
	}
	if got := errorFields["realm"]; got != "jahsy" {
		t.Fatalf("expected error.realm jahsy, got %v", got)
	}
}

func TestResponseJSONTransformsCanBeScopedToMatchingUpstreamHeaderRegex(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/problem+json")
		_, _ = w.Write([]byte(`{"status":"error"}`))
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
					Path:    "/{realm}/auth/profile/{client_id}",
					Methods: []string{"GET"},
					ResponseTransformHeaderRegex: map[string]string{
						"Content-Type": "^application/(problem\\+json|json)$",
					},
					ResponseJSONFields: map[string]string{
						"error.realm":        "{{realm}}",
						"error.content_type": "{{response_header.Content-Type}}",
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

	req := httptest.NewRequest(http.MethodGet, "http://gateway.local/jahsy/auth/profile/test-client", nil)
	rec := httptest.NewRecorder()
	gw.GetRouter().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 response, got %d", rec.Code)
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("expected JSON response, got %q: %v", rec.Body.String(), err)
	}
	errorFields, ok := payload["error"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected error object from response header gated JSON transform, got %v", payload["error"])
	}
	if got := errorFields["realm"]; got != "jahsy" {
		t.Fatalf("expected error.realm jahsy, got %v", got)
	}
	if got := errorFields["content_type"]; got != "application/problem+json" {
		t.Fatalf("expected error.content_type from upstream response header, got %v", got)
	}
}

func TestErrorResponseEnvelopeCanNormalizePlaintextBackendErrors(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Upstream-Trace", "trace-502")
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte("backend unavailable"))
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
					Path:    "/{realm}/auth/profile/{client_id}",
					Methods: []string{"GET"},
					ErrorResponseFields: map[string]string{
						"error.status":         "json:{{response_status}}",
						"error.message":        "{{response_body}}",
						"error.upstream_trace": "{{response_header.X-Upstream-Trace}}",
						"request_id":           "{{request_id}}",
						"realm":                "{{realm}}",
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

	req := httptest.NewRequest(http.MethodGet, "http://gateway.local/jahsy/auth/profile/test-client", nil)
	req.Header.Set("X-Request-Id", "req-err-1")
	rec := httptest.NewRecorder()
	gw.GetRouter().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("expected 502 response, got %d", rec.Code)
	}
	if got := rec.Header().Get("Content-Type"); !strings.Contains(got, "application/json") {
		t.Fatalf("expected normalized JSON content type, got %q", got)
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("expected JSON response, got %q: %v", rec.Body.String(), err)
	}
	errorFields, ok := payload["error"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected error object, got %v", payload["error"])
	}
	if got, ok := errorFields["status"].(float64); !ok || got != 502 {
		t.Fatalf("expected numeric error.status 502, got %v", errorFields["status"])
	}
	if got := errorFields["message"]; got != "backend unavailable" {
		t.Fatalf("expected error.message from plaintext backend body, got %v", got)
	}
	if got := errorFields["upstream_trace"]; got != "trace-502" {
		t.Fatalf("expected error.upstream_trace from upstream header, got %v", got)
	}
	if got := payload["request_id"]; got != "req-err-1" {
		t.Fatalf("expected request_id req-err-1, got %v", got)
	}
	if got := payload["realm"]; got != "jahsy" {
		t.Fatalf("expected realm jahsy, got %v", got)
	}
}

func TestSuccessResponseEnvelopeCanNormalizePlaintextBackendSuccess(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Upstream-Trace", "trace-200")
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
					Path:    "/{realm}/auth/profile/{client_id}",
					Methods: []string{"GET"},
					SuccessResponseFields: map[string]string{
						"data.status":         "{{response_body}}",
						"data.upstream_trace": "{{response_header.X-Upstream-Trace}}",
						"data.api_key":        "sk-live-secret",
						"status":              "success",
						"request_id":          "{{request_id}}",
						"realm":               "{{realm}}",
					},
					ResponseRedactJSONFields: []string{"data.api_key"},
					RedactionValue:           "***",
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

	req := httptest.NewRequest(http.MethodGet, "http://gateway.local/jahsy/auth/profile/test-client", nil)
	req.Header.Set("X-Request-Id", "req-ok-1")
	rec := httptest.NewRecorder()
	gw.GetRouter().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 response, got %d", rec.Code)
	}
	if got := rec.Header().Get("Content-Type"); !strings.Contains(got, "application/json") {
		t.Fatalf("expected normalized JSON content type, got %q", got)
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("expected JSON response, got %q: %v", rec.Body.String(), err)
	}
	if got := payload["status"]; got != "success" {
		t.Fatalf("expected status success, got %v", got)
	}
	data, ok := payload["data"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected data object, got %v", payload["data"])
	}
	if got := data["status"]; got != "ok" {
		t.Fatalf("expected data.status from plaintext backend body, got %v", got)
	}
	if got := data["upstream_trace"]; got != "trace-200" {
		t.Fatalf("expected data.upstream_trace from upstream header, got %v", got)
	}
	if got := data["api_key"]; got != "***" {
		t.Fatalf("expected data.api_key to be redacted, got %v", got)
	}
	if got := payload["request_id"]; got != "req-ok-1" {
		t.Fatalf("expected request_id req-ok-1, got %v", got)
	}
	if got := payload["realm"]; got != "jahsy" {
		t.Fatalf("expected realm jahsy, got %v", got)
	}
}

func TestRequestJSONTransformsAreSkippedWhenConditionsDoNotMatch(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("failed to read upstream request body: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
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
					Path:    "/{realm}/auth/profile/{client_id}",
					Methods: []string{"POST"},
					RequestJSONFields: map[string]string{
						"meta.realm": "{{realm}}",
					},
					RemoveRequestJSONFields: []string{"legacy"},
					TransformWhenHeaders: map[string]string{
						"X-Transform-Mode": "beta",
					},
					TransformWhenQueryParams: map[string]string{
						"transform": "1",
					},
					TransformWhenHeaderRegex: map[string]string{
						"X-Env": "^prod-[a-z]+$",
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

	req := httptest.NewRequest(http.MethodPost, "http://gateway.local/jahsy/auth/profile/test-client?mode=preview", strings.NewReader(`{"status":"ok","legacy":"keep-me"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Transform-Mode", "beta")
	req.Header.Set("X-Env", "dev-blue")
	req.URL.RawQuery = "mode=preview&transform=1"
	rec := httptest.NewRecorder()

	gw.GetRouter().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 response, got %d", rec.Code)
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("expected JSON response, got %q: %v", rec.Body.String(), err)
	}
	if _, exists := payload["meta"]; exists {
		t.Fatalf("expected meta field to be absent when transforms are gated off, got %v", payload["meta"])
	}
	if got := payload["legacy"]; got != "keep-me" {
		t.Fatalf("expected legacy field to remain when transforms are gated off, got %v", got)
	}
}

func TestTransformScopesGateOnlyConfiguredRewriteFamilies(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("failed to read upstream request body: %v", err)
		}
		var payload map[string]interface{}
		if err := json.Unmarshal(body, &payload); err != nil {
			t.Fatalf("failed to decode upstream request body: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(payload)
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
					Path:    "/{realm}/auth/profile/{client_id}",
					Methods: []string{"POST"},
					RequestJSONFields: map[string]string{
						"meta.realm": "{{realm}}",
					},
					RemoveRequestJSONFields: []string{"legacy"},
					ResponseJSONFields: map[string]string{
						"response.realm": "{{realm}}",
					},
					TransformWhenHeaders: map[string]string{
						"X-Transform-Mode": "beta",
					},
					TransformScopes: []string{"request_json"},
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

	req := httptest.NewRequest(http.MethodPost, "http://gateway.local/jahsy/auth/profile/test-client", strings.NewReader(`{"status":"ok","legacy":"keep-me"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	gw.GetRouter().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 response, got %d", rec.Code)
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("expected JSON response, got %q: %v", rec.Body.String(), err)
	}
	if _, exists := payload["meta"]; exists {
		t.Fatalf("expected request_json transforms to stay gated off, got %v", payload["meta"])
	}
	if got := payload["legacy"]; got != "keep-me" {
		t.Fatalf("expected gated request_json transforms to preserve legacy, got %v", got)
	}
	responseFields, ok := payload["response"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected response object from ungated response_json transform, got %v", payload["response"])
	}
	if got := responseFields["realm"]; got != "jahsy" {
		t.Fatalf("expected response.realm jahsy from ungated response_json transform, got %v", got)
	}
}

func TestTransformMethodsLimitTransformsToSelectedHTTPMethods(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("failed to read upstream request body: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
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
					Path:             "/{realm}/auth/profile/{client_id}",
					Methods:          []string{"POST", "PUT"},
					TransformMethods: []string{"POST"},
					RequestJSONFields: map[string]string{
						"meta.realm": "{{realm}}",
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

	postReq := httptest.NewRequest(http.MethodPost, "http://gateway.local/jahsy/auth/profile/test-client", strings.NewReader(`{"status":"ok"}`))
	postReq.Header.Set("Content-Type", "application/json")
	postRec := httptest.NewRecorder()
	gw.GetRouter().ServeHTTP(postRec, postReq)
	if postRec.Code != http.StatusOK {
		t.Fatalf("expected POST 200 response, got %d", postRec.Code)
	}
	var postPayload map[string]interface{}
	if err := json.Unmarshal(postRec.Body.Bytes(), &postPayload); err != nil {
		t.Fatalf("expected POST JSON response, got %q: %v", postRec.Body.String(), err)
	}
	if _, exists := postPayload["meta"]; !exists {
		t.Fatalf("expected POST transforms to apply, got %v", postPayload)
	}

	putReq := httptest.NewRequest(http.MethodPut, "http://gateway.local/jahsy/auth/profile/test-client", strings.NewReader(`{"status":"ok"}`))
	putReq.Header.Set("Content-Type", "application/json")
	putRec := httptest.NewRecorder()
	gw.GetRouter().ServeHTTP(putRec, putReq)
	if putRec.Code != http.StatusOK {
		t.Fatalf("expected PUT 200 response, got %d", putRec.Code)
	}
	var putPayload map[string]interface{}
	if err := json.Unmarshal(putRec.Body.Bytes(), &putPayload); err != nil {
		t.Fatalf("expected PUT JSON response, got %q: %v", putRec.Body.String(), err)
	}
	if _, exists := putPayload["meta"]; exists {
		t.Fatalf("expected PUT transforms to be skipped by transformMethods, got %v", putPayload["meta"])
	}
}
