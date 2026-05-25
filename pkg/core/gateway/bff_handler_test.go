package gateway

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bhangun/iket/pkg/config"
	"github.com/bhangun/iket/pkg/logging"
	"github.com/bhangun/iket/pkg/metrics"
)

func TestBFFRouteComposesParallelUpstreamResponses(t *testing.T) {
	profile := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/users/u123" {
			t.Fatalf("unexpected profile path: %s", r.URL.Path)
		}
		if got := r.Header.Get("X-User-ID"); got != "u123" {
			t.Fatalf("expected templated step header, got %q", got)
		}
		if got := r.Header.Get("X-Route-User"); got != "u123" {
			t.Fatalf("expected templated route header, got %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"u123","name":"Aba"}`))
	}))
	defer profile.Close()

	billing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("tenant"); got != "jahsy" {
			t.Fatalf("expected templated query param, got %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"plan":"pro"}`))
	}))
	defer billing.Close()

	cfg := bffTestConfig(config.RouterConfig{
		Path:     "/app/{user_id}",
		Method:   http.MethodGet,
		Protocol: "bff",
		RequestHeaders: map[string]string{
			"X-Route-User": "{{var.user_id}}",
		},
		BFF: &config.BFFConfig{
			IncludeMeta: true,
			Steps: []config.BFFStepConfig{
				{
					Name:    "profile",
					URL:     profile.URL + "/users/{{var.user_id}}",
					Headers: map[string]string{"X-User-ID": "{{var.user_id}}"},
				},
				{
					Name:        "billing",
					URL:         billing.URL + "/account",
					QueryParams: map[string]string{"tenant": "{{query.tenant}}"},
				},
			},
			ResponseFields: map[string]string{
				"user.id":        "{{step.profile.json.id}}",
				"user.name":      "{{step.profile.json.name}}",
				"subscription":   "{{step.billing.json.plan}}",
				"billing_status": "{{step.billing.status}}",
				"request_id":     "{{request_id}}",
			},
		},
	})
	gw := newBFFTestGateway(t, cfg)

	req := httptest.NewRequest(http.MethodGet, "http://gateway.local/app/u123?tenant=jahsy", nil)
	req.Header.Set("X-Request-Id", "req-1")
	rec := httptest.NewRecorder()
	gw.GetRouter().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("invalid json response: %v", err)
	}
	user := payload["user"].(map[string]interface{})
	if user["id"] != "u123" || user["name"] != "Aba" {
		t.Fatalf("unexpected composed user: %#v", user)
	}
	if payload["subscription"] != "pro" {
		t.Fatalf("expected subscription pro, got %#v", payload["subscription"])
	}
	if payload["billing_status"] != float64(http.StatusOK) {
		t.Fatalf("expected numeric upstream status, got %#v", payload["billing_status"])
	}
	if payload["request_id"] != "req-1" {
		t.Fatalf("expected request id mapping, got %#v", payload["request_id"])
	}
	if payload["meta"] == nil {
		t.Fatalf("expected bff meta to be included")
	}
}

func TestBFFRouteUsesRequestJSONTemplateValues(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/orders/c1" {
			t.Fatalf("unexpected order path: %s", r.URL.Path)
		}
		if got := r.URL.Query().Get("sku"); got != "sku-1" {
			t.Fatalf("expected request JSON query param, got %q", got)
		}
		if got := r.Header.Get("X-Customer-ID"); got != "c1" {
			t.Fatalf("expected request JSON header, got %q", got)
		}
		var body map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("expected JSON upstream body: %v", err)
		}
		if body["sku"] != "sku-1" {
			t.Fatalf("expected request JSON sku in upstream body, got %#v", body["sku"])
		}
		if body["qty"] != float64(2) {
			t.Fatalf("expected request JSON quantity in upstream body, got %#v", body["qty"])
		}
		if body["customer_id"] != "c1" {
			t.Fatalf("expected request JSON customer id in upstream body, got %#v", body["customer_id"])
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id":"order-1"}`))
	}))
	defer upstream.Close()

	cfg := bffTestConfig(config.RouterConfig{
		Path:     "/orders",
		Method:   http.MethodPost,
		Protocol: "bff",
		BFF: &config.BFFConfig{
			ResponseStatus: "{{request.json.response_status}}",
			ResponseHeaders: map[string]string{
				"X-Order-Sku": "{{request.json.sku}}",
			},
			Steps: []config.BFFStepConfig{
				{
					Name:        "create",
					Method:      http.MethodPost,
					URL:         upstream.URL + "/orders/{{request.json.customer.id}}",
					QueryParams: map[string]string{"sku": "{{request.json.sku}}"},
					Headers:     map[string]string{"X-Customer-ID": "{{request.json.customer.id}}"},
					Body:        `json:{"sku":"{{request.json.sku}}","qty":{{request.json.quantity}},"customer_id":"{{request.json.customer.id}}"}`,
					RequireJSON: true,
				},
			},
			ResponseFields: map[string]string{
				"id":       "{{step.create.json.id}}",
				"sku":      "{{request.json.sku}}",
				"quantity": "{{request.json.quantity}}",
			},
		},
	})
	gw := newBFFTestGateway(t, cfg)

	body := strings.NewReader(`{"sku":"sku-1","quantity":2,"customer":{"id":"c1"},"response_status":202}`)
	req := httptest.NewRequest(http.MethodPost, "http://gateway.local/orders", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	gw.GetRouter().ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d: %s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("X-Order-Sku"); got != "sku-1" {
		t.Fatalf("expected response header from request JSON, got %q", got)
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("invalid json response: %v", err)
	}
	if payload["id"] != "order-1" {
		t.Fatalf("expected upstream id, got %#v", payload["id"])
	}
	if payload["sku"] != "sku-1" {
		t.Fatalf("expected request JSON sku in response, got %#v", payload["sku"])
	}
	if payload["quantity"] != float64(2) {
		t.Fatalf("expected request JSON quantity in response, got %#v", payload["quantity"])
	}
}

func TestBFFRouteValidatesRequiredRequestJSON(t *testing.T) {
	calls := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer upstream.Close()

	cfg := bffTestConfig(config.RouterConfig{
		Path:     "/orders",
		Method:   http.MethodPost,
		Protocol: "bff",
		BFF: &config.BFFConfig{
			RequireRequestJSON:       true,
			RequiredRequestJSONPaths: []string{"sku", "customer.id"},
			Steps: []config.BFFStepConfig{{
				Name: "create",
				URL:  upstream.URL + "/orders",
			}},
		},
	})
	gw := newBFFTestGateway(t, cfg)

	invalid := httptest.NewRequest(http.MethodPost, "http://gateway.local/orders", strings.NewReader(`{"sku":`))
	invalid.Header.Set("Content-Type", "application/json")
	invalidRec := httptest.NewRecorder()
	gw.GetRouter().ServeHTTP(invalidRec, invalid)
	if invalidRec.Code != http.StatusBadRequest {
		t.Fatalf("expected invalid JSON to return 400, got %d: %s", invalidRec.Code, invalidRec.Body.String())
	}
	if calls != 0 {
		t.Fatalf("expected invalid JSON to stop before upstream, got %d calls", calls)
	}

	missing := httptest.NewRequest(http.MethodPost, "http://gateway.local/orders", strings.NewReader(`{"sku":"sku-1"}`))
	missing.Header.Set("Content-Type", "application/json")
	missingRec := httptest.NewRecorder()
	gw.GetRouter().ServeHTTP(missingRec, missing)
	if missingRec.Code != http.StatusBadRequest {
		t.Fatalf("expected missing required JSON path to return 400, got %d: %s", missingRec.Code, missingRec.Body.String())
	}
	if !strings.Contains(missingRec.Body.String(), `customer.id`) {
		t.Fatalf("expected missing path detail, got %s", missingRec.Body.String())
	}
	if calls != 0 {
		t.Fatalf("expected missing required JSON path to stop before upstream, got %d calls", calls)
	}

	valid := httptest.NewRequest(http.MethodPost, "http://gateway.local/orders", strings.NewReader(`{"sku":"sku-1","customer":{"id":"c1"}}`))
	valid.Header.Set("Content-Type", "application/json")
	validRec := httptest.NewRecorder()
	gw.GetRouter().ServeHTTP(validRec, valid)
	if validRec.Code != http.StatusOK {
		t.Fatalf("expected valid JSON to continue, got %d: %s", validRec.Code, validRec.Body.String())
	}
	if calls != 1 {
		t.Fatalf("expected valid JSON to call upstream once, got %d calls", calls)
	}
}

func TestBFFRouteSetsTemplatedResponseHeaders(t *testing.T) {
	profile := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"u123","tier":"gold"}`))
	}))
	defer profile.Close()

	cfg := bffTestConfig(config.RouterConfig{
		Path:   "/headers/{user_id}",
		Method: http.MethodGet,
		BFF: &config.BFFConfig{
			Steps: []config.BFFStepConfig{{
				Name: "profile",
				URL:  profile.URL + "/users/{{var.user_id}}",
			}},
			ResponseFields: map[string]string{
				"user_id": "{{step.profile.json.id}}",
			},
			ResponseHeaders: map[string]string{
				"Cache-Control": "private, max-age=30",
				"Vary":          "Authorization, X-Client-Mode",
				"X-BFF-User":    "{{step.profile.json.id}}",
				"X-BFF-Tier":    "{{step.profile.json.tier}}",
				"X-Trace-Copy":  "{{request_id}}",
			},
		},
	})
	gw := newBFFTestGateway(t, cfg)

	req := httptest.NewRequest(http.MethodGet, "http://gateway.local/headers/u123", nil)
	req.Header.Set("X-Request-Id", "req-headers")
	rec := httptest.NewRecorder()
	gw.GetRouter().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Cache-Control") != "private, max-age=30" {
		t.Fatalf("expected templated Cache-Control header, got %q", rec.Header().Get("Cache-Control"))
	}
	if rec.Header().Get("Vary") != "Authorization, X-Client-Mode" {
		t.Fatalf("expected Vary header, got %q", rec.Header().Get("Vary"))
	}
	if rec.Header().Get("X-BFF-User") != "u123" || rec.Header().Get("X-BFF-Tier") != "gold" {
		t.Fatalf("expected response headers from upstream JSON, got user=%q tier=%q", rec.Header().Get("X-BFF-User"), rec.Header().Get("X-BFF-Tier"))
	}
	if rec.Header().Get("X-Trace-Copy") != "req-headers" {
		t.Fatalf("expected request id response header, got %q", rec.Header().Get("X-Trace-Copy"))
	}
}

func TestBFFRouteSetsTemplatedResponseStatus(t *testing.T) {
	create := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id":"job-1"}`))
	}))
	defer create.Close()

	cfg := bffTestConfig(config.RouterConfig{
		Path:   "/commands",
		Method: http.MethodPost,
		BFF: &config.BFFConfig{
			ResponseStatus: "{{step.create.status}}",
			Steps: []config.BFFStepConfig{{
				Name:   "create",
				Method: http.MethodPost,
				URL:    create.URL + "/commands",
			}},
			ResponseFields: map[string]string{
				"id":     "{{step.create.json.id}}",
				"status": "{{step.create.status}}",
			},
		},
	})
	gw := newBFFTestGateway(t, cfg)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "http://gateway.local/commands", nil)
	gw.GetRouter().ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected templated response status 201, got %d: %s", rec.Code, rec.Body.String())
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("invalid json response: %v", err)
	}
	if payload["id"] != "job-1" || payload["status"] != float64(http.StatusCreated) {
		t.Fatalf("expected created payload with upstream status, got %#v", payload)
	}
}

func TestBFFRouteInfersDependentStepFromTemplateReference(t *testing.T) {
	var mu sync.Mutex
	profileCompleted := false
	profile := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		profileCompleted = true
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"u123","segment":"vip"}`))
	}))
	defer profile.Close()

	recommendations := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		completed := profileCompleted
		mu.Unlock()
		if !completed {
			http.Error(w, "profile dependency was not completed", http.StatusConflict)
			return
		}
		if got := r.URL.Query().Get("segment"); got != "vip" {
			http.Error(w, "unexpected segment "+got, http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"segment":"vip","items":["one"]}`))
	}))
	defer recommendations.Close()

	cfg := bffTestConfig(config.RouterConfig{
		Path:   "/dependent/{user_id}",
		Method: http.MethodGet,
		BFF: &config.BFFConfig{
			Steps: []config.BFFStepConfig{
				{
					Name: "recommendations",
					URL:  recommendations.URL + "/recommendations?segment={{step.profile.json.segment}}",
				},
				{
					Name: "profile",
					URL:  profile.URL + "/users/{{var.user_id}}",
				},
			},
			ResponseFields: map[string]string{
				"user_id":                "{{step.profile.json.id}}",
				"recommendation_segment": "{{step.recommendations.json.segment}}",
			},
		},
	})
	gw := newBFFTestGateway(t, cfg)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://gateway.local/dependent/u123", nil)
	gw.GetRouter().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected dependent BFF route to succeed, got %d: %s", rec.Code, rec.Body.String())
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("invalid json response: %v", err)
	}
	if payload["user_id"] != "u123" || payload["recommendation_segment"] != "vip" {
		t.Fatalf("expected dependency-fed response, got %#v", payload)
	}
}

func TestBFFRouteMetaIncludesStepDependencyGraph(t *testing.T) {
	profile := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"u123"}`))
	}))
	defer profile.Close()
	entitlements := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"tier":"gold"}`))
	}))
	defer entitlements.Close()
	recommendations := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("user"); got != "u123" {
			t.Fatalf("expected inferred dependency value in recommendations query, got %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"items":["one"]}`))
	}))
	defer recommendations.Close()

	cfg := bffTestConfig(config.RouterConfig{
		Path:   "/meta/{user_id}",
		Method: http.MethodGet,
		BFF: &config.BFFConfig{
			IncludeMeta: true,
			Steps: []config.BFFStepConfig{
				{
					Name:      "recommendations",
					URL:       recommendations.URL + "/recommendations?user={{step.profile.json.id}}",
					DependsOn: []string{"entitlements"},
				},
				{Name: "entitlements", URL: entitlements.URL + "/entitlements/{{var.user_id}}"},
				{Name: "profile", URL: profile.URL + "/users/{{var.user_id}}"},
			},
			ResponseFields: map[string]string{
				"user_id": "{{step.profile.json.id}}",
				"tier":    "{{step.entitlements.json.tier}}",
				"items":   "{{step.recommendations.json.items}}",
			},
		},
	})
	gw := newBFFTestGateway(t, cfg)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://gateway.local/meta/u123", nil)
	gw.GetRouter().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected BFF route to succeed, got %d: %s", rec.Code, rec.Body.String())
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("invalid json response: %v", err)
	}
	meta := payload["meta"].(map[string]interface{})
	steps := meta["steps"].(map[string]interface{})
	recommendationsMeta := steps["recommendations"].(map[string]interface{})
	assertBFFMetaStringSlice(t, "dependencies", recommendationsMeta["dependencies"], "entitlements", "profile")
	assertBFFMetaStringSlice(t, "explicit_dependencies", recommendationsMeta["explicit_dependencies"], "entitlements")
	assertBFFMetaStringSlice(t, "inferred_dependencies", recommendationsMeta["inferred_dependencies"], "profile")
}

func TestBFFRouteAllowsOptionalStepFailure(t *testing.T) {
	requiredFalse := false
	profile := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"u123"}`))
	}))
	defer profile.Close()
	recommendations := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "temporarily unavailable", http.StatusInternalServerError)
	}))
	defer recommendations.Close()

	cfg := bffTestConfig(config.RouterConfig{
		Path:   "/home/{user_id}",
		Method: http.MethodGet,
		BFF: &config.BFFConfig{
			Steps: []config.BFFStepConfig{
				{Name: "profile", URL: profile.URL + "/users/{{var.user_id}}"},
				{Name: "recommendations", URL: recommendations.URL + "/users/{{var.user_id}}/recommendations", Required: &requiredFalse},
			},
			ResponseFields: map[string]string{
				"user_id":               "{{step.profile.json.id}}",
				"recommendations_ok":    "{{step.recommendations.ok}}",
				"recommendations_error": "{{step.recommendations.error}}",
			},
		},
	})
	gw := newBFFTestGateway(t, cfg)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://gateway.local/home/u123", nil)
	gw.GetRouter().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("invalid json response: %v", err)
	}
	if payload["user_id"] != "u123" {
		t.Fatalf("expected user id, got %#v", payload["user_id"])
	}
	if payload["recommendations_ok"] != false {
		t.Fatalf("expected optional failure to map ok=false, got %#v", payload["recommendations_ok"])
	}
	wantError := "BFF upstream recommendations returned status 500"
	if payload["recommendations_error"] != wantError {
		t.Fatalf("expected optional failure error %q, got %#v", wantError, payload["recommendations_error"])
	}
}

func TestBFFRouteAllowsPartialResponseForRequiredStepFailure(t *testing.T) {
	recommendations := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`not-json`))
	}))
	defer recommendations.Close()
	profile := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"u123","name":"Aba"}`))
	}))
	defer profile.Close()

	cfg := bffTestConfig(config.RouterConfig{
		Path:   "/partial/{user_id}",
		Method: http.MethodGet,
		BFF: &config.BFFConfig{
			Mode:                  "sequential",
			AllowPartialResponse:  true,
			IncludeMeta:           true,
			PartialResponseStatus: http.StatusMultiStatus,
			Steps: []config.BFFStepConfig{
				{Name: "recommendations", URL: recommendations.URL + "/users/{{var.user_id}}/recommendations", RequireJSON: true},
				{Name: "profile", URL: profile.URL + "/users/{{var.user_id}}"},
			},
			ResponseFields: map[string]string{
				"user.id":                "{{step.profile.json.id}}",
				"user.name":              "{{step.profile.json.name}}",
				"partial":                "{{bff.partial}}",
				"degraded":               "{{bff.degraded}}",
				"total_steps":            "{{bff.total_steps}}",
				"completed_steps":        "{{bff.completed_steps}}",
				"completed_count":        "{{bff.completed_count}}",
				"errors":                 "{{bff.errors}}",
				"error_summary":          "{{bff.error_summary}}",
				"failed_steps":           "{{bff.failed_steps}}",
				"failed_count":           "{{bff.failed_count}}",
				"skipped_count":          "{{bff.skipped_count}}",
				"recommendations_ok":     "{{step.recommendations.ok}}",
				"recommendations_status": "{{step.recommendations.status}}",
				"recommendations_error":  "{{step.recommendations.error}}",
			},
			ResponseHeaders: map[string]string{
				"X-BFF-Partial":       "{{bff.partial}}",
				"X-BFF-Error-Summary": "{{bff.error_summary}}",
				"X-BFF-Failed-Steps":  "{{bff.failed_steps | join:,}}",
				"X-BFF-Failed-Count":  "{{bff.failed_count}}",
				"X-BFF-Skipped-Steps": "{{bff.skipped_steps | join:,}}",
			},
		},
	})
	gw := newBFFTestGateway(t, cfg)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://gateway.local/partial/u123", nil)
	gw.GetRouter().ServeHTTP(rec, req)

	if rec.Code != http.StatusMultiStatus {
		t.Fatalf("expected partial BFF route to succeed, got %d: %s", rec.Code, rec.Body.String())
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("invalid json response: %v", err)
	}
	user := payload["user"].(map[string]interface{})
	if user["id"] != "u123" || user["name"] != "Aba" {
		t.Fatalf("expected sequential execution to continue after failed required step, got %#v", user)
	}
	if payload["partial"] != true || payload["degraded"] != true || payload["failed_count"] != float64(1) || payload["skipped_count"] != float64(0) {
		t.Fatalf("expected BFF summary fields, got partial=%#v degraded=%#v failed_count=%#v skipped_count=%#v", payload["partial"], payload["degraded"], payload["failed_count"], payload["skipped_count"])
	}
	if payload["total_steps"] != float64(2) || payload["completed_count"] != float64(1) {
		t.Fatalf("expected BFF step counts, got total=%#v completed=%#v", payload["total_steps"], payload["completed_count"])
	}
	assertBFFMetaStringSlice(t, "failed_steps", payload["failed_steps"], "recommendations")
	assertBFFMetaStringSlice(t, "completed_steps", payload["completed_steps"], "profile")
	if payload["recommendations_ok"] != false || payload["recommendations_status"] != float64(http.StatusOK) {
		t.Fatalf("expected failed step status to be shaped, got ok=%#v status=%#v", payload["recommendations_ok"], payload["recommendations_status"])
	}
	if got := rec.Header().Get("X-BFF-Partial"); got != "true" {
		t.Fatalf("expected partial response header true, got %q", got)
	}
	if got := rec.Header().Get("X-BFF-Failed-Steps"); got != "recommendations" {
		t.Fatalf("expected failed steps response header, got %q", got)
	}
	if got := rec.Header().Get("X-BFF-Failed-Count"); got != "1" {
		t.Fatalf("expected failed count response header, got %q", got)
	}
	if got := rec.Header().Get("X-BFF-Skipped-Steps"); got != "" {
		t.Fatalf("expected empty skipped steps response header, got %q", got)
	}
	wantError := "BFF step response body must contain valid JSON"
	recommendationsError, _ := payload["recommendations_error"].(string)
	if !strings.Contains(recommendationsError, wantError) {
		t.Fatalf("expected failed step error containing %q, got %#v", wantError, payload["recommendations_error"])
	}
	errorsPayload := payload["errors"].(map[string]interface{})
	errorsRecommendation, _ := errorsPayload["recommendations"].(string)
	if !strings.Contains(errorsRecommendation, wantError) {
		t.Fatalf("expected BFF errors map to contain %q, got %#v", wantError, payload["errors"])
	}
	errorSummary, _ := payload["error_summary"].(string)
	if !strings.Contains(errorSummary, "recommendations: "+wantError) {
		t.Fatalf("expected BFF error summary to contain failed step error, got %#v", payload["error_summary"])
	}
	if got := rec.Header().Get("X-BFF-Error-Summary"); !strings.Contains(got, "recommendations: "+wantError) {
		t.Fatalf("expected error summary response header to contain failed step error, got %q", got)
	}
	meta := payload["meta"].(map[string]interface{})
	if meta["partial"] != true {
		t.Fatalf("expected partial meta flag to be true, got %#v", meta["partial"])
	}
	if meta["degraded"] != true || meta["total_steps"] != float64(2) || meta["completed_count"] != float64(1) || meta["failed_count"] != float64(1) || meta["skipped_count"] != float64(0) {
		t.Fatalf("expected meta summary counts, got %#v", meta)
	}
	assertBFFMetaStringSlice(t, "completed_steps", meta["completed_steps"], "profile")
	assertBFFMetaStringSlice(t, "failed_steps", meta["failed_steps"], "recommendations")
	assertBFFMetaStringSlice(t, "skipped_steps", meta["skipped_steps"])
	metaErrors := meta["errors"].(map[string]interface{})
	metaError, _ := metaErrors["recommendations"].(string)
	if !strings.Contains(metaError, wantError) {
		t.Fatalf("expected meta errors map to contain %q, got %#v", wantError, meta["errors"])
	}
	steps := meta["steps"].(map[string]interface{})
	recommendationsMeta := steps["recommendations"].(map[string]interface{})
	recommendationsMetaError, _ := recommendationsMeta["error"].(string)
	if !strings.Contains(recommendationsMetaError, wantError) {
		t.Fatalf("expected meta error containing %q, got %#v", wantError, recommendationsMeta["error"])
	}
}

func TestBFFRouteUsesTemplateDefaults(t *testing.T) {
	profile := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"u123"}`))
	}))
	defer profile.Close()

	collector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("locale"); got != "en-US" {
			t.Fatalf("expected default locale query value, got %q", got)
		}
		if got := r.URL.Query().Get("name"); got != "Guest" {
			t.Fatalf("expected default name query value, got %q", got)
		}
		if got := r.Header.Get("X-Tier"); got != "free" {
			t.Fatalf("expected default tier header, got %q", got)
		}
		var body map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("expected JSON upstream body: %v", err)
		}
		if body["active"] != true {
			t.Fatalf("expected default active body value, got %#v", body["active"])
		}
		if body["limit"] != float64(10) {
			t.Fatalf("expected default limit body value, got %#v", body["limit"])
		}
		if body["name"] != "Guest" {
			t.Fatalf("expected default name body value, got %#v", body["name"])
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"accepted":true}`))
	}))
	defer collector.Close()

	cfg := bffTestConfig(config.RouterConfig{
		Path:     "/defaults/{user_id}",
		Method:   http.MethodPost,
		Protocol: "bff",
		BFF: &config.BFFConfig{
			Steps: []config.BFFStepConfig{
				{
					Name:    "collect",
					Method:  http.MethodPost,
					URL:     collector.URL + "/collect?locale={{request.json.locale|default:en-US}}&name={{step.profile.json.name|default:Guest}}",
					Headers: map[string]string{"X-Tier": "{{step.profile.json.tier | default:free}}"},
					Body:    `json:{"active":{{request.json.active | default:true}},"limit":{{query.limit | default:10}},"name":"{{step.profile.json.name | default:Guest}}"}`,
				},
				{
					Name: "profile",
					URL:  profile.URL + "/users/{{var.user_id}}",
				},
			},
			ResponseFields: map[string]string{
				"accepted": "{{step.collect.json.accepted}}",
				"active":   "{{request.json.active | default:true}}",
				"limit":    "{{query.limit | default:10}}",
				"locale":   "{{request.json.locale | default:en-US}}",
				"name":     "{{step.profile.json.name | default:Guest}}",
				"tier":     "{{step.profile.json.tier | default:free}}",
			},
		},
	})
	gw := newBFFTestGateway(t, cfg)

	req := httptest.NewRequest(http.MethodPost, "http://gateway.local/defaults/u123", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	gw.GetRouter().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("invalid json response: %v", err)
	}
	if payload["accepted"] != true || payload["active"] != true {
		t.Fatalf("expected boolean defaults in response, got %#v", payload)
	}
	if payload["limit"] != float64(10) {
		t.Fatalf("expected numeric default in response, got %#v", payload["limit"])
	}
	if payload["locale"] != "en-US" || payload["name"] != "Guest" || payload["tier"] != "free" {
		t.Fatalf("expected string defaults in response, got %#v", payload)
	}
}

func TestBFFRouteRequiredTemplateFilterFailsStepBeforeUpstream(t *testing.T) {
	calls := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer upstream.Close()

	cfg := bffTestConfig(config.RouterConfig{
		Path:     "/required-step",
		Method:   http.MethodPost,
		Protocol: "bff",
		BFF: &config.BFFConfig{
			Steps: []config.BFFStepConfig{{
				Name: "profile",
				URL:  upstream.URL + "/users/{{request.json.user_id | required:user_id required}}",
			}},
		},
	})
	gw := newBFFTestGateway(t, cfg)

	req := httptest.NewRequest(http.MethodPost, "http://gateway.local/required-step", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	gw.GetRouter().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("expected missing required template to return 502, got %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "user_id required") {
		t.Fatalf("expected required filter message in response, got %s", rec.Body.String())
	}
	if calls != 0 {
		t.Fatalf("expected missing required template to stop before upstream, got %d calls", calls)
	}
}

func TestBFFRouteRequiredTemplateFilterFailsResponseMapping(t *testing.T) {
	profile := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"u123"}`))
	}))
	defer profile.Close()

	cfg := bffTestConfig(config.RouterConfig{
		Path:   "/required-response",
		Method: http.MethodGet,
		BFF: &config.BFFConfig{
			Steps: []config.BFFStepConfig{{
				Name: "profile",
				URL:  profile.URL + "/users/u123",
			}},
			ResponseFields: map[string]string{
				"email": "{{step.profile.json.email | required:profile email missing}}",
			},
		},
	})
	gw := newBFFTestGateway(t, cfg)

	rec := httptest.NewRecorder()
	gw.GetRouter().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://gateway.local/required-response", nil))

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected missing required response template to return 500, got %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "profile email missing") {
		t.Fatalf("expected required response message, got %s", rec.Body.String())
	}
}

func TestBFFRouteUsesTemplateEncodingFilters(t *testing.T) {
	collector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/collect/team a" {
			t.Fatalf("expected urlpath-escaped path to decode correctly, got %q", r.URL.Path)
		}
		if r.URL.EscapedPath() != "/collect/team%20a" {
			t.Fatalf("expected escaped path to preserve encoding, got %q", r.URL.EscapedPath())
		}
		if got := r.URL.Query().Get("name"); got != `Aba "Ace" & Co` {
			t.Fatalf("expected urlquery name value, got %q", got)
		}
		if got := r.URL.Query().Get("note"); got != "line\nbreak & more" {
			t.Fatalf("expected urlquery note value, got %q", got)
		}
		var body map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("expected JSON upstream body: %v", err)
		}
		if body["name"] != `Aba "Ace" & Co` {
			t.Fatalf("expected json-encoded name body value, got %#v", body["name"])
		}
		if body["note"] != "line\nbreak & more" {
			t.Fatalf("expected json-encoded note body value, got %#v", body["note"])
		}
		if body["alias"] != "Guest" {
			t.Fatalf("expected default value to be json encoded, got %#v", body["alias"])
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"accepted":true}`))
	}))
	defer collector.Close()

	cfg := bffTestConfig(config.RouterConfig{
		Path:     "/encode",
		Method:   http.MethodPost,
		Protocol: "bff",
		BFF: &config.BFFConfig{
			Steps: []config.BFFStepConfig{{
				Name:   "collect",
				Method: http.MethodPost,
				URL:    collector.URL + "/collect/{{request.json.path|urlpath}}?name={{request.json.name|urlquery}}&note={{request.json.note|urlquery}}",
				Body:   `json:{"name":{{request.json.name | json}},"note":{{request.json.note | json}},"alias":{{request.json.alias | default:Guest | json}}}`,
			}},
			ResponseFields: map[string]string{
				"accepted": "{{step.collect.json.accepted}}",
			},
		},
	})
	gw := newBFFTestGateway(t, cfg)

	body := strings.NewReader(`{"name":"Aba \"Ace\" & Co","note":"line\nbreak & more","path":"team a"}`)
	req := httptest.NewRequest(http.MethodPost, "http://gateway.local/encode", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	gw.GetRouter().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("invalid json response: %v", err)
	}
	if payload["accepted"] != true {
		t.Fatalf("expected accepted response, got %#v", payload)
	}
}

func TestBFFRouteUsesStringTemplateFilters(t *testing.T) {
	collector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/normalize/aba-ace" {
			t.Fatalf("expected normalized path, got %q", r.URL.Path)
		}
		if got := r.URL.Query().Get("code"); got != "ABA_123" {
			t.Fatalf("expected upper replace query value, got %q", got)
		}
		if got := r.Header.Get("X-Normalized-Name"); got != "aba ace" {
			t.Fatalf("expected lower trimmed header, got %q", got)
		}
		if got := r.Header.Get("X-Normalized-Tags"); got != "vip,beta" {
			t.Fatalf("expected normalized tag array header, got %q", got)
		}
		var body map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("expected JSON upstream body: %v", err)
		}
		if body["name"] != "aba ace" {
			t.Fatalf("expected normalized name body, got %#v", body["name"])
		}
		tags, ok := body["tags"].([]interface{})
		if !ok || len(tags) != 2 || tags[0] != "vip" || tags[1] != "beta" {
			t.Fatalf("expected normalized unique tag array, got %#v", body["tags"])
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"accepted":true}`))
	}))
	defer collector.Close()

	cfg := bffTestConfig(config.RouterConfig{
		Path:     "/normalize",
		Method:   http.MethodPost,
		Protocol: "bff",
		BFF: &config.BFFConfig{
			Steps: []config.BFFStepConfig{{
				Name:   "collect",
				Method: http.MethodPost,
				URL:    collector.URL + "/normalize/{{request.json.name | trim | lower | replace: ,- | urlpath}}?code={{request.json.code | upper | replace:-,_ | urlquery}}",
				Headers: map[string]string{
					"X-Normalized-Name": "{{request.json.name | trim | lower}}",
					"X-Normalized-Tags": "{{request.json.tags[] | trim | lower | compact | unique | join:,}}",
				},
				Body: `json:{"name":{{request.json.name | trim | lower | json}},"tags":{{request.json.tags[] | trim | lower | compact | unique | json}}}`,
			}},
			ResponseFields: map[string]string{
				"accepted": "{{step.collect.json.accepted}}",
				"name":     "{{request.json.name | trim | lower}}",
				"tags":     "{{request.json.tags[] | trim | lower | compact | unique}}",
			},
		},
	})
	gw := newBFFTestGateway(t, cfg)

	body := strings.NewReader(`{"name":"  Aba Ace  ","code":"aba-123","tags":[" VIP ","vip","Beta"," "]}`)
	req := httptest.NewRequest(http.MethodPost, "http://gateway.local/normalize", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	gw.GetRouter().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("invalid json response: %v", err)
	}
	if payload["accepted"] != true || payload["name"] != "aba ace" {
		t.Fatalf("expected normalized response fields, got %#v", payload)
	}
	tags := payload["tags"].([]interface{})
	if len(tags) != 2 || tags[0] != "vip" || tags[1] != "beta" {
		t.Fatalf("expected normalized response tags, got %#v", tags)
	}
}

func TestBFFRouteUsesWildcardJSONPathTemplateValues(t *testing.T) {
	catalog := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("skus"); got != "sku-1,sku-2" {
			t.Fatalf("expected compact unique joined request wildcard skus query value, got %q", got)
		}
		if got := r.Header.Get("X-Sku-Count"); got != "2" {
			t.Fatalf("expected compact unique request wildcard len header, got %q", got)
		}
		if got := r.Header.Get("X-First-Sku"); got != "sku-1" {
			t.Fatalf("expected first request wildcard header, got %q", got)
		}
		if got := r.Header.Get("X-Last-Sku"); got != "sku-1" {
			t.Fatalf("expected last request wildcard header, got %q", got)
		}
		var body map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("expected JSON upstream body: %v", err)
		}
		skus, ok := body["skus"].([]interface{})
		if !ok {
			t.Fatalf("expected request wildcard skus array, got %#v", body["skus"])
		}
		if len(skus) != 2 || skus[0] != "sku-1" || skus[1] != "sku-2" {
			t.Fatalf("expected compact unique request wildcard skus to be preserved, got %#v", skus)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"products":[{"id":"p1","price":10},{"id":"p2","price":20},{"id":"p1","price":30},{"id":"","price":40}],"empty":[]}`))
	}))
	defer catalog.Close()

	cfg := bffTestConfig(config.RouterConfig{
		Path:     "/wildcard",
		Method:   http.MethodPost,
		Protocol: "bff",
		BFF: &config.BFFConfig{
			Steps: []config.BFFStepConfig{{
				Name:   "catalog",
				Method: http.MethodPost,
				URL:    catalog.URL + "/catalog?skus={{request.json.items[].sku | compact | unique | join:, | urlquery}}",
				Headers: map[string]string{
					"X-First-Sku": "{{request.json.items[].sku | compact | first}}",
					"X-Last-Sku":  "{{request.json.items[].sku | compact | last}}",
					"X-Sku-Count": "{{request.json.items[].sku | compact | unique | len}}",
				},
				Body: `json:{"skus":{{request.json.items[].sku | compact | unique | json}}}`,
			}},
			ResponseFields: map[string]string{
				"empty":       "{{step.catalog.json.empty[]}}",
				"empty_count": "{{step.catalog.json.empty[] | len}}",
				"empty_first": "{{step.catalog.json.empty[] | first | default:none}}",
				"first_id":    "{{step.catalog.json.products[0].id}}",
				"id_count":    "{{step.catalog.json.products[].id | compact | unique | len}}",
				"ids_csv":     "{{step.catalog.json.products[].id | compact | unique | join:;}}",
				"last_id":     "{{step.catalog.json.products[].id | compact | last}}",
				"prices":      "{{step.catalog.json.products[].price}}",
				"product_ids": "{{step.catalog.json.products[].id}}",
				"skus":        "{{request.json.items[].sku}}",
				"skus_csv":    "{{request.json.items[].sku | compact | unique | join:,}}",
			},
		},
	})
	gw := newBFFTestGateway(t, cfg)

	body := strings.NewReader(`{"items":[{"sku":"sku-1"},{"sku":"sku-2"},{"sku":""},{"sku":"sku-1"},{"missing":true}]}`)
	req := httptest.NewRequest(http.MethodPost, "http://gateway.local/wildcard", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	gw.GetRouter().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("invalid json response: %v", err)
	}
	skus := payload["skus"].([]interface{})
	if len(skus) != 4 || skus[0] != "sku-1" || skus[1] != "sku-2" || skus[2] != "" || skus[3] != "sku-1" {
		t.Fatalf("expected raw request wildcard skus in response, got %#v", skus)
	}
	productIDs := payload["product_ids"].([]interface{})
	if len(productIDs) != 4 || productIDs[0] != "p1" || productIDs[1] != "p2" || productIDs[2] != "p1" || productIDs[3] != "" {
		t.Fatalf("expected product ids from wildcard response path, got %#v", productIDs)
	}
	prices := payload["prices"].([]interface{})
	if len(prices) != 4 || prices[0] != float64(10) || prices[1] != float64(20) || prices[2] != float64(30) || prices[3] != float64(40) {
		t.Fatalf("expected prices from wildcard response path, got %#v", prices)
	}
	if payload["first_id"] != "p1" {
		t.Fatalf("expected indexed path to still return scalar, got %#v", payload["first_id"])
	}
	if payload["last_id"] != "p1" {
		t.Fatalf("expected compact last wildcard value, got %#v", payload["last_id"])
	}
	if payload["id_count"] != float64(2) || payload["empty_count"] != float64(0) {
		t.Fatalf("expected wildcard counts, got id_count=%#v empty_count=%#v", payload["id_count"], payload["empty_count"])
	}
	if payload["ids_csv"] != "p1;p2" || payload["skus_csv"] != "sku-1,sku-2" {
		t.Fatalf("expected joined wildcard values, got ids=%#v skus=%#v", payload["ids_csv"], payload["skus_csv"])
	}
	if payload["empty_first"] != "none" {
		t.Fatalf("expected first on empty wildcard array to allow default, got %#v", payload["empty_first"])
	}
	empty := payload["empty"].([]interface{})
	if len(empty) != 0 {
		t.Fatalf("expected empty wildcard array, got %#v", empty)
	}
}

func TestBFFRouteTreatsConfiguredStatusAsSuccess(t *testing.T) {
	profile := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"found":false}`))
	}))
	defer profile.Close()

	cfg := bffTestConfig(config.RouterConfig{
		Path:   "/lookup/{user_id}",
		Method: http.MethodGet,
		BFF: &config.BFFConfig{
			Steps: []config.BFFStepConfig{{
				Name:            "profile",
				URL:             profile.URL + "/users/{{var.user_id}}",
				SuccessStatuses: []int{http.StatusOK, http.StatusNotFound},
			}},
			ResponseFields: map[string]string{
				"found":  "{{step.profile.json.found}}",
				"ok":     "{{step.profile.ok}}",
				"status": "{{step.profile.status}}",
			},
		},
	})
	gw := newBFFTestGateway(t, cfg)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://gateway.local/lookup/u404", nil)
	gw.GetRouter().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected configured 404 success to keep BFF response successful, got %d: %s", rec.Code, rec.Body.String())
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("invalid json response: %v", err)
	}
	if payload["found"] != false || payload["ok"] != true || payload["status"] != float64(http.StatusNotFound) {
		t.Fatalf("expected 404 to be exposed as successful domain result, got %#v", payload)
	}
}

func TestBFFRouteSkipsConditionalStep(t *testing.T) {
	profile := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"u123"}`))
	}))
	defer profile.Close()

	recommendationCalls := 0
	recommendations := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		recommendationCalls++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"items":["one"]}`))
	}))
	defer recommendations.Close()

	cfg := bffTestConfig(config.RouterConfig{
		Path:   "/conditional/{user_id}",
		Method: http.MethodGet,
		BFF: &config.BFFConfig{
			IncludeMeta: true,
			Steps: []config.BFFStepConfig{
				{Name: "profile", URL: profile.URL + "/users/{{var.user_id}}"},
				{
					Name: "recommendations",
					URL:  recommendations.URL + "/users/{{var.user_id}}/recommendations",
					When: "{{query.include_recs}} == true",
					WhenHeaders: map[string]string{
						"X-Client-Mode": "full",
					},
					WhenQueryParams: map[string]string{
						"client": "mobile",
					},
				},
			},
			ResponseFields: map[string]string{
				"user_id":                 "{{step.profile.json.id}}",
				"partial":                 "{{bff.partial}}",
				"degraded":                "{{bff.degraded}}",
				"total_steps":             "{{bff.total_steps}}",
				"completed_count":         "{{bff.completed_count}}",
				"failed_count":            "{{bff.failed_count}}",
				"skipped_count":           "{{bff.skipped_count}}",
				"recommendations_ok":      "{{step.recommendations.ok}}",
				"recommendations_skipped": "{{step.recommendations.skipped}}",
				"recommendations_status":  "{{step.recommendations.status}}",
			},
		},
	})
	gw := newBFFTestGateway(t, cfg)

	skipped := httptest.NewRecorder()
	gw.GetRouter().ServeHTTP(skipped, httptest.NewRequest(http.MethodGet, "http://gateway.local/conditional/u123", nil))
	if skipped.Code != http.StatusOK {
		t.Fatalf("expected skipped required step to still succeed, got %d: %s", skipped.Code, skipped.Body.String())
	}
	if recommendationCalls != 0 {
		t.Fatalf("expected skipped conditional step to avoid upstream call, got %d", recommendationCalls)
	}
	var skippedPayload map[string]interface{}
	if err := json.Unmarshal(skipped.Body.Bytes(), &skippedPayload); err != nil {
		t.Fatalf("invalid skipped json response: %v", err)
	}
	if skippedPayload["user_id"] != "u123" {
		t.Fatalf("expected profile response to remain available, got %#v", skippedPayload["user_id"])
	}
	if skippedPayload["recommendations_skipped"] != true || skippedPayload["recommendations_ok"] != false {
		t.Fatalf("expected skipped token true and ok token false, got skipped=%#v ok=%#v", skippedPayload["recommendations_skipped"], skippedPayload["recommendations_ok"])
	}
	if skippedPayload["recommendations_status"] != float64(0) {
		t.Fatalf("expected skipped step status 0, got %#v", skippedPayload["recommendations_status"])
	}
	if skippedPayload["partial"] != false || skippedPayload["degraded"] != true || skippedPayload["failed_count"] != float64(0) || skippedPayload["skipped_count"] != float64(1) {
		t.Fatalf("expected skipped summary fields, got partial=%#v degraded=%#v failed_count=%#v skipped_count=%#v", skippedPayload["partial"], skippedPayload["degraded"], skippedPayload["failed_count"], skippedPayload["skipped_count"])
	}
	if skippedPayload["total_steps"] != float64(2) || skippedPayload["completed_count"] != float64(1) {
		t.Fatalf("expected skipped step counts, got total=%#v completed=%#v", skippedPayload["total_steps"], skippedPayload["completed_count"])
	}
	meta := skippedPayload["meta"].(map[string]interface{})
	if meta["partial"] != false {
		t.Fatalf("expected skipped-only response to not be partial, got %#v", meta["partial"])
	}
	if meta["degraded"] != true || meta["total_steps"] != float64(2) || meta["completed_count"] != float64(1) || meta["failed_count"] != float64(0) || meta["skipped_count"] != float64(1) {
		t.Fatalf("expected skipped meta summary counts, got %#v", meta)
	}
	assertBFFMetaStringSlice(t, "completed_steps", meta["completed_steps"], "profile")
	assertBFFMetaStringSlice(t, "failed_steps", meta["failed_steps"])
	assertBFFMetaStringSlice(t, "skipped_steps", meta["skipped_steps"], "recommendations")
	steps := meta["steps"].(map[string]interface{})
	recommendationsMeta := steps["recommendations"].(map[string]interface{})
	if recommendationsMeta["skipped"] != true {
		t.Fatalf("expected meta skipped flag to be true, got %#v", recommendationsMeta["skipped"])
	}

	included := httptest.NewRecorder()
	includedReq := httptest.NewRequest(http.MethodGet, "http://gateway.local/conditional/u123?include_recs=true&client=mobile", nil)
	includedReq.Header.Set("X-Client-Mode", "full")
	gw.GetRouter().ServeHTTP(included, includedReq)
	if included.Code != http.StatusOK {
		t.Fatalf("expected included conditional step to succeed, got %d: %s", included.Code, included.Body.String())
	}
	if recommendationCalls != 1 {
		t.Fatalf("expected included conditional step to call upstream once, got %d", recommendationCalls)
	}
	var includedPayload map[string]interface{}
	if err := json.Unmarshal(included.Body.Bytes(), &includedPayload); err != nil {
		t.Fatalf("invalid included json response: %v", err)
	}
	if includedPayload["recommendations_skipped"] != false || includedPayload["recommendations_ok"] != true {
		t.Fatalf("expected included step skipped=false and ok=true, got skipped=%#v ok=%#v", includedPayload["recommendations_skipped"], includedPayload["recommendations_ok"])
	}
	if includedPayload["partial"] != false || includedPayload["degraded"] != false || includedPayload["failed_count"] != float64(0) || includedPayload["skipped_count"] != float64(0) {
		t.Fatalf("expected included summary fields, got partial=%#v degraded=%#v failed_count=%#v skipped_count=%#v", includedPayload["partial"], includedPayload["degraded"], includedPayload["failed_count"], includedPayload["skipped_count"])
	}
	if includedPayload["total_steps"] != float64(2) || includedPayload["completed_count"] != float64(2) {
		t.Fatalf("expected included step counts, got total=%#v completed=%#v", includedPayload["total_steps"], includedPayload["completed_count"])
	}
}

func TestBFFRouteUsesStepFallbackOnUpstreamFailure(t *testing.T) {
	profile := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "temporarily unavailable", http.StatusServiceUnavailable)
	}))
	defer profile.Close()

	cfg := bffTestConfig(config.RouterConfig{
		Path:   "/fallback/{user_id}",
		Method: http.MethodGet,
		BFF: &config.BFFConfig{
			IncludeMeta: true,
			Steps: []config.BFFStepConfig{{
				Name: "profile",
				URL:  profile.URL + "/users/{{var.user_id}}",
				Fallback: &config.BFFStepFallback{
					Status: http.StatusOK,
					Body:   `json:{"id":"{{var.user_id}}","name":"Guest"}`,
					Headers: map[string]string{
						"X-Fallback-Source": "static-profile",
					},
				},
			}},
			ResponseFields: map[string]string{
				"user.id":          "{{step.profile.json.id}}",
				"user.name":        "{{step.profile.json.name}}",
				"profile_status":   "{{step.profile.status}}",
				"profile_source":   "{{step.profile.header.X-Fallback-Source}}",
				"profile_fallback": "{{step.profile.fallback}}",
			},
		},
	})
	gw := newBFFTestGateway(t, cfg)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://gateway.local/fallback/u123", nil)
	gw.GetRouter().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected fallback to recover required step, got %d: %s", rec.Code, rec.Body.String())
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("invalid json response: %v", err)
	}
	user := payload["user"].(map[string]interface{})
	if user["id"] != "u123" || user["name"] != "Guest" {
		t.Fatalf("unexpected fallback user: %#v", user)
	}
	if payload["profile_status"] != float64(http.StatusOK) {
		t.Fatalf("expected fallback status 200, got %#v", payload["profile_status"])
	}
	if payload["profile_source"] != "static-profile" {
		t.Fatalf("expected fallback header source, got %#v", payload["profile_source"])
	}
	if payload["profile_fallback"] != true {
		t.Fatalf("expected fallback token to be true, got %#v", payload["profile_fallback"])
	}
	meta := payload["meta"].(map[string]interface{})
	steps := meta["steps"].(map[string]interface{})
	profileMeta := steps["profile"].(map[string]interface{})
	if profileMeta["fallback"] != true {
		t.Fatalf("expected meta fallback flag to be exposed, got %#v", profileMeta["fallback"])
	}
}

func TestBFFRouteUsesFallbackOnOversizedStepResponse(t *testing.T) {
	profile := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"blob":"` + strings.Repeat("x", 64) + `"}`))
	}))
	defer profile.Close()

	cfg := bffTestConfig(config.RouterConfig{
		Path:   "/limited/{user_id}",
		Method: http.MethodGet,
		BFF: &config.BFFConfig{
			MaxStepResponseBodyBytes: 16,
			Steps: []config.BFFStepConfig{{
				Name: "profile",
				URL:  profile.URL + "/users/{{var.user_id}}",
				Fallback: &config.BFFStepFallback{
					Status: http.StatusOK,
					Body:   `json:{"id":"{{var.user_id}}","limited":true}`,
				},
			}},
			ResponseFields: map[string]string{
				"user_id":  "{{step.profile.json.id}}",
				"limited":  "{{step.profile.json.limited}}",
				"fallback": "{{step.profile.fallback}}",
			},
		},
	})
	gw := newBFFTestGateway(t, cfg)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://gateway.local/limited/u123", nil)
	gw.GetRouter().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected fallback to recover oversized response, got %d: %s", rec.Code, rec.Body.String())
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("invalid json response: %v", err)
	}
	if payload["user_id"] != "u123" || payload["limited"] != true || payload["fallback"] != true {
		t.Fatalf("expected limited fallback payload, got %#v", payload)
	}
}

func TestBFFRouteUsesFallbackOnInvalidRequiredJSON(t *testing.T) {
	profile := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte(`not-json`))
	}))
	defer profile.Close()

	cfg := bffTestConfig(config.RouterConfig{
		Path:   "/json-required/{user_id}",
		Method: http.MethodGet,
		BFF: &config.BFFConfig{
			Steps: []config.BFFStepConfig{{
				Name:        "profile",
				URL:         profile.URL + "/users/{{var.user_id}}",
				RequireJSON: true,
				Fallback: &config.BFFStepFallback{
					Status: http.StatusOK,
					Body:   `json:{"id":"{{var.user_id}}","source":"fallback"}`,
				},
			}},
			ResponseFields: map[string]string{
				"user_id":  "{{step.profile.json.id}}",
				"source":   "{{step.profile.json.source}}",
				"fallback": "{{step.profile.fallback}}",
			},
		},
	})
	gw := newBFFTestGateway(t, cfg)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://gateway.local/json-required/u123", nil)
	gw.GetRouter().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected fallback to recover invalid required json, got %d: %s", rec.Code, rec.Body.String())
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("invalid json response: %v", err)
	}
	if payload["user_id"] != "u123" || payload["source"] != "fallback" || payload["fallback"] != true {
		t.Fatalf("expected invalid JSON fallback payload, got %#v", payload)
	}
}

func TestBFFRouteUsesFallbackOnMissingRequiredJSONPath(t *testing.T) {
	profile := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"u123"}`))
	}))
	defer profile.Close()

	cfg := bffTestConfig(config.RouterConfig{
		Path:   "/json-path-required/{user_id}",
		Method: http.MethodGet,
		BFF: &config.BFFConfig{
			Steps: []config.BFFStepConfig{{
				Name:              "profile",
				URL:               profile.URL + "/users/{{var.user_id}}",
				RequiredJSONPaths: []string{"plan.tier"},
				Fallback: &config.BFFStepFallback{
					Status: http.StatusOK,
					Body:   `json:{"id":"{{var.user_id}}","plan":{"tier":"free"},"source":"fallback"}`,
				},
			}},
			ResponseFields: map[string]string{
				"user_id":  "{{step.profile.json.id}}",
				"tier":     "{{step.profile.json.plan.tier}}",
				"source":   "{{step.profile.json.source}}",
				"fallback": "{{step.profile.fallback}}",
			},
		},
	})
	gw := newBFFTestGateway(t, cfg)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://gateway.local/json-path-required/u123", nil)
	gw.GetRouter().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected fallback to recover missing required json path, got %d: %s", rec.Code, rec.Body.String())
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("invalid json response: %v", err)
	}
	if payload["user_id"] != "u123" || payload["tier"] != "free" || payload["source"] != "fallback" || payload["fallback"] != true {
		t.Fatalf("expected missing path fallback payload, got %#v", payload)
	}
}

func TestBFFRouteCanBeEnabledOnTheFly(t *testing.T) {
	bffDisabled := false
	legacy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"mode":"legacy"}`))
	}))
	defer legacy.Close()
	profile := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"u123","name":"Aba"}`))
	}))
	defer profile.Close()

	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Services: []config.ServiceConfig{{
			Version: 1,
			Services: []config.Service{{
				Name: "app",
				Host: legacy.URL,
				Routes: []config.RouterConfig{{
					Path:     "/app/{user_id}",
					Method:   http.MethodGet,
					Backends: []config.Backend{{URLPattern: "/app/{user_id}"}},
					BFF: &config.BFFConfig{
						Enabled: &bffDisabled,
						Steps: []config.BFFStepConfig{{
							Name: "profile",
							URL:  profile.URL + "/users/{{var.user_id}}",
						}},
						ResponseFields: map[string]string{
							"mode": "bff",
							"name": "{{step.profile.json.name}}",
						},
					},
				}},
			}},
		}},
	}
	gw := newBFFTestGateway(t, cfg)

	initial := httptest.NewRecorder()
	gw.GetRouter().ServeHTTP(initial, httptest.NewRequest(http.MethodGet, "http://gateway.local/app/u123", nil))
	if initial.Code != http.StatusOK {
		t.Fatalf("expected initial route to proxy, got %d: %s", initial.Code, initial.Body.String())
	}
	var initialPayload map[string]interface{}
	if err := json.Unmarshal(initial.Body.Bytes(), &initialPayload); err != nil {
		t.Fatalf("invalid initial json response: %v", err)
	}
	if initialPayload["mode"] != "legacy" {
		t.Fatalf("expected initial legacy response, got %#v", initialPayload)
	}

	updated := bffTestConfig(config.RouterConfig{
		Path:     "/app/{user_id}",
		Method:   http.MethodGet,
		Protocol: "bff",
		BFF: &config.BFFConfig{
			Steps: []config.BFFStepConfig{{
				Name: "profile",
				URL:  profile.URL + "/users/{{var.user_id}}",
			}},
			ResponseFields: map[string]string{
				"mode": "bff",
				"name": "{{step.profile.json.name}}",
			},
		},
	})
	if err := gw.UpdateConfig(updated); err != nil {
		t.Fatalf("UpdateConfig returned error: %v", err)
	}

	rec := httptest.NewRecorder()
	gw.GetRouter().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://gateway.local/app/u123", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected hot-enabled bff route to respond, got %d: %s", rec.Code, rec.Body.String())
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("invalid json response: %v", err)
	}
	if payload["mode"] != "bff" || payload["name"] != "Aba" {
		t.Fatalf("expected hot-enabled bff response, got %#v", payload)
	}
}

func TestBFFRouteRecordsStepMetrics(t *testing.T) {
	profile := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"u123"}`))
	}))
	defer profile.Close()

	collector := metrics.NewCollector()
	cfg := bffTestConfig(config.RouterConfig{
		Path:   "/metrics/{user_id}",
		Method: http.MethodGet,
		BFF: &config.BFFConfig{
			Steps: []config.BFFStepConfig{{
				Name: "profile",
				URL:  profile.URL + "/users/{{var.user_id}}",
			}},
			ResponseFields: map[string]string{
				"user_id": "{{step.profile.json.id}}",
			},
		},
	})
	gw, err := NewGateway(Dependencies{Config: cfg, Logger: logging.NewLogger(false), Metrics: collector}, "test")
	if err != nil {
		t.Fatalf("NewGateway returned error: %v", err)
	}
	if err := gw.Initialize(); err != nil {
		t.Fatalf("Initialize returned error: %v", err)
	}

	rec := httptest.NewRecorder()
	gw.GetRouter().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://gateway.local/metrics/u123", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	metricsRec := httptest.NewRecorder()
	collector.ServeHTTP(metricsRec, httptest.NewRequest(http.MethodGet, "http://gateway.local/metrics", nil))
	metricsBody := metricsRec.Body.String()
	for _, want := range []string{
		"gateway_bff_step_requests_total",
		`route="/metrics/{user_id}"`,
		`step="profile"`,
		`status="200"`,
		`required="true"`,
		`outcome="success"`,
		"gateway_bff_step_duration_seconds",
	} {
		if !strings.Contains(metricsBody, want) {
			t.Fatalf("expected metrics output to contain %s, got:\n%s", want, metricsBody)
		}
	}
}

func TestBFFRouteRetriesStepRetryableStatus(t *testing.T) {
	attempts := 0
	profile := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts == 1 {
			http.Error(w, "try again", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"u123","name":"Aba"}`))
	}))
	defer profile.Close()

	cfg := bffTestConfig(config.RouterConfig{
		Path:   "/retry/{user_id}",
		Method: http.MethodGet,
		BFF: &config.BFFConfig{
			IncludeMeta: true,
			Steps: []config.BFFStepConfig{{
				Name:       "profile",
				URL:        profile.URL + "/users/{{var.user_id}}",
				RetryCount: 1,
			}},
			ResponseFields: map[string]string{
				"name":     "{{step.profile.json.name}}",
				"attempts": "{{step.profile.attempts}}",
			},
		},
	})
	gw := newBFFTestGateway(t, cfg)

	rec := httptest.NewRecorder()
	gw.GetRouter().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://gateway.local/retry/u123", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("expected retry to recover, got %d: %s", rec.Code, rec.Body.String())
	}
	if attempts != 2 {
		t.Fatalf("expected upstream to be called twice, got %d", attempts)
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("invalid json response: %v", err)
	}
	if payload["name"] != "Aba" {
		t.Fatalf("expected retried upstream response, got %#v", payload["name"])
	}
	if payload["attempts"] != float64(2) {
		t.Fatalf("expected attempts to be exposed, got %#v", payload["attempts"])
	}
	meta := payload["meta"].(map[string]interface{})
	steps := meta["steps"].(map[string]interface{})
	profileMeta := steps["profile"].(map[string]interface{})
	if profileMeta["attempts"] != float64(2) {
		t.Fatalf("expected meta attempts to be exposed, got %#v", profileMeta["attempts"])
	}
}

func TestBFFRouteCachesStepResponse(t *testing.T) {
	calls := 0
	profile := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"u123","name":"Aba"}`))
	}))
	defer profile.Close()

	cfg := bffTestConfig(config.RouterConfig{
		Path:   "/cached/{user_id}",
		Method: http.MethodGet,
		BFF: &config.BFFConfig{
			IncludeMeta: true,
			Steps: []config.BFFStepConfig{{
				Name:     "profile",
				URL:      profile.URL + "/users/{{var.user_id}}",
				CacheTTL: "1m",
			}},
			ResponseFields: map[string]string{
				"name":      "{{step.profile.json.name}}",
				"cache_hit": "{{step.profile.cache_hit}}",
				"attempts":  "{{step.profile.attempts}}",
			},
		},
	})
	gw := newBFFTestGateway(t, cfg)

	first := httptest.NewRecorder()
	gw.GetRouter().ServeHTTP(first, httptest.NewRequest(http.MethodGet, "http://gateway.local/cached/u123", nil))
	if first.Code != http.StatusOK {
		t.Fatalf("expected first request to succeed, got %d: %s", first.Code, first.Body.String())
	}

	second := httptest.NewRecorder()
	gw.GetRouter().ServeHTTP(second, httptest.NewRequest(http.MethodGet, "http://gateway.local/cached/u123", nil))
	if second.Code != http.StatusOK {
		t.Fatalf("expected second request to succeed, got %d: %s", second.Code, second.Body.String())
	}
	if calls != 1 {
		t.Fatalf("expected cached step to call upstream once, got %d", calls)
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(second.Body.Bytes(), &payload); err != nil {
		t.Fatalf("invalid json response: %v", err)
	}
	if payload["name"] != "Aba" {
		t.Fatalf("expected cached upstream value, got %#v", payload["name"])
	}
	if payload["cache_hit"] != true {
		t.Fatalf("expected second response to expose cache hit, got %#v", payload["cache_hit"])
	}
	if payload["attempts"] != float64(0) {
		t.Fatalf("expected cached response to use zero upstream attempts, got %#v", payload["attempts"])
	}
	meta := payload["meta"].(map[string]interface{})
	steps := meta["steps"].(map[string]interface{})
	profileMeta := steps["profile"].(map[string]interface{})
	if profileMeta["cache_hit"] != true {
		t.Fatalf("expected meta cache hit to be exposed, got %#v", profileMeta["cache_hit"])
	}
}

func TestBFFRouteCoalescesConcurrentCacheMisses(t *testing.T) {
	var mu sync.Mutex
	calls := 0
	started := make(chan struct{})
	release := make(chan struct{})
	profile := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		calls++
		if calls == 1 {
			close(started)
		}
		mu.Unlock()
		<-release
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"u123","name":"Aba"}`))
	}))
	defer profile.Close()

	cfg := bffTestConfig(config.RouterConfig{
		Path:   "/coalesced/{user_id}",
		Method: http.MethodGet,
		BFF: &config.BFFConfig{
			Steps: []config.BFFStepConfig{{
				Name:     "profile",
				URL:      profile.URL + "/users/{{var.user_id}}",
				CacheTTL: "1m",
			}},
			ResponseFields: map[string]string{
				"name":      "{{step.profile.json.name}}",
				"coalesced": "{{step.profile.coalesced}}",
			},
		},
	})
	gw := newBFFTestGateway(t, cfg)

	const waiters = 6
	recorders := make([]*httptest.ResponseRecorder, waiters+1)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		recorders[0] = httptest.NewRecorder()
		gw.GetRouter().ServeHTTP(recorders[0], httptest.NewRequest(http.MethodGet, "http://gateway.local/coalesced/u123", nil))
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for first upstream call")
	}

	for i := 1; i <= waiters; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			recorders[i] = httptest.NewRecorder()
			gw.GetRouter().ServeHTTP(recorders[i], httptest.NewRequest(http.MethodGet, "http://gateway.local/coalesced/u123", nil))
		}()
	}
	time.Sleep(20 * time.Millisecond)
	close(release)
	wg.Wait()

	mu.Lock()
	gotCalls := calls
	mu.Unlock()
	if gotCalls != 1 {
		t.Fatalf("expected concurrent cache miss to make one upstream call, got %d", gotCalls)
	}

	coalescedResponses := 0
	for i, rec := range recorders {
		if rec.Code != http.StatusOK {
			t.Fatalf("response %d expected 200, got %d: %s", i, rec.Code, rec.Body.String())
		}
		var payload map[string]interface{}
		if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
			t.Fatalf("response %d invalid json: %v", i, err)
		}
		if payload["name"] != "Aba" {
			t.Fatalf("response %d expected composed value, got %#v", i, payload["name"])
		}
		if payload["coalesced"] == true {
			coalescedResponses++
		}
	}
	if coalescedResponses == 0 {
		t.Fatal("expected at least one waiter to report coalesced=true")
	}
}

func TestBFFRouteServesStaleCachedStepOnUpstreamFailure(t *testing.T) {
	calls := 0
	fail := false
	profile := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if fail {
			http.Error(w, "temporarily unavailable", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"u123","name":"Aba"}`))
	}))
	defer profile.Close()

	cfg := bffTestConfig(config.RouterConfig{
		Path:   "/stale/{user_id}",
		Method: http.MethodGet,
		BFF: &config.BFFConfig{
			IncludeMeta: true,
			Steps: []config.BFFStepConfig{{
				Name:         "profile",
				URL:          profile.URL + "/users/{{var.user_id}}",
				CacheTTL:     "1ms",
				StaleIfError: "1m",
			}},
			ResponseFields: map[string]string{
				"name":        "{{step.profile.json.name}}",
				"cache_hit":   "{{step.profile.cache_hit}}",
				"cache_stale": "{{step.profile.cache_stale}}",
				"attempts":    "{{step.profile.attempts}}",
			},
		},
	})
	gw := newBFFTestGateway(t, cfg)

	first := httptest.NewRecorder()
	gw.GetRouter().ServeHTTP(first, httptest.NewRequest(http.MethodGet, "http://gateway.local/stale/u123", nil))
	if first.Code != http.StatusOK {
		t.Fatalf("expected first request to succeed, got %d: %s", first.Code, first.Body.String())
	}

	time.Sleep(5 * time.Millisecond)
	fail = true

	second := httptest.NewRecorder()
	gw.GetRouter().ServeHTTP(second, httptest.NewRequest(http.MethodGet, "http://gateway.local/stale/u123", nil))
	if second.Code != http.StatusOK {
		t.Fatalf("expected stale fallback to succeed, got %d: %s", second.Code, second.Body.String())
	}
	if calls != 2 {
		t.Fatalf("expected one fresh call and one failed refresh call, got %d", calls)
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(second.Body.Bytes(), &payload); err != nil {
		t.Fatalf("invalid json response: %v", err)
	}
	if payload["name"] != "Aba" {
		t.Fatalf("expected stale cached value, got %#v", payload["name"])
	}
	if payload["cache_hit"] != true || payload["cache_stale"] != true {
		t.Fatalf("expected stale cache flags, got cache_hit=%#v cache_stale=%#v", payload["cache_hit"], payload["cache_stale"])
	}
	if payload["attempts"] != float64(1) {
		t.Fatalf("expected stale fallback to expose refresh attempts, got %#v", payload["attempts"])
	}
	meta := payload["meta"].(map[string]interface{})
	steps := meta["steps"].(map[string]interface{})
	profileMeta := steps["profile"].(map[string]interface{})
	if profileMeta["cache_stale"] != true {
		t.Fatalf("expected meta stale flag to be exposed, got %#v", profileMeta["cache_stale"])
	}
}

func assertBFFMetaStringSlice(t *testing.T, field string, value interface{}, want ...string) {
	t.Helper()
	raw, ok := value.([]interface{})
	if !ok {
		t.Fatalf("expected meta %s to be an array, got %#v", field, value)
	}
	got := make([]string, 0, len(raw))
	for _, item := range raw {
		text, ok := item.(string)
		if !ok {
			t.Fatalf("expected meta %s entries to be strings, got %#v", field, raw)
		}
		got = append(got, text)
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("expected meta %s %v, got %v", field, want, got)
	}
}

func bffTestConfig(route config.RouterConfig) *config.Config {
	return &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Services: []config.ServiceConfig{{
			Version: 1,
			Services: []config.Service{{
				Name:   "bff",
				Host:   "http://gateway.local",
				Routes: []config.RouterConfig{route},
			}},
		}},
	}
}

func newBFFTestGateway(t *testing.T, cfg *config.Config) *Gateway {
	t.Helper()
	gw, err := NewGateway(Dependencies{Config: cfg, Logger: logging.NewLogger(false)}, "test")
	if err != nil {
		t.Fatalf("NewGateway returned error: %v", err)
	}
	if err := gw.Initialize(); err != nil {
		t.Fatalf("Initialize returned error: %v", err)
	}
	return gw
}
