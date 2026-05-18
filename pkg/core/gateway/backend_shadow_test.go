package gateway

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bhangun/iket/pkg/config"
	"github.com/bhangun/iket/pkg/logging"
)

func TestRouteShadowTrafficMatches(t *testing.T) {
	route := config.RouterConfig{ShadowTrafficPercent: 100}
	if !routeShadowTrafficMatches(route, "any-client") {
		t.Fatalf("expected 100%% shadow traffic to always match")
	}
	if routeShadowTrafficMatches(config.RouterConfig{ShadowTrafficPercent: 0}, "any-client") {
		t.Fatalf("expected 0%% shadow traffic to be disabled")
	}
}

func TestDispatchShadowRequestMirrorsToAlternateBackend(t *testing.T) {
	calls := make(chan *http.Request, 1)
	gw, err := NewGateway(Dependencies{Config: &config.Config{Server: config.ServerConfig{Port: 8080}}, Logger: logging.NewLogger(false)}, "test")
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}
	route := config.RouterConfig{
		Path:                 "/hello",
		Method:               "GET",
		ServiceName:          "shadow",
		ServiceHost:          "http://primary.internal",
		ShadowTrafficPercent: 100,
	}
	backend := config.Backend{URLPattern: "/mirror/hello", Host: "http://shadow.internal"}
	dispatchShadowRequest(gw, roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		calls <- r.Clone(r.Context())
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader("shadow")),
			Request:    r,
		}, nil
	}), httptest.NewRequest(http.MethodGet, "http://primary.internal/hello", nil), route, &shadowTarget{
		backend:     backend,
		destination: "http://shadow.internal",
		scheme:      "http",
		host:        "shadow.internal",
		path:        "/mirror/hello",
	}, logging.NewLogger(false))

	select {
	case req := <-calls:
		if req.URL.Host != "shadow.internal" {
			t.Fatalf("expected shadow request host shadow.internal, got %q", req.URL.Host)
		}
		if req.URL.Path != "/mirror/hello" {
			t.Fatalf("expected shadow request path /mirror/hello, got %q", req.URL.Path)
		}
		if req.Header.Get("X-Iket-Shadow") != "true" {
			t.Fatalf("expected X-Iket-Shadow header to be set")
		}
	case <-time.After(1 * time.Second):
		t.Fatalf("timed out waiting for shadow request dispatch")
	}

	statuses := gw.BackendStatuses()
	if len(statuses) != 0 {
		t.Fatalf("expected no enumerated backend statuses without configured services, got %d", len(statuses))
	}
	state := gw.backendState[gw.backendStateKey(route, backend, "http://shadow.internal")]
	if state.ShadowRequests != 1 {
		t.Fatalf("expected one shadow request to be recorded, got %d", state.ShadowRequests)
	}
	if state.ShadowFailures != 0 {
		t.Fatalf("expected no shadow failures, got %d", state.ShadowFailures)
	}
}

func TestDispatchShadowRequestRecordsFailures(t *testing.T) {
	gw, err := NewGateway(Dependencies{Config: &config.Config{Server: config.ServerConfig{Port: 8080}}, Logger: logging.NewLogger(false)}, "test")
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}
	route := config.RouterConfig{
		Path:                 "/hello",
		Method:               "GET",
		ServiceName:          "shadow",
		ServiceHost:          "http://primary.internal",
		ShadowTrafficPercent: 100,
	}
	backend := config.Backend{URLPattern: "/mirror/hello", Host: "http://shadow.internal"}
	dispatchShadowRequest(gw, roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		return nil, fmt.Errorf("shadow failed")
	}), httptest.NewRequest(http.MethodGet, "http://primary.internal/hello", nil), route, &shadowTarget{
		backend:     backend,
		destination: "http://shadow.internal",
		scheme:      "http",
		host:        "shadow.internal",
		path:        "/mirror/hello",
	}, logging.NewLogger(false))

	state := gw.backendState[gw.backendStateKey(route, backend, "http://shadow.internal")]
	if state.ShadowRequests != 1 {
		t.Fatalf("expected one shadow request to be recorded, got %d", state.ShadowRequests)
	}
	if state.ShadowFailures != 1 {
		t.Fatalf("expected one shadow failure to be recorded, got %d", state.ShadowFailures)
	}
	if state.LastShadowError == "" {
		t.Fatalf("expected shadow error to be recorded")
	}
}

func TestBackendStatusesExposeShadowComparisonSummary(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Services: []config.ServiceConfig{{
			Version: 1,
			Services: []config.Service{{
				Name: "identity",
				Host: "http://identity-default:8080",
				Routes: []config.RouterConfig{{
					Path:                 "/auth/{rest:.*}",
					Methods:              []string{"GET"},
					ShadowTrafficPercent: 100,
					Backends: []config.Backend{{
						URLPattern: "/v1/{rest:.*}",
						Host:       "http://identity-v1:8080",
					}},
				}},
			}},
		}},
	}
	gw, err := NewGateway(Dependencies{Config: cfg, Logger: logging.NewLogger(false)}, "test")
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}
	route := cfg.GetAllRoutesFromServices(logging.NewLogger(false))[0]
	backend := route.Backends[0]
	destination := gw.backendDestination(route, backend)

	gw.recordBackendSuccessWithStatus(route, backend, destination, http.StatusOK, 100*time.Millisecond, time.Now().UTC())
	gw.recordShadowResult(route, backend, destination, http.StatusOK, 180*time.Millisecond, nil)
	gw.recordShadowResult(route, backend, destination, http.StatusBadGateway, 220*time.Millisecond, fmt.Errorf("shadow failed"))

	statuses := gw.BackendStatuses()
	if len(statuses) != 1 {
		t.Fatalf("expected 1 backend status, got %d", len(statuses))
	}
	status := statuses[0]
	if status.ShadowRequests != 2 || status.ShadowFailures != 1 {
		t.Fatalf("expected shadow counters 2/1, got %d/%d", status.ShadowRequests, status.ShadowFailures)
	}
	if status.ShadowFailureRate <= 0.49 || status.ShadowFailureRate >= 0.51 {
		t.Fatalf("expected shadow failure rate near 0.5, got %f", status.ShadowFailureRate)
	}
	if status.ShadowLatencyEWMAMs <= 0 {
		t.Fatalf("expected shadow latency ewma to be recorded, got %d", status.ShadowLatencyEWMAMs)
	}
	if status.ShadowVsLiveLatencyDeltaMs <= 0 {
		t.Fatalf("expected positive shadow-vs-live latency delta, got %d", status.ShadowVsLiveLatencyDeltaMs)
	}
}

func TestShadowRouteSummariesAggregateByRoute(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Services: []config.ServiceConfig{{
			Version: 1,
			Services: []config.Service{{
				Name: "identity",
				Host: "http://identity-default:8080",
				Routes: []config.RouterConfig{{
					Path:                 "/auth/{rest:.*}",
					Methods:              []string{"GET"},
					ShadowTrafficPercent: 100,
					Backends: []config.Backend{
						{URLPattern: "/v1/{rest:.*}", Host: "http://identity-v1:8080"},
						{URLPattern: "/v2/{rest:.*}", Host: "http://identity-v2:8080"},
					},
				}},
			}},
		}},
	}
	gw, err := NewGateway(Dependencies{Config: cfg, Logger: logging.NewLogger(false)}, "test")
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}
	route := cfg.GetAllRoutesFromServices(logging.NewLogger(false))[0]
	for _, backend := range route.Backends {
		destination := gw.backendDestination(route, backend)
		gw.recordBackendSuccessWithStatus(route, backend, destination, http.StatusOK, 100*time.Millisecond, time.Now().UTC())
		gw.recordShadowResult(route, backend, destination, http.StatusOK, 150*time.Millisecond, nil)
	}

	summaries := gw.ShadowRouteSummaries()
	if len(summaries) != 1 {
		t.Fatalf("expected 1 aggregated shadow summary, got %d", len(summaries))
	}
	summary := summaries[0]
	if summary.ServiceName != "identity" || summary.RoutePath != "/auth/{rest:.*}" {
		t.Fatalf("unexpected summary identity: %+v", summary)
	}
	if summary.ShadowRequests != 2 || summary.ShadowFailures != 0 {
		t.Fatalf("expected aggregated shadow counters 2/0, got %d/%d", summary.ShadowRequests, summary.ShadowFailures)
	}
	if len(summary.Backends) != 2 {
		t.Fatalf("expected both backends to appear in aggregate, got %v", summary.Backends)
	}
}

func TestShadowRouteEvaluationsApplyConfiguredThresholds(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Services: []config.ServiceConfig{{
			Version: 1,
			Services: []config.Service{{
				Name: "identity",
				Host: "http://identity-default:8080",
				Routes: []config.RouterConfig{{
					Path:                  "/auth/{rest:.*}",
					Methods:               []string{"GET"},
					ShadowTrafficPercent:  100,
					ShadowMinRequests:     1,
					ShadowMaxErrorRate:    0.10,
					ShadowMaxLatencyDelta: "50ms",
					Backends: []config.Backend{
						{URLPattern: "/v1/{rest:.*}", Host: "http://identity-v1:8080"},
					},
				}},
			}},
		}},
	}
	gw, err := NewGateway(Dependencies{Config: cfg, Logger: logging.NewLogger(false)}, "test")
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}
	route := cfg.GetAllRoutesFromServices(logging.NewLogger(false))[0]
	backend := route.Backends[0]
	destination := gw.backendDestination(route, backend)
	gw.recordBackendSuccessWithStatus(route, backend, destination, http.StatusOK, 100*time.Millisecond, time.Now().UTC())
	gw.recordShadowResult(route, backend, destination, http.StatusOK, 170*time.Millisecond, nil)

	evaluations := gw.ShadowRouteEvaluations()
	if len(evaluations) != 1 {
		t.Fatalf("expected 1 evaluation, got %d", len(evaluations))
	}
	evaluation := evaluations[0]
	if !evaluation.PolicyConfigured {
		t.Fatalf("expected policy to be configured")
	}
	if evaluation.Healthy {
		t.Fatalf("expected evaluation to fail due to latency delta, got healthy=true")
	}
	if len(evaluation.Reasons) == 0 {
		t.Fatalf("expected at least one evaluation reason")
	}
}
