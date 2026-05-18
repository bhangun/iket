package gateway

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/bhangun/iket/pkg/config"
	"github.com/bhangun/iket/pkg/logging"
)

func TestSelectRouteBackendSkipsTemporarilyUnhealthyBackend(t *testing.T) {
	cfg := &config.Config{Server: config.ServerConfig{Port: 8080}}
	gw, err := NewGateway(Dependencies{Config: cfg, Logger: logging.NewLogger(false)}, "test")
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}

	route := config.RouterConfig{
		Path:        "/auth/{rest:.*}",
		ServiceName: "identity",
		ServiceHost: "http://identity-default:8080",
		Backends: []config.Backend{
			{URLPattern: "/v1/{rest:.*}", Host: "http://identity-v1:8080", Weight: 5, FailureThreshold: 1, Cooldown: "1m"},
			{URLPattern: "/v2/{rest:.*}", Host: "http://identity-v2:8080", Weight: 1, FailureThreshold: 1, Cooldown: "1m"},
		},
	}

	primary, primaryDestination := gw.selectRouteBackend(route, "sticky-client")
	if primaryDestination != "http://identity-v1:8080" {
		t.Fatalf("expected primary destination identity-v1, got %q with backend %+v", primaryDestination, primary)
	}

	gw.recordBackendFailure(route, primary, primaryDestination, context.DeadlineExceeded)

	fallback, fallbackDestination := gw.selectRouteBackend(route, "sticky-client")
	if fallbackDestination != "http://identity-v2:8080" {
		t.Fatalf("expected fallback destination identity-v2, got %q with backend %+v", fallbackDestination, fallback)
	}
}

func TestRecordBackendSuccessClearsUnhealthyState(t *testing.T) {
	cfg := &config.Config{Server: config.ServerConfig{Port: 8080}}
	gw, err := NewGateway(Dependencies{Config: cfg, Logger: logging.NewLogger(false)}, "test")
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}

	route := config.RouterConfig{
		Path:        "/auth/{rest:.*}",
		ServiceName: "identity",
		ServiceHost: "http://identity-default:8080",
	}
	backend := config.Backend{
		URLPattern:       "/v1/{rest:.*}",
		Host:             "http://identity-v1:8080",
		FailureThreshold: 1,
		Cooldown:         "1m",
	}
	destination := gw.backendDestination(route, backend)

	gw.recordBackendFailure(route, backend, destination, context.DeadlineExceeded)
	if gw.isBackendAvailable(route, backend, destination, time.Now().UTC()) {
		t.Fatalf("expected backend to be unavailable immediately after failure")
	}

	gw.recordBackendSuccess(route, backend, destination)
	if !gw.isBackendAvailable(route, backend, destination, time.Now().UTC()) {
		t.Fatalf("expected backend success to clear unhealthy state")
	}
}

func TestSelectRouteBackendAllowsOnlyOneHalfOpenProbe(t *testing.T) {
	cfg := &config.Config{Server: config.ServerConfig{Port: 8080}}
	gw, err := NewGateway(Dependencies{Config: cfg, Logger: logging.NewLogger(false)}, "test")
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}

	route := config.RouterConfig{
		Path:        "/auth/{rest:.*}",
		ServiceName: "identity",
		ServiceHost: "http://identity-default:8080",
		Backends: []config.Backend{
			{URLPattern: "/v1/{rest:.*}", Host: "http://identity-v1:8080", FailureThreshold: 1, Cooldown: "1m"},
		},
	}
	backend := route.Backends[0]
	destination := gw.backendDestination(route, backend)

	gw.recordBackendFailureWithStatus(route, backend, destination, http.StatusBadGateway, context.DeadlineExceeded, time.Now().UTC().Add(-2*time.Minute))

	selected, selectedDestination := gw.selectRouteBackend(route, "sticky-client")
	if selectedDestination != destination {
		t.Fatalf("expected half-open probe to reserve backend %q, got %q", destination, selectedDestination)
	}
	if selected.Host != backend.Host {
		t.Fatalf("expected selected backend host %q, got %q", backend.Host, selected.Host)
	}

	selectedAgain, selectedAgainDestination := gw.selectRouteBackend(route, "sticky-client")
	if selectedAgainDestination != "" || selectedAgain != (config.Backend{}) {
		t.Fatalf("expected second half-open selection to be blocked, got backend %+v destination %q", selectedAgain, selectedAgainDestination)
	}
}

func TestSelectRouteBackendRespectsConfiguredHalfOpenLimit(t *testing.T) {
	cfg := &config.Config{Server: config.ServerConfig{Port: 8080}}
	gw, err := NewGateway(Dependencies{Config: cfg, Logger: logging.NewLogger(false)}, "test")
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}

	route := config.RouterConfig{
		Path:        "/auth/{rest:.*}",
		ServiceName: "identity",
		ServiceHost: "http://identity-default:8080",
		Backends: []config.Backend{
			{URLPattern: "/v1/{rest:.*}", Host: "http://identity-v1:8080", FailureThreshold: 1, Cooldown: "1m", HalfOpenMaxRequests: 2},
		},
	}
	backend := route.Backends[0]
	destination := gw.backendDestination(route, backend)

	gw.recordBackendFailureWithStatus(route, backend, destination, http.StatusBadGateway, context.DeadlineExceeded, time.Now().UTC().Add(-2*time.Minute))

	if _, got := gw.selectRouteBackend(route, "client-a"); got == "" {
		t.Fatalf("expected first half-open reservation to succeed")
	}
	if _, got := gw.selectRouteBackend(route, "client-b"); got == "" {
		t.Fatalf("expected second half-open reservation to succeed")
	}
	if backend, got := gw.selectRouteBackend(route, "client-c"); got != "" || backend != (config.Backend{}) {
		t.Fatalf("expected third half-open reservation to be blocked, got backend %+v destination %q", backend, got)
	}
}

func TestRecordBackendSuccessRequiresConfiguredRecoveryThreshold(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Services: []config.ServiceConfig{{
			Version: 1,
			Services: []config.Service{{
				Name: "identity",
				Host: "http://identity-default:8080",
				Routes: []config.RouterConfig{{
					Path:    "/auth/{rest:.*}",
					Methods: []string{"GET"},
					Backends: []config.Backend{{
						URLPattern:               "/v1/{rest:.*}",
						Host:                     "http://identity-v1:8080",
						FailureThreshold:         1,
						Cooldown:                 "1m",
						RecoverySuccessThreshold: 2,
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
	now := time.Now().UTC().Add(-2 * time.Minute)

	gw.recordBackendFailureWithStatus(route, backend, destination, http.StatusBadGateway, context.DeadlineExceeded, now)
	if _, got := gw.selectRouteBackend(route, "client-a"); got == "" {
		t.Fatalf("expected half-open reservation to succeed")
	}

	gw.recordBackendSuccessWithStatus(route, backend, destination, http.StatusOK, 0, time.Now().UTC())
	statuses := gw.BackendStatuses()
	if len(statuses) != 1 {
		t.Fatalf("expected one backend status, got %d", len(statuses))
	}
	if statuses[0].CircuitState != "half_open" {
		t.Fatalf("expected first success to keep circuit half_open, got %q", statuses[0].CircuitState)
	}
	if statuses[0].ConsecutiveSuccesses != 1 {
		t.Fatalf("expected one recorded recovery success, got %d", statuses[0].ConsecutiveSuccesses)
	}

	if _, got := gw.selectRouteBackend(route, "client-b"); got == "" {
		t.Fatalf("expected second half-open reservation to succeed")
	}
	gw.recordBackendSuccessWithStatus(route, backend, destination, http.StatusOK, 0, time.Now().UTC())
	statuses = gw.BackendStatuses()
	if statuses[0].CircuitState != "closed" {
		t.Fatalf("expected second success to close circuit, got %q", statuses[0].CircuitState)
	}
}

func TestSlowResponsesCanEjectBackendAsOutlier(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Services: []config.ServiceConfig{{
			Version: 1,
			Services: []config.Service{{
				Name: "identity",
				Host: "http://identity-default:8080",
				Routes: []config.RouterConfig{{
					Path:    "/auth/{rest:.*}",
					Methods: []string{"GET"},
					Backends: []config.Backend{{
						URLPattern:                      "/v1/{rest:.*}",
						Host:                            "http://identity-v1:8080",
						Cooldown:                        "1m",
						OutlierLatencyThreshold:         "100ms",
						OutlierConsecutiveSlowResponses: 2,
						OutlierCooldown:                 "2m",
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

	gw.recordBackendSuccessWithStatus(route, backend, destination, http.StatusOK, 150*time.Millisecond, time.Now().UTC())
	statuses := gw.BackendStatuses()
	if statuses[0].CircuitState != "closed" {
		t.Fatalf("expected circuit to remain closed after first slow response, got %q", statuses[0].CircuitState)
	}
	if statuses[0].ConsecutiveSlowResponses != 1 {
		t.Fatalf("expected one slow response to be tracked, got %d", statuses[0].ConsecutiveSlowResponses)
	}

	gw.recordBackendSuccessWithStatus(route, backend, destination, http.StatusOK, 175*time.Millisecond, time.Now().UTC())
	statuses = gw.BackendStatuses()
	if statuses[0].CircuitState != "open" {
		t.Fatalf("expected repeated slow responses to eject backend, got %q", statuses[0].CircuitState)
	}
	if statuses[0].LastObservedLatencyMs < 175 {
		t.Fatalf("expected last observed latency to be recorded, got %d", statuses[0].LastObservedLatencyMs)
	}
}

func TestAdaptiveLatencyRoutingPrefersFasterBackend(t *testing.T) {
	cfg := &config.Config{Server: config.ServerConfig{Port: 8080}}
	gw, err := NewGateway(Dependencies{Config: cfg, Logger: logging.NewLogger(false)}, "test")
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}

	route := config.RouterConfig{
		Path:                   "/auth/{rest:.*}",
		ServiceName:            "identity",
		ServiceHost:            "http://identity-default:8080",
		AdaptiveLatencyRouting: true,
		Backends: []config.Backend{
			{URLPattern: "/v1/{rest:.*}", Host: "http://identity-v1:8080", Weight: 1},
			{URLPattern: "/v2/{rest:.*}", Host: "http://identity-v2:8080", Weight: 1},
		},
	}

	fast := route.Backends[0]
	fastDest := gw.backendDestination(route, fast)
	slow := route.Backends[1]
	slowDest := gw.backendDestination(route, slow)

	gw.recordBackendSuccessWithStatus(route, slow, slowDest, http.StatusOK, 250*time.Millisecond, time.Now().UTC())
	gw.recordBackendSuccessWithStatus(route, fast, fastDest, http.StatusOK, 40*time.Millisecond, time.Now().UTC())

	selected, destination := gw.selectRouteBackend(route, "sticky-client")
	if destination != fastDest || selected.Host != fast.Host {
		t.Fatalf("expected adaptive routing to prefer faster backend %q, got %q", fastDest, destination)
	}
}

func TestBackendStatusesExposeHealthMetadata(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Services: []config.ServiceConfig{{
			Version: 1,
			Services: []config.Service{{
				Name: "identity",
				Host: "http://identity-default:8080",
				Routes: []config.RouterConfig{{
					Path:    "/auth/{rest:.*}",
					Methods: []string{"GET"},
					Backends: []config.Backend{
						{
							URLPattern:       "/v1/{rest:.*}",
							Host:             "http://identity-v1:8080",
							Weight:           2,
							FailureThreshold: 1,
							Cooldown:         "1m",
							HealthCheckPath:  "/health",
							HealthInterval:   "30s",
							HealthTimeout:    "2s",
						},
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
	gw.recordBackendFailure(route, backend, destination, context.DeadlineExceeded)

	statuses := gw.BackendStatuses()
	if len(statuses) != 1 {
		t.Fatalf("expected 1 backend status, got %d", len(statuses))
	}
	status := statuses[0]
	if status.Destination != "http://identity-v1:8080" {
		t.Fatalf("expected destination identity-v1, got %q", status.Destination)
	}
	if status.Available {
		t.Fatalf("expected backend to be unavailable after recorded failure")
	}
	if status.CircuitState != "open" {
		t.Fatalf("expected circuit state open after recorded failure, got %q", status.CircuitState)
	}
	if status.LatencyEWMAMs != 0 {
		t.Fatalf("expected zero latency EWMA before successes, got %d", status.LatencyEWMAMs)
	}
	if status.HealthCheckPath != "/health" || status.HealthInterval != "30s" || status.HealthTimeout != "2s" {
		t.Fatalf("expected health metadata to be exposed, got %+v", status)
	}
}

func TestBackendStatusesExposeLatencyEWMA(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Services: []config.ServiceConfig{{
			Version: 1,
			Services: []config.Service{{
				Name: "identity",
				Host: "http://identity-default:8080",
				Routes: []config.RouterConfig{{
					Path:    "/auth/{rest:.*}",
					Methods: []string{"GET"},
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
	gw.recordBackendSuccessWithStatus(route, backend, destination, http.StatusOK, 120*time.Millisecond, time.Now().UTC())

	statuses := gw.BackendStatuses()
	if len(statuses) != 1 {
		t.Fatalf("expected 1 backend status, got %d", len(statuses))
	}
	if statuses[0].LatencyEWMAMs < 120 {
		t.Fatalf("expected latency EWMA to be recorded, got %d", statuses[0].LatencyEWMAMs)
	}
}

func TestBackendStatusesExposeHalfOpenState(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Services: []config.ServiceConfig{{
			Version: 1,
			Services: []config.Service{{
				Name: "identity",
				Host: "http://identity-default:8080",
				Routes: []config.RouterConfig{{
					Path:    "/auth/{rest:.*}",
					Methods: []string{"GET"},
					Backends: []config.Backend{{
						URLPattern:       "/v1/{rest:.*}",
						Host:             "http://identity-v1:8080",
						FailureThreshold: 1,
						Cooldown:         "1m",
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
	gw.recordBackendFailureWithStatus(route, backend, destination, http.StatusBadGateway, context.DeadlineExceeded, time.Now().UTC().Add(-2*time.Minute))
	if _, got := gw.selectRouteBackend(route, "sticky-client"); got == "" {
		t.Fatalf("expected first half-open reservation to succeed")
	}

	statuses := gw.BackendStatuses()
	if len(statuses) != 1 {
		t.Fatalf("expected 1 backend status, got %d", len(statuses))
	}
	if statuses[0].CircuitState != "half_open" {
		t.Fatalf("expected circuit state half_open, got %q", statuses[0].CircuitState)
	}
	if !statuses[0].ProbeInFlight {
		t.Fatalf("expected half-open probe to be marked in flight")
	}
	if statuses[0].HalfOpenInFlight != 1 {
		t.Fatalf("expected half-open in-flight count 1, got %d", statuses[0].HalfOpenInFlight)
	}
}
