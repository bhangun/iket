package gateway

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/bhangun/iket/pkg/config"
)

type backendRuntimeState struct {
	ConsecutiveFailures      int
	ConsecutiveSuccesses     int
	ConsecutiveSlowResponses int
	LatencyEWMA              time.Duration
	ShadowRequests           int
	ShadowFailures           int
	ShadowLatencyEWMA        time.Duration
	UnhealthyUntil           time.Time
	ProbeInFlight            bool
	HalfOpenInFlight         int
	LastChecked              time.Time
	LastSuccess              time.Time
	LastFailure              time.Time
	LastStatusCode           int
	LastObservedLatency      time.Duration
	LastShadowStatusCode     int
	LastShadowLatency        time.Duration
	LastShadowError          string
	LastError                string
}

type BackendStatus struct {
	ServiceName                     string    `json:"service_name"`
	RoutePath                       string    `json:"route_path"`
	Destination                     string    `json:"destination"`
	URLPattern                      string    `json:"url_pattern"`
	Weight                          int       `json:"weight"`
	CircuitState                    string    `json:"circuit_state"`
	Available                       bool      `json:"available"`
	ProbeInFlight                   bool      `json:"probe_in_flight"`
	HalfOpenInFlight                int       `json:"half_open_in_flight"`
	HalfOpenMaxRequests             int       `json:"half_open_max_requests"`
	ConsecutiveSuccesses            int       `json:"consecutive_successes"`
	RecoverySuccessThreshold        int       `json:"recovery_success_threshold"`
	ConsecutiveSlowResponses        int       `json:"consecutive_slow_responses"`
	OutlierLatencyThreshold         string    `json:"outlier_latency_threshold,omitempty"`
	OutlierConsecutiveSlowResponses int       `json:"outlier_consecutive_slow_responses"`
	LastObservedLatencyMs           int64     `json:"last_observed_latency_ms,omitempty"`
	LatencyEWMAMs                   int64     `json:"latency_ewma_ms,omitempty"`
	ShadowRequests                  int       `json:"shadow_requests"`
	ShadowFailures                  int       `json:"shadow_failures"`
	ShadowFailureRate               float64   `json:"shadow_failure_rate,omitempty"`
	ShadowLatencyEWMAMs             int64     `json:"shadow_latency_ewma_ms,omitempty"`
	LastShadowStatusCode            int       `json:"last_shadow_status_code,omitempty"`
	LastShadowLatencyMs             int64     `json:"last_shadow_latency_ms,omitempty"`
	LastShadowError                 string    `json:"last_shadow_error,omitempty"`
	ShadowVsLiveLatencyDeltaMs      int64     `json:"shadow_vs_live_latency_delta_ms,omitempty"`
	ConsecutiveFailures             int       `json:"consecutive_failures"`
	UnhealthyUntil                  time.Time `json:"unhealthy_until,omitempty"`
	LastChecked                     time.Time `json:"last_checked,omitempty"`
	LastSuccess                     time.Time `json:"last_success,omitempty"`
	LastFailure                     time.Time `json:"last_failure,omitempty"`
	LastStatusCode                  int       `json:"last_status_code,omitempty"`
	LastError                       string    `json:"last_error,omitempty"`
	HealthCheckPath                 string    `json:"health_check_path,omitempty"`
	HealthInterval                  string    `json:"health_interval,omitempty"`
	HealthTimeout                   string    `json:"health_timeout,omitempty"`
}

type ShadowRouteSummary struct {
	ServiceName                string   `json:"service_name"`
	RoutePath                  string   `json:"route_path"`
	ShadowRequests             int      `json:"shadow_requests"`
	ShadowFailures             int      `json:"shadow_failures"`
	ShadowFailureRate          float64  `json:"shadow_failure_rate,omitempty"`
	LiveLatencyEWMAMs          int64    `json:"live_latency_ewma_ms,omitempty"`
	ShadowLatencyEWMAMs        int64    `json:"shadow_latency_ewma_ms,omitempty"`
	ShadowVsLiveLatencyDeltaMs int64    `json:"shadow_vs_live_latency_delta_ms,omitempty"`
	Backends                   []string `json:"backends,omitempty"`
	HealthyBackends            int      `json:"healthy_backends"`
}

type ShadowRouteEvaluation struct {
	ShadowRouteSummary
	PolicyConfigured      bool     `json:"policy_configured"`
	Healthy               bool     `json:"healthy"`
	Reasons               []string `json:"reasons,omitempty"`
	MinRequests           int      `json:"min_requests,omitempty"`
	MaxErrorRate          float64  `json:"max_error_rate,omitempty"`
	MaxLatencyDeltaMs     int64    `json:"max_latency_delta_ms,omitempty"`
	MaxLatencyDeltaSource string   `json:"max_latency_delta,omitempty"`
}

type shadowRouteAggregate struct {
	ShadowRouteSummary
	backends      map[string]struct{}
	liveSamples   int64
	shadowSamples int64
	deltaSamples  int64
}

func (g *Gateway) BackendStatuses() []BackendStatus {
	g.mu.RLock()
	cfg := g.config
	g.mu.RUnlock()
	if cfg == nil {
		return nil
	}
	now := time.Now().UTC()
	statuses := make([]BackendStatus, 0)
	for _, route := range cfg.GetAllRoutesFromServices(g.logger) {
		if len(route.Backends) == 0 {
			continue
		}
		for _, backend := range route.Backends {
			destination := strings.TrimSpace(backend.Host)
			if destination == "" {
				destination = strings.TrimSpace(route.ServiceHost)
			}
			key := g.backendStateKey(route, backend, destination)
			g.backendStateMu.RLock()
			state := g.backendState[key]
			g.backendStateMu.RUnlock()
			circuitState := backendCircuitState(state, now)
			shadowFailureRate := float64(0)
			if state.ShadowRequests > 0 {
				shadowFailureRate = float64(state.ShadowFailures) / float64(state.ShadowRequests)
			}
			shadowVsLiveDelta := int64(0)
			if state.ShadowLatencyEWMA > 0 && state.LatencyEWMA > 0 {
				shadowVsLiveDelta = (state.ShadowLatencyEWMA - state.LatencyEWMA).Milliseconds()
			}
			statuses = append(statuses, BackendStatus{
				ServiceName:                     route.ServiceName,
				RoutePath:                       route.Path,
				Destination:                     destination,
				URLPattern:                      backend.URLPattern,
				Weight:                          effectiveBackendWeight(backend),
				CircuitState:                    circuitState,
				Available:                       circuitState != "open" && state.HalfOpenInFlight < backendHalfOpenMaxRequests(backend),
				ProbeInFlight:                   state.ProbeInFlight,
				HalfOpenInFlight:                state.HalfOpenInFlight,
				HalfOpenMaxRequests:             backendHalfOpenMaxRequests(backend),
				ConsecutiveSuccesses:            state.ConsecutiveSuccesses,
				RecoverySuccessThreshold:        backendRecoverySuccessThreshold(backend),
				ConsecutiveSlowResponses:        state.ConsecutiveSlowResponses,
				OutlierLatencyThreshold:         strings.TrimSpace(backend.OutlierLatencyThreshold),
				OutlierConsecutiveSlowResponses: backendOutlierSlowResponseThreshold(backend),
				LastObservedLatencyMs:           state.LastObservedLatency.Milliseconds(),
				LatencyEWMAMs:                   state.LatencyEWMA.Milliseconds(),
				ShadowRequests:                  state.ShadowRequests,
				ShadowFailures:                  state.ShadowFailures,
				ShadowFailureRate:               shadowFailureRate,
				ShadowLatencyEWMAMs:             state.ShadowLatencyEWMA.Milliseconds(),
				LastShadowStatusCode:            state.LastShadowStatusCode,
				LastShadowLatencyMs:             state.LastShadowLatency.Milliseconds(),
				LastShadowError:                 state.LastShadowError,
				ShadowVsLiveLatencyDeltaMs:      shadowVsLiveDelta,
				ConsecutiveFailures:             state.ConsecutiveFailures,
				UnhealthyUntil:                  state.UnhealthyUntil,
				LastChecked:                     state.LastChecked,
				LastSuccess:                     state.LastSuccess,
				LastFailure:                     state.LastFailure,
				LastStatusCode:                  state.LastStatusCode,
				LastError:                       state.LastError,
				HealthCheckPath:                 strings.TrimSpace(backend.HealthCheckPath),
				HealthInterval:                  strings.TrimSpace(backend.HealthInterval),
				HealthTimeout:                   strings.TrimSpace(backend.HealthTimeout),
			})
		}
	}
	sort.SliceStable(statuses, func(i, j int) bool {
		if statuses[i].ServiceName == statuses[j].ServiceName {
			if statuses[i].RoutePath == statuses[j].RoutePath {
				return statuses[i].Destination < statuses[j].Destination
			}
			return statuses[i].RoutePath < statuses[j].RoutePath
		}
		return statuses[i].ServiceName < statuses[j].ServiceName
	})
	return statuses
}

func (g *Gateway) ShadowRouteSummaries() []ShadowRouteSummary {
	statuses := g.BackendStatuses()
	aggregates := make(map[string]*shadowRouteAggregate)
	for _, status := range statuses {
		if status.ShadowRequests == 0 {
			continue
		}
		key := status.ServiceName + "|" + status.RoutePath
		entry := aggregates[key]
		if entry == nil {
			entry = &shadowRouteAggregate{
				ShadowRouteSummary: ShadowRouteSummary{
					ServiceName: status.ServiceName,
					RoutePath:   status.RoutePath,
				},
				backends: make(map[string]struct{}),
			}
			aggregates[key] = entry
		}
		entry.ShadowRequests += status.ShadowRequests
		entry.ShadowFailures += status.ShadowFailures
		if status.LatencyEWMAMs > 0 {
			entry.LiveLatencyEWMAMs += status.LatencyEWMAMs
			entry.liveSamples++
		}
		if status.ShadowLatencyEWMAMs > 0 {
			entry.ShadowLatencyEWMAMs += status.ShadowLatencyEWMAMs
			entry.shadowSamples++
		}
		if status.ShadowVsLiveLatencyDeltaMs != 0 {
			entry.ShadowVsLiveLatencyDeltaMs += status.ShadowVsLiveLatencyDeltaMs
			entry.deltaSamples++
		}
		if status.Available {
			entry.HealthyBackends++
		}
		if status.Destination != "" {
			entry.backends[status.Destination] = struct{}{}
		}
	}
	summaries := make([]ShadowRouteSummary, 0, len(aggregates))
	for _, entry := range aggregates {
		if entry.ShadowRequests > 0 {
			entry.ShadowFailureRate = float64(entry.ShadowFailures) / float64(entry.ShadowRequests)
		}
		if entry.liveSamples > 0 {
			entry.LiveLatencyEWMAMs /= entry.liveSamples
		}
		if entry.shadowSamples > 0 {
			entry.ShadowLatencyEWMAMs /= entry.shadowSamples
		}
		if entry.deltaSamples > 0 {
			entry.ShadowVsLiveLatencyDeltaMs /= entry.deltaSamples
		}
		if len(entry.backends) > 0 {
			entry.Backends = make([]string, 0, len(entry.backends))
			for backend := range entry.backends {
				entry.Backends = append(entry.Backends, backend)
			}
			sort.Strings(entry.Backends)
		}
		summaries = append(summaries, entry.ShadowRouteSummary)
	}
	sort.SliceStable(summaries, func(i, j int) bool {
		if summaries[i].ServiceName == summaries[j].ServiceName {
			return summaries[i].RoutePath < summaries[j].RoutePath
		}
		return summaries[i].ServiceName < summaries[j].ServiceName
	})
	return summaries
}

func (g *Gateway) ShadowRouteEvaluations() []ShadowRouteEvaluation {
	summaries := g.ShadowRouteSummaries()
	summaryIndex := make(map[string]ShadowRouteSummary, len(summaries))
	for _, summary := range summaries {
		summaryIndex[summary.ServiceName+"|"+summary.RoutePath] = summary
	}
	g.mu.RLock()
	cfg := g.config
	g.mu.RUnlock()
	if cfg == nil {
		return nil
	}
	routeIndex := make(map[string]config.RouterConfig)
	for _, route := range cfg.GetAllRoutesFromServices(g.logger) {
		if route.ShadowTrafficPercent <= 0 && !shadowPolicyConfigured(route) {
			continue
		}
		routeIndex[route.ServiceName+"|"+route.Path] = route
	}
	evaluations := make([]ShadowRouteEvaluation, 0, len(routeIndex))
	keys := make([]string, 0, len(routeIndex))
	for key := range routeIndex {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		route := routeIndex[key]
		summary := summaryIndex[key]
		evaluation := ShadowRouteEvaluation{
			ShadowRouteSummary: ShadowRouteSummary{
				ServiceName:                route.ServiceName,
				RoutePath:                  route.Path,
				ShadowRequests:             summary.ShadowRequests,
				ShadowFailures:             summary.ShadowFailures,
				ShadowFailureRate:          summary.ShadowFailureRate,
				LiveLatencyEWMAMs:          summary.LiveLatencyEWMAMs,
				ShadowLatencyEWMAMs:        summary.ShadowLatencyEWMAMs,
				ShadowVsLiveLatencyDeltaMs: summary.ShadowVsLiveLatencyDeltaMs,
				Backends:                   append([]string(nil), summary.Backends...),
				HealthyBackends:            summary.HealthyBackends,
			},
			Healthy: true,
		}
		evaluation.MinRequests = route.ShadowMinRequests
		evaluation.MaxErrorRate = route.ShadowMaxErrorRate
		evaluation.MaxLatencyDeltaSource = strings.TrimSpace(route.ShadowMaxLatencyDelta)
		if evaluation.MinRequests > 0 || evaluation.MaxErrorRate > 0 || evaluation.MaxLatencyDeltaSource != "" {
			evaluation.PolicyConfigured = true
		}
		if evaluation.MinRequests > 0 && summary.ShadowRequests < evaluation.MinRequests {
			evaluation.Healthy = false
			evaluation.Reasons = append(evaluation.Reasons, fmt.Sprintf("shadow requests %d below required minimum %d", summary.ShadowRequests, evaluation.MinRequests))
		}
		if evaluation.MaxErrorRate > 0 && summary.ShadowFailureRate > evaluation.MaxErrorRate {
			evaluation.Healthy = false
			evaluation.Reasons = append(evaluation.Reasons, fmt.Sprintf("shadow failure rate %.3f exceeds max %.3f", summary.ShadowFailureRate, evaluation.MaxErrorRate))
		}
		if evaluation.MaxLatencyDeltaSource != "" {
			if maxDelta, err := time.ParseDuration(evaluation.MaxLatencyDeltaSource); err == nil {
				evaluation.MaxLatencyDeltaMs = maxDelta.Milliseconds()
				if summary.ShadowVsLiveLatencyDeltaMs > evaluation.MaxLatencyDeltaMs {
					evaluation.Healthy = false
					evaluation.Reasons = append(evaluation.Reasons, fmt.Sprintf("shadow latency delta %dms exceeds max %dms", summary.ShadowVsLiveLatencyDeltaMs, evaluation.MaxLatencyDeltaMs))
				}
			}
		}
		evaluations = append(evaluations, evaluation)
	}
	return evaluations
}

func shadowPolicyConfigured(route config.RouterConfig) bool {
	return route.ShadowMinRequests > 0 || route.ShadowMaxErrorRate > 0 || strings.TrimSpace(route.ShadowMaxLatencyDelta) != ""
}
