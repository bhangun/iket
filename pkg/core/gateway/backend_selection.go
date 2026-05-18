package gateway

import (
	"sort"
	"strings"
	"time"

	"github.com/bhangun/iket/pkg/config"
)

const defaultBackendCooldown = 30 * time.Second

func (g *Gateway) selectRouteBackend(route config.RouterConfig, bucketKey string) (config.Backend, string) {
	if len(route.Backends) == 0 {
		return config.Backend{}, strings.TrimSpace(route.ServiceHost)
	}
	now := time.Now().UTC()
	for _, index := range g.preferredBackendIndexes(route, bucketKey) {
		backend := route.Backends[index]
		destination := g.backendDestination(route, backend)
		if g.reserveBackend(route, backend, destination, now) {
			return backend, destination
		}
	}
	return config.Backend{}, ""
}

func (g *Gateway) backendDestination(route config.RouterConfig, backend config.Backend) string {
	if strings.TrimSpace(backend.Host) != "" {
		return strings.TrimSpace(backend.Host)
	}
	return strings.TrimSpace(route.ServiceHost)
}

func (g *Gateway) selectAlternateRouteBackend(route config.RouterConfig, selected config.Backend, bucketKey string) (config.Backend, string) {
	if len(route.Backends) < 2 {
		return config.Backend{}, ""
	}
	now := time.Now().UTC()
	for _, index := range g.preferredBackendIndexes(route, bucketKey) {
		backend := route.Backends[index]
		if backend == selected {
			continue
		}
		destination := g.backendDestination(route, backend)
		if destination == "" {
			continue
		}
		if g.isBackendAvailable(route, backend, destination, now) {
			return backend, destination
		}
	}
	return config.Backend{}, ""
}

func (g *Gateway) preferredBackendIndexes(route config.RouterConfig, bucketKey string) []int {
	indexes := make([]int, len(route.Backends))
	for i := range route.Backends {
		indexes[i] = i
	}
	start := PreferredRouteBackendIndex(route, bucketKey)
	if start < 0 {
		start = 0
	}
	if !route.AdaptiveLatencyRouting {
		return rotateBackendIndexes(indexes, start)
	}
	type scoredIndex struct {
		index       int
		score       float64
		hasLatency  bool
		staticOrder int
	}
	scored := make([]scoredIndex, 0, len(route.Backends))
	for offset := 0; offset < len(route.Backends); offset++ {
		index := (start + offset) % len(route.Backends)
		backend := route.Backends[index]
		destination := g.backendDestination(route, backend)
		state := g.backendStateSnapshot(route, backend, destination)
		score := float64(0)
		hasLatency := state.LatencyEWMA > 0
		if hasLatency {
			score = float64(state.LatencyEWMA) / float64(effectiveBackendWeight(backend))
		}
		scored = append(scored, scoredIndex{
			index:       index,
			score:       score,
			hasLatency:  hasLatency,
			staticOrder: offset,
		})
	}
	sort.SliceStable(scored, func(i, j int) bool {
		if scored[i].hasLatency != scored[j].hasLatency {
			return scored[i].hasLatency
		}
		if scored[i].hasLatency && scored[i].score != scored[j].score {
			return scored[i].score < scored[j].score
		}
		return scored[i].staticOrder < scored[j].staticOrder
	})
	ordered := make([]int, 0, len(scored))
	for _, item := range scored {
		ordered = append(ordered, item.index)
	}
	return ordered
}

func rotateBackendIndexes(indexes []int, start int) []int {
	if len(indexes) == 0 {
		return nil
	}
	ordered := make([]int, 0, len(indexes))
	for offset := 0; offset < len(indexes); offset++ {
		ordered = append(ordered, indexes[(start+offset)%len(indexes)])
	}
	return ordered
}

func (g *Gateway) backendStateSnapshot(route config.RouterConfig, backend config.Backend, destination string) backendRuntimeState {
	key := g.backendStateKey(route, backend, destination)
	g.backendStateMu.RLock()
	defer g.backendStateMu.RUnlock()
	return g.backendState[key]
}

func (g *Gateway) backendStateKey(route config.RouterConfig, backend config.Backend, destination string) string {
	return strings.TrimSpace(route.ServiceName) + "|" + strings.TrimSpace(route.Path) + "|" + strings.TrimSpace(destination) + "|" + strings.TrimSpace(backend.URLPattern)
}

func (g *Gateway) isBackendAvailable(route config.RouterConfig, backend config.Backend, destination string, now time.Time) bool {
	key := g.backendStateKey(route, backend, destination)
	g.backendStateMu.RLock()
	state, ok := g.backendState[key]
	g.backendStateMu.RUnlock()
	if !ok {
		return true
	}
	return backendCircuitState(state, now) != "open"
}

func (g *Gateway) reserveBackend(route config.RouterConfig, backend config.Backend, destination string, now time.Time) bool {
	key := g.backendStateKey(route, backend, destination)
	g.backendStateMu.Lock()
	defer g.backendStateMu.Unlock()
	state, ok := g.backendState[key]
	if !ok || state.UnhealthyUntil.IsZero() {
		return true
	}
	if now.Before(state.UnhealthyUntil) {
		return false
	}
	maxHalfOpen := backendHalfOpenMaxRequests(backend)
	if state.HalfOpenInFlight >= maxHalfOpen {
		return false
	}
	state.ProbeInFlight = true
	state.HalfOpenInFlight++
	g.backendState[key] = state
	return true
}

func (g *Gateway) recordBackendFailure(route config.RouterConfig, backend config.Backend, destination string, cause error) {
	g.recordBackendFailureWithStatus(route, backend, destination, 0, cause, time.Now().UTC())
}

func (g *Gateway) recordBackendFailureWithStatus(route config.RouterConfig, backend config.Backend, destination string, statusCode int, cause error, now time.Time) {
	key := g.backendStateKey(route, backend, destination)
	threshold := backend.FailureThreshold
	if threshold <= 0 {
		threshold = 1
	}
	cooldown := defaultBackendCooldown
	if raw := strings.TrimSpace(backend.Cooldown); raw != "" {
		if parsed, err := time.ParseDuration(raw); err == nil && parsed > 0 {
			cooldown = parsed
		}
	}
	g.backendStateMu.Lock()
	defer g.backendStateMu.Unlock()
	state := g.backendState[key]
	state.LastChecked = now
	state.LastStatusCode = statusCode
	state.ConsecutiveFailures++
	state.ConsecutiveSuccesses = 0
	state.LastFailure = now
	state.ProbeInFlight = false
	if state.HalfOpenInFlight > 0 {
		state.HalfOpenInFlight--
	}
	if cause != nil {
		state.LastError = cause.Error()
	}
	if state.ConsecutiveFailures >= threshold {
		state.UnhealthyUntil = now.Add(cooldown)
	}
	g.backendState[key] = state
}

func (g *Gateway) recordBackendSuccess(route config.RouterConfig, backend config.Backend, destination string) {
	g.recordBackendSuccessWithStatus(route, backend, destination, 0, 0, time.Now().UTC())
}

func (g *Gateway) recordBackendSuccessWithStatus(route config.RouterConfig, backend config.Backend, destination string, statusCode int, latency time.Duration, now time.Time) {
	key := g.backendStateKey(route, backend, destination)
	g.backendStateMu.Lock()
	defer g.backendStateMu.Unlock()
	state := g.backendState[key]
	state.LastChecked = now
	state.LastSuccess = now
	state.LastStatusCode = statusCode
	state.LastObservedLatency = latency
	state.LatencyEWMA = updateLatencyEWMA(state.LatencyEWMA, latency)
	state.LastError = ""
	state.ProbeInFlight = false
	if state.HalfOpenInFlight > 0 {
		state.HalfOpenInFlight--
	}
	if isBackendLatencyOutlier(backend, latency) {
		state.ConsecutiveSlowResponses++
	} else {
		state.ConsecutiveSlowResponses = 0
	}
	if !state.UnhealthyUntil.IsZero() {
		state.ConsecutiveSuccesses++
		if state.ConsecutiveSuccesses >= backendRecoverySuccessThreshold(backend) {
			state.ConsecutiveFailures = 0
			state.ConsecutiveSuccesses = 0
			state.ConsecutiveSlowResponses = 0
			state.UnhealthyUntil = time.Time{}
		}
	} else {
		state.ConsecutiveFailures = 0
		state.ConsecutiveSuccesses = 0
		slowThreshold := backendOutlierSlowResponseThreshold(backend)
		if slowThreshold > 0 && state.ConsecutiveSlowResponses >= slowThreshold {
			state.UnhealthyUntil = now.Add(backendOutlierCooldown(backend))
			state.ConsecutiveSuccesses = 0
		} else {
			state.UnhealthyUntil = time.Time{}
		}
	}
	g.backendState[key] = state
}
