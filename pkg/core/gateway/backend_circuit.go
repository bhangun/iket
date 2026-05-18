package gateway

import (
	"net/http"
	"strings"
	"time"

	"github.com/bhangun/iket/pkg/config"
)

func shouldRecordBackendFailureStatus(statusCode int) bool {
	return statusCode >= http.StatusInternalServerError
}

func backendCircuitState(state backendRuntimeState, now time.Time) string {
	if !state.UnhealthyUntil.IsZero() && now.Before(state.UnhealthyUntil) {
		return "open"
	}
	if !state.UnhealthyUntil.IsZero() {
		return "half_open"
	}
	return "closed"
}

func backendHalfOpenMaxRequests(backend config.Backend) int {
	if backend.HalfOpenMaxRequests <= 0 {
		return 1
	}
	return backend.HalfOpenMaxRequests
}

func backendRecoverySuccessThreshold(backend config.Backend) int {
	if backend.RecoverySuccessThreshold <= 0 {
		return 1
	}
	return backend.RecoverySuccessThreshold
}

func backendOutlierSlowResponseThreshold(backend config.Backend) int {
	if backend.OutlierConsecutiveSlowResponses <= 0 {
		return 0
	}
	return backend.OutlierConsecutiveSlowResponses
}

func backendOutlierLatencyThreshold(backend config.Backend) time.Duration {
	if strings.TrimSpace(backend.OutlierLatencyThreshold) == "" {
		return 0
	}
	threshold, err := time.ParseDuration(strings.TrimSpace(backend.OutlierLatencyThreshold))
	if err != nil || threshold <= 0 {
		return 0
	}
	return threshold
}

func backendOutlierCooldown(backend config.Backend) time.Duration {
	if strings.TrimSpace(backend.OutlierCooldown) != "" {
		if parsed, err := time.ParseDuration(strings.TrimSpace(backend.OutlierCooldown)); err == nil && parsed > 0 {
			return parsed
		}
	}
	if strings.TrimSpace(backend.Cooldown) != "" {
		if parsed, err := time.ParseDuration(strings.TrimSpace(backend.Cooldown)); err == nil && parsed > 0 {
			return parsed
		}
	}
	return defaultBackendCooldown
}

func isBackendLatencyOutlier(backend config.Backend, latency time.Duration) bool {
	threshold := backendOutlierLatencyThreshold(backend)
	return threshold > 0 && latency >= threshold
}

func updateLatencyEWMA(current, observed time.Duration) time.Duration {
	if observed <= 0 {
		return current
	}
	if current <= 0 {
		return observed
	}
	const alpha = 0.2
	return time.Duration((1.0-alpha)*float64(current) + alpha*float64(observed))
}
