package gateway

import (
	"crypto/rand"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/bhangun/iket/pkg/config"
)

func routeRetryAttempts(route config.RouterConfig) int {
	if route.RetryCount <= 0 {
		return 1
	}
	return route.RetryCount + 1
}

func routeRetryBackoff(route config.RouterConfig) time.Duration {
	if strings.TrimSpace(route.RetryBackoff) == "" {
		return 0
	}
	backoff, err := time.ParseDuration(strings.TrimSpace(route.RetryBackoff))
	if err != nil || backoff < 0 {
		return 0
	}
	return backoff
}

func routeRetryJitter(route config.RouterConfig) time.Duration {
	if strings.TrimSpace(route.RetryJitter) == "" {
		return 0
	}
	jitter, err := time.ParseDuration(strings.TrimSpace(route.RetryJitter))
	if err != nil || jitter < 0 {
		return 0
	}
	return jitter
}

func retryJitterOffset(max time.Duration) time.Duration {
	if max <= 0 {
		return 0
	}
	n, err := rand.Int(rand.Reader, big.NewInt(max.Nanoseconds()+1))
	if err != nil {
		return 0
	}
	return time.Duration(n.Int64())
}

func routeRetryStatusSet(route config.RouterConfig) map[int]bool {
	if len(route.RetryStatuses) == 0 {
		return map[int]bool{
			http.StatusBadGateway:         true,
			http.StatusServiceUnavailable: true,
			http.StatusGatewayTimeout:     true,
			http.StatusTooManyRequests:    true,
		}
	}
	statuses := make(map[int]bool, len(route.RetryStatuses))
	for _, statusCode := range route.RetryStatuses {
		statuses[statusCode] = true
	}
	return statuses
}

func routeRetryAllowedForMethod(route config.RouterConfig, method string) bool {
	if route.RetryUnsafe {
		return true
	}
	switch strings.ToUpper(strings.TrimSpace(method)) {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace, http.MethodPut, http.MethodDelete:
		return true
	default:
		return false
	}
}
