package api

import (
	"net/http"
	"strconv"
	"strings"
	"time"
)

func parseGatewayPolicyAlertQuery(r *http.Request) (time.Duration, string, int) {
	return parseGatewayAlertQuery(r, 5*time.Minute, "5m", 3)
}

func parseGatewayLimitAlertQuery(r *http.Request) (time.Duration, string, int) {
	return parseGatewayAlertQuery(r, 5*time.Minute, "5m", 3)
}

func parseGatewayAlertQuery(r *http.Request, defaultWindow time.Duration, defaultWindowSource string, defaultMinCount int) (time.Duration, string, int) {
	window, windowSource := parseGatewayWindowQuery(r, defaultWindow, defaultWindowSource)
	minCount := parsePositiveIntQuery(r, "min_count", defaultMinCount)
	return window, windowSource, minCount
}

func parseGatewayWindowQuery(r *http.Request, defaultWindow time.Duration, defaultWindowSource string) (time.Duration, string) {
	if raw := strings.TrimSpace(r.URL.Query().Get("window")); raw != "" {
		if parsed, err := time.ParseDuration(raw); err == nil && parsed > 0 {
			return parsed, raw
		}
	}
	return defaultWindow, defaultWindowSource
}

func parsePositiveIntQuery(r *http.Request, key string, fallback int) int {
	if raw := strings.TrimSpace(r.URL.Query().Get(key)); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil && parsed > 0 {
			return parsed
		}
	}
	return fallback
}
