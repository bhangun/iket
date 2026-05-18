package api

import (
	coreerrors "github.com/bhangun/iket/pkg/core/errors"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

func proposalProposerFromRequest(r *http.Request) string {
	if r == nil {
		return ""
	}
	return strings.TrimSpace(r.URL.Query().Get("proposer"))
}

func proposalEnvironmentFromRequest(r *http.Request) string {
	if r == nil {
		return ""
	}
	return strings.TrimSpace(r.URL.Query().Get("environment"))
}

func proposalCanaryServicesFromRequest(r *http.Request, record *configProposalRecord) []string {
	if r == nil {
		if record == nil {
			return nil
		}
		return append([]string(nil), record.CanaryServices...)
	}
	values := normalizeQueryList(r.URL.Query()["canary_service"])
	if len(values) > 0 {
		return values
	}
	if record == nil {
		return nil
	}
	return append([]string(nil), record.CanaryServices...)
}

func proposalCanaryRoutesFromRequest(r *http.Request, record *configProposalRecord) []string {
	if r == nil {
		if record == nil {
			return nil
		}
		return append([]string(nil), record.CanaryRoutes...)
	}
	values := normalizeQueryList(r.URL.Query()["canary_route"])
	if len(values) > 0 {
		return values
	}
	if record == nil {
		return nil
	}
	return append([]string(nil), record.CanaryRoutes...)
}

func proposalCanaryHeadersFromRequest(r *http.Request, record *configProposalRecord) []string {
	if r == nil {
		if record == nil {
			return nil
		}
		return append([]string(nil), record.CanaryHeaders...)
	}
	values := normalizeHeaderQueryList(r.URL.Query()["canary_header"])
	if len(values) > 0 {
		return values
	}
	if record == nil {
		return nil
	}
	return append([]string(nil), record.CanaryHeaders...)
}

func proposalCanaryPercentFromRequest(r *http.Request, record *configProposalRecord) (int, error) {
	if r == nil {
		if record == nil {
			return 0, nil
		}
		return record.CanaryPercent, nil
	}
	value := strings.TrimSpace(r.URL.Query().Get("canary_percent"))
	if value == "" {
		if record == nil {
			return 0, nil
		}
		return record.CanaryPercent, nil
	}
	percent, err := strconv.Atoi(value)
	if err != nil {
		return 0, coreerrors.New(coreerrors.CodeCanaryConfigInvalid, "Invalid canary_percent, expected integer between 1 and 99")
	}
	if percent < 1 || percent > 99 {
		return 0, coreerrors.New(coreerrors.CodeCanaryConfigInvalid, "Invalid canary_percent, expected integer between 1 and 99")
	}
	return percent, nil
}

func proposalCanaryStepsFromRequest(r *http.Request, record *configProposalRecord) ([]int, error) {
	if r == nil {
		if record == nil {
			return nil, nil
		}
		return append([]int(nil), record.CanarySteps...), nil
	}
	values := r.URL.Query()["canary_step"]
	if len(values) == 0 {
		if record == nil {
			return nil, nil
		}
		return append([]int(nil), record.CanarySteps...), nil
	}
	steps := make([]int, 0, len(values))
	seen := make(map[int]struct{})
	for _, raw := range values {
		for _, part := range strings.Split(raw, ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			step, err := strconv.Atoi(part)
			if err != nil || step < 1 || step > 100 {
				return nil, coreerrors.New(coreerrors.CodeCanaryConfigInvalid, "Invalid canary_step, expected integer between 1 and 100")
			}
			if _, ok := seen[step]; ok {
				continue
			}
			seen[step] = struct{}{}
			steps = append(steps, step)
		}
	}
	sort.Ints(steps)
	return steps, nil
}

func proposalCanaryMinRequestsFromRequest(r *http.Request, record *configProposalRecord) (int, error) {
	if r == nil {
		if record == nil {
			return 0, nil
		}
		return record.CanaryMinRequests, nil
	}
	value := strings.TrimSpace(r.URL.Query().Get("canary_min_requests"))
	if value == "" {
		if record == nil {
			return 0, nil
		}
		return record.CanaryMinRequests, nil
	}
	minRequests, err := strconv.Atoi(value)
	if err != nil || minRequests < 0 {
		return 0, coreerrors.New(coreerrors.CodeCanaryConfigInvalid, "Invalid canary_min_requests, expected non-negative integer")
	}
	return minRequests, nil
}

func proposalCanaryMaxErrorRateFromRequest(r *http.Request, record *configProposalRecord) (float64, error) {
	if r == nil {
		if record == nil {
			return 0, nil
		}
		return record.CanaryMaxErrorRate, nil
	}
	value := strings.TrimSpace(r.URL.Query().Get("canary_max_error_rate"))
	if value == "" {
		if record == nil {
			return 0, nil
		}
		return record.CanaryMaxErrorRate, nil
	}
	rate, err := strconv.ParseFloat(value, 64)
	if err != nil || rate < 0 || rate > 1 {
		return 0, coreerrors.New(coreerrors.CodeCanaryConfigInvalid, "Invalid canary_max_error_rate, expected number between 0 and 1")
	}
	return rate, nil
}

func proposalCanaryMaxP95LatencyFromRequest(r *http.Request, record *configProposalRecord) (string, error) {
	if r == nil {
		if record == nil {
			return "", nil
		}
		return strings.TrimSpace(record.CanaryMaxP95Latency), nil
	}
	value := strings.TrimSpace(r.URL.Query().Get("canary_max_p95_latency"))
	if value == "" {
		if record == nil {
			return "", nil
		}
		return strings.TrimSpace(record.CanaryMaxP95Latency), nil
	}
	if _, err := time.ParseDuration(value); err != nil {
		return "", coreerrors.New(coreerrors.CodeCanaryConfigInvalid, "Invalid canary_max_p95_latency, expected Go duration like 500ms or 2s")
	}
	return value, nil
}

func proposalCanaryAutoReconcileFromRequest(r *http.Request, record *configProposalRecord) (bool, error) {
	if r == nil {
		return record != nil && record.CanaryAutoReconcile, nil
	}
	value := strings.TrimSpace(r.URL.Query().Get("canary_auto"))
	if value == "" {
		if record == nil {
			return false, nil
		}
		return record.CanaryAutoReconcile, nil
	}
	enabled, err := strconv.ParseBool(value)
	if err != nil {
		return false, coreerrors.New(coreerrors.CodeCanaryConfigInvalid, "Invalid canary_auto, expected true or false")
	}
	return enabled, nil
}

func proposalCanaryAutoIntervalFromRequest(r *http.Request, record *configProposalRecord) (string, error) {
	if r == nil {
		if record == nil {
			return "", nil
		}
		return strings.TrimSpace(record.CanaryAutoInterval), nil
	}
	value := strings.TrimSpace(r.URL.Query().Get("canary_auto_interval"))
	if value == "" {
		if record == nil {
			return "", nil
		}
		return strings.TrimSpace(record.CanaryAutoInterval), nil
	}
	if _, err := time.ParseDuration(value); err != nil {
		return "", coreerrors.New(coreerrors.CodeCanaryConfigInvalid, "Invalid canary_auto_interval, expected Go duration like 30s or 5m")
	}
	return value, nil
}

func proposalCanaryAutoReviewerFromRequest(r *http.Request, record *configProposalRecord) string {
	if r == nil {
		if record == nil {
			return ""
		}
		return strings.TrimSpace(record.CanaryAutoReviewer)
	}
	value := strings.TrimSpace(r.URL.Query().Get("canary_auto_reviewer"))
	if value != "" {
		return value
	}
	if record == nil {
		return ""
	}
	return strings.TrimSpace(record.CanaryAutoReviewer)
}

func normalizeQueryList(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func normalizeHeaderQueryList(values []string) []string {
	normalized := normalizeQueryList(values)
	if len(normalized) == 0 {
		return nil
	}
	out := make([]string, 0, len(normalized))
	for _, value := range normalized {
		if strings.Contains(value, "=") {
			out = append(out, value)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func mergeNormalizedLists(base, extra []string) []string {
	return normalizeQueryList(append(append([]string(nil), base...), extra...))
}

func appendUniqueString(values []string, candidate string) []string {
	candidate = strings.TrimSpace(candidate)
	if candidate == "" {
		return values
	}
	for _, value := range values {
		if strings.EqualFold(strings.TrimSpace(value), candidate) {
			return values
		}
	}
	return append(values, candidate)
}

func proposalNotBeforeFromRequest(r *http.Request) (time.Time, error) {
	if r == nil {
		return time.Time{}, nil
	}
	value := strings.TrimSpace(r.URL.Query().Get("not_before"))
	if value == "" {
		return time.Time{}, nil
	}
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}, coreerrors.New(coreerrors.CodeValidationError, "Invalid not_before timestamp, expected RFC3339")
	}
	return parsed.UTC(), nil
}
