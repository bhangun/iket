package api

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	coreerrors "github.com/bhangun/iket/pkg/core/errors"
	"github.com/bhangun/iket/pkg/logging"
)

func (api *ManagementAPI) buildProposalCanaryEvaluation(record *configProposalRecord) (map[string]interface{}, error) {
	if record == nil {
		return nil, managedError(coreerrors.CodeProposalNotFound, "Proposal not found", nil)
	}
	if !hasProposalCanaryPlan(record) && record.Status != "canary_active" {
		return nil, managedCanaryStateError("Proposal does not have a canary rollout", nil)
	}
	services, routes, err := proposalCanaryMetricTargets(record)
	if err != nil {
		return nil, err
	}
	logs := filterCanaryLogEntries(api.logger.RecentLogs(2000, ""), services, routes)
	requests := 0
	failed := 0
	durations := make([]time.Duration, 0, len(logs))
	for _, entry := range logs {
		status, ok := fieldInt(entry.Fields, "status_code")
		if !ok {
			continue
		}
		requests++
		if status >= 500 {
			failed++
		}
		if duration, ok := fieldDuration(entry.Fields, "duration"); ok {
			durations = append(durations, duration)
		}
	}
	avg := averageDuration(durations)
	p95 := percentileDuration(durations, 95)
	p99 := percentileDuration(durations, 99)
	errorRate := 0.0
	if requests > 0 {
		errorRate = float64(failed) / float64(requests)
	}

	thresholds := canaryEvaluationThresholds{
		MinRequests:   record.CanaryMinRequests,
		MaxErrorRate:  record.CanaryMaxErrorRate,
		MaxP95Latency: strings.TrimSpace(record.CanaryMaxP95Latency),
	}
	healthy := true
	reasons := make([]string, 0)
	if thresholds.MinRequests > 0 && requests < thresholds.MinRequests {
		healthy = false
		reasons = append(reasons, fmt.Sprintf("canary observed %d request(s), below minimum %d", requests, thresholds.MinRequests))
	}
	if thresholds.MaxErrorRate > 0 && errorRate > thresholds.MaxErrorRate {
		healthy = false
		reasons = append(reasons, fmt.Sprintf("canary error rate %.4f exceeded limit %.4f", errorRate, thresholds.MaxErrorRate))
	}
	if thresholds.MaxP95Latency != "" {
		limit, _ := time.ParseDuration(thresholds.MaxP95Latency)
		if limit > 0 && p95 > limit {
			healthy = false
			reasons = append(reasons, fmt.Sprintf("canary p95 latency %s exceeded limit %s", p95, limit))
		}
	}
	if len(reasons) == 0 {
		reasons = append(reasons, "canary metrics are within configured thresholds")
	}

	return map[string]interface{}{
		"proposal_id":       record.ID,
		"status":            record.Status,
		"environment":       record.Environment,
		"canary_services":   record.CanaryServices,
		"canary_routes":     record.CanaryRoutes,
		"canary_headers":    record.CanaryHeaders,
		"canary_percent":    record.CanaryPercent,
		"canary_steps":      record.CanarySteps,
		"target_services":   services,
		"target_routes":     routes,
		"thresholds":        thresholds,
		"requests":          requests,
		"failed_requests":   failed,
		"error_rate":        errorRate,
		"average_latency":   avg.String(),
		"p95_latency":       p95.String(),
		"p99_latency":       p99.String(),
		"healthy":           healthy,
		"reasons":           reasons,
		"evaluation_window": "recent_logs_2000",
	}, nil
}

type canaryEvaluationThresholds struct {
	MinRequests   int     `json:"min_requests,omitempty"`
	MaxErrorRate  float64 `json:"max_error_rate,omitempty"`
	MaxP95Latency string  `json:"max_p95_latency,omitempty"`
}

func proposalCanaryMetricTargets(record *configProposalRecord) ([]string, []string, error) {
	if record == nil || record.Config == nil {
		return nil, nil, managedProposalVerificationError("Proposal has no stored configuration", nil)
	}
	planServices := normalizeQueryList(record.CanaryServices)
	planRoutes := normalizeQueryList(record.CanaryRoutes)
	targetServices := make([]string, 0)
	targetRoutes := make([]string, 0)
	for _, svcCfg := range record.Config.Services {
		for _, svc := range svcCfg.Services {
			if !serviceSelectedForCanary(svc, planServices, planRoutes) {
				continue
			}
			serviceName := displayServiceName(svc)
			if len(record.CanaryHeaders) > 0 || record.CanaryPercent > 0 {
				serviceName = canaryServiceName(serviceName)
			}
			targetServices = appendUniqueString(targetServices, serviceName)
			serviceOnly := serviceSelectedOnlyByName(svc, planServices, planRoutes)
			for _, route := range svc.Routes {
				if serviceOnly || routeSelectedForCanary(svc, route, planRoutes) {
					targetRoutes = appendUniqueString(targetRoutes, strings.TrimSpace(route.Path))
				}
			}
		}
	}
	if len(targetServices) == 0 && len(targetRoutes) == 0 {
		return nil, nil, managedCanaryConfigError("Canary plan did not match any proposal services or routes", nil)
	}
	sort.Strings(targetServices)
	sort.Strings(targetRoutes)
	return targetServices, targetRoutes, nil
}

func filterCanaryLogEntries(entries []logging.LogEntry, serviceNames, routeNames []string) []logging.LogEntry {
	if len(entries) == 0 {
		return nil
	}
	serviceSet := make(map[string]struct{}, len(serviceNames))
	for _, name := range serviceNames {
		name = strings.TrimSpace(name)
		if name != "" {
			serviceSet[name] = struct{}{}
		}
	}
	routeSet := make(map[string]struct{}, len(routeNames))
	for _, name := range routeNames {
		name = strings.TrimSpace(name)
		if name != "" {
			routeSet[name] = struct{}{}
		}
	}
	filtered := make([]logging.LogEntry, 0, len(entries))
	for _, entry := range entries {
		serviceName := fieldString(entry.Fields, "service_name")
		routeName := fieldString(entry.Fields, "route_name")
		_, serviceMatch := serviceSet[serviceName]
		_, routeMatch := routeSet[routeName]
		if serviceMatch || routeMatch {
			filtered = append(filtered, entry)
		}
	}
	return filtered
}

func fieldInt(fields map[string]interface{}, key string) (int, bool) {
	if fields == nil {
		return 0, false
	}
	value, ok := fields[key]
	if !ok || value == nil {
		return 0, false
	}
	switch v := value.(type) {
	case int:
		return v, true
	case int64:
		return int(v), true
	case float64:
		return int(v), true
	case json.Number:
		i, err := v.Int64()
		return int(i), err == nil
	case string:
		i, err := strconv.Atoi(strings.TrimSpace(v))
		return i, err == nil
	default:
		return 0, false
	}
}

func fieldDuration(fields map[string]interface{}, key string) (time.Duration, bool) {
	if fields == nil {
		return 0, false
	}
	value, ok := fields[key]
	if !ok || value == nil {
		return 0, false
	}
	switch v := value.(type) {
	case string:
		d, err := time.ParseDuration(strings.TrimSpace(v))
		return d, err == nil
	case time.Duration:
		return v, true
	case float64:
		return time.Duration(v * float64(time.Second)), true
	default:
		return 0, false
	}
}

func averageDuration(values []time.Duration) time.Duration {
	if len(values) == 0 {
		return 0
	}
	var total time.Duration
	for _, value := range values {
		total += value
	}
	return total / time.Duration(len(values))
}

func percentileDuration(values []time.Duration, percentile int) time.Duration {
	if len(values) == 0 {
		return 0
	}
	sorted := append([]time.Duration(nil), values...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	if percentile <= 0 {
		return sorted[0]
	}
	if percentile >= 100 {
		return sorted[len(sorted)-1]
	}
	index := (len(sorted)*percentile + 99) / 100
	if index <= 0 {
		index = 1
	}
	if index > len(sorted) {
		index = len(sorted)
	}
	return sorted[index-1]
}
