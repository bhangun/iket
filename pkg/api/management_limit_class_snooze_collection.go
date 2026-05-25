package api

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/bhangun/iket/pkg/core/gateway"
)

func (api *ManagementAPI) collectGatewayLimitClassSnoozes(r *http.Request, now time.Time) (int, []map[string]interface{}, string, error) {
	bucketClassFilter := strings.TrimSpace(r.URL.Query().Get("bucket_class"))
	serviceNameFilter := strings.TrimSpace(r.URL.Query().Get("service_name"))
	routePathFilter := strings.TrimSpace(r.URL.Query().Get("route_path"))
	limitTypeFilter := strings.TrimSpace(r.URL.Query().Get("limit_type"))
	keyTypeFilter := strings.TrimSpace(r.URL.Query().Get("key_type"))
	expiringWithinValue := strings.TrimSpace(r.URL.Query().Get("expiring_within"))

	var expiringWithin time.Duration
	if expiringWithinValue != "" {
		parsed, err := time.ParseDuration(expiringWithinValue)
		if err != nil || parsed <= 0 {
			return 0, nil, expiringWithinValue, managedValidationError("expiring_within must be a positive Go duration such as 15m or 1h", err)
		}
		expiringWithin = parsed
	}
	api.queueDigestNotifyMu.Lock()
	snoozes := make([]map[string]interface{}, 0, len(api.limitClassAlertIncidentState))
	for _, state := range api.limitClassAlertIncidentState {
		if state.SnoozedUntil.IsZero() || !state.SnoozedUntil.After(now) {
			continue
		}
		entry := api.buildGatewayLimitClassAlertIncidentData(state, gateway.RouteLimitClassAlert{
			Severity:    state.Severity,
			ServiceName: state.ServiceName,
			RoutePath:   state.RoutePath,
			LimitType:   state.LimitType,
			KeyType:     state.KeyType,
			BucketClass: state.BucketClass,
			Count:       state.LastCount,
		}, now)
		remaining := state.SnoozedUntil.Sub(now)
		thresholds := api.limitClassSnoozeThresholds(state.BucketClass)
		entry["remaining_snooze_seconds"] = remaining.Seconds()
		entry["expiring_soon"] = expiringWithin > 0 && remaining <= expiringWithin
		entry["severity"] = limitClassSnoozeSeverity(remaining, thresholds)
		entry["snooze_stage"] = limitClassSnoozeSeverity(remaining, thresholds)
		if bucketClassFilter != "" && strings.TrimSpace(fmt.Sprint(entry["bucket_class"])) != bucketClassFilter {
			continue
		}
		if serviceNameFilter != "" && strings.TrimSpace(fmt.Sprint(entry["service_name"])) != serviceNameFilter {
			continue
		}
		if routePathFilter != "" && strings.TrimSpace(fmt.Sprint(entry["route_path"])) != routePathFilter {
			continue
		}
		if limitTypeFilter != "" && strings.TrimSpace(fmt.Sprint(entry["limit_type"])) != limitTypeFilter {
			continue
		}
		if keyTypeFilter != "" && strings.TrimSpace(fmt.Sprint(entry["key_type"])) != keyTypeFilter {
			continue
		}
		if expiringWithin > 0 && remaining > expiringWithin {
			continue
		}
		snoozes = append(snoozes, entry)
	}
	api.queueDigestNotifyMu.Unlock()
	totalSnoozes := len(snoozes)

	sort.Slice(snoozes, func(i, j int) bool {
		leftRemaining := 0.0
		if value, ok := snoozes[i]["remaining_snooze_seconds"].(float64); ok {
			leftRemaining = value
		}
		rightRemaining := 0.0
		if value, ok := snoozes[j]["remaining_snooze_seconds"].(float64); ok {
			rightRemaining = value
		}
		if leftRemaining == rightRemaining {
			return strings.TrimSpace(fmt.Sprint(snoozes[i]["incident_id"])) < strings.TrimSpace(fmt.Sprint(snoozes[j]["incident_id"]))
		}
		return leftRemaining < rightRemaining
	})

	return totalSnoozes, snoozes, expiringWithinValue, nil
}

type limitClassSnoozeThresholds struct {
	ElevatedWithin time.Duration
	CriticalWithin time.Duration
}

func (api *ManagementAPI) limitClassSnoozeThresholds(bucketClass string) limitClassSnoozeThresholds {
	thresholds := limitClassSnoozeThresholds{
		ElevatedWithin: 15 * time.Minute,
		CriticalWithin: 5 * time.Minute,
	}
	cfg := api.gateway.GetConfig()
	if cfg == nil {
		return thresholds
	}
	policy := cfg.Security.MutationPolicy.LimitClassSnoozeNotifications
	if strings.TrimSpace(policy.SnoozeElevatedWithin) != "" {
		if parsed, err := time.ParseDuration(strings.TrimSpace(policy.SnoozeElevatedWithin)); err == nil && parsed > 0 {
			thresholds.ElevatedWithin = parsed
		}
	}
	if strings.TrimSpace(policy.SnoozeCriticalWithin) != "" {
		if parsed, err := time.ParseDuration(strings.TrimSpace(policy.SnoozeCriticalWithin)); err == nil && parsed > 0 {
			thresholds.CriticalWithin = parsed
		}
	}
	if bucketClass != "" {
		if classConfig, ok := cfg.Security.LimitAlertBucketClasses[strings.TrimSpace(bucketClass)]; ok {
			if strings.TrimSpace(classConfig.SnoozeElevatedWithin) != "" {
				if parsed, err := time.ParseDuration(strings.TrimSpace(classConfig.SnoozeElevatedWithin)); err == nil && parsed > 0 {
					thresholds.ElevatedWithin = parsed
				}
			}
			if strings.TrimSpace(classConfig.SnoozeCriticalWithin) != "" {
				if parsed, err := time.ParseDuration(strings.TrimSpace(classConfig.SnoozeCriticalWithin)); err == nil && parsed > 0 {
					thresholds.CriticalWithin = parsed
				}
			}
		}
	}
	return thresholds
}

func limitClassSnoozeSeverity(remaining time.Duration, thresholds limitClassSnoozeThresholds) string {
	switch {
	case remaining <= 0:
		return "critical"
	case thresholds.CriticalWithin > 0 && remaining <= thresholds.CriticalWithin:
		return "critical"
	case thresholds.ElevatedWithin > 0 && remaining <= thresholds.ElevatedWithin:
		return "elevated"
	default:
		return "warning"
	}
}
