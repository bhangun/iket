package api

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/bhangun/iket/pkg/core/gateway"
)

func (api *ManagementAPI) reconcileGatewayLimitClassAlertNotifications(now time.Time) {
	cfg := api.gateway.GetConfig()
	if cfg == nil {
		return
	}
	policy := cfg.Security.MutationPolicy.LimitClassAlertNotifications
	if !policy.Enabled {
		return
	}
	interval := policyAlertNotificationInterval(policy)
	minInterval := policyAlertNotificationMinInterval(policy)
	window := policyAlertNotificationWindow(policy)
	minCount := policyAlertNotificationMinCount(policy)
	minSeverity := normalizeSLABreachTier(policy.MinSeverity)

	api.queueDigestNotifyMu.Lock()
	lastSent := api.lastLimitClassAlertNotificationAt
	lastChecksum := api.lastLimitClassAlertNotificationChecksum
	api.queueDigestNotifyMu.Unlock()
	if !lastSent.IsZero() && now.Sub(lastSent) < interval {
		return
	}

	summary := api.gateway.RouteLimitClassAlertSummaryAt(now, window, minCount)
	summary.Window = window.String()
	summary = filterLimitClassAlertSummaryBySeverity(summary, minSeverity)
	openedEvents, stageChangedEvents, resolvedEvents := api.updateGatewayLimitClassAlertIncidentState(summary.Alerts, now)
	if summary.TotalAlerts == 0 {
		for _, event := range resolvedEvents {
			api.emitManagementEvent(event)
		}
		api.queueDigestNotifyMu.Lock()
		api.lastLimitClassAlertNotificationAt = now
		api.lastLimitClassAlertNotificationChecksum = ""
		api.queueDigestNotifyMu.Unlock()
		return
	}

	checksum := proposalQueueDigestChecksum(map[string]interface{}{
		"window":           summary.Window,
		"window_seconds":   summary.WindowSeconds,
		"min_count":        summary.MinCount,
		"top_bucket_class": summary.TopBucketClass,
		"by_severity":      summary.BySeverity,
		"alerts":           summary.Alerts,
	})
	if policy.OnlyOnChange && checksum != "" && checksum == lastChecksum {
		return
	}
	if !lastSent.IsZero() && now.Sub(lastSent) < minInterval {
		return
	}

	api.emitManagementEvent(managementWebhookEvent{
		Event:      "gateway.limit_class_alert_digest",
		OccurredAt: now,
		Data: map[string]interface{}{
			"window":           summary.Window,
			"window_seconds":   summary.WindowSeconds,
			"min_count":        summary.MinCount,
			"min_severity":     minSeverity,
			"total_alerts":     summary.TotalAlerts,
			"top_bucket_class": summary.TopBucketClass,
			"by_severity":      summary.BySeverity,
			"alerts":           summary.Alerts,
		},
	})
	for _, event := range openedEvents {
		api.emitManagementEvent(event)
	}
	for _, event := range stageChangedEvents {
		api.emitManagementEvent(event)
	}
	for _, event := range resolvedEvents {
		api.emitManagementEvent(event)
	}
	for _, alert := range summary.Alerts {
		api.emitManagementEvent(managementWebhookEvent{
			Event:      "gateway.limit_class_alert",
			OccurredAt: now,
			Data: map[string]interface{}{
				"window":                summary.Window,
				"window_seconds":        summary.WindowSeconds,
				"min_count":             summary.MinCount,
				"severity":              alert.Severity,
				"service_name":          alert.ServiceName,
				"route_path":            alert.RoutePath,
				"limit_type":            alert.LimitType,
				"key_type":              alert.KeyType,
				"bucket_class":          alert.BucketClass,
				"count":                 alert.Count,
				"queued_admissions":     alert.QueuedAdmissions,
				"queue_full_rejections": alert.QueueFullRejections,
				"average_queue_wait_ms": alert.AverageQueueWaitMs,
				"max_queue_wait_ms":     alert.MaxQueueWaitMs,
				"since":                 alert.Since,
			},
		})
	}

	api.queueDigestNotifyMu.Lock()
	api.lastLimitClassAlertNotificationAt = now
	api.lastLimitClassAlertNotificationChecksum = checksum
	api.queueDigestNotifyMu.Unlock()
}

func (api *ManagementAPI) autoNotifyGatewayLimitClassAlerts() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		api.reconcileGatewayLimitClassAlertNotifications(time.Now().UTC())
	}
}

func filterLimitClassAlertSummaryBySeverity(summary gateway.RouteLimitClassAlertSummary, minSeverity string) gateway.RouteLimitClassAlertSummary {
	minRank := slaBreachTierRank(minSeverity)
	if minRank <= 0 {
		return summary
	}
	filtered := gateway.RouteLimitClassAlertSummary{
		Window:         summary.Window,
		WindowSeconds:  summary.WindowSeconds,
		MinCount:       summary.MinCount,
		TopBucketClass: summary.TopBucketClass,
		BySeverity:     map[string]int{"warning": 0, "elevated": 0, "critical": 0},
	}
	for _, alert := range summary.Alerts {
		if slaBreachTierRank(alert.Severity) < minRank {
			continue
		}
		filtered.Alerts = append(filtered.Alerts, alert)
		filtered.BySeverity[alert.Severity]++
	}
	filtered.TotalAlerts = len(filtered.Alerts)
	if len(filtered.Alerts) > 0 {
		filtered.TopBucketClass = filtered.Alerts[0].BucketClass
	}
	return filtered
}

func (api *ManagementAPI) updateGatewayLimitClassAlertIncidentState(alerts []gateway.RouteLimitClassAlert, now time.Time) ([]managementWebhookEvent, []managementWebhookEvent, []managementWebhookEvent) {
	current := make(map[string]gateway.RouteLimitClassAlert, len(alerts))
	for _, alert := range alerts {
		current[gatewayLimitClassAlertIncidentKey(alert)] = alert
	}

	api.queueDigestNotifyMu.Lock()
	defer api.queueDigestNotifyMu.Unlock()

	opened := make([]managementWebhookEvent, 0)
	stageChanged := make([]managementWebhookEvent, 0)
	resolved := make([]managementWebhookEvent, 0)

	for key, alert := range current {
		state, ok := api.limitClassAlertIncidentState[key]
		if !ok || strings.TrimSpace(state.IncidentID) == "" {
			state = gatewayLimitClassAlertIncidentState{
				IncidentID:  fmt.Sprintf("lcal-%s-%s", now.UTC().Format("20060102-150405.000000000"), shortLimitClassAlertIncidentSuffix(key)),
				Severity:    strings.TrimSpace(alert.Severity),
				ServiceName: strings.TrimSpace(alert.ServiceName),
				RoutePath:   strings.TrimSpace(alert.RoutePath),
				LimitType:   strings.TrimSpace(alert.LimitType),
				KeyType:     strings.TrimSpace(alert.KeyType),
				BucketClass: strings.TrimSpace(alert.BucketClass),
				FirstSeenAt: now,
				LastSeenAt:  now,
				LastCount:   alert.Count,
			}
			api.limitClassAlertIncidentState[key] = state
			opened = append(opened, managementWebhookEvent{
				Event:      "gateway.limit_class_alert_opened",
				OccurredAt: now,
				Data:       buildGatewayLimitClassAlertIncidentData(state, alert, now),
			})
			continue
		}

		previousSeverity := state.Severity
		state.LastSeenAt = now
		state.LastCount = alert.Count
		if slaBreachTierRank(alert.Severity) > slaBreachTierRank(previousSeverity) {
			state.Severity = strings.TrimSpace(alert.Severity)
			api.limitClassAlertIncidentState[key] = state
			data := buildGatewayLimitClassAlertIncidentData(state, alert, now)
			data["previous_severity"] = previousSeverity
			stageChanged = append(stageChanged, managementWebhookEvent{
				Event:      "gateway.limit_class_alert_stage_changed",
				OccurredAt: now,
				Data:       data,
			})
			continue
		}
		api.limitClassAlertIncidentState[key] = state
	}

	for key, state := range api.limitClassAlertIncidentState {
		if _, ok := current[key]; ok {
			continue
		}
		resolved = append(resolved, managementWebhookEvent{
			Event:      "gateway.limit_class_alert_resolved",
			OccurredAt: now,
			Data: buildGatewayLimitClassAlertIncidentData(state, gateway.RouteLimitClassAlert{
				Severity:    state.Severity,
				ServiceName: state.ServiceName,
				RoutePath:   state.RoutePath,
				LimitType:   state.LimitType,
				KeyType:     state.KeyType,
				BucketClass: state.BucketClass,
				Count:       state.LastCount,
			}, now),
		})
		delete(api.limitClassAlertIncidentState, key)
	}

	return opened, stageChanged, resolved
}

func gatewayLimitClassAlertIncidentKey(alert gateway.RouteLimitClassAlert) string {
	return strings.TrimSpace(alert.ServiceName) + "|" + strings.TrimSpace(alert.RoutePath) + "|" + strings.TrimSpace(alert.LimitType) + "|" + strings.TrimSpace(alert.BucketClass)
}

func shortLimitClassAlertIncidentSuffix(key string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(key)))
	return hex.EncodeToString(sum[:4])
}

func buildGatewayLimitClassAlertIncidentData(state gatewayLimitClassAlertIncidentState, alert gateway.RouteLimitClassAlert, now time.Time) map[string]interface{} {
	age := 0.0
	if !state.FirstSeenAt.IsZero() {
		age = now.Sub(state.FirstSeenAt).Seconds()
		if age < 0 {
			age = 0
		}
	}
	severity := strings.TrimSpace(alert.Severity)
	if severity == "" {
		severity = strings.TrimSpace(state.Severity)
	}
	count := alert.Count
	if count <= 0 {
		count = state.LastCount
	}
	return map[string]interface{}{
		"incident_id":           strings.TrimSpace(state.IncidentID),
		"severity":              severity,
		"service_name":          strings.TrimSpace(state.ServiceName),
		"route_path":            strings.TrimSpace(state.RoutePath),
		"limit_type":            strings.TrimSpace(state.LimitType),
		"key_type":              strings.TrimSpace(alert.KeyType),
		"bucket_class":          strings.TrimSpace(alert.BucketClass),
		"count":                 count,
		"queued_admissions":     alert.QueuedAdmissions,
		"queue_full_rejections": alert.QueueFullRejections,
		"average_queue_wait_ms": alert.AverageQueueWaitMs,
		"max_queue_wait_ms":     alert.MaxQueueWaitMs,
		"first_seen_at":         state.FirstSeenAt,
		"last_seen_at":          state.LastSeenAt,
		"incident_age_seconds":  age,
	}
}

func (api *ManagementAPI) getGatewayLimitClassIncidents(w http.ResponseWriter, r *http.Request) {
	now := time.Now().UTC()

	api.queueDigestNotifyMu.Lock()
	incidents := make([]map[string]interface{}, 0, len(api.limitClassAlertIncidentState))
	for _, state := range api.limitClassAlertIncidentState {
		incidents = append(incidents, buildGatewayLimitClassAlertIncidentData(state, gateway.RouteLimitClassAlert{
			Severity:    state.Severity,
			ServiceName: state.ServiceName,
			RoutePath:   state.RoutePath,
			LimitType:   state.LimitType,
			KeyType:     state.KeyType,
			BucketClass: state.BucketClass,
			Count:       state.LastCount,
		}, now))
	}
	api.queueDigestNotifyMu.Unlock()

	sort.Slice(incidents, func(i, j int) bool {
		leftSeverity := normalizeSLABreachTier(fmt.Sprint(incidents[i]["severity"]))
		rightSeverity := normalizeSLABreachTier(fmt.Sprint(incidents[j]["severity"]))
		if slaBreachTierRank(leftSeverity) == slaBreachTierRank(rightSeverity) {
			leftAge := floatValue(incidents[i]["incident_age_seconds"])
			rightAge := floatValue(incidents[j]["incident_age_seconds"])
			if leftAge == rightAge {
				return strings.TrimSpace(fmt.Sprint(incidents[i]["incident_id"])) < strings.TrimSpace(fmt.Sprint(incidents[j]["incident_id"]))
			}
			return leftAge > rightAge
		}
		return slaBreachTierRank(leftSeverity) > slaBreachTierRank(rightSeverity)
	})

	api.writeJSON(w, map[string]interface{}{
		"total_incidents": len(incidents),
		"incidents":       incidents,
		"generated_at":    now,
	})
}
