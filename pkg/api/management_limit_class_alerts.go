package api

import (
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
	detailedMinPriority := policy.DetailedMinBucketClassPriority
	detailedMaxClasses := policy.DetailedMaxBucketClasses

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
	summary = api.filterLimitClassAlertSummaryBySnooze(summary, now)
	openedEvents = api.filterLimitClassIncidentEventsBySnooze(openedEvents, now)
	stageChangedEvents = api.filterLimitClassIncidentEventsBySnooze(stageChangedEvents, now)
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

	digestAlerts, summarizedEntries := api.splitLimitClassAlertDigestRows(summary.Alerts, detailedMinPriority, detailedMaxClasses)

	api.emitManagementEvent(managementWebhookEvent{
		Event:      "gateway.limit_class_alert_digest",
		OccurredAt: now,
		Data: map[string]interface{}{
			"window":                             summary.Window,
			"window_seconds":                     summary.WindowSeconds,
			"min_count":                          summary.MinCount,
			"min_severity":                       minSeverity,
			"total_alerts":                       len(digestAlerts),
			"top_bucket_class":                   summary.TopBucketClass,
			"by_severity":                        summary.BySeverity,
			"alerts":                             digestAlerts,
			"summarized_class_alert_count":       len(summary.Alerts) - len(digestAlerts),
			"summarized_class_alerts_by_class":   summarizedEntries,
			"detailed_min_bucket_class_priority": detailedMinPriority,
			"detailed_max_bucket_classes":        detailedMaxClasses,
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
				"bucket_class_priority": api.limitAlertBucketClassPriority(alert.BucketClass),
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
