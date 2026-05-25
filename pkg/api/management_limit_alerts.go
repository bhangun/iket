package api

import "time"

func (api *ManagementAPI) reconcileGatewayLimitAlertNotifications(now time.Time) {
	cfg := api.gateway.GetConfig()
	if cfg == nil {
		return
	}
	policy := cfg.Security.MutationPolicy.LimitAlertNotifications
	if !policy.Enabled {
		return
	}
	interval := policyAlertNotificationInterval(policy)
	minInterval := policyAlertNotificationMinInterval(policy)
	window := policyAlertNotificationWindow(policy)
	minCount := policyAlertNotificationMinCount(policy)
	minSeverity := normalizeSLABreachTier(policy.MinSeverity)

	api.queueDigestNotifyMu.Lock()
	lastSent := api.lastLimitAlertNotificationAt
	lastChecksum := api.lastLimitAlertNotificationChecksum
	api.queueDigestNotifyMu.Unlock()
	if !lastSent.IsZero() && now.Sub(lastSent) < interval {
		return
	}

	evaluationMinCount := effectiveLimitAlertEvaluationMinCount(minCount, cfg, policy)
	summary := api.gateway.RouteLimitAlertSummaryAt(now, window, evaluationMinCount)
	summary.Window = window.String()
	summary = applyLimitAlertPolicies(summary, policy, cfg)
	summary = filterLimitAlertSummaryBySeverity(summary, minSeverity)
	openedEvents, stageChangedEvents, resolvedEvents := api.updateGatewayLimitAlertIncidentState(summary.Alerts, now)
	if summary.TotalAlerts == 0 {
		for _, event := range resolvedEvents {
			api.emitManagementEvent(event)
		}
		api.queueDigestNotifyMu.Lock()
		api.lastLimitAlertNotificationAt = now
		api.lastLimitAlertNotificationChecksum = ""
		api.queueDigestNotifyMu.Unlock()
		return
	}

	checksum := proposalQueueDigestChecksum(map[string]interface{}{
		"window":         summary.Window,
		"window_seconds": summary.WindowSeconds,
		"min_count":      summary.MinCount,
		"by_severity":    summary.BySeverity,
		"alerts":         summary.Alerts,
	})
	if policy.OnlyOnChange && checksum != "" && checksum == lastChecksum {
		return
	}
	if !lastSent.IsZero() && now.Sub(lastSent) < minInterval {
		return
	}

	api.emitManagementEvent(managementWebhookEvent{
		Event:      "gateway.limit_alert_digest",
		OccurredAt: now,
		Data: map[string]interface{}{
			"window":         summary.Window,
			"window_seconds": summary.WindowSeconds,
			"min_count":      summary.MinCount,
			"min_severity":   minSeverity,
			"total_alerts":   summary.TotalAlerts,
			"by_severity":    summary.BySeverity,
			"alerts":         summary.Alerts,
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
			Event:      "gateway.limit_alert",
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
				"bucket_id":             alert.BucketID,
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
	api.lastLimitAlertNotificationAt = now
	api.lastLimitAlertNotificationChecksum = checksum
	api.queueDigestNotifyMu.Unlock()
}

func (api *ManagementAPI) autoNotifyGatewayLimitAlerts() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		api.reconcileGatewayLimitAlertNotifications(time.Now().UTC())
	}
}
