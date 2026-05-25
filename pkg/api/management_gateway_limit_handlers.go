package api

import (
	"net/http"
	"time"

	"github.com/bhangun/iket/pkg/config"
)

func (api *ManagementAPI) getGatewayLimitHits(w http.ResponseWriter, r *http.Request) {
	summary := api.gateway.RouteLimitHitSummary()
	window, windowSource := parseGatewayWindowQuery(r, 5*time.Minute, "5m")
	recent := api.gateway.RouteLimitHitWindowSummary(window)
	recent.Window = windowSource
	api.writeJSON(w, map[string]interface{}{
		"total":         summary.Total,
		"updated_at":    summary.UpdatedAt,
		"types":         summary.Types,
		"routes":        summary.Routes,
		"recent_window": recent,
	})
}

func (api *ManagementAPI) getGatewayLimitBuckets(w http.ResponseWriter, r *http.Request) {
	window, windowSource, minCount := parseGatewayLimitAlertQuery(r)
	summary := api.gateway.RouteLimitBucketSummary(window, minCount)
	summary.Window = windowSource
	api.writeJSON(w, summary)
}

func (api *ManagementAPI) getGatewayLimitClasses(w http.ResponseWriter, r *http.Request) {
	window, windowSource, minCount := parseGatewayLimitAlertQuery(r)
	summary := api.gateway.RouteLimitClassSummary(window, minCount)
	summary.Window = windowSource
	api.writeJSON(w, summary)
}

func (api *ManagementAPI) getGatewayLimitClassAlerts(w http.ResponseWriter, r *http.Request) {
	window, windowSource, minCount := parseGatewayLimitAlertQuery(r)
	summary := api.gateway.RouteLimitClassAlertSummary(window, minCount)
	summary.Window = windowSource
	api.writeJSON(w, summary)
}

func (api *ManagementAPI) notifyGatewayLimitClassAlerts(w http.ResponseWriter, r *http.Request) {
	window, windowSource, minCount := parseGatewayLimitAlertQuery(r)
	summary := api.gateway.RouteLimitClassAlertSummary(window, minCount)
	summary.Window = windowSource
	summary = api.filterLimitClassAlertSummaryBySnooze(summary, time.Now().UTC())

	digestDeliveries := 0
	if summary.TotalAlerts > 0 {
		digestDeliveries = api.emitManagementEvent(managementWebhookEvent{
			Event:      "gateway.limit_class_alert_digest",
			OccurredAt: time.Now().UTC(),
			Data: map[string]interface{}{
				"window":           summary.Window,
				"window_seconds":   summary.WindowSeconds,
				"min_count":        summary.MinCount,
				"total_alerts":     summary.TotalAlerts,
				"top_bucket_class": summary.TopBucketClass,
				"by_severity":      summary.BySeverity,
				"alerts":           summary.Alerts,
			},
		})
	}

	alertDeliveries := 0
	for _, alert := range summary.Alerts {
		alertDeliveries += api.emitManagementEvent(managementWebhookEvent{
			Event:      "gateway.limit_class_alert",
			OccurredAt: time.Now().UTC(),
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

	api.writeJSON(w, map[string]interface{}{
		"window":            summary.Window,
		"min_count":         summary.MinCount,
		"total_alerts":      summary.TotalAlerts,
		"digest_deliveries": digestDeliveries,
		"alert_deliveries":  alertDeliveries,
		"alerts":            summary.Alerts,
	})
}

func (api *ManagementAPI) getGatewayLimitAlerts(w http.ResponseWriter, r *http.Request) {
	window, windowSource, minCount := parseGatewayLimitAlertQuery(r)
	cfg := api.gateway.GetConfig()
	evaluationMinCount := effectiveLimitAlertEvaluationMinCount(minCount, cfg, config.PolicyAlertNotificationPolicy{})
	if cfg != nil {
		evaluationMinCount = effectiveLimitAlertEvaluationMinCount(minCount, cfg, cfg.Security.MutationPolicy.LimitAlertNotifications)
	}
	summary := api.gateway.RouteLimitAlertSummary(window, evaluationMinCount)
	summary.Window = windowSource
	if cfg != nil {
		summary = applyLimitAlertPolicies(summary, cfg.Security.MutationPolicy.LimitAlertNotifications, cfg)
		summary.Window = windowSource
	}
	api.writeJSON(w, summary)
}

func (api *ManagementAPI) notifyGatewayLimitAlerts(w http.ResponseWriter, r *http.Request) {
	window, windowSource, minCount := parseGatewayLimitAlertQuery(r)
	summary := api.gateway.RouteLimitAlertSummary(window, minCount)
	summary.Window = windowSource
	if cfg := api.gateway.GetConfig(); cfg != nil {
		summary.Alerts = classifyRouteLimitAlerts(cfg, summary.Alerts)
	}

	digestDeliveries := api.emitManagementEvent(managementWebhookEvent{
		Event:      "gateway.limit_alert_digest",
		OccurredAt: time.Now().UTC(),
		Data: map[string]interface{}{
			"window":         summary.Window,
			"window_seconds": summary.WindowSeconds,
			"min_count":      summary.MinCount,
			"total_alerts":   summary.TotalAlerts,
			"by_severity":    summary.BySeverity,
			"alerts":         summary.Alerts,
		},
	})

	alertDeliveries := 0
	for _, alert := range summary.Alerts {
		alertDeliveries += api.emitManagementEvent(managementWebhookEvent{
			Event:      "gateway.limit_alert",
			OccurredAt: time.Now().UTC(),
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

	api.writeJSON(w, map[string]interface{}{
		"window":            summary.Window,
		"min_count":         summary.MinCount,
		"total_alerts":      summary.TotalAlerts,
		"digest_deliveries": digestDeliveries,
		"alert_deliveries":  alertDeliveries,
		"alerts":            summary.Alerts,
	})
}
