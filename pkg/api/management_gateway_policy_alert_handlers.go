package api

import (
	"net/http"
	"time"
)

func (api *ManagementAPI) getGatewayPolicyHits(w http.ResponseWriter, r *http.Request) {
	summary := api.gateway.PolicyHitSummary()
	window, windowSource := parseGatewayWindowQuery(r, 5*time.Minute, "5m")
	recent := api.gateway.PolicyHitWindowSummary(window)
	recent.Window = windowSource
	api.writeJSON(w, map[string]interface{}{
		"total":         summary.Total,
		"updated_at":    summary.UpdatedAt,
		"reasons":       summary.Reasons,
		"routes":        summary.Routes,
		"recent_window": recent,
	})
}

func (api *ManagementAPI) getGatewayPolicyAlerts(w http.ResponseWriter, r *http.Request) {
	window, windowSource, minCount := parseGatewayPolicyAlertQuery(r)
	summary := api.gateway.PolicyAlertSummary(window, minCount)
	summary.Window = windowSource
	api.writeJSON(w, summary)
}

func (api *ManagementAPI) notifyGatewayPolicyAlerts(w http.ResponseWriter, r *http.Request) {
	window, windowSource, minCount := parseGatewayPolicyAlertQuery(r)
	summary := api.gateway.PolicyAlertSummary(window, minCount)
	summary.Window = windowSource

	digestPayload := managementWebhookEvent{
		Event:      "gateway.policy_alert_digest",
		OccurredAt: time.Now().UTC(),
		Data: map[string]interface{}{
			"window":         summary.Window,
			"window_seconds": summary.WindowSeconds,
			"min_count":      summary.MinCount,
			"total_alerts":   summary.TotalAlerts,
			"by_severity":    summary.BySeverity,
			"alerts":         summary.Alerts,
		},
	}
	digestDeliveries := api.emitManagementEvent(digestPayload)

	alertDeliveries := 0
	for _, alert := range summary.Alerts {
		alertDeliveries += api.emitManagementEvent(managementWebhookEvent{
			Event:      "gateway.policy_alert",
			OccurredAt: time.Now().UTC(),
			Data: map[string]interface{}{
				"window":         summary.Window,
				"window_seconds": summary.WindowSeconds,
				"min_count":      summary.MinCount,
				"severity":       alert.Severity,
				"service_name":   alert.ServiceName,
				"route_path":     alert.RoutePath,
				"reason":         alert.Reason,
				"count":          alert.Count,
				"since":          alert.Since,
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
