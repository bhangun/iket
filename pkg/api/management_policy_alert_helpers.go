package api

import (
	"strings"
	"time"

	"github.com/bhangun/iket/pkg/core/gateway"
)

func filterPolicyAlertSummaryBySeverity(summary gateway.PolicyAlertSummary, minSeverity string) gateway.PolicyAlertSummary {
	minRank := slaBreachTierRank(minSeverity)
	if minRank <= 0 {
		return summary
	}
	filtered := gateway.PolicyAlertSummary{
		Window:        summary.Window,
		WindowSeconds: summary.WindowSeconds,
		MinCount:      summary.MinCount,
		BySeverity:    map[string]int{"warning": 0, "elevated": 0, "critical": 0},
	}
	for _, alert := range summary.Alerts {
		if slaBreachTierRank(alert.Severity) < minRank {
			continue
		}
		filtered.Alerts = append(filtered.Alerts, alert)
		filtered.BySeverity[alert.Severity]++
	}
	filtered.TotalAlerts = len(filtered.Alerts)
	return filtered
}

func gatewayPolicyAlertIncidentKey(alert gateway.PolicyAlert) string {
	return strings.TrimSpace(alert.ServiceName) + "|" + strings.TrimSpace(alert.RoutePath) + "|" + strings.TrimSpace(alert.Reason)
}

func buildGatewayPolicyAlertIncidentData(state gatewayPolicyAlertIncidentState, count int, severity string, now time.Time) map[string]interface{} {
	if count <= 0 {
		count = state.LastCount
	}
	if strings.TrimSpace(severity) == "" {
		severity = state.Severity
	}
	age := 0.0
	if !state.FirstSeenAt.IsZero() {
		age = now.Sub(state.FirstSeenAt).Seconds()
		if age < 0 {
			age = 0
		}
	}
	return map[string]interface{}{
		"incident_id":          strings.TrimSpace(state.IncidentID),
		"severity":             strings.TrimSpace(severity),
		"service_name":         strings.TrimSpace(state.ServiceName),
		"route_path":           strings.TrimSpace(state.RoutePath),
		"reason":               strings.TrimSpace(state.Reason),
		"count":                count,
		"first_seen_at":        state.FirstSeenAt,
		"last_seen_at":         state.LastSeenAt,
		"incident_age_seconds": age,
	}
}
