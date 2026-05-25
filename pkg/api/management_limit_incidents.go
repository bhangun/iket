package api

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/bhangun/iket/pkg/core/gateway"
)

func (api *ManagementAPI) updateGatewayLimitAlertIncidentState(alerts []gateway.RouteLimitAlert, now time.Time) ([]managementWebhookEvent, []managementWebhookEvent, []managementWebhookEvent) {
	current := make(map[string]gateway.RouteLimitAlert, len(alerts))
	for _, alert := range alerts {
		current[gatewayLimitAlertIncidentKey(alert)] = alert
	}

	api.queueDigestNotifyMu.Lock()
	defer api.queueDigestNotifyMu.Unlock()

	opened := make([]managementWebhookEvent, 0)
	stageChanged := make([]managementWebhookEvent, 0)
	resolved := make([]managementWebhookEvent, 0)

	for key, alert := range current {
		state, ok := api.limitAlertIncidentState[key]
		if !ok || strings.TrimSpace(state.IncidentID) == "" {
			state = gatewayLimitAlertIncidentState{
				IncidentID:  fmt.Sprintf("lal-%s-%s", now.UTC().Format("20060102-150405.000000000"), shortLimitAlertIncidentSuffix(key)),
				Severity:    strings.TrimSpace(alert.Severity),
				ServiceName: strings.TrimSpace(alert.ServiceName),
				RoutePath:   strings.TrimSpace(alert.RoutePath),
				LimitType:   strings.TrimSpace(alert.LimitType),
				KeyType:     strings.TrimSpace(alert.KeyType),
				BucketID:    strings.TrimSpace(alert.BucketID),
				BucketClass: strings.TrimSpace(alert.BucketClass),
				FirstSeenAt: now,
				LastSeenAt:  now,
				LastCount:   alert.Count,
			}
			api.limitAlertIncidentState[key] = state
			opened = append(opened, managementWebhookEvent{
				Event:      "gateway.limit_alert_opened",
				OccurredAt: now,
				Data:       buildGatewayLimitAlertIncidentData(state, alert, now),
			})
			continue
		}

		previousSeverity := state.Severity
		state.LastSeenAt = now
		state.LastCount = alert.Count
		if slaBreachTierRank(alert.Severity) > slaBreachTierRank(previousSeverity) {
			state.Severity = strings.TrimSpace(alert.Severity)
			api.limitAlertIncidentState[key] = state
			data := buildGatewayLimitAlertIncidentData(state, alert, now)
			data["previous_severity"] = previousSeverity
			stageChanged = append(stageChanged, managementWebhookEvent{
				Event:      "gateway.limit_alert_stage_changed",
				OccurredAt: now,
				Data:       data,
			})
			continue
		}
		api.limitAlertIncidentState[key] = state
	}

	for key, state := range api.limitAlertIncidentState {
		if _, ok := current[key]; ok {
			continue
		}
		resolved = append(resolved, managementWebhookEvent{
			Event:      "gateway.limit_alert_resolved",
			OccurredAt: now,
			Data: buildGatewayLimitAlertIncidentData(state, gateway.RouteLimitAlert{
				Severity:    state.Severity,
				ServiceName: state.ServiceName,
				RoutePath:   state.RoutePath,
				LimitType:   state.LimitType,
				KeyType:     state.KeyType,
				BucketID:    state.BucketID,
				BucketClass: state.BucketClass,
				Count:       state.LastCount,
			}, now),
		})
		delete(api.limitAlertIncidentState, key)
	}

	return opened, stageChanged, resolved
}

func gatewayLimitAlertIncidentKey(alert gateway.RouteLimitAlert) string {
	return strings.TrimSpace(alert.ServiceName) + "|" + strings.TrimSpace(alert.RoutePath) + "|" + strings.TrimSpace(alert.LimitType) + "|" + strings.TrimSpace(alert.BucketID)
}

func shortLimitAlertIncidentSuffix(key string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(key)))
	return hex.EncodeToString(sum[:4])
}

func buildGatewayLimitAlertIncidentData(state gatewayLimitAlertIncidentState, alert gateway.RouteLimitAlert, now time.Time) map[string]interface{} {
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
		"bucket_id":             strings.TrimSpace(alert.BucketID),
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
