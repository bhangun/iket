package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/bhangun/iket/pkg/core/gateway"
	"github.com/gorilla/mux"
)

func (api *ManagementAPI) filterLimitClassAlertSummaryBySnooze(summary gateway.RouteLimitClassAlertSummary, now time.Time) gateway.RouteLimitClassAlertSummary {
	filtered := gateway.RouteLimitClassAlertSummary{
		Window:        summary.Window,
		WindowSeconds: summary.WindowSeconds,
		MinCount:      summary.MinCount,
		BySeverity:    map[string]int{"warning": 0, "elevated": 0, "critical": 0},
	}

	api.queueDigestNotifyMu.Lock()
	defer api.queueDigestNotifyMu.Unlock()

	for _, alert := range summary.Alerts {
		state, ok := api.limitClassAlertIncidentState[gatewayLimitClassAlertIncidentKey(alert)]
		if ok && !state.SnoozedUntil.IsZero() && state.SnoozedUntil.After(now) {
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

func (api *ManagementAPI) filterLimitClassIncidentEventsBySnooze(events []managementWebhookEvent, now time.Time) []managementWebhookEvent {
	if len(events) == 0 {
		return events
	}
	filtered := make([]managementWebhookEvent, 0, len(events))
	api.queueDigestNotifyMu.Lock()
	defer api.queueDigestNotifyMu.Unlock()
	for _, event := range events {
		incidentID := strings.TrimSpace(fmt.Sprint(event.Data["incident_id"]))
		suppressed := false
		for _, state := range api.limitClassAlertIncidentState {
			if strings.TrimSpace(state.IncidentID) != incidentID {
				continue
			}
			if !state.SnoozedUntil.IsZero() && state.SnoozedUntil.After(now) {
				suppressed = true
			}
			break
		}
		if suppressed {
			continue
		}
		filtered = append(filtered, event)
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
				Data:       api.buildGatewayLimitClassAlertIncidentData(state, alert, now),
			})
			continue
		}

		previousSeverity := state.Severity
		state.LastSeenAt = now
		state.LastCount = alert.Count
		if slaBreachTierRank(alert.Severity) > slaBreachTierRank(previousSeverity) {
			state.Severity = strings.TrimSpace(alert.Severity)
			api.limitClassAlertIncidentState[key] = state
			data := api.buildGatewayLimitClassAlertIncidentData(state, alert, now)
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
			Data: api.buildGatewayLimitClassAlertIncidentData(state, gateway.RouteLimitClassAlert{
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

func (api *ManagementAPI) buildGatewayLimitClassAlertIncidentData(state gatewayLimitClassAlertIncidentState, alert gateway.RouteLimitClassAlert, now time.Time) map[string]interface{} {
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
		"bucket_class_priority": api.limitAlertBucketClassPriority(strings.TrimSpace(alert.BucketClass)),
		"count":                 count,
		"queued_admissions":     alert.QueuedAdmissions,
		"queue_full_rejections": alert.QueueFullRejections,
		"average_queue_wait_ms": alert.AverageQueueWaitMs,
		"max_queue_wait_ms":     alert.MaxQueueWaitMs,
		"first_seen_at":         state.FirstSeenAt,
		"last_seen_at":          state.LastSeenAt,
		"incident_age_seconds":  age,
		"acknowledged":          !state.AcknowledgedAt.IsZero(),
		"acknowledged_at":       state.AcknowledgedAt,
		"acknowledged_by":       strings.TrimSpace(state.AcknowledgedBy),
		"acknowledge_note":      strings.TrimSpace(state.AcknowledgeNote),
		"snoozed":               !state.SnoozedUntil.IsZero() && state.SnoozedUntil.After(now),
		"snoozed_until":         state.SnoozedUntil,
		"snoozed_by":            strings.TrimSpace(state.SnoozedBy),
		"snooze_note":           strings.TrimSpace(state.SnoozeNote),
	}
}

func (api *ManagementAPI) getGatewayLimitClassIncidents(w http.ResponseWriter, r *http.Request) {
	now := time.Now().UTC()
	severityFilter := normalizeSLABreachTier(r.URL.Query().Get("severity"))
	bucketClassFilter := strings.TrimSpace(r.URL.Query().Get("bucket_class"))
	serviceNameFilter := strings.TrimSpace(r.URL.Query().Get("service_name"))
	routePathFilter := strings.TrimSpace(r.URL.Query().Get("route_path"))
	limitTypeFilter := strings.TrimSpace(r.URL.Query().Get("limit_type"))
	keyTypeFilter := strings.TrimSpace(r.URL.Query().Get("key_type"))

	api.queueDigestNotifyMu.Lock()
	incidents := make([]map[string]interface{}, 0, len(api.limitClassAlertIncidentState))
	for _, state := range api.limitClassAlertIncidentState {
		incident := api.buildGatewayLimitClassAlertIncidentData(state, gateway.RouteLimitClassAlert{
			Severity:    state.Severity,
			ServiceName: state.ServiceName,
			RoutePath:   state.RoutePath,
			LimitType:   state.LimitType,
			KeyType:     state.KeyType,
			BucketClass: state.BucketClass,
			Count:       state.LastCount,
		}, now)
		if severityFilter != "" && normalizeSLABreachTier(fmt.Sprint(incident["severity"])) != severityFilter {
			continue
		}
		if bucketClassFilter != "" && strings.TrimSpace(fmt.Sprint(incident["bucket_class"])) != bucketClassFilter {
			continue
		}
		if serviceNameFilter != "" && strings.TrimSpace(fmt.Sprint(incident["service_name"])) != serviceNameFilter {
			continue
		}
		if routePathFilter != "" && strings.TrimSpace(fmt.Sprint(incident["route_path"])) != routePathFilter {
			continue
		}
		if limitTypeFilter != "" && strings.TrimSpace(fmt.Sprint(incident["limit_type"])) != limitTypeFilter {
			continue
		}
		if keyTypeFilter != "" && strings.TrimSpace(fmt.Sprint(incident["key_type"])) != keyTypeFilter {
			continue
		}
		incidents = append(incidents, incident)
	}
	api.queueDigestNotifyMu.Unlock()

	sort.Slice(incidents, func(i, j int) bool {
		leftSeverity := normalizeSLABreachTier(fmt.Sprint(incidents[i]["severity"]))
		rightSeverity := normalizeSLABreachTier(fmt.Sprint(incidents[j]["severity"]))
		if slaBreachTierRank(leftSeverity) == slaBreachTierRank(rightSeverity) {
			leftAge := 0.0
			if value, ok := incidents[i]["incident_age_seconds"].(float64); ok {
				leftAge = value
			}
			rightAge := 0.0
			if value, ok := incidents[j]["incident_age_seconds"].(float64); ok {
				rightAge = value
			}
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

func (api *ManagementAPI) acknowledgeGatewayLimitClassIncident(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	incidentID := strings.TrimSpace(vars["id"])
	if incidentID == "" {
		api.writeManagedError(w, managedRequiredFieldError("Incident ID is required"), http.StatusBadRequest)
		return
	}

	var request struct {
		Reviewer string `json:"reviewer"`
		Note     string `json:"note"`
	}
	if r.Body != nil {
		defer r.Body.Close()
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil && err != io.EOF {
			api.writeManagedError(w, managedValidationError("Invalid acknowledgement payload", err), http.StatusBadRequest)
			return
		}
	}

	reviewer := strings.TrimSpace(request.Reviewer)
	if reviewer == "" {
		reviewer = strings.TrimSpace(r.URL.Query().Get("reviewer"))
	}
	if reviewer == "" {
		api.writeManagedError(w, managedRequiredFieldError("Reviewer is required to acknowledge a limit class incident"), http.StatusBadRequest)
		return
	}
	note := strings.TrimSpace(request.Note)
	if note == "" {
		note = strings.TrimSpace(r.URL.Query().Get("note"))
	}

	now := time.Now().UTC()
	var updated gatewayLimitClassAlertIncidentState
	var found bool

	api.queueDigestNotifyMu.Lock()
	for key, state := range api.limitClassAlertIncidentState {
		if strings.TrimSpace(state.IncidentID) != incidentID {
			continue
		}
		state.AcknowledgedAt = now
		state.AcknowledgedBy = reviewer
		state.AcknowledgeNote = note
		api.limitClassAlertIncidentState[key] = state
		updated = state
		found = true
		break
	}
	api.queueDigestNotifyMu.Unlock()

	if !found {
		api.writeManagedError(w, managedError("incident_not_found", "Limit class incident not found", nil), http.StatusNotFound)
		return
	}

	payload := api.buildGatewayLimitClassAlertIncidentData(updated, gateway.RouteLimitClassAlert{
		Severity:    updated.Severity,
		ServiceName: updated.ServiceName,
		RoutePath:   updated.RoutePath,
		LimitType:   updated.LimitType,
		KeyType:     updated.KeyType,
		BucketClass: updated.BucketClass,
		Count:       updated.LastCount,
	}, now)
	payload["reviewer"] = reviewer
	payload["note"] = note
	api.emitManagementEvent(managementWebhookEvent{
		Event:      "gateway.limit_class_alert_acknowledged",
		OccurredAt: now,
		Data:       payload,
	})

	api.writeJSON(w, APIResponse{
		Success: true,
		Message: "Limit class incident acknowledged successfully",
		Data:    payload,
	})
}
