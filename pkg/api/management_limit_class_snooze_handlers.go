package api

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/bhangun/iket/pkg/core/gateway"
	"github.com/gorilla/mux"
)

func (api *ManagementAPI) getGatewayLimitClassSnoozes(w http.ResponseWriter, r *http.Request) {
	total, snoozes, expiringWithinValue, err := api.collectGatewayLimitClassSnoozes(r, time.Now().UTC())
	if err != nil {
		api.writeManagedError(w, err, http.StatusBadRequest)
		return
	}
	api.writeJSON(w, map[string]interface{}{
		"total_snoozes":   total,
		"snoozes":         snoozes,
		"expiring_within": expiringWithinValue,
		"generated_at":    time.Now().UTC(),
	})
}

func (api *ManagementAPI) notifyGatewayLimitClassSnoozes(w http.ResponseWriter, r *http.Request) {
	now := time.Now().UTC()
	totalSnoozes, snoozes, expiringWithinValue, err := api.collectGatewayLimitClassSnoozes(r, now)
	if err != nil {
		api.writeManagedError(w, err, http.StatusBadRequest)
		return
	}

	digestDeliveries := 0
	if totalSnoozes > 0 {
		digestDeliveries = api.emitManagementEvent(managementWebhookEvent{
			Event:      "gateway.limit_class_snooze_expiring_digest",
			OccurredAt: now,
			Data: map[string]interface{}{
				"total_snoozes":   totalSnoozes,
				"expiring_within": expiringWithinValue,
				"snoozes":         snoozes,
			},
		})
	}

	snoozeDeliveries := 0
	for _, snooze := range snoozes {
		snoozeDeliveries += api.emitManagementEvent(managementWebhookEvent{
			Event:      "gateway.limit_class_snooze_expiring",
			OccurredAt: now,
			Data:       snooze,
		})
	}

	api.writeJSON(w, map[string]interface{}{
		"total_snoozes":     totalSnoozes,
		"snoozes":           snoozes,
		"expiring_within":   expiringWithinValue,
		"digest_deliveries": digestDeliveries,
		"snooze_deliveries": snoozeDeliveries,
		"generated_at":      now,
	})
}

func (api *ManagementAPI) snoozeGatewayLimitClassIncident(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	incidentID := strings.TrimSpace(vars["id"])
	if incidentID == "" {
		api.writeManagedError(w, managedRequiredFieldError("Incident ID is required"), http.StatusBadRequest)
		return
	}

	var request struct {
		Reviewer string `json:"reviewer"`
		Duration string `json:"duration"`
		Note     string `json:"note"`
	}
	if r.Body != nil {
		defer r.Body.Close()
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil && err != io.EOF {
			api.writeManagedError(w, managedValidationError("Invalid snooze payload", err), http.StatusBadRequest)
			return
		}
	}

	reviewer := strings.TrimSpace(request.Reviewer)
	if reviewer == "" {
		reviewer = strings.TrimSpace(r.URL.Query().Get("reviewer"))
	}
	if reviewer == "" {
		api.writeManagedError(w, managedRequiredFieldError("Reviewer is required to snooze a limit class incident"), http.StatusBadRequest)
		return
	}
	durationValue := strings.TrimSpace(request.Duration)
	if durationValue == "" {
		durationValue = strings.TrimSpace(r.URL.Query().Get("duration"))
	}
	if durationValue == "" {
		api.writeManagedError(w, managedRequiredFieldError("Duration is required to snooze a limit class incident"), http.StatusBadRequest)
		return
	}
	duration, err := time.ParseDuration(durationValue)
	if err != nil || duration <= 0 {
		api.writeManagedError(w, managedValidationError("Duration must be a positive Go duration such as 15m or 1h", err), http.StatusBadRequest)
		return
	}
	note := strings.TrimSpace(request.Note)
	if note == "" {
		note = strings.TrimSpace(r.URL.Query().Get("note"))
	}

	now := time.Now().UTC()
	snoozedUntil := now.Add(duration)
	var updated gatewayLimitClassAlertIncidentState
	var found bool

	api.queueDigestNotifyMu.Lock()
	for key, state := range api.limitClassAlertIncidentState {
		if strings.TrimSpace(state.IncidentID) != incidentID {
			continue
		}
		state.SnoozedUntil = snoozedUntil
		state.SnoozedBy = reviewer
		state.SnoozeNote = note
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
	payload["duration"] = duration.String()
	api.emitManagementEvent(managementWebhookEvent{
		Event:      "gateway.limit_class_alert_snoozed",
		OccurredAt: now,
		Data:       payload,
	})

	api.writeJSON(w, APIResponse{
		Success: true,
		Message: "Limit class incident snoozed successfully",
		Data:    payload,
	})
}
