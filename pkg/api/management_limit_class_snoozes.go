package api

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

func (api *ManagementAPI) reconcileGatewayLimitClassSnoozeNotifications(now time.Time) {
	cfg := api.gateway.GetConfig()
	if cfg == nil {
		return
	}
	policy := cfg.Security.MutationPolicy.LimitClassSnoozeNotifications
	if !policy.Enabled {
		return
	}
	interval := policyAlertNotificationInterval(policy)
	minInterval := policyAlertNotificationMinInterval(policy)
	expiringWithin := strings.TrimSpace(policy.Window)
	if expiringWithin == "" {
		expiringWithin = "15m"
	}
	detailedMinPriority := policy.DetailedMinBucketClassPriority
	detailedMaxClasses := policy.DetailedMaxBucketClasses

	api.queueDigestNotifyMu.Lock()
	lastSent := api.lastLimitClassSnoozeNotificationAt
	lastChecksum := api.lastLimitClassSnoozeNotificationChecksum
	api.queueDigestNotifyMu.Unlock()
	if !lastSent.IsZero() && now.Sub(lastSent) < interval {
		return
	}

	req, err := http.NewRequest(http.MethodGet, "/api/v1/gateway/limit-class-snoozes?expiring_within="+url.QueryEscape(expiringWithin), nil)
	if err != nil {
		return
	}
	totalSnoozes, snoozes, expiringWithinValue, err := api.collectGatewayLimitClassSnoozes(req, now)
	if err != nil {
		return
	}
	stageEvents := api.updateGatewayLimitClassSnoozeStageState(snoozes, now)
	if totalSnoozes == 0 {
		api.queueDigestNotifyMu.Lock()
		api.limitClassSnoozeStageState = make(map[string]gatewayLimitClassSnoozeStateSnapshot)
		api.lastLimitClassSnoozeNotificationAt = now
		api.lastLimitClassSnoozeNotificationChecksum = ""
		api.queueDigestNotifyMu.Unlock()
		for _, event := range stageEvents {
			api.emitManagementEvent(event)
		}
		return
	}

	digestSnoozes, excludedSummary := api.splitLimitClassSnoozeDigestRows(snoozes, detailedMinPriority, detailedMaxClasses)

	checksum := proposalQueueDigestChecksum(map[string]interface{}{
		"expiring_within": expiringWithinValue,
		"total_snoozes":   totalSnoozes,
		"snoozes":         snoozes,
	})
	if policy.OnlyOnChange && checksum != "" && checksum == lastChecksum {
		return
	}
	if !lastSent.IsZero() && now.Sub(lastSent) < minInterval {
		return
	}

	if len(digestSnoozes) > 0 {
		api.emitManagementEvent(managementWebhookEvent{
			Event:      "gateway.limit_class_snooze_expiring_digest",
			OccurredAt: now,
			Data: map[string]interface{}{
				"total_snoozes":                      len(digestSnoozes),
				"expiring_within":                    expiringWithinValue,
				"snoozes":                            digestSnoozes,
				"excluded_class_snooze_count":        len(snoozes) - len(digestSnoozes),
				"excluded_class_snoozes_by_class":    excludedSummary,
				"detailed_min_bucket_class_priority": detailedMinPriority,
				"detailed_max_bucket_classes":        detailedMaxClasses,
			},
		})
	}
	for _, snooze := range snoozes {
		if !api.limitClassSnoozeEventAllowed(strings.TrimSpace(fmt.Sprint(snooze["bucket_class"])), "expiring") {
			continue
		}
		api.emitManagementEvent(managementWebhookEvent{
			Event:      "gateway.limit_class_snooze_expiring",
			OccurredAt: now,
			Data:       snooze,
		})
	}
	for _, event := range stageEvents {
		api.emitManagementEvent(event)
	}

	api.queueDigestNotifyMu.Lock()
	api.lastLimitClassSnoozeNotificationAt = now
	api.lastLimitClassSnoozeNotificationChecksum = checksum
	api.queueDigestNotifyMu.Unlock()
}

func (api *ManagementAPI) autoNotifyGatewayLimitClassSnoozes() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		api.reconcileGatewayLimitClassSnoozeNotifications(time.Now().UTC())
	}
}

type gatewayLimitClassSnoozeStateSnapshot struct {
	Stage string
	Data  map[string]interface{}
}

func (api *ManagementAPI) updateGatewayLimitClassSnoozeStageState(snoozes []map[string]interface{}, now time.Time) []managementWebhookEvent {
	api.queueDigestNotifyMu.Lock()
	defer api.queueDigestNotifyMu.Unlock()

	nextState := make(map[string]gatewayLimitClassSnoozeStateSnapshot, len(snoozes))
	events := make([]managementWebhookEvent, 0)
	for _, snooze := range snoozes {
		incidentID := strings.TrimSpace(fmt.Sprint(snooze["incident_id"]))
		if incidentID == "" {
			continue
		}
		currentStage := normalizeSLABreachTier(strings.TrimSpace(fmt.Sprint(snooze["snooze_stage"])))
		if currentStage == "" {
			currentStage = normalizeSLABreachTier(strings.TrimSpace(fmt.Sprint(snooze["severity"])))
		}
		if currentStage == "" {
			continue
		}
		nextState[incidentID] = gatewayLimitClassSnoozeStateSnapshot{
			Stage: currentStage,
			Data:  cloneStringInterfaceMap(snooze),
		}
		previousSnapshot := api.limitClassSnoozeStageState[incidentID]
		previousStage := normalizeSLABreachTier(previousSnapshot.Stage)
		if previousStage != "" && previousStage != currentStage {
			if !api.limitClassSnoozeEventAllowed(strings.TrimSpace(fmt.Sprint(snooze["bucket_class"])), "stage_changed") {
				continue
			}
			payload := cloneStringInterfaceMap(snooze)
			payload["previous_stage"] = previousStage
			payload["current_stage"] = currentStage
			payload["severity"] = currentStage
			payload["snooze_stage"] = currentStage
			events = append(events, managementWebhookEvent{
				Event:      "gateway.limit_class_snooze_stage_changed",
				OccurredAt: now,
				Data:       payload,
			})
		}
	}
	for incidentID, previousSnapshot := range api.limitClassSnoozeStageState {
		if _, ok := nextState[incidentID]; ok {
			continue
		}
		previousStage := normalizeSLABreachTier(previousSnapshot.Stage)
		payload := cloneStringInterfaceMap(previousSnapshot.Data)
		if !api.limitClassSnoozeEventAllowed(strings.TrimSpace(fmt.Sprint(payload["bucket_class"])), "resumed") {
			continue
		}
		payload["incident_id"] = incidentID
		payload["previous_stage"] = previousStage
		payload["current_stage"] = "resumed"
		payload["resumed"] = true
		payload["resumed_at"] = now
		payload["severity"] = previousStage
		payload["snooze_stage"] = previousStage
		events = append(events, managementWebhookEvent{
			Event:      "gateway.limit_class_snooze_resumed",
			OccurredAt: now,
			Data:       payload,
		})
	}
	api.limitClassSnoozeStageState = nextState
	return events
}

func cloneStringInterfaceMap(input map[string]interface{}) map[string]interface{} {
	cloned := make(map[string]interface{}, len(input))
	for key, value := range input {
		cloned[key] = value
	}
	return cloned
}

func (api *ManagementAPI) limitClassSnoozeEventAllowed(bucketClass, eventType string) bool {
	cfg := api.gateway.GetConfig()
	if cfg == nil {
		return true
	}
	classConfig, ok := cfg.Security.LimitAlertBucketClasses[strings.TrimSpace(bucketClass)]
	if !ok || len(classConfig.SnoozeEventTypes) == 0 {
		return true
	}
	for _, allowed := range classConfig.SnoozeEventTypes {
		if strings.EqualFold(strings.TrimSpace(allowed), eventType) {
			return true
		}
	}
	return false
}

func (api *ManagementAPI) limitClassSnoozeIncludedInDigest(bucketClass string) bool {
	cfg := api.gateway.GetConfig()
	if cfg == nil {
		return true
	}
	classConfig, ok := cfg.Security.LimitAlertBucketClasses[strings.TrimSpace(bucketClass)]
	if !ok {
		return true
	}
	return !classConfig.SnoozeExcludeFromDigest
}
