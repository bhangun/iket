package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/bhangun/iket/pkg/config"
	"net/http"
	"sort"
	"strings"
	"time"
)

func (api *ManagementAPI) notifyProposalQueueDigest(w http.ResponseWriter, r *http.Request) {
	queueSnapshot, statusCode, err := api.buildProposalQueueSnapshot(r)
	if err != nil {
		api.writeManagedError(w, err, statusCode)
		return
	}
	digestData := buildProposalQueueDigestEventData(queueSnapshot)
	payload := managementWebhookEvent{
		Event:       "proposal.digest",
		OccurredAt:  time.Now().UTC(),
		Environment: strings.TrimSpace(fmt.Sprint(digestData["environment"])),
		Data:        digestData,
	}
	deliveredEvents := make([]map[string]interface{}, 0, 2)
	digestDeliveries := api.emitManagementEvent(payload)
	deliveredEvents = append(deliveredEvents, map[string]interface{}{
		"event":      payload.Event,
		"deliveries": digestDeliveries,
	})
	slaBreachCount := 0
	if attention, ok := digestData["attention_required"].(map[string]interface{}); ok {
		switch value := attention["sla_breach_count"].(type) {
		case int:
			slaBreachCount = value
		case float64:
			slaBreachCount = int(value)
		}
	}
	queueKey := proposalQueueDigestNotificationKey(strings.TrimSpace(fmt.Sprint(digestData["environment"])))
	slaState, resolvedState, previousState := api.updateProposalQueueSLABreachState(queueKey, payload.OccurredAt, slaBreachCount)
	if slaBreachCount > 0 {
		slaStateData := buildProposalQueueSLABreachStateData(slaState, payload.OccurredAt)
		previousTier := ""
		if previousState != nil {
			previousTier = proposalQueueSLABreachTierAt(*previousState, payload.OccurredAt)
		}
		currentTier := strings.TrimSpace(fmt.Sprint(slaStateData["tier"]))
		if previousTier != currentTier {
			stagePayload := managementWebhookEvent{
				Event:       "proposal.sla_stage_changed",
				OccurredAt:  time.Now().UTC(),
				Environment: strings.TrimSpace(fmt.Sprint(digestData["environment"])),
				Data: map[string]interface{}{
					"queue_summary":        digestData["queue_summary"],
					"sla_breach_state":     slaStateData,
					"incident_id":          slaStateData["incident_id"],
					"previous_stage":       previousTier,
					"current_stage":        currentTier,
					"triggered_from_event": "proposal.digest",
				},
			}
			stageDeliveries := api.emitManagementEvent(stagePayload)
			deliveredEvents = append(deliveredEvents, map[string]interface{}{
				"event":      stagePayload.Event,
				"deliveries": stageDeliveries,
			})
		}
		slaPayload := managementWebhookEvent{
			Event:       "proposal.sla_breach",
			OccurredAt:  time.Now().UTC(),
			Environment: strings.TrimSpace(fmt.Sprint(digestData["environment"])),
			Data: map[string]interface{}{
				"queue_summary":        digestData["queue_summary"],
				"attention_required":   digestData["attention_required"],
				"top_sla_breaches":     digestData["top_sla_breaches"],
				"sla_breach_state":     slaStateData,
				"sla_breach_tier":      slaStateData["tier"],
				"triggered_from_event": "proposal.digest",
			},
		}
		slaDeliveries := api.emitManagementEvent(slaPayload)
		deliveredEvents = append(deliveredEvents, map[string]interface{}{
			"event":      slaPayload.Event,
			"deliveries": slaDeliveries,
		})
	} else if resolvedState != nil {
		resolvedStateData := buildProposalQueueSLABreachStateData(*resolvedState, payload.OccurredAt)
		resolvedPayload := managementWebhookEvent{
			Event:       "proposal.sla_resolved",
			OccurredAt:  time.Now().UTC(),
			Environment: strings.TrimSpace(fmt.Sprint(digestData["environment"])),
			Data: map[string]interface{}{
				"queue_summary":       digestData["queue_summary"],
				"resolved_sla_state":  resolvedStateData,
				"incident_id":         resolvedStateData["incident_id"],
				"resolved_from_event": "proposal.digest",
			},
		}
		resolvedDeliveries := api.emitManagementEvent(resolvedPayload)
		deliveredEvents = append(deliveredEvents, map[string]interface{}{
			"event":      resolvedPayload.Event,
			"deliveries": resolvedDeliveries,
		})
	}
	api.writeJSON(w, APIResponse{
		Success: true,
		Message: "Proposal queue digest notifications emitted",
		Data: map[string]interface{}{
			"events": deliveredEvents,
			"digest": digestData,
		},
	})
}

func buildProposalQueueDigestEventData(queueSnapshot map[string]interface{}) map[string]interface{} {
	queueItems, _ := queueSnapshot["queue"].([]map[string]interface{})
	if queueItems == nil {
		if genericQueue, ok := queueSnapshot["queue"].([]interface{}); ok {
			queueItems = make([]map[string]interface{}, 0, len(genericQueue))
			for _, item := range genericQueue {
				if entry, ok := item.(map[string]interface{}); ok {
					queueItems = append(queueItems, entry)
				}
			}
		}
	}
	summary, _ := queueSnapshot["summary"].(map[string]interface{})
	topReady := make([]map[string]interface{}, 0)
	topBlocked := make([]map[string]interface{}, 0)
	topSLABreaches := make([]map[string]interface{}, 0)
	blockerCounts := map[string]int{}
	blockerProposalIDs := map[string][]string{}
	environments := map[string]int{}
	for _, item := range queueItems {
		proposalID := strings.TrimSpace(fmt.Sprint(item["id"]))
		environment := strings.TrimSpace(fmt.Sprint(item["environment"]))
		if environment != "" {
			environments[environment]++
		}
		entry := map[string]interface{}{
			"proposal_id":           proposalID,
			"environment":           environment,
			"next_action":           item["next_action"],
			"urgency":               item["urgency"],
			"priority_score":        item["priority_score"],
			"priority_reason":       item["priority_reason"],
			"sla_breached":          item["sla_breached"],
			"sla_age_seconds":       item["sla_age_seconds"],
			"sla_threshold_seconds": item["sla_threshold_seconds"],
		}
		if breached, _ := item["sla_breached"].(bool); breached {
			topSLABreaches = append(topSLABreaches, entry)
		}
		if ready, _ := item["ready_for_apply"].(bool); ready {
			entry["ready_age_seconds"] = item["ready_age_seconds"]
			topReady = append(topReady, entry)
			continue
		}
		if blockers, ok := item["blockers"].([]string); ok {
			if len(blockers) > 0 {
				entry["primary_blocker"] = blockers[0]
			}
			for _, blocker := range blockers {
				blockerCounts[blocker]++
				blockerProposalIDs[blocker] = append(blockerProposalIDs[blocker], proposalID)
			}
		} else if blockers, ok := item["blockers"].([]interface{}); ok {
			for i, raw := range blockers {
				blocker := strings.TrimSpace(fmt.Sprint(raw))
				if blocker == "" {
					continue
				}
				if i == 0 {
					entry["primary_blocker"] = blocker
				}
				blockerCounts[blocker]++
				blockerProposalIDs[blocker] = append(blockerProposalIDs[blocker], proposalID)
			}
		}
		entry["blocker_count"] = item["blocker_count"]
		topBlocked = append(topBlocked, entry)
	}
	sort.SliceStable(topReady, func(i, j int) bool {
		return int64Value(topReady[i]["ready_age_seconds"]) > int64Value(topReady[j]["ready_age_seconds"])
	})
	sort.SliceStable(topBlocked, func(i, j int) bool {
		return intValue(topBlocked[i]["priority_score"]) > intValue(topBlocked[j]["priority_score"])
	})
	sort.SliceStable(topSLABreaches, func(i, j int) bool {
		return int64Value(topSLABreaches[i]["sla_age_seconds"]) > int64Value(topSLABreaches[j]["sla_age_seconds"])
	})
	if len(topReady) > 5 {
		topReady = topReady[:5]
	}
	if len(topBlocked) > 5 {
		topBlocked = topBlocked[:5]
	}
	if len(topSLABreaches) > 5 {
		topSLABreaches = topSLABreaches[:5]
	}
	topBlockers := make([]map[string]interface{}, 0, len(blockerCounts))
	for reason, count := range blockerCounts {
		topBlockers = append(topBlockers, map[string]interface{}{
			"reason":       reason,
			"count":        count,
			"proposal_ids": blockerProposalIDs[reason],
		})
	}
	sort.SliceStable(topBlockers, func(i, j int) bool {
		if intValue(topBlockers[i]["count"]) != intValue(topBlockers[j]["count"]) {
			return intValue(topBlockers[i]["count"]) > intValue(topBlockers[j]["count"])
		}
		return strings.TrimSpace(fmt.Sprint(topBlockers[i]["reason"])) < strings.TrimSpace(fmt.Sprint(topBlockers[j]["reason"]))
	})
	if len(topBlockers) > 5 {
		topBlockers = topBlockers[:5]
	}
	environment := ""
	if len(environments) == 1 {
		for key := range environments {
			environment = key
		}
	}
	return map[string]interface{}{
		"generated_at":     time.Now().UTC(),
		"environment":      environment,
		"queue_summary":    summary,
		"top_ready":        topReady,
		"top_blocked":      topBlocked,
		"top_blockers":     topBlockers,
		"top_sla_breaches": topSLABreaches,
		"attention_required": map[string]interface{}{
			"sla_breach_count": func() interface{} {
				if summary != nil && summary["sla_breach_count"] != nil {
					return summary["sla_breach_count"]
				}
				return len(topSLABreaches)
			}(),
			"sla_breaches_by_environment": func() interface{} {
				if summary != nil && summary["sla_breaches_by_environment"] != nil {
					return summary["sla_breaches_by_environment"]
				}
				return map[string]int{}
			}(),
			"oldest_sla_breach": func() interface{} {
				if summary != nil && summary["oldest_sla_breach"] != nil {
					return summary["oldest_sla_breach"]
				}
				return map[string]interface{}{}
			}(),
		},
	}
}

func proposalQueueDigestNotificationInterval(policy config.ProposalQueueNotificationPolicy) time.Duration {
	if parsed, ok := parseProposalQueueUrgencyThreshold(strings.TrimSpace(policy.Interval)); ok {
		return parsed
	}
	return 15 * time.Minute
}

func proposalQueueDigestNotificationMinInterval(policy config.ProposalQueueNotificationPolicy) time.Duration {
	if parsed, ok := parseProposalQueueUrgencyThreshold(strings.TrimSpace(policy.MinNotificationInterval)); ok {
		return parsed
	}
	return 5 * time.Minute
}

func proposalQueueDigestNotificationKey(environment string) string {
	environment = strings.TrimSpace(environment)
	if environment == "" {
		return "all"
	}
	return environment
}

func proposalQueueDigestChecksum(digest map[string]interface{}) string {
	payload := map[string]interface{}{
		"queue_summary":      digest["queue_summary"],
		"attention_required": digest["attention_required"],
		"top_sla_breaches":   digest["top_sla_breaches"],
		"top_blockers":       digest["top_blockers"],
		"environment":        digest["environment"],
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func (api *ManagementAPI) updateProposalQueueSLABreachState(key string, now time.Time, slaBreachCount int) (proposalQueueSLABreachState, *proposalQueueSLABreachState, *proposalQueueSLABreachState) {
	api.queueDigestNotifyMu.Lock()
	defer api.queueDigestNotifyMu.Unlock()
	if slaBreachCount <= 0 {
		if existing, ok := api.queueDigestSLABreachState[key]; ok {
			delete(api.queueDigestSLABreachState, key)
			api.clearProposalQueueSLABreachEscalationStateLocked(key)
			return proposalQueueSLABreachState{}, &existing, nil
		}
		delete(api.queueDigestSLABreachState, key)
		api.clearProposalQueueSLABreachEscalationStateLocked(key)
		return proposalQueueSLABreachState{}, nil, nil
	}
	state := api.queueDigestSLABreachState[key]
	var previous *proposalQueueSLABreachState
	if strings.TrimSpace(state.IncidentID) != "" {
		copyState := state
		previous = &copyState
	}
	if strings.TrimSpace(state.IncidentID) == "" {
		state.IncidentID = fmt.Sprintf("sla-%s", now.UTC().Format("20060102-150405.000000000"))
	}
	if state.FirstBreachedAt.IsZero() {
		state.FirstBreachedAt = now
	}
	state.ConsecutiveBreaches++
	state.LastBreachedAt = now
	api.queueDigestSLABreachState[key] = state
	return state, nil, previous
}

func (api *ManagementAPI) clearProposalQueueSLABreachEscalationStateLocked(queueKey string) {
	suffix := "||" + queueKey
	for key := range api.slaBreachEscalationState {
		if strings.HasSuffix(key, suffix) {
			delete(api.slaBreachEscalationState, key)
		}
	}
}

func (api *ManagementAPI) currentProposalQueueSLABreachState(key string) proposalQueueSLABreachState {
	api.queueDigestNotifyMu.Lock()
	defer api.queueDigestNotifyMu.Unlock()
	return api.queueDigestSLABreachState[key]
}

func buildProposalQueueSLABreachStateData(state proposalQueueSLABreachState, now time.Time) map[string]interface{} {
	age := 0.0
	if !state.FirstBreachedAt.IsZero() {
		age = now.Sub(state.FirstBreachedAt).Seconds()
		if age < 0 {
			age = 0
		}
	}
	return map[string]interface{}{
		"incident_id":          state.IncidentID,
		"consecutive_breaches": state.ConsecutiveBreaches,
		"first_breached_at":    state.FirstBreachedAt,
		"last_breached_at":     state.LastBreachedAt,
		"breach_age_seconds":   age,
		"tier":                 classifyProposalQueueSLABreachTier(state, age),
	}
}

func classifyProposalQueueSLABreachTier(state proposalQueueSLABreachState, breachAgeSeconds float64) string {
	if state.ConsecutiveBreaches >= 3 || breachAgeSeconds >= 15*60 {
		return "critical"
	}
	if state.ConsecutiveBreaches >= 2 || breachAgeSeconds >= 5*60 {
		return "elevated"
	}
	return "warning"
}

func proposalQueueSLABreachTierAt(state proposalQueueSLABreachState, now time.Time) string {
	if strings.TrimSpace(state.IncidentID) == "" {
		return ""
	}
	age := 0.0
	if !state.FirstBreachedAt.IsZero() {
		age = now.Sub(state.FirstBreachedAt).Seconds()
		if age < 0 {
			age = 0
		}
	}
	return classifyProposalQueueSLABreachTier(state, age)
}
