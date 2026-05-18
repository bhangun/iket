package api

import (
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

func (api *ManagementAPI) buildProposalQueueSnapshot(r *http.Request) (map[string]interface{}, int, error) {
	cfg := api.gateway.GetConfig()
	proposals, err := listConfigProposals()
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}

	query := r.URL.Query()
	filterEnv := strings.TrimSpace(query.Get("environment"))
	filterStatus := strings.TrimSpace(query.Get("status"))
	filterReady := strings.TrimSpace(query.Get("ready"))
	filterNextAction := strings.TrimSpace(query.Get("next_action"))
	filterUrgency := strings.TrimSpace(query.Get("urgency"))
	if filterUrgency != "" && !isValidProposalQueueUrgency(filterUrgency) {
		return nil, http.StatusBadRequest, managedValidationError("Urgency filter must be fresh, aging, or overdue", nil)
	}
	limit := 0
	if rawLimit := strings.TrimSpace(query.Get("limit")); rawLimit != "" {
		parsed, err := strconv.Atoi(rawLimit)
		if err != nil || parsed <= 0 {
			return nil, http.StatusBadRequest, managedValidationError("Limit must be a positive integer", nil)
		}
		limit = parsed
	}
	readyFilterEnabled := false
	readyFilterValue := false
	if filterReady != "" {
		readyFilterValue, err = strconv.ParseBool(filterReady)
		if err != nil {
			return nil, http.StatusBadRequest, managedValidationError("Ready filter must be true or false", nil)
		}
		readyFilterEnabled = true
	}

	queue := make([]map[string]interface{}, 0, len(proposals))
	readyCount := 0
	blockedCount := 0
	needsApprovalCount := 0
	needsScheduleCount := 0
	needsVerificationCount := 0
	byEnvironment := map[string]int{}
	byStatus := map[string]int{}
	byNextAction := map[string]int{}
	byUrgency := map[string]int{}
	slaBreachesByEnvironment := map[string]int{}
	oldestBlockedAgeSeconds := int64(0)
	oldestBlockedID := ""
	oldestReadyAgeSeconds := int64(0)
	oldestReadyID := ""
	oldestOverdueAgeSeconds := int64(0)
	oldestOverdueID := ""
	slaBreachCount := 0
	highestPriorityScore := -1
	highestPriorityID := ""
	highestPriorityReason := ""
	now := time.Now().UTC()

	for _, proposal := range proposals {
		id, _ := proposal["id"].(string)
		if strings.TrimSpace(id) == "" {
			continue
		}
		record, err := loadConfigProposal(id)
		if err != nil {
			continue
		}
		readiness, err := api.buildProposalReadiness(record)
		if err != nil {
			continue
		}
		ready, _ := readiness["ready_for_apply"].(bool)
		blockers, _ := readiness["blockers"].([]string)
		if filterEnv != "" && record.Environment != filterEnv {
			continue
		}
		if filterStatus != "" && record.Status != filterStatus {
			continue
		}
		if readyFilterEnabled && ready != readyFilterValue {
			continue
		}
		nextAction, needsApproval, needsSchedule, needsVerification := queueNextAction(record, readiness, blockers)
		if filterNextAction != "" && nextAction != filterNextAction {
			continue
		}
		ageSeconds := int64(now.Sub(record.CreatedAt).Seconds())
		readySince, readyAgeSeconds := queueReadySince(record, readiness)
		urgencyThresholds := resolveProposalQueueUrgencyThresholds(cfg, record.Environment)
		urgency := queueUrgency(urgencyThresholds, ready, ageSeconds, readyAgeSeconds)
		if filterUrgency != "" && urgency != filterUrgency {
			continue
		}
		slaBreached := urgency == "overdue"
		slaAgeSeconds := ageSeconds
		slaTarget := "blocked_overdue_after"
		slaThresholdSeconds := int64(urgencyThresholds.blockedOverdueAfter.Seconds())
		if ready {
			slaAgeSeconds = readyAgeSeconds
			slaTarget = "ready_overdue_after"
			slaThresholdSeconds = int64(urgencyThresholds.readyOverdueAfter.Seconds())
		}
		priorityScore, priorityReason := queuePriority(record, readiness, blockers, nextAction, ageSeconds, readyAgeSeconds)

		queue = append(queue, map[string]interface{}{
			"id":                    record.ID,
			"action":                record.Action,
			"status":                record.Status,
			"environment":           record.Environment,
			"promoted_from":         record.PromotedFrom,
			"label":                 record.Label,
			"change_ref":            record.ChangeRef,
			"created_by":            record.CreatedBy,
			"created_at":            record.CreatedAt,
			"approval_count":        readiness["approval_count"],
			"required_approvals":    readiness["required_approvals"],
			"ready_for_apply":       ready,
			"needs_approval":        needsApproval,
			"needs_schedule":        needsSchedule,
			"needs_verification":    needsVerification,
			"next_action":           nextAction,
			"urgency":               urgency,
			"sla_breached":          slaBreached,
			"sla_target":            slaTarget,
			"sla_age_seconds":       slaAgeSeconds,
			"sla_threshold_seconds": slaThresholdSeconds,
			"age_seconds":           ageSeconds,
			"ready_since":           readySince,
			"ready_age_seconds":     readyAgeSeconds,
			"priority_score":        priorityScore,
			"priority_reason":       priorityReason,
			"blocker_count":         len(blockers),
			"blockers":              blockers,
			"readiness":             readiness,
		})
		if ready {
			readyCount++
			if oldestReadyID == "" || readyAgeSeconds > oldestReadyAgeSeconds {
				oldestReadyAgeSeconds = readyAgeSeconds
				oldestReadyID = record.ID
			}
		} else {
			blockedCount++
			if oldestBlockedID == "" || ageSeconds > oldestBlockedAgeSeconds {
				oldestBlockedAgeSeconds = ageSeconds
				oldestBlockedID = record.ID
			}
		}
		envKey := strings.TrimSpace(record.Environment)
		if envKey == "" {
			envKey = "default"
		}
		if urgency == "overdue" {
			slaBreachCount++
			comparisonAge := ageSeconds
			if ready {
				comparisonAge = readyAgeSeconds
			}
			if oldestOverdueID == "" || comparisonAge > oldestOverdueAgeSeconds {
				oldestOverdueAgeSeconds = comparisonAge
				oldestOverdueID = record.ID
			}
			slaBreachesByEnvironment[envKey]++
		}
		if needsApproval {
			needsApprovalCount++
		}
		if needsSchedule {
			needsScheduleCount++
		}
		if needsVerification {
			needsVerificationCount++
		}
		if priorityScore > highestPriorityScore {
			highestPriorityScore = priorityScore
			highestPriorityID = record.ID
			highestPriorityReason = priorityReason
		}
		byEnvironment[envKey]++
		statusKey := strings.TrimSpace(record.Status)
		if statusKey == "" {
			statusKey = "unknown"
		}
		byStatus[statusKey]++
		nextActionKey := strings.TrimSpace(nextAction)
		if nextActionKey == "" {
			nextActionKey = "unknown"
		}
		byNextAction[nextActionKey]++
		byUrgency[urgency]++
	}

	sort.SliceStable(queue, func(i, j int) bool {
		iPriority, _ := queue[i]["priority_score"].(int)
		jPriority, _ := queue[j]["priority_score"].(int)
		if iPriority != jPriority {
			return iPriority > jPriority
		}
		iReady, _ := queue[i]["ready_for_apply"].(bool)
		jReady, _ := queue[j]["ready_for_apply"].(bool)
		if iReady != jReady {
			return iReady && !jReady
		}

		iCreated, _ := queue[i]["created_at"].(time.Time)
		jCreated, _ := queue[j]["created_at"].(time.Time)
		if !iCreated.Equal(jCreated) {
			return iCreated.Before(jCreated)
		}

		iID, _ := queue[i]["id"].(string)
		jID, _ := queue[j]["id"].(string)
		return iID < jID
	})
	if limit > 0 && len(queue) > limit {
		queue = queue[:limit]
	}

	return map[string]interface{}{
		"queue": queue,
		"summary": map[string]interface{}{
			"total":                       len(queue),
			"ready_count":                 readyCount,
			"blocked_count":               blockedCount,
			"needs_approval_count":        needsApprovalCount,
			"needs_schedule_count":        needsScheduleCount,
			"needs_verification_count":    needsVerificationCount,
			"by_environment":              byEnvironment,
			"by_status":                   byStatus,
			"by_next_action":              byNextAction,
			"by_urgency":                  byUrgency,
			"sla_breach_count":            slaBreachCount,
			"sla_breaches_by_environment": slaBreachesByEnvironment,
			"oldest_blocked": map[string]interface{}{
				"proposal_id": oldestBlockedID,
				"age_seconds": oldestBlockedAgeSeconds,
			},
			"oldest_ready": map[string]interface{}{
				"proposal_id":       oldestReadyID,
				"ready_age_seconds": oldestReadyAgeSeconds,
			},
			"oldest_overdue": map[string]interface{}{
				"proposal_id": oldestOverdueID,
				"age_seconds": oldestOverdueAgeSeconds,
			},
			"oldest_sla_breach": map[string]interface{}{
				"proposal_id": oldestOverdueID,
				"age_seconds": oldestOverdueAgeSeconds,
			},
			"highest_priority": map[string]interface{}{
				"proposal_id": highestPriorityID,
				"score":       highestPriorityScore,
				"reason":      highestPriorityReason,
			},
			"filters": map[string]interface{}{
				"environment": filterEnv,
				"status":      filterStatus,
				"next_action": filterNextAction,
				"urgency":     filterUrgency,
				"ready": func() interface{} {
					if readyFilterEnabled {
						return readyFilterValue
					}
					return nil
				}(),
			},
		},
	}, http.StatusOK, nil
}
