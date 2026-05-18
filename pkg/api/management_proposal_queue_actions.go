package api

import (
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

func (api *ManagementAPI) applyReadyProposalQueue(w http.ResponseWriter, r *http.Request) {
	cfg := api.gateway.GetConfig()
	dryRun := r.URL.Query().Get("dry_run") == "true"
	reviewer := strings.TrimSpace(r.URL.Query().Get("reviewer"))
	reviewNote := strings.TrimSpace(r.URL.Query().Get("review_note"))
	filterEnv := strings.TrimSpace(r.URL.Query().Get("environment"))
	filterStatus := strings.TrimSpace(r.URL.Query().Get("status"))
	filterNextAction := strings.TrimSpace(r.URL.Query().Get("next_action"))
	filterUrgency := strings.TrimSpace(r.URL.Query().Get("urgency"))
	if filterNextAction != "" && filterNextAction != "apply" {
		api.writeManagedError(w, managedValidationError("next_action filter for apply-ready must be apply", nil), http.StatusBadRequest)
		return
	}
	if filterUrgency != "" && !isValidProposalQueueUrgency(filterUrgency) {
		api.writeManagedError(w, managedValidationError("urgency filter must be fresh, aging, or overdue", nil), http.StatusBadRequest)
		return
	}
	limit := 0
	if rawLimit := strings.TrimSpace(r.URL.Query().Get("limit")); rawLimit != "" {
		parsed, err := strconv.Atoi(rawLimit)
		if err != nil || parsed <= 0 {
			api.writeManagedError(w, managedValidationError("limit must be a positive integer", err), http.StatusBadRequest)
			return
		}
		limit = parsed
	}
	if !dryRun && reviewer == "" {
		api.writeManagedError(w, managedRequiredFieldError("Reviewer is required to apply ready proposals"), http.StatusBadRequest)
		return
	}

	proposals, err := listConfigProposals()
	if err != nil {
		api.writeManagedError(w, managedConfigError("Failed to list proposals", err), http.StatusInternalServerError)
		return
	}

	type readyCandidate struct {
		record          *configProposalRecord
		readySince      time.Time
		readyAgeSeconds int64
	}
	candidates := make([]readyCandidate, 0)
	for _, proposal := range proposals {
		id, _ := proposal["id"].(string)
		if strings.TrimSpace(id) == "" {
			continue
		}
		record, err := loadConfigProposal(id)
		if err != nil {
			continue
		}
		if filterEnv != "" && record.Environment != filterEnv {
			continue
		}
		if filterStatus != "" && record.Status != filterStatus {
			continue
		}
		readiness, err := api.buildProposalReadiness(record)
		if err != nil {
			continue
		}
		if ready, _ := readiness["ready_for_apply"].(bool); !ready {
			continue
		}
		readySince, readyAgeSeconds := queueReadySince(record, readiness)
		urgency := queueUrgency(resolveProposalQueueUrgencyThresholds(cfg, record.Environment), true, int64(time.Now().UTC().Sub(record.CreatedAt).Seconds()), readyAgeSeconds)
		if filterUrgency != "" && urgency != filterUrgency {
			continue
		}
		candidates = append(candidates, readyCandidate{
			record:          record,
			readySince:      readySince,
			readyAgeSeconds: readyAgeSeconds,
		})
	}

	sort.SliceStable(candidates, func(i, j int) bool {
		if !candidates[i].readySince.Equal(candidates[j].readySince) {
			return candidates[i].readySince.Before(candidates[j].readySince)
		}
		return candidates[i].record.ID < candidates[j].record.ID
	})
	if limit > 0 && len(candidates) > limit {
		candidates = candidates[:limit]
	}

	resultItems := make([]map[string]interface{}, 0, len(candidates))
	if dryRun {
		for _, candidate := range candidates {
			resultItems = append(resultItems, map[string]interface{}{
				"proposal_id":       candidate.record.ID,
				"status":            candidate.record.Status,
				"environment":       candidate.record.Environment,
				"ready_since":       candidate.readySince,
				"ready_age_seconds": candidate.readyAgeSeconds,
				"would_apply":       true,
			})
		}
		api.writeJSON(w, APIResponse{
			Success: true,
			Message: "Ready proposal batch apply preview generated successfully",
			Data: map[string]interface{}{
				"dry_run":         true,
				"candidate_count": len(resultItems),
				"filters": map[string]interface{}{
					"environment": filterEnv,
					"status":      filterStatus,
					"next_action": "apply",
					"urgency":     filterUrgency,
				},
				"results": resultItems,
			},
		})
		return
	}

	label, note, changeRef := revisionMetadataFromRequest(r)
	appliedCount := 0
	failedCount := 0
	for _, candidate := range candidates {
		result, statusCode, err := api.applyProposalRecord(candidate.record, reviewer, reviewNote, label, note, changeRef)
		if err != nil {
			failedCount++
			resultItems = append(resultItems, map[string]interface{}{
				"proposal_id": candidate.record.ID,
				"success":     false,
				"status_code": statusCode,
				"error":       err.Error(),
			})
			continue
		}
		appliedCount++
		entry := map[string]interface{}{
			"proposal_id": candidate.record.ID,
			"success":     true,
		}
		for k, v := range result {
			entry[k] = v
		}
		resultItems = append(resultItems, entry)
	}

	api.writeJSON(w, APIResponse{
		Success: failedCount == 0,
		Message: "Ready proposal batch apply completed",
		Data: map[string]interface{}{
			"dry_run":         false,
			"candidate_count": len(candidates),
			"applied_count":   appliedCount,
			"failed_count":    failedCount,
			"filters": map[string]interface{}{
				"environment": filterEnv,
				"status":      filterStatus,
				"next_action": "apply",
				"urgency":     filterUrgency,
			},
			"results": resultItems,
		},
	})
}

func (api *ManagementAPI) approveReadyProposalQueue(w http.ResponseWriter, r *http.Request) {
	cfg := api.gateway.GetConfig()
	dryRun := r.URL.Query().Get("dry_run") == "true"
	reviewer := strings.TrimSpace(r.URL.Query().Get("reviewer"))
	reviewNote := strings.TrimSpace(r.URL.Query().Get("review_note"))
	filterEnv := strings.TrimSpace(r.URL.Query().Get("environment"))
	filterStatus := strings.TrimSpace(r.URL.Query().Get("status"))
	filterNextAction := strings.TrimSpace(r.URL.Query().Get("next_action"))
	if filterNextAction != "" && filterNextAction != "needs_approval" {
		api.writeManagedError(w, managedValidationError("next_action filter for approve-ready must be needs_approval", nil), http.StatusBadRequest)
		return
	}
	filterUrgency := strings.TrimSpace(r.URL.Query().Get("urgency"))
	if filterUrgency != "" && !isValidProposalQueueUrgency(filterUrgency) {
		api.writeManagedError(w, managedValidationError("urgency filter must be fresh, aging, or overdue", nil), http.StatusBadRequest)
		return
	}
	limit := 0
	if rawLimit := strings.TrimSpace(r.URL.Query().Get("limit")); rawLimit != "" {
		parsed, err := strconv.Atoi(rawLimit)
		if err != nil || parsed <= 0 {
			api.writeManagedError(w, managedValidationError("limit must be a positive integer", err), http.StatusBadRequest)
			return
		}
		limit = parsed
	}
	if !dryRun && reviewer == "" {
		api.writeManagedError(w, managedRequiredFieldError("Reviewer is required to approve ready proposals"), http.StatusBadRequest)
		return
	}

	proposals, err := listConfigProposals()
	if err != nil {
		api.writeManagedError(w, managedConfigError("Failed to list proposals", err), http.StatusInternalServerError)
		return
	}

	type approvalCandidate struct {
		record     *configProposalRecord
		nextAction string
		createdAt  time.Time
	}
	candidates := make([]approvalCandidate, 0)
	for _, proposal := range proposals {
		id, _ := proposal["id"].(string)
		if strings.TrimSpace(id) == "" {
			continue
		}
		record, err := loadConfigProposal(id)
		if err != nil {
			continue
		}
		if filterEnv != "" && record.Environment != filterEnv {
			continue
		}
		if filterStatus != "" && record.Status != filterStatus {
			continue
		}
		readiness, err := api.buildProposalReadiness(record)
		if err != nil {
			continue
		}
		if ready, _ := readiness["ready_for_apply"].(bool); ready {
			continue
		}
		blockers, _ := readiness["blockers"].([]string)
		nextAction, needsApproval, _, _ := queueNextAction(record, readiness, blockers)
		if !needsApproval {
			continue
		}
		urgency := queueUrgency(resolveProposalQueueUrgencyThresholds(cfg, record.Environment), false, int64(time.Now().UTC().Sub(record.CreatedAt).Seconds()), 0)
		if filterUrgency != "" && urgency != filterUrgency {
			continue
		}
		candidates = append(candidates, approvalCandidate{
			record:     record,
			nextAction: nextAction,
			createdAt:  record.CreatedAt,
		})
	}

	sort.SliceStable(candidates, func(i, j int) bool {
		if !candidates[i].createdAt.Equal(candidates[j].createdAt) {
			return candidates[i].createdAt.Before(candidates[j].createdAt)
		}
		return candidates[i].record.ID < candidates[j].record.ID
	})
	if limit > 0 && len(candidates) > limit {
		candidates = candidates[:limit]
	}

	resultItems := make([]map[string]interface{}, 0, len(candidates))
	if dryRun {
		for _, candidate := range candidates {
			resultItems = append(resultItems, map[string]interface{}{
				"proposal_id":   candidate.record.ID,
				"status":        candidate.record.Status,
				"environment":   candidate.record.Environment,
				"would_approve": true,
			})
		}
		api.writeJSON(w, APIResponse{
			Success: true,
			Message: "Ready proposal batch approval preview generated successfully",
			Data: map[string]interface{}{
				"dry_run":         true,
				"candidate_count": len(resultItems),
				"filters": map[string]interface{}{
					"environment": filterEnv,
					"status":      filterStatus,
					"next_action": "needs_approval",
					"urgency":     filterUrgency,
				},
				"results": resultItems,
			},
		})
		return
	}

	approvedCount := 0
	failedCount := 0
	for _, candidate := range candidates {
		result, statusCode, err := api.approveProposalRecord(candidate.record, reviewer, reviewNote)
		if err != nil {
			failedCount++
			resultItems = append(resultItems, map[string]interface{}{
				"proposal_id": candidate.record.ID,
				"success":     false,
				"status_code": statusCode,
				"error":       err.Error(),
			})
			continue
		}
		approvedCount++
		entry := map[string]interface{}{
			"proposal_id": candidate.record.ID,
			"success":     true,
		}
		for k, v := range result {
			entry[k] = v
		}
		resultItems = append(resultItems, entry)
	}

	api.writeJSON(w, APIResponse{
		Success: failedCount == 0,
		Message: "Ready proposal batch approval completed",
		Data: map[string]interface{}{
			"dry_run":         false,
			"candidate_count": len(candidates),
			"approved_count":  approvedCount,
			"failed_count":    failedCount,
			"filters": map[string]interface{}{
				"environment": filterEnv,
				"status":      filterStatus,
				"next_action": "needs_approval",
				"urgency":     filterUrgency,
			},
			"results": resultItems,
		},
	})
}
