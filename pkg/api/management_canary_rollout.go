package api

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	coreerrors "github.com/bhangun/iket/pkg/core/errors"
	"github.com/bhangun/iket/pkg/logging"
)

func (api *ManagementAPI) performProposalCanaryReconcile(record *configProposalRecord, reviewer, reviewNote, label, note, changeRef string, now time.Time) (map[string]interface{}, error) {
	evaluation, err := api.buildProposalCanaryEvaluation(record)
	if err != nil {
		return nil, managedCanaryStateError("Evaluate canary rollout", err)
	}
	if healthy, _ := evaluation["healthy"].(bool); !healthy {
		record.CanaryLastReconciled = now
		record.CanaryNextReconcile = time.Time{}
		revisionID, rollbackErr := api.rollbackProposalCanary(record, reviewer, reviewNote, canaryEvaluationReasons(evaluation))
		if rollbackErr != nil {
			return nil, managedCanaryStateError(fmt.Sprintf("%s; automatic rollback also failed", canaryEvaluationReasons(evaluation)), rollbackErr)
		}
		return map[string]interface{}{
			"success": false,
			"message": "Canary reconcile detected unhealthy metrics and rollback was applied",
			"data": map[string]interface{}{
				"proposal_id":     record.ID,
				"status":          record.Status,
				"revision_id":     revisionID,
				"rollback":        true,
				"action_taken":    "rollback",
				"rollback_reason": canaryEvaluationReasons(evaluation),
				"evaluation":      evaluation,
			},
		}, nil
	}

	nextPercent, complete, stepErr := nextCanaryAdvanceStep(record)
	if stepErr != nil {
		complete = true
	}
	if complete || record.CanaryPercent <= 0 {
		data, err := api.performProposalCanaryCompletion(record, reviewer, reviewNote, label, note, changeRef, now)
		if err != nil {
			return nil, managedCanaryStateError("Complete canary rollout", err)
		}
		data["action_taken"] = "complete"
		data["evaluation"] = evaluation
		return map[string]interface{}{
			"success": true,
			"message": "Proposal canary reconcile completed the rollout successfully",
			"data":    data,
		}, nil
	}

	data, err := api.performProposalCanaryAdvance(record, reviewer, reviewNote, label, note, changeRef, now, nextPercent)
	if err != nil {
		return nil, managedCanaryStateError("Advance canary rollout", err)
	}
	data["action_taken"] = "advance"
	data["evaluation"] = evaluation
	return map[string]interface{}{
		"success": true,
		"message": "Proposal canary reconcile advanced the rollout successfully",
		"data":    data,
	}, nil
}

func nextCanaryAdvanceStep(record *configProposalRecord) (nextPercent int, complete bool, err error) {
	if record == nil {
		return 0, false, managedError(coreerrors.CodeProposalNotFound, "Proposal not found", nil)
	}
	if len(record.CanarySteps) == 0 {
		return 0, false, managedCanaryStateError("Proposal does not define any canary steps", nil)
	}
	steps := append([]int(nil), record.CanarySteps...)
	sort.Ints(steps)
	current := record.CanaryPercent
	for _, step := range steps {
		if step > current {
			if step >= 100 {
				return 100, true, nil
			}
			return step, false, nil
		}
	}
	if current > 0 && current < 100 {
		return 100, true, nil
	}
	return 0, false, managedCanaryStateError("No further canary steps remain", nil)
}

func (api *ManagementAPI) performProposalCanaryAdvance(record *configProposalRecord, reviewer, reviewNote, label, note, changeRef string, now time.Time, nextPercent int) (map[string]interface{}, error) {
	record.CanaryPercent = nextPercent
	applyCfg, applySummary, err := api.buildCanaryApplyConfig(record)
	if err != nil {
		return nil, managedCanaryConfigError("Build advanced canary config", err)
	}
	if err := api.applyManagedConfigChange(applyCfg, record.Action, label, note, changeRef, applySummary); err != nil {
		return nil, err
	}
	record.ReviewedAt = now
	record.ReviewedBy = reviewer
	record.ReviewNote = reviewNote
	scheduleNextProposalCanaryReconcile(record, now)
	revisions, err := listConfigRevisions()
	if err == nil && len(revisions) > 0 {
		if latest, ok := revisions[0]["id"].(string); ok {
			record.RevisionID = latest
		}
	}
	if err := saveConfigProposalRecord(record); err != nil {
		api.logger.Warn("Canary advance applied but failed to update proposal record", logging.Error(err))
	}
	result := map[string]interface{}{
		"proposal_id":            record.ID,
		"status":                 record.Status,
		"reviewed_by":            record.ReviewedBy,
		"review_note":            record.ReviewNote,
		"canary_percent":         record.CanaryPercent,
		"canary_steps":           record.CanarySteps,
		"canary_auto":            record.CanaryAutoReconcile,
		"canary_auto_interval":   record.CanaryAutoInterval,
		"canary_auto_reviewer":   record.CanaryAutoReviewer,
		"canary_last_reconciled": record.CanaryLastReconciled,
		"canary_next_reconcile":  record.CanaryNextReconcile,
		"revision_id":            record.RevisionID,
		"summary":                applySummary,
	}
	api.emitProposalEvent("proposal.canary_advanced", record, result)
	return result, nil
}

func (api *ManagementAPI) performProposalCanaryCompletion(record *configProposalRecord, reviewer, reviewNote, label, note, changeRef string, now time.Time) (map[string]interface{}, error) {
	if err := api.applyManagedConfigChange(record.Config, record.Action, label, note, changeRef, record.Summary); err != nil {
		return nil, err
	}
	record.Status = "applied"
	record.ReviewedAt = now
	record.AppliedAt = now
	record.ReviewedBy = reviewer
	record.ReviewNote = reviewNote
	scheduleNextProposalCanaryReconcile(record, now)
	revisions, err := listConfigRevisions()
	if err == nil && len(revisions) > 0 {
		if latest, ok := revisions[0]["id"].(string); ok {
			record.RevisionID = latest
		}
	}
	if err := saveConfigProposalRecord(record); err != nil {
		api.logger.Warn("Canary completion applied but failed to update proposal record", logging.Error(err))
	}
	result := map[string]interface{}{
		"proposal_id":            record.ID,
		"status":                 record.Status,
		"revision_id":            record.RevisionID,
		"reviewed_by":            record.ReviewedBy,
		"review_note":            record.ReviewNote,
		"canary_last_reconciled": record.CanaryLastReconciled,
		"canary_next_reconcile":  record.CanaryNextReconcile,
		"summary":                record.Summary,
	}
	api.emitProposalEvent("proposal.canary_completed", record, result)
	return result, nil
}

func (api *ManagementAPI) enforceProposalCanaryEvaluation(record *configProposalRecord) error {
	if record == nil || !hasCanaryMetricThresholds(record) {
		return nil
	}
	evaluation, err := api.buildProposalCanaryEvaluation(record)
	if err != nil {
		return managedCanaryStateError("Failed to evaluate canary metrics", err)
	}
	if healthy, _ := evaluation["healthy"].(bool); healthy {
		return nil
	}
	reasons, _ := evaluation["reasons"].([]string)
	if len(reasons) == 0 {
		if values, ok := evaluation["reasons"].([]interface{}); ok {
			for _, value := range values {
				if text := strings.TrimSpace(fmt.Sprint(value)); text != "" {
					reasons = append(reasons, text)
				}
			}
		}
	}
	if len(reasons) == 0 {
		return managedCanaryStateError("Canary rollout failed configured metric thresholds", nil)
	}
	return managedCanaryStateError(fmt.Sprintf("Canary rollout failed configured metric thresholds: %s", strings.Join(reasons, "; ")), nil)
}

func (api *ManagementAPI) writeProposalCanaryRollbackOrError(w http.ResponseWriter, record *configProposalRecord, reviewer, reviewNote string, evalErr error) {
	revisionID, rollbackErr := api.rollbackProposalCanary(record, reviewer, reviewNote, evalErr.Error())
	if rollbackErr != nil {
		api.writeManagedError(w, managedCanaryStateError(fmt.Sprintf("%s; automatic rollback also failed", evalErr.Error()), rollbackErr), http.StatusConflict)
		return
	}
	api.writeJSON(w, APIResponse{
		Success: false,
		Message: "Canary guard failed and rollback was applied",
		Data: map[string]interface{}{
			"proposal_id":     record.ID,
			"status":          record.Status,
			"revision_id":     revisionID,
			"rollback":        true,
			"rollback_reason": evalErr.Error(),
		},
	})
}

func canaryEvaluationReasons(evaluation map[string]interface{}) string {
	reasons, _ := evaluation["reasons"].([]string)
	if len(reasons) == 0 {
		if values, ok := evaluation["reasons"].([]interface{}); ok {
			for _, value := range values {
				if text := strings.TrimSpace(fmt.Sprint(value)); text != "" {
					reasons = append(reasons, text)
				}
			}
		}
	}
	if len(reasons) == 0 {
		return "canary rollout failed configured metric thresholds"
	}
	return strings.Join(reasons, "; ")
}

func (api *ManagementAPI) rollbackProposalCanary(record *configProposalRecord, reviewer, reviewNote, reason string) (string, error) {
	if record == nil || record.CanaryBaselineConfig == nil {
		return "", fmt.Errorf("canary baseline configuration is not available for rollback")
	}
	summary := map[string]interface{}{
		"canary_rollback": true,
		"proposal_id":     record.ID,
		"reason":          strings.TrimSpace(reason),
	}
	if err := api.applyManagedConfigChange(record.CanaryBaselineConfig, "rollback_canary", "canary-rollback", reason, record.ChangeRef, summary); err != nil {
		return "", err
	}
	record.Status = "canary_aborted"
	record.ReviewedAt = time.Now().UTC()
	record.ReviewedBy = reviewer
	record.ReviewNote = reviewNote
	record.CanaryNextReconcile = time.Time{}
	revisions, err := listConfigRevisions()
	if err == nil && len(revisions) > 0 {
		if latest, ok := revisions[0]["id"].(string); ok {
			record.RevisionID = latest
		}
	}
	if err := saveConfigProposalRecord(record); err != nil {
		api.logger.Warn("Canary rollback applied but failed to update proposal record", logging.Error(err))
	}
	api.emitProposalEvent("proposal.canary_aborted", record, map[string]interface{}{
		"revision_id":     record.RevisionID,
		"rollback_reason": strings.TrimSpace(reason),
	})
	return record.RevisionID, nil
}

func hasCanaryMetricThresholds(record *configProposalRecord) bool {
	if record == nil {
		return false
	}
	return record.CanaryMinRequests > 0 || record.CanaryMaxErrorRate > 0 || strings.TrimSpace(record.CanaryMaxP95Latency) != ""
}

func hasProposalCanaryPlan(record *configProposalRecord) bool {
	return record != nil && (len(record.CanaryServices) > 0 || len(record.CanaryRoutes) > 0)
}

func proposalApplyMessage(record *configProposalRecord) string {
	if record != nil && record.Status == "canary_active" {
		return "Proposal canary rollout started successfully"
	}
	return "Proposal applied successfully"
}
