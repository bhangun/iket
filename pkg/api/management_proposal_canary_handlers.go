package api

import (
	"fmt"
	"github.com/bhangun/iket/pkg/logging"
	"github.com/gorilla/mux"
	"net/http"
	"strings"
	"time"
)

func (api *ManagementAPI) getProposalCanaryStatus(w http.ResponseWriter, r *http.Request) {
	record, err := loadConfigProposal(mux.Vars(r)["id"])
	if err != nil {
		api.writeManagedError(w, err, http.StatusNotFound)
		return
	}
	if !hasProposalCanaryPlan(record) && record.Status != "canary_active" {
		api.writeManagedError(w, managedCanaryStateError("Proposal does not have an active canary rollout", nil), http.StatusBadRequest)
		return
	}
	planSummary, err := api.describeProposalCanaryPlan(record)
	if err != nil {
		api.writeManagedError(w, managedCanaryConfigError("Failed to inspect canary rollout", err), http.StatusBadRequest)
		return
	}
	verification, err := api.buildProposalVerification(record)
	if err != nil {
		api.writeManagedError(w, managedProposalVerificationError("Failed to verify proposal", err), http.StatusInternalServerError)
		return
	}
	evaluation, err := api.buildProposalCanaryEvaluation(record)
	if err != nil {
		evaluation = map[string]interface{}{
			"healthy": false,
			"reasons": []string{err.Error()},
		}
	}
	api.writeJSON(w, APIResponse{
		Success: true,
		Message: "Proposal canary status retrieved successfully",
		Data: map[string]interface{}{
			"proposal_id":            record.ID,
			"status":                 record.Status,
			"environment":            record.Environment,
			"promoted_from":          record.PromotedFrom,
			"canary_services":        record.CanaryServices,
			"canary_routes":          record.CanaryRoutes,
			"canary_headers":         record.CanaryHeaders,
			"canary_percent":         record.CanaryPercent,
			"canary_steps":           record.CanarySteps,
			"canary_min_requests":    record.CanaryMinRequests,
			"canary_max_error_rate":  record.CanaryMaxErrorRate,
			"canary_max_p95_latency": record.CanaryMaxP95Latency,
			"canary_auto":            record.CanaryAutoReconcile,
			"canary_auto_interval":   record.CanaryAutoInterval,
			"canary_auto_reviewer":   record.CanaryAutoReviewer,
			"canary_last_reconciled": record.CanaryLastReconciled,
			"canary_next_reconcile":  record.CanaryNextReconcile,
			"approval_count":         proposalApprovalCount(api.gateway.GetConfig(), record),
			"required_approvals":     requiredProposalApprovers(api.gateway.GetConfig(), record),
			"plan_summary":           planSummary,
			"verification":           verification,
			"evaluation":             evaluation,
		},
	})
}

func (api *ManagementAPI) expandProposalCanary(w http.ResponseWriter, r *http.Request) {
	record, err := loadConfigProposal(mux.Vars(r)["id"])
	if err != nil {
		api.writeManagedError(w, err, http.StatusNotFound)
		return
	}
	if record.Config == nil {
		api.writeManagedError(w, managedProposalVerificationError("Proposal has no stored configuration", nil), http.StatusInternalServerError)
		return
	}
	if record.Status != "pending" && record.Status != "approved" && record.Status != "canary_active" {
		api.writeManagedError(w, managedProposalConflict(fmt.Sprintf("Proposal cannot expand canary because it is %s", record.Status), nil), http.StatusConflict)
		return
	}
	record.CanaryServices = mergeNormalizedLists(record.CanaryServices, normalizeQueryList(r.URL.Query()["canary_service"]))
	record.CanaryRoutes = mergeNormalizedLists(record.CanaryRoutes, normalizeQueryList(r.URL.Query()["canary_route"]))
	canaryPercent, err := proposalCanaryPercentFromRequest(r, record)
	if err != nil {
		api.writeManagedError(w, err, http.StatusBadRequest)
		return
	}
	record.CanaryPercent = canaryPercent
	canarySteps, err := proposalCanaryStepsFromRequest(r, record)
	if err != nil {
		api.writeManagedError(w, err, http.StatusBadRequest)
		return
	}
	record.CanarySteps = canarySteps
	canaryMinRequests, err := proposalCanaryMinRequestsFromRequest(r, record)
	if err != nil {
		api.writeManagedError(w, err, http.StatusBadRequest)
		return
	}
	record.CanaryMinRequests = canaryMinRequests
	canaryMaxErrorRate, err := proposalCanaryMaxErrorRateFromRequest(r, record)
	if err != nil {
		api.writeManagedError(w, err, http.StatusBadRequest)
		return
	}
	record.CanaryMaxErrorRate = canaryMaxErrorRate
	canaryMaxP95Latency, err := proposalCanaryMaxP95LatencyFromRequest(r, record)
	if err != nil {
		api.writeManagedError(w, err, http.StatusBadRequest)
		return
	}
	record.CanaryMaxP95Latency = canaryMaxP95Latency
	canaryAutoReconcile, err := proposalCanaryAutoReconcileFromRequest(r, record)
	if err != nil {
		api.writeManagedError(w, err, http.StatusBadRequest)
		return
	}
	record.CanaryAutoReconcile = canaryAutoReconcile
	canaryAutoInterval, err := proposalCanaryAutoIntervalFromRequest(r, record)
	if err != nil {
		api.writeManagedError(w, err, http.StatusBadRequest)
		return
	}
	record.CanaryAutoInterval = canaryAutoInterval
	record.CanaryAutoReviewer = proposalCanaryAutoReviewerFromRequest(r, record)
	if len(record.CanaryServices) == 0 && len(record.CanaryRoutes) == 0 {
		api.writeManagedError(w, managedCanaryConfigError("At least one canary_service or canary_route is required", nil), http.StatusBadRequest)
		return
	}

	if record.Status != "canary_active" {
		if err := saveConfigProposalRecord(record); err != nil {
			api.writeManagedError(w, managedCanaryStateError("Failed to update proposal canary plan", err), http.StatusInternalServerError)
			return
		}
		planSummary, err := api.describeProposalCanaryPlan(record)
		if err != nil {
			api.writeManagedError(w, managedCanaryConfigError("Failed to inspect canary rollout", err), http.StatusBadRequest)
			return
		}
		api.writeJSON(w, APIResponse{
			Success: true,
			Message: "Proposal canary plan updated successfully",
			Data: map[string]interface{}{
				"proposal_id":            record.ID,
				"status":                 record.Status,
				"canary_services":        record.CanaryServices,
				"canary_routes":          record.CanaryRoutes,
				"canary_percent":         record.CanaryPercent,
				"canary_min_requests":    record.CanaryMinRequests,
				"canary_max_error_rate":  record.CanaryMaxErrorRate,
				"canary_max_p95_latency": record.CanaryMaxP95Latency,
				"canary_auto":            record.CanaryAutoReconcile,
				"canary_auto_interval":   record.CanaryAutoInterval,
				"canary_auto_reviewer":   record.CanaryAutoReviewer,
				"approval_count":         proposalApprovalCount(api.gateway.GetConfig(), record),
				"required_approvals":     requiredProposalApprovers(api.gateway.GetConfig(), record),
				"plan_summary":           planSummary,
			},
		})
		return
	}

	reviewer, reviewNote := proposalReviewMetadataFromRequest(r, record)
	if strings.TrimSpace(reviewer) == "" {
		api.writeManagedError(w, managedRequiredFieldError("Reviewer is required to expand an active canary rollout"), http.StatusBadRequest)
		return
	}
	if err := api.enforceProposalReviewer(record, reviewer); err != nil {
		api.writeManagedError(w, err, http.StatusForbidden)
		return
	}
	now := time.Now().UTC()
	if err := api.enforceProposalExpiration(record, now); err != nil {
		api.writeManagedError(w, err, http.StatusConflict)
		return
	}
	if err := api.enforceProposalFreshness(record, now); err != nil {
		api.writeManagedError(w, err, http.StatusConflict)
		return
	}
	if err := api.enforceProposalVerification(record); err != nil {
		api.writeManagedError(w, err, http.StatusConflict)
		return
	}
	if err := api.enforceProposalCanaryEvaluation(record); err != nil {
		revisionID, rollbackErr := api.rollbackProposalCanary(record, reviewer, reviewNote, err.Error())
		if rollbackErr != nil {
			api.writeManagedError(w, managedCanaryStateError(fmt.Sprintf("%s; automatic rollback also failed", err.Error()), rollbackErr), http.StatusConflict)
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
				"rollback_reason": err.Error(),
			},
		})
		return
	}
	if err := api.enforceProposalBlackoutWindow(record.Action, now); err != nil {
		api.writeManagedError(w, err, http.StatusConflict)
		return
	}
	label, note, changeRef := proposalMetadataFromRequest(r, record)
	applyCfg, applySummary, err := api.buildCanaryApplyConfig(record)
	if err != nil {
		api.writeManagedError(w, managedCanaryConfigError("Failed to build expanded canary config", err), http.StatusBadRequest)
		return
	}
	if err := api.applyManagedConfigChange(applyCfg, record.Action, label, note, changeRef, applySummary); err != nil {
		api.writeManagedError(w, managedCanaryStateError("Failed to expand canary rollout", err), http.StatusInternalServerError)
		return
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
		api.logger.Warn("Canary expansion applied but failed to update proposal record", logging.Error(err))
	}
	api.writeJSON(w, APIResponse{
		Success: true,
		Message: "Proposal canary rollout expanded successfully",
		Data: map[string]interface{}{
			"proposal_id":            record.ID,
			"status":                 record.Status,
			"reviewed_by":            record.ReviewedBy,
			"review_note":            record.ReviewNote,
			"canary_services":        record.CanaryServices,
			"canary_routes":          record.CanaryRoutes,
			"canary_headers":         record.CanaryHeaders,
			"canary_percent":         record.CanaryPercent,
			"canary_steps":           record.CanarySteps,
			"canary_min_requests":    record.CanaryMinRequests,
			"canary_max_error_rate":  record.CanaryMaxErrorRate,
			"canary_max_p95_latency": record.CanaryMaxP95Latency,
			"canary_auto":            record.CanaryAutoReconcile,
			"canary_auto_interval":   record.CanaryAutoInterval,
			"canary_auto_reviewer":   record.CanaryAutoReviewer,
			"canary_last_reconciled": record.CanaryLastReconciled,
			"canary_next_reconcile":  record.CanaryNextReconcile,
			"revision_id":            record.RevisionID,
			"summary":                applySummary,
		},
	})
}

func (api *ManagementAPI) completeProposalCanary(w http.ResponseWriter, r *http.Request) {
	record, err := loadConfigProposal(mux.Vars(r)["id"])
	if err != nil {
		api.writeManagedError(w, err, http.StatusNotFound)
		return
	}
	if record.Config == nil {
		api.writeManagedError(w, managedProposalVerificationError("Proposal has no stored configuration", nil), http.StatusInternalServerError)
		return
	}
	if record.Status != "canary_active" {
		api.writeManagedError(w, managedCanaryStateError(fmt.Sprintf("Proposal canary is not active; current status is %s", record.Status), nil), http.StatusConflict)
		return
	}
	reviewer, reviewNote := proposalReviewMetadataFromRequest(r, record)
	if strings.TrimSpace(reviewer) == "" {
		api.writeManagedError(w, managedRequiredFieldError("Reviewer is required to complete an active canary rollout"), http.StatusBadRequest)
		return
	}
	if err := api.enforceProposalReviewer(record, reviewer); err != nil {
		api.writeManagedError(w, err, http.StatusForbidden)
		return
	}
	now := time.Now().UTC()
	if err := api.enforceProposalExpiration(record, now); err != nil {
		api.writeManagedError(w, err, http.StatusConflict)
		return
	}
	if err := api.enforceProposalFreshness(record, now); err != nil {
		api.writeManagedError(w, err, http.StatusConflict)
		return
	}
	if err := api.enforceProposalVerification(record); err != nil {
		api.writeManagedError(w, err, http.StatusConflict)
		return
	}
	if err := api.enforceProposalCanaryEvaluation(record); err != nil {
		revisionID, rollbackErr := api.rollbackProposalCanary(record, reviewer, reviewNote, err.Error())
		if rollbackErr != nil {
			api.writeManagedError(w, managedCanaryStateError(fmt.Sprintf("%s; automatic rollback also failed", err.Error()), rollbackErr), http.StatusConflict)
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
				"rollback_reason": err.Error(),
			},
		})
		return
	}
	if err := api.enforceProposalBlackoutWindow(record.Action, now); err != nil {
		api.writeManagedError(w, err, http.StatusConflict)
		return
	}
	label, note, changeRef := proposalMetadataFromRequest(r, record)
	if err := api.applyManagedConfigChange(record.Config, record.Action, label, note, changeRef, record.Summary); err != nil {
		api.writeManagedError(w, managedCanaryStateError("Failed to complete canary rollout", err), http.StatusInternalServerError)
		return
	}
	record.Status = "applied"
	record.ReviewedAt = now
	record.AppliedAt = now
	record.ReviewedBy = reviewer
	record.ReviewNote = reviewNote
	revisions, err := listConfigRevisions()
	if err == nil && len(revisions) > 0 {
		if latest, ok := revisions[0]["id"].(string); ok {
			record.RevisionID = latest
		}
	}
	if err := saveConfigProposalRecord(record); err != nil {
		api.logger.Warn("Canary completion applied but failed to update proposal record", logging.Error(err))
	}
	api.writeJSON(w, APIResponse{
		Success: true,
		Message: "Proposal canary rollout completed successfully",
		Data: map[string]interface{}{
			"proposal_id": record.ID,
			"status":      record.Status,
			"revision_id": record.RevisionID,
			"reviewed_by": record.ReviewedBy,
			"review_note": record.ReviewNote,
			"summary":     record.Summary,
		},
	})
}
