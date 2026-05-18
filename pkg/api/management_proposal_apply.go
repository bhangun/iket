package api

import (
	"fmt"
	"github.com/bhangun/iket/pkg/logging"
	"github.com/gorilla/mux"
	"net/http"
	"strings"
	"time"
)

func (api *ManagementAPI) applyProposal(w http.ResponseWriter, r *http.Request) {
	record, err := loadConfigProposal(mux.Vars(r)["id"])
	if err != nil {
		api.writeManagedError(w, err, http.StatusNotFound)
		return
	}
	reviewer, reviewNote := proposalReviewMetadataFromRequest(r, record)
	label, note, changeRef := proposalMetadataFromRequest(r, record)
	result, statusCode, err := api.applyProposalRecord(record, reviewer, reviewNote, label, note, changeRef)
	if err != nil {
		api.writeManagedError(w, err, statusCode)
		return
	}
	api.writeJSON(w, APIResponse{
		Success: true,
		Message: proposalApplyMessage(record),
		Data:    result,
	})
}

func (api *ManagementAPI) applyProposalRecord(record *configProposalRecord, reviewer, reviewNote, label, note, changeRef string) (map[string]interface{}, int, error) {
	if record.Status != "pending" && record.Status != "approved" {
		return nil, http.StatusConflict, managedProposalConflict(fmt.Sprintf("Proposal is already %s", record.Status), nil)
	}
	if record.Config == nil {
		return nil, http.StatusInternalServerError, managedProposalVerificationError("Proposal has no stored configuration", nil)
	}
	if strings.TrimSpace(reviewer) == "" {
		return nil, http.StatusBadRequest, managedRequiredFieldError("Reviewer is required to apply a proposal")
	}
	if err := api.enforceProposalReviewer(record, reviewer); err != nil {
		return nil, http.StatusForbidden, err
	}
	now := time.Now().UTC()
	if err := api.enforceProposalExpiration(record, now); err != nil {
		return nil, http.StatusConflict, err
	}
	upsertProposalApproval(record, reviewer, reviewNote)
	requiredApprovers := requiredProposalApprovers(api.gateway.GetConfig(), record)
	if proposalApprovalCount(api.gateway.GetConfig(), record) < requiredApprovers {
		record.Status = proposalStatusAfterApproval(api.gateway.GetConfig(), record)
		if err := saveConfigProposalRecord(record); err != nil {
			api.logger.Warn("Proposal approval recorded but failed to persist before apply gate", logging.Error(err))
		}
		return nil, http.StatusConflict, managedProposalConflict(fmt.Sprintf("Proposal requires %d approval(s) before apply; current fresh approvals: %d", requiredApprovers, proposalApprovalCount(api.gateway.GetConfig(), record)), nil)
	}
	if err := api.enforceProposalFreshness(record, now); err != nil {
		return nil, http.StatusConflict, err
	}
	if err := api.enforceProposalVerification(record); err != nil {
		return nil, http.StatusConflict, err
	}
	if !record.NotBefore.IsZero() && now.Before(record.NotBefore) {
		record.Status = proposalStatusAfterApproval(api.gateway.GetConfig(), record)
		if err := saveConfigProposalRecord(record); err != nil {
			api.logger.Warn("Proposal approval recorded but failed to persist before not_before gate", logging.Error(err))
		}
		return nil, http.StatusConflict, managedProposalConflict(fmt.Sprintf("Proposal cannot be applied before %s", record.NotBefore.Format(time.RFC3339)), nil)
	}
	if err := api.enforceProposalBlackoutWindow(record.Action, now); err != nil {
		record.Status = proposalStatusAfterApproval(api.gateway.GetConfig(), record)
		if errSave := saveConfigProposalRecord(record); errSave != nil {
			api.logger.Warn("Proposal approval recorded but failed to persist before blackout gate", logging.Error(errSave))
		}
		return nil, http.StatusConflict, err
	}
	applyCfg := record.Config
	applySummary := record.Summary
	if hasProposalCanaryPlan(record) {
		baselineCfg, cloneErr := cloneConfig(api.gateway.GetConfig())
		if cloneErr != nil {
			return nil, http.StatusInternalServerError, managedCanaryStateError("Failed to capture canary baseline config", cloneErr)
		}
		record.CanaryBaselineConfig = baselineCfg
		applyCfg, applySummary, cloneErr = api.buildCanaryApplyConfig(record)
		if cloneErr != nil {
			return nil, http.StatusBadRequest, managedCanaryConfigError("Failed to build canary apply config", cloneErr)
		}
	}
	if err := api.applyManagedConfigChange(applyCfg, record.Action, label, note, changeRef, applySummary); err != nil {
		return nil, http.StatusInternalServerError, managedProposalConflict("Failed to apply proposal", err)
	}
	if hasProposalCanaryPlan(record) {
		record.Status = "canary_active"
		scheduleNextProposalCanaryReconcile(record, now)
	} else {
		record.Status = "applied"
		record.CanaryNextReconcile = time.Time{}
	}
	record.ReviewedAt = now
	record.AppliedAt = record.ReviewedAt
	record.ReviewedBy = reviewer
	record.ReviewNote = reviewNote
	revisions, err := listConfigRevisions()
	if err == nil && len(revisions) > 0 {
		if latest, ok := revisions[0]["id"].(string); ok {
			record.RevisionID = latest
		}
	}
	if err := saveConfigProposalRecord(record); err != nil {
		api.logger.Warn("Proposal applied but failed to update proposal record", logging.Error(err))
	}
	result := map[string]interface{}{
		"proposal_id":    record.ID,
		"status":         record.Status,
		"revision_id":    record.RevisionID,
		"reviewed_by":    record.ReviewedBy,
		"review_note":    record.ReviewNote,
		"approval_count": proposalApprovalCount(api.gateway.GetConfig(), record),
		"summary":        applySummary,
	}
	if hasProposalCanaryPlan(record) {
		api.emitProposalEvent("proposal.canary_started", record, map[string]interface{}{
			"revision_id":    record.RevisionID,
			"summary":        applySummary,
			"canary_percent": record.CanaryPercent,
			"canary_steps":   record.CanarySteps,
		})
	} else {
		api.emitProposalEvent("proposal.applied", record, map[string]interface{}{
			"revision_id": record.RevisionID,
			"summary":     applySummary,
		})
	}
	return result, http.StatusOK, nil
}

func (api *ManagementAPI) promoteProposal(w http.ResponseWriter, r *http.Request) {
	record, err := loadConfigProposal(mux.Vars(r)["id"])
	if err != nil {
		api.writeManagedError(w, err, http.StatusNotFound)
		return
	}
	if record.Config == nil {
		api.writeManagedError(w, managedProposalVerificationError("Proposal has no stored configuration", nil), http.StatusInternalServerError)
		return
	}
	if record.Status == "rejected" || record.Status == "expired" {
		api.writeManagedError(w, managedProposalConflict(fmt.Sprintf("Proposal cannot be promoted because it is %s", record.Status), nil), http.StatusConflict)
		return
	}
	environment := proposalEnvironmentFromRequest(r)
	if environment == "" {
		api.writeManagedError(w, managedRequiredFieldError("Environment is required to promote a proposal"), http.StatusBadRequest)
		return
	}
	notBefore, err := proposalNotBeforeFromRequest(r)
	if err != nil {
		api.writeManagedError(w, err, http.StatusBadRequest)
		return
	}
	if err := api.enforceProposalSchedule(record.Action, notBefore); err != nil {
		api.writeManagedError(w, err, http.StatusBadRequest)
		return
	}
	label, note, changeRef := proposalMetadataFromRequest(r, record)
	proposer := proposalProposerFromRequest(r)
	if proposer == "" {
		proposer = record.CreatedBy
	}
	clonedCfg, err := cloneConfig(record.Config)
	if err != nil {
		api.writeManagedError(w, managedProposalVerificationError("Failed to clone promoted proposal", err), http.StatusInternalServerError)
		return
	}
	canaryPercent, err := proposalCanaryPercentFromRequest(r, record)
	if err != nil {
		api.writeManagedError(w, err, http.StatusBadRequest)
		return
	}
	canarySteps, err := proposalCanaryStepsFromRequest(r, record)
	if err != nil {
		api.writeManagedError(w, err, http.StatusBadRequest)
		return
	}
	canaryMinRequests, err := proposalCanaryMinRequestsFromRequest(r, record)
	if err != nil {
		api.writeManagedError(w, err, http.StatusBadRequest)
		return
	}
	canaryMaxErrorRate, err := proposalCanaryMaxErrorRateFromRequest(r, record)
	if err != nil {
		api.writeManagedError(w, err, http.StatusBadRequest)
		return
	}
	canaryMaxP95Latency, err := proposalCanaryMaxP95LatencyFromRequest(r, record)
	if err != nil {
		api.writeManagedError(w, err, http.StatusBadRequest)
		return
	}
	canaryAutoReconcile, err := proposalCanaryAutoReconcileFromRequest(r, record)
	if err != nil {
		api.writeManagedError(w, err, http.StatusBadRequest)
		return
	}
	canaryAutoInterval, err := proposalCanaryAutoIntervalFromRequest(r, record)
	if err != nil {
		api.writeManagedError(w, err, http.StatusBadRequest)
		return
	}
	canaryAutoReviewer := proposalCanaryAutoReviewerFromRequest(r, record)
	promotedID, err := saveConfigProposal(record.Action, record.Strategy, proposer, environment, record.ID, record.ConfigHash, proposalCanaryServicesFromRequest(r, record), proposalCanaryRoutesFromRequest(r, record), proposalCanaryHeadersFromRequest(r, record), canaryPercent, canarySteps, canaryMinRequests, canaryMaxErrorRate, canaryMaxP95Latency, canaryAutoReconcile, canaryAutoInterval, canaryAutoReviewer, label, note, changeRef, notBefore, requiredProposalApprovers(api.gateway.GetConfig(), record), record.Summary, clonedCfg)
	if err != nil {
		api.writeManagedError(w, managedProposalConflict("Failed to promote proposal", err), http.StatusInternalServerError)
		return
	}
	api.writeJSON(w, APIResponse{
		Success: true,
		Message: "Proposal promoted successfully",
		Data: map[string]interface{}{
			"proposal_id":            promotedID,
			"promoted_from":          record.ID,
			"environment":            environment,
			"not_before":             notBefore,
			"canary_services":        proposalCanaryServicesFromRequest(r, record),
			"canary_routes":          proposalCanaryRoutesFromRequest(r, record),
			"canary_headers":         proposalCanaryHeadersFromRequest(r, record),
			"canary_percent":         canaryPercent,
			"canary_steps":           canarySteps,
			"canary_min_requests":    canaryMinRequests,
			"canary_max_error_rate":  canaryMaxErrorRate,
			"canary_max_p95_latency": canaryMaxP95Latency,
			"canary_auto":            canaryAutoReconcile,
			"canary_auto_interval":   canaryAutoInterval,
			"canary_auto_reviewer":   canaryAutoReviewer,
			"required_count":         requiredProposalApprovers(api.gateway.GetConfig(), record),
		},
	})
	api.emitProposalEvent("proposal.promoted", record, map[string]interface{}{
		"promoted_proposal_id": promotedID,
		"environment":          environment,
		"not_before":           notBefore,
	})
}

func (api *ManagementAPI) rejectProposal(w http.ResponseWriter, r *http.Request) {
	record, err := loadConfigProposal(mux.Vars(r)["id"])
	if err != nil {
		api.writeManagedError(w, err, http.StatusNotFound)
		return
	}
	if record.Status != "pending" {
		api.writeManagedError(w, managedProposalConflict(fmt.Sprintf("Proposal is already %s", record.Status), nil), http.StatusConflict)
		return
	}
	reviewer, reviewNote := proposalReviewMetadataFromRequest(r, record)
	if strings.TrimSpace(reviewer) == "" {
		api.writeManagedError(w, managedRequiredFieldError("Reviewer is required to reject a proposal"), http.StatusBadRequest)
		return
	}
	if err := api.enforceProposalReviewer(record, reviewer); err != nil {
		api.writeManagedError(w, err, http.StatusForbidden)
		return
	}
	record.Status = "rejected"
	record.ReviewedAt = time.Now().UTC()
	record.ReviewedBy = reviewer
	record.ReviewNote = reviewNote
	if err := saveConfigProposalRecord(record); err != nil {
		api.writeManagedError(w, managedProposalConflict("Failed to reject proposal", err), http.StatusInternalServerError)
		return
	}
	api.writeJSON(w, APIResponse{
		Success: true,
		Message: "Proposal rejected successfully",
		Data: map[string]interface{}{
			"proposal_id": record.ID,
			"status":      record.Status,
			"reviewed_by": record.ReviewedBy,
			"review_note": record.ReviewNote,
		},
	})
	api.emitProposalEvent("proposal.rejected", record, map[string]interface{}{
		"reviewed_by": record.ReviewedBy,
		"review_note": record.ReviewNote,
	})
}
