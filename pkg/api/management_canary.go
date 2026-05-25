package api

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/mux"
)

func (api *ManagementAPI) evaluateProposalCanary(w http.ResponseWriter, r *http.Request) {
	record, err := loadConfigProposal(mux.Vars(r)["id"])
	if err != nil {
		api.writeManagedError(w, err, http.StatusNotFound)
		return
	}
	evaluation, err := api.buildProposalCanaryEvaluation(record)
	if err != nil {
		api.writeManagedError(w, managedCanaryConfigError("Failed to evaluate canary rollout", err), http.StatusBadRequest)
		return
	}
	api.writeJSON(w, APIResponse{
		Success: true,
		Message: "Proposal canary evaluation completed successfully",
		Data:    evaluation,
	})
}

func (api *ManagementAPI) advanceProposalCanary(w http.ResponseWriter, r *http.Request) {
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
		api.writeManagedError(w, managedRequiredFieldError("Reviewer is required to advance an active canary rollout"), http.StatusBadRequest)
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
		api.writeProposalCanaryRollbackOrError(w, record, reviewer, reviewNote, err)
		return
	}
	if err := api.enforceProposalBlackoutWindow(record.Action, now); err != nil {
		api.writeManagedError(w, err, http.StatusConflict)
		return
	}

	nextPercent, complete, err := nextCanaryAdvanceStep(record)
	if err != nil {
		api.writeManagedError(w, err, http.StatusBadRequest)
		return
	}
	if complete {
		label, note, changeRef := proposalMetadataFromRequest(r, record)
		data, err := api.performProposalCanaryCompletion(record, reviewer, reviewNote, label, note, changeRef, now)
		if err != nil {
			api.writeManagedError(w, managedCanaryStateError("Failed to complete canary rollout", err), http.StatusInternalServerError)
			return
		}
		api.writeJSON(w, APIResponse{
			Success: true,
			Message: "Proposal canary rollout completed successfully",
			Data:    data,
		})
		return
	}
	label, note, changeRef := proposalMetadataFromRequest(r, record)
	data, err := api.performProposalCanaryAdvance(record, reviewer, reviewNote, label, note, changeRef, now, nextPercent)
	if err != nil {
		api.writeManagedError(w, managedCanaryStateError("Failed to advance canary rollout", err), http.StatusInternalServerError)
		return
	}
	api.writeJSON(w, APIResponse{
		Success: true,
		Message: "Proposal canary rollout advanced successfully",
		Data:    data,
	})
}

func (api *ManagementAPI) reconcileProposalCanary(w http.ResponseWriter, r *http.Request) {
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
		api.writeManagedError(w, managedRequiredFieldError("Reviewer is required to reconcile an active canary rollout"), http.StatusBadRequest)
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
	if err := api.enforceProposalBlackoutWindow(record.Action, now); err != nil {
		api.writeManagedError(w, err, http.StatusConflict)
		return
	}
	label, note, changeRef := proposalMetadataFromRequest(r, record)
	data, err := api.performProposalCanaryReconcile(record, reviewer, reviewNote, label, note, changeRef, now)
	if err != nil {
		api.writeManagedError(w, managedCanaryStateError("Failed to reconcile canary rollout", err), http.StatusInternalServerError)
		return
	}
	success, _ := data["success"].(bool)
	message, _ := data["message"].(string)
	api.writeJSON(w, APIResponse{
		Success: success,
		Message: message,
		Data:    data["data"],
	})
}
