package api

import (
	"github.com/gorilla/mux"
	"net/http"
)

func (api *ManagementAPI) getProposal(w http.ResponseWriter, r *http.Request) {
	record, err := loadConfigProposal(mux.Vars(r)["id"])
	if err != nil {
		api.writeManagedError(w, err, http.StatusNotFound)
		return
	}
	serviceCount := 0
	routeCount := 0
	if record.Config != nil {
		for _, svcCfg := range record.Config.Services {
			serviceCount += len(svcCfg.Services)
			for _, svc := range svcCfg.Services {
				routeCount += len(svc.Routes)
			}
		}
	}
	api.writeJSON(w, map[string]interface{}{
		"id":                     record.ID,
		"action":                 record.Action,
		"status":                 record.Status,
		"created_by":             record.CreatedBy,
		"environment":            record.Environment,
		"promoted_from":          record.PromotedFrom,
		"config_hash":            record.ConfigHash,
		"source_config_hash":     record.SourceConfigHash,
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
		"label":                  record.Label,
		"note":                   record.Note,
		"change_ref":             record.ChangeRef,
		"strategy":               record.Strategy,
		"created_at":             record.CreatedAt,
		"not_before":             record.NotBefore,
		"reviewed_at":            record.ReviewedAt,
		"applied_at":             record.AppliedAt,
		"reviewed_by":            record.ReviewedBy,
		"review_note":            record.ReviewNote,
		"expired_at":             record.ExpiredAt,
		"expiration_reason":      record.ExpirationReason,
		"approval_count":         proposalApprovalCount(api.gateway.GetConfig(), record),
		"required_approvals":     requiredProposalApprovers(api.gateway.GetConfig(), record),
		"approvals":              record.Approvals,
		"summary":                record.Summary,
		"service_count":          serviceCount,
		"route_count":            routeCount,
		"revision_id":            record.RevisionID,
		"config":                 record.Config,
	})
}

func (api *ManagementAPI) approveProposal(w http.ResponseWriter, r *http.Request) {
	record, err := loadConfigProposal(mux.Vars(r)["id"])
	if err != nil {
		api.writeManagedError(w, err, http.StatusNotFound)
		return
	}
	reviewer, reviewNote := proposalReviewMetadataFromRequest(r, record)
	result, statusCode, err := api.approveProposalRecord(record, reviewer, reviewNote)
	if err != nil {
		api.writeManagedError(w, err, statusCode)
		return
	}
	api.writeJSON(w, APIResponse{
		Success: true,
		Message: "Proposal approval recorded successfully",
		Data:    result,
	})
}

func (api *ManagementAPI) verifyProposal(w http.ResponseWriter, r *http.Request) {
	record, err := loadConfigProposal(mux.Vars(r)["id"])
	if err != nil {
		api.writeManagedError(w, err, http.StatusNotFound)
		return
	}
	if record.Config == nil {
		api.writeManagedError(w, managedProposalVerificationError("Proposal has no stored configuration", nil), http.StatusInternalServerError)
		return
	}
	result, err := api.buildProposalVerification(record)
	if err != nil {
		api.writeManagedError(w, managedProposalVerificationError("Failed to verify proposal", err), http.StatusInternalServerError)
		return
	}
	if err := api.observeProposalShadowVerification(record, result); err != nil {
		api.writeManagedError(w, managedProposalVerificationError("Failed to persist proposal shadow verification", err), http.StatusInternalServerError)
		return
	}
	api.markProposalShadowReady(record, result)
	api.writeJSON(w, result)
}

func (api *ManagementAPI) getProposalReadiness(w http.ResponseWriter, r *http.Request) {
	record, err := loadConfigProposal(mux.Vars(r)["id"])
	if err != nil {
		api.writeManagedError(w, err, http.StatusNotFound)
		return
	}
	result, err := api.buildProposalReadiness(record)
	if err != nil {
		api.writeManagedError(w, managedProposalVerificationError("Failed to evaluate proposal readiness", err), http.StatusInternalServerError)
		return
	}
	api.writeJSON(w, result)
}

func (api *ManagementAPI) explainBlockedProposal(w http.ResponseWriter, r *http.Request) {
	record, err := loadConfigProposal(mux.Vars(r)["id"])
	if err != nil {
		api.writeManagedError(w, err, http.StatusNotFound)
		return
	}
	readiness, err := api.buildProposalReadiness(record)
	if err != nil {
		api.writeManagedError(w, managedProposalVerificationError("Failed to explain blocked proposal", err), http.StatusInternalServerError)
		return
	}
	if ready, _ := readiness["ready_for_apply"].(bool); ready {
		api.writeJSON(w, map[string]interface{}{
			"proposal_id":     record.ID,
			"ready_for_apply": true,
			"explanation":     "proposal is ready to apply",
			"next_action":     "apply",
			"readiness":       readiness,
		})
		return
	}
	blockers, _ := readiness["blockers"].([]string)
	nextAction, needsApproval, needsSchedule, needsVerification := queueNextAction(record, readiness, blockers)
	primary := ""
	if len(blockers) > 0 {
		primary = blockers[0]
	}
	api.writeJSON(w, map[string]interface{}{
		"proposal_id":        record.ID,
		"ready_for_apply":    false,
		"next_action":        nextAction,
		"primary_blocker":    primary,
		"needs_approval":     needsApproval,
		"needs_schedule":     needsSchedule,
		"needs_verification": needsVerification,
		"blocker_count":      len(blockers),
		"blockers":           blockers,
		"explanation":        queueExplanation(nextAction, primary),
		"readiness":          readiness,
	})
}
