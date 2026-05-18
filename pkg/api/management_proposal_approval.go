package api

import (
	"fmt"
	"github.com/bhangun/iket/pkg/config"
	"net/http"
	"strings"
	"time"
)

func (api *ManagementAPI) approveProposalRecord(record *configProposalRecord, reviewer, reviewNote string) (map[string]interface{}, int, error) {
	if record.Status == "rejected" || record.Status == "applied" {
		return nil, http.StatusConflict, managedProposalConflict(fmt.Sprintf("Proposal is already %s", record.Status), nil)
	}
	if strings.TrimSpace(reviewer) == "" {
		return nil, http.StatusBadRequest, managedRequiredFieldError("Reviewer is required to approve a proposal")
	}
	if err := api.enforceProposalReviewer(record, reviewer); err != nil {
		return nil, http.StatusForbidden, err
	}
	if err := api.enforceProposalExpiration(record, time.Now().UTC()); err != nil {
		return nil, http.StatusConflict, err
	}
	upsertProposalApproval(record, reviewer, reviewNote)
	record.ReviewedAt = time.Now().UTC()
	record.ReviewedBy = reviewer
	record.ReviewNote = reviewNote
	record.Status = proposalStatusAfterApproval(api.gateway.GetConfig(), record)
	if err := saveConfigProposalRecord(record); err != nil {
		return nil, http.StatusInternalServerError, managedProposalConflict("Failed to approve proposal", err)
	}
	result := map[string]interface{}{
		"proposal_id":    record.ID,
		"status":         record.Status,
		"approval_count": proposalApprovalCount(api.gateway.GetConfig(), record),
		"required_count": requiredProposalApprovers(api.gateway.GetConfig(), record),
	}
	api.emitProposalEvent("proposal.approved", record, map[string]interface{}{
		"approval_count": result["approval_count"],
		"required_count": result["required_count"],
	})
	return result, http.StatusOK, nil
}

func upsertProposalApproval(record *configProposalRecord, reviewer, reviewNote string) {
	if record == nil || strings.TrimSpace(reviewer) == "" {
		return
	}
	reviewer = strings.TrimSpace(reviewer)
	reviewNote = strings.TrimSpace(reviewNote)
	for i := range record.Approvals {
		if strings.EqualFold(strings.TrimSpace(record.Approvals[i].Reviewer), reviewer) {
			record.Approvals[i].Reviewer = reviewer
			record.Approvals[i].ReviewNote = reviewNote
			record.Approvals[i].CreatedAt = time.Now().UTC()
			return
		}
	}
	record.Approvals = append(record.Approvals, proposalApproval{
		Reviewer:   reviewer,
		ReviewNote: reviewNote,
		CreatedAt:  time.Now().UTC(),
	})
}

func proposalApprovalCount(cfg *config.Config, record *configProposalRecord) int {
	if record == nil {
		return 0
	}
	maxApprovalAge := proposalApprovalMaxAge(cfg)
	now := time.Now().UTC()
	seen := make(map[string]struct{})
	for _, approval := range record.Approvals {
		if maxApprovalAge > 0 && approval.CreatedAt.Add(maxApprovalAge).Before(now) {
			continue
		}
		reviewer := strings.ToLower(strings.TrimSpace(approval.Reviewer))
		if reviewer == "" {
			continue
		}
		seen[reviewer] = struct{}{}
	}
	return len(seen)
}

func requiredProposalApprovers(cfg *config.Config, record *configProposalRecord) int {
	if record == nil {
		return 1
	}
	if record.RequiredApprovals > 0 {
		return record.RequiredApprovals
	}
	if cfg == nil {
		return 1
	}
	policy := cfg.Security.MutationPolicy
	if !policy.Enabled || !isHighImpactMutationAction(record.Action) || policy.MinApproversForHighImpactProposals <= 0 {
		return 1
	}
	return policy.MinApproversForHighImpactProposals
}

func proposalStatusAfterApproval(cfg *config.Config, record *configProposalRecord) string {
	if proposalApprovalCount(cfg, record) >= requiredProposalApprovers(cfg, record) {
		return "approved"
	}
	return "pending"
}
