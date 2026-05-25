package api

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/bhangun/iket/pkg/config"
	"github.com/bhangun/iket/pkg/core/gateway"
)

func (api *ManagementAPI) enforceProposalVerification(record *configProposalRecord) error {
	if record == nil {
		return nil
	}
	cfg := api.gateway.GetConfig()
	if cfg == nil {
		return nil
	}
	policy := cfg.Security.MutationPolicy
	if !policy.Enabled || !policy.RequireVerificationForPromotedHighImpactProposals {
		return nil
	}
	if !isHighImpactMutationAction(record.Action) || strings.TrimSpace(record.PromotedFrom) == "" {
		return nil
	}
	result, err := api.buildProposalVerification(record)
	if err != nil {
		return managedProposalVerificationError("Failed to verify promoted proposal", err)
	}
	if integrityOK, _ := result["integrity_ok"].(bool); !integrityOK {
		return managedProposalVerificationError("Promoted proposal failed integrity verification", nil)
	}
	if sourceVerified, _ := result["source_verified"].(bool); !sourceVerified {
		return managedProposalVerificationError("Promoted proposal source could not be verified", nil)
	}
	if matchesSource, _ := result["matches_source"].(bool); !matchesSource {
		return managedProposalVerificationError("Promoted proposal no longer matches its source proposal", nil)
	}
	if policy.RequireShadowEvaluationForPromotedHighImpactProposals {
		shadowVerification, _ := result["shadow_verification"].(map[string]interface{})
		if checked, _ := shadowVerification["checked"].(bool); checked {
			if allHealthy, _ := shadowVerification["all_healthy"].(bool); !allHealthy {
				if err := api.observeProposalShadowVerification(record, result); err != nil {
					return managedProposalVerificationError("Failed to persist proposal shadow verification", err)
				}
				return managedProposalVerificationError("Promoted proposal failed shadow evaluation", nil)
			}
		}
	}
	if err := api.observeProposalShadowVerification(record, result); err != nil {
		return managedProposalVerificationError("Failed to persist proposal shadow verification", err)
	}
	api.markProposalShadowReady(record, result)
	if policy.MinShadowHealthyVerificationsForPromotedHighImpactProposals > 0 {
		shadowVerification, _ := result["shadow_verification"].(map[string]interface{})
		if checked, _ := shadowVerification["checked"].(bool); checked && record.ShadowVerificationPasses < policy.MinShadowHealthyVerificationsForPromotedHighImpactProposals {
			return managedProposalVerificationError(fmt.Sprintf("Promoted proposal requires %d consecutive healthy shadow verifications; current streak: %d", policy.MinShadowHealthyVerificationsForPromotedHighImpactProposals, record.ShadowVerificationPasses), nil)
		}
	}
	return nil
}

func (api *ManagementAPI) buildProposalShadowVerification(record *configProposalRecord) (map[string]interface{}, error) {
	healthyStreak := 0
	lastVerifiedAt := time.Time{}
	lastHealthy := false
	shadowReady := false
	shadowReadyAt := time.Time{}
	if record != nil {
		healthyStreak = record.ShadowVerificationPasses
		lastVerifiedAt = record.ShadowLastVerifiedAt
		lastHealthy = record.ShadowLastHealthy
		shadowReady = record.ShadowReady
		shadowReadyAt = record.ShadowReadyAt
	}
	result := map[string]interface{}{
		"checked":          false,
		"all_healthy":      true,
		"matched_routes":   []gateway.ShadowRouteEvaluation{},
		"failed_routes":    []gateway.ShadowRouteEvaluation{},
		"expected_routes":  0,
		"healthy_streak":   healthyStreak,
		"last_verified_at": lastVerifiedAt,
		"last_healthy":     lastHealthy,
		"shadow_ready":     shadowReady,
		"shadow_ready_at":  shadowReadyAt,
	}
	if record == nil || record.Config == nil {
		return result, nil
	}
	expected := proposalShadowPolicyRouteKeys(record)
	if len(expected) == 0 {
		return result, nil
	}
	result["checked"] = true
	result["expected_routes"] = len(expected)
	evaluations := api.gateway.ShadowRouteEvaluations()
	index := make(map[string]gateway.ShadowRouteEvaluation, len(evaluations))
	for _, evaluation := range evaluations {
		index[evaluation.ServiceName+"|"+evaluation.RoutePath] = evaluation
	}
	matched := make([]gateway.ShadowRouteEvaluation, 0, len(expected))
	failed := make([]gateway.ShadowRouteEvaluation, 0)
	keys := make([]string, 0, len(expected))
	for key := range expected {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		evaluation, ok := index[key]
		if !ok {
			serviceName, routePath := splitShadowRouteKey(key)
			evaluation = gateway.ShadowRouteEvaluation{
				ShadowRouteSummary: gateway.ShadowRouteSummary{
					ServiceName: serviceName,
					RoutePath:   routePath,
				},
				PolicyConfigured: true,
				Healthy:          false,
				Reasons:          []string{"shadow route evaluation is not available yet"},
			}
		}
		matched = append(matched, evaluation)
		if !evaluation.Healthy {
			failed = append(failed, evaluation)
		}
	}
	result["matched_routes"] = matched
	result["failed_routes"] = failed
	result["all_healthy"] = len(failed) == 0
	return result, nil
}

func (api *ManagementAPI) buildProposalReadiness(record *configProposalRecord) (map[string]interface{}, error) {
	if record == nil {
		return nil, managedRequiredFieldError("Proposal is required")
	}
	now := time.Now().UTC()
	approvalCount := proposalApprovalCount(api.gateway.GetConfig(), record)
	requiredApprovals := requiredProposalApprovers(api.gateway.GetConfig(), record)
	verification, err := api.buildProposalVerification(record)
	if err != nil {
		return nil, err
	}
	blockers := make([]string, 0)
	statusEligible := record.Status == "pending" || record.Status == "approved"
	if !statusEligible {
		blockers = append(blockers, fmt.Sprintf("proposal status %q is not eligible for apply", record.Status))
	}
	if approvalCount < requiredApprovals {
		blockers = append(blockers, fmt.Sprintf("requires %d approval(s); current fresh approvals: %d", requiredApprovals, approvalCount))
	}
	recordClone := *record
	if err := api.enforceProposalExpiration(&recordClone, now); err != nil {
		blockers = append(blockers, err.Error())
	}
	recordClone = *record
	if err := api.enforceProposalFreshness(&recordClone, now); err != nil {
		blockers = append(blockers, err.Error())
	}
	notBeforeReady := record.NotBefore.IsZero() || !now.Before(record.NotBefore)
	if !notBeforeReady {
		blockers = append(blockers, fmt.Sprintf("proposal cannot be applied before %s", record.NotBefore.Format(time.RFC3339)))
	}
	blackoutBlocked := false
	if err := api.enforceProposalBlackoutWindow(record.Action, now); err != nil {
		blackoutBlocked = true
		blockers = append(blockers, err.Error())
	}
	verificationReady, verificationBlockers := api.proposalVerificationReadiness(record, verification)
	blockers = append(blockers, verificationBlockers...)
	shadowVerification, _ := verification["shadow_verification"].(map[string]interface{})
	shadowReady, _ := shadowVerification["shadow_ready"].(bool)
	return map[string]interface{}{
		"proposal_id":        record.ID,
		"status":             record.Status,
		"environment":        record.Environment,
		"promoted_from":      record.PromotedFrom,
		"ready_for_apply":    len(blockers) == 0,
		"status_eligible":    statusEligible,
		"approval_count":     approvalCount,
		"required_approvals": requiredApprovals,
		"not_before":         record.NotBefore,
		"not_before_ready":   notBeforeReady,
		"blackout_blocked":   blackoutBlocked,
		"verification_ready": verificationReady,
		"shadow_ready":       shadowReady,
		"verification":       verification,
		"blockers":           blockers,
		"evaluated_at":       now,
	}, nil
}

func (api *ManagementAPI) proposalVerificationReadiness(record *configProposalRecord, result map[string]interface{}) (bool, []string) {
	blockers := make([]string, 0)
	if record == nil {
		return false, []string{"proposal is required"}
	}
	cfg := api.gateway.GetConfig()
	if cfg == nil {
		return true, blockers
	}
	policy := cfg.Security.MutationPolicy
	if !policy.Enabled || !policy.RequireVerificationForPromotedHighImpactProposals {
		return true, blockers
	}
	if !isHighImpactMutationAction(record.Action) || strings.TrimSpace(record.PromotedFrom) == "" {
		return true, blockers
	}
	if integrityOK, _ := result["integrity_ok"].(bool); !integrityOK {
		blockers = append(blockers, "promoted proposal failed integrity verification")
	}
	if sourceVerified, _ := result["source_verified"].(bool); !sourceVerified {
		blockers = append(blockers, "promoted proposal source could not be verified")
	}
	if matchesSource, _ := result["matches_source"].(bool); !matchesSource {
		blockers = append(blockers, "promoted proposal no longer matches its source proposal")
	}
	shadowVerification, _ := result["shadow_verification"].(map[string]interface{})
	if policy.RequireShadowEvaluationForPromotedHighImpactProposals {
		if checked, _ := shadowVerification["checked"].(bool); checked {
			if allHealthy, _ := shadowVerification["all_healthy"].(bool); !allHealthy {
				blockers = append(blockers, "promoted proposal failed shadow evaluation")
			}
		}
	}
	if policy.MinShadowHealthyVerificationsForPromotedHighImpactProposals > 0 {
		if checked, _ := shadowVerification["checked"].(bool); checked && record.ShadowVerificationPasses < policy.MinShadowHealthyVerificationsForPromotedHighImpactProposals {
			blockers = append(blockers, fmt.Sprintf("promoted proposal requires %d consecutive healthy shadow verifications; current streak: %d", policy.MinShadowHealthyVerificationsForPromotedHighImpactProposals, record.ShadowVerificationPasses))
		}
	}
	return len(blockers) == 0, blockers
}

func (api *ManagementAPI) observeProposalShadowVerification(record *configProposalRecord, result map[string]interface{}) error {
	if record == nil {
		return nil
	}
	shadowVerification, _ := result["shadow_verification"].(map[string]interface{})
	if len(shadowVerification) == 0 {
		return nil
	}
	checked, _ := shadowVerification["checked"].(bool)
	if !checked {
		return nil
	}
	allHealthy, _ := shadowVerification["all_healthy"].(bool)
	record.ShadowLastVerifiedAt = time.Now().UTC()
	record.ShadowLastHealthy = allHealthy
	if allHealthy {
		record.ShadowVerificationPasses++
	} else {
		record.ShadowVerificationPasses = 0
	}
	shadowVerification["healthy_streak"] = record.ShadowVerificationPasses
	shadowVerification["last_verified_at"] = record.ShadowLastVerifiedAt
	shadowVerification["last_healthy"] = record.ShadowLastHealthy
	shadowVerification["shadow_ready"] = record.ShadowReady
	shadowVerification["shadow_ready_at"] = record.ShadowReadyAt
	return saveConfigProposalRecord(record)
}

func (api *ManagementAPI) markProposalShadowReady(record *configProposalRecord, result map[string]interface{}) {
	if record == nil {
		return
	}
	shadowVerification, _ := result["shadow_verification"].(map[string]interface{})
	if len(shadowVerification) == 0 {
		return
	}
	checked, _ := shadowVerification["checked"].(bool)
	if !checked {
		return
	}
	cfg := api.gateway.GetConfig()
	if cfg == nil {
		return
	}
	required := cfg.Security.MutationPolicy.MinShadowHealthyVerificationsForPromotedHighImpactProposals
	if required <= 0 {
		required = 1
	}
	allHealthy, _ := shadowVerification["all_healthy"].(bool)
	readyNow := allHealthy && record.ShadowVerificationPasses >= required
	if readyNow && !record.ShadowReady {
		record.ShadowReady = true
		record.ShadowReadyAt = time.Now().UTC()
		shadowVerification["shadow_ready"] = true
		shadowVerification["shadow_ready_at"] = record.ShadowReadyAt
		if err := saveConfigProposalRecord(record); err == nil {
			api.emitProposalEvent("proposal.shadow_ready", record, map[string]interface{}{
				"healthy_streak":  record.ShadowVerificationPasses,
				"required_streak": required,
				"shadow_ready_at": record.ShadowReadyAt,
			})
		}
		return
	}
	if !readyNow && record.ShadowReady {
		record.ShadowReady = false
		record.ShadowReadyAt = time.Time{}
		shadowVerification["shadow_ready"] = false
		shadowVerification["shadow_ready_at"] = record.ShadowReadyAt
		_ = saveConfigProposalRecord(record)
	}
}

func proposalShadowPolicyRouteKeys(record *configProposalRecord) map[string]struct{} {
	keys := make(map[string]struct{})
	if record == nil || record.Config == nil {
		return keys
	}
	planServices := normalizeQueryList(record.CanaryServices)
	planRoutes := normalizeQueryList(record.CanaryRoutes)
	for _, svc := range flattenServices(record.Config) {
		serviceSelected := serviceSelectedForCanary(svc, planServices, planRoutes)
		serviceOnly := serviceSelectedOnlyByName(svc, planServices, planRoutes)
		for _, route := range svc.Routes {
			if !proposalShadowPolicyConfigured(route) {
				continue
			}
			if len(planServices) > 0 || len(planRoutes) > 0 {
				if !serviceSelected {
					continue
				}
				if !serviceOnly && !routeSelectedForCanary(svc, route, planRoutes) {
					continue
				}
			}
			keys[displayServiceName(svc)+"|"+route.Path] = struct{}{}
		}
	}
	return keys
}

func proposalShadowPolicyConfigured(route config.RouterConfig) bool {
	return route.ShadowMinRequests > 0 || route.ShadowMaxErrorRate > 0 || strings.TrimSpace(route.ShadowMaxLatencyDelta) != ""
}

func splitShadowRouteKey(key string) (string, string) {
	parts := strings.SplitN(key, "|", 2)
	if len(parts) != 2 {
		return key, ""
	}
	return parts[0], parts[1]
}
