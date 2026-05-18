package api

import (
	"encoding/json"
	"fmt"
	"github.com/bhangun/iket/pkg/config"
	coreerrors "github.com/bhangun/iket/pkg/core/errors"
	"github.com/bhangun/iket/pkg/core/gateway"
	"github.com/bhangun/iket/pkg/logging"
	"github.com/gorilla/mux"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
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

func (api *ManagementAPI) buildProposalCanaryEvaluation(record *configProposalRecord) (map[string]interface{}, error) {
	if record == nil {
		return nil, managedError(coreerrors.CodeProposalNotFound, "Proposal not found", nil)
	}
	if !hasProposalCanaryPlan(record) && record.Status != "canary_active" {
		return nil, managedCanaryStateError("Proposal does not have a canary rollout", nil)
	}
	services, routes, err := proposalCanaryMetricTargets(record)
	if err != nil {
		return nil, err
	}
	logs := filterCanaryLogEntries(api.logger.RecentLogs(2000, ""), services, routes)
	requests := 0
	failed := 0
	durations := make([]time.Duration, 0, len(logs))
	for _, entry := range logs {
		status, ok := fieldInt(entry.Fields, "status_code")
		if !ok {
			continue
		}
		requests++
		if status >= 500 {
			failed++
		}
		if duration, ok := fieldDuration(entry.Fields, "duration"); ok {
			durations = append(durations, duration)
		}
	}
	avg := averageDuration(durations)
	p95 := percentileDuration(durations, 95)
	p99 := percentileDuration(durations, 99)
	errorRate := 0.0
	if requests > 0 {
		errorRate = float64(failed) / float64(requests)
	}

	thresholds := canaryEvaluationThresholds{
		MinRequests:   record.CanaryMinRequests,
		MaxErrorRate:  record.CanaryMaxErrorRate,
		MaxP95Latency: strings.TrimSpace(record.CanaryMaxP95Latency),
	}
	healthy := true
	reasons := make([]string, 0)
	if thresholds.MinRequests > 0 && requests < thresholds.MinRequests {
		healthy = false
		reasons = append(reasons, fmt.Sprintf("canary observed %d request(s), below minimum %d", requests, thresholds.MinRequests))
	}
	if thresholds.MaxErrorRate > 0 && errorRate > thresholds.MaxErrorRate {
		healthy = false
		reasons = append(reasons, fmt.Sprintf("canary error rate %.4f exceeded limit %.4f", errorRate, thresholds.MaxErrorRate))
	}
	if thresholds.MaxP95Latency != "" {
		limit, _ := time.ParseDuration(thresholds.MaxP95Latency)
		if limit > 0 && p95 > limit {
			healthy = false
			reasons = append(reasons, fmt.Sprintf("canary p95 latency %s exceeded limit %s", p95, limit))
		}
	}
	if len(reasons) == 0 {
		reasons = append(reasons, "canary metrics are within configured thresholds")
	}

	return map[string]interface{}{
		"proposal_id":       record.ID,
		"status":            record.Status,
		"environment":       record.Environment,
		"canary_services":   record.CanaryServices,
		"canary_routes":     record.CanaryRoutes,
		"canary_headers":    record.CanaryHeaders,
		"canary_percent":    record.CanaryPercent,
		"canary_steps":      record.CanarySteps,
		"target_services":   services,
		"target_routes":     routes,
		"thresholds":        thresholds,
		"requests":          requests,
		"failed_requests":   failed,
		"error_rate":        errorRate,
		"average_latency":   avg.String(),
		"p95_latency":       p95.String(),
		"p99_latency":       p99.String(),
		"healthy":           healthy,
		"reasons":           reasons,
		"evaluation_window": "recent_logs_2000",
	}, nil
}

func proposalCanaryMetricTargets(record *configProposalRecord) ([]string, []string, error) {
	if record == nil || record.Config == nil {
		return nil, nil, managedProposalVerificationError("Proposal has no stored configuration", nil)
	}
	planServices := normalizeQueryList(record.CanaryServices)
	planRoutes := normalizeQueryList(record.CanaryRoutes)
	targetServices := make([]string, 0)
	targetRoutes := make([]string, 0)
	for _, svcCfg := range record.Config.Services {
		for _, svc := range svcCfg.Services {
			if !serviceSelectedForCanary(svc, planServices, planRoutes) {
				continue
			}
			serviceName := displayServiceName(svc)
			if len(record.CanaryHeaders) > 0 || record.CanaryPercent > 0 {
				serviceName = canaryServiceName(serviceName)
			}
			targetServices = appendUniqueString(targetServices, serviceName)
			serviceOnly := serviceSelectedOnlyByName(svc, planServices, planRoutes)
			for _, route := range svc.Routes {
				if serviceOnly || routeSelectedForCanary(svc, route, planRoutes) {
					targetRoutes = appendUniqueString(targetRoutes, strings.TrimSpace(route.Path))
				}
			}
		}
	}
	if len(targetServices) == 0 && len(targetRoutes) == 0 {
		return nil, nil, managedCanaryConfigError("Canary plan did not match any proposal services or routes", nil)
	}
	sort.Strings(targetServices)
	sort.Strings(targetRoutes)
	return targetServices, targetRoutes, nil
}

func filterCanaryLogEntries(entries []logging.LogEntry, serviceNames, routeNames []string) []logging.LogEntry {
	if len(entries) == 0 {
		return nil
	}
	serviceSet := make(map[string]struct{}, len(serviceNames))
	for _, name := range serviceNames {
		name = strings.TrimSpace(name)
		if name != "" {
			serviceSet[name] = struct{}{}
		}
	}
	routeSet := make(map[string]struct{}, len(routeNames))
	for _, name := range routeNames {
		name = strings.TrimSpace(name)
		if name != "" {
			routeSet[name] = struct{}{}
		}
	}
	filtered := make([]logging.LogEntry, 0, len(entries))
	for _, entry := range entries {
		serviceName := fieldString(entry.Fields, "service_name")
		routeName := fieldString(entry.Fields, "route_name")
		_, serviceMatch := serviceSet[serviceName]
		_, routeMatch := routeSet[routeName]
		if serviceMatch || routeMatch {
			filtered = append(filtered, entry)
		}
	}
	return filtered
}

func fieldInt(fields map[string]interface{}, key string) (int, bool) {
	if fields == nil {
		return 0, false
	}
	value, ok := fields[key]
	if !ok || value == nil {
		return 0, false
	}
	switch v := value.(type) {
	case int:
		return v, true
	case int64:
		return int(v), true
	case float64:
		return int(v), true
	case json.Number:
		i, err := v.Int64()
		return int(i), err == nil
	case string:
		i, err := strconv.Atoi(strings.TrimSpace(v))
		return i, err == nil
	default:
		return 0, false
	}
}

func fieldDuration(fields map[string]interface{}, key string) (time.Duration, bool) {
	if fields == nil {
		return 0, false
	}
	value, ok := fields[key]
	if !ok || value == nil {
		return 0, false
	}
	switch v := value.(type) {
	case string:
		d, err := time.ParseDuration(strings.TrimSpace(v))
		return d, err == nil
	case time.Duration:
		return v, true
	case float64:
		return time.Duration(v * float64(time.Second)), true
	default:
		return 0, false
	}
}

func averageDuration(values []time.Duration) time.Duration {
	if len(values) == 0 {
		return 0
	}
	var total time.Duration
	for _, value := range values {
		total += value
	}
	return total / time.Duration(len(values))
}

func percentileDuration(values []time.Duration, percentile int) time.Duration {
	if len(values) == 0 {
		return 0
	}
	sorted := append([]time.Duration(nil), values...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	if percentile <= 0 {
		return sorted[0]
	}
	if percentile >= 100 {
		return sorted[len(sorted)-1]
	}
	index := (len(sorted)*percentile + 99) / 100
	if index <= 0 {
		index = 1
	}
	if index > len(sorted) {
		index = len(sorted)
	}
	return sorted[index-1]
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

func proposalCanaryAutoInterval(record *configProposalRecord) time.Duration {
	if record == nil || !record.CanaryAutoReconcile {
		return 0
	}
	value := strings.TrimSpace(record.CanaryAutoInterval)
	if value == "" {
		return defaultProposalCanaryAutoReconcileInterval
	}
	interval, err := time.ParseDuration(value)
	if err != nil || interval <= 0 {
		return defaultProposalCanaryAutoReconcileInterval
	}
	return interval
}

func proposalCanaryAutoReviewer(record *configProposalRecord) string {
	if record == nil {
		return ""
	}
	if reviewer := strings.TrimSpace(record.CanaryAutoReviewer); reviewer != "" {
		return reviewer
	}
	if reviewer := strings.TrimSpace(record.ReviewedBy); reviewer != "" {
		return reviewer
	}
	if reviewer := strings.TrimSpace(record.CreatedBy); reviewer != "" {
		return reviewer
	}
	return "canary-controller"
}

func scheduleNextProposalCanaryReconcile(record *configProposalRecord, now time.Time) {
	if record == nil {
		return
	}
	record.CanaryLastReconciled = now
	if record.Status == "canary_active" && record.CanaryAutoReconcile {
		record.CanaryNextReconcile = now.Add(proposalCanaryAutoInterval(record))
		return
	}
	record.CanaryNextReconcile = time.Time{}
}

func (api *ManagementAPI) autoReconcileCanaries() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		api.reconcileAutoCanaries(time.Now().UTC())
	}
}

func (api *ManagementAPI) autoNotifyProposalQueueDigests() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		api.reconcileProposalQueueDigestNotifications(time.Now().UTC())
	}
}

func (api *ManagementAPI) autoNotifyGatewayPolicyAlerts() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		api.reconcileGatewayPolicyAlertNotifications(time.Now().UTC())
	}
}

func (api *ManagementAPI) reconcileAutoCanaries(now time.Time) {
	proposals, err := listConfigProposals()
	if err != nil {
		return
	}
	for _, proposal := range proposals {
		id, _ := proposal["id"].(string)
		if strings.TrimSpace(id) == "" {
			continue
		}
		record, err := loadConfigProposal(id)
		if err != nil || record == nil {
			continue
		}
		if record.Status != "canary_active" || !record.CanaryAutoReconcile {
			continue
		}
		if !record.CanaryNextReconcile.IsZero() && now.Before(record.CanaryNextReconcile) {
			continue
		}
		reviewer := proposalCanaryAutoReviewer(record)
		data, err := api.performProposalCanaryReconcile(record, reviewer, "Automatic canary reconcile", record.Label, record.Note, record.ChangeRef, now)
		if err != nil {
			api.logger.Warn("Automatic canary reconcile failed",
				logging.String("proposal_id", record.ID),
				logging.String("reviewer", reviewer),
				logging.Error(err))
			continue
		}
		actionTaken := ""
		if payload, ok := data["data"].(map[string]interface{}); ok {
			actionTaken = strings.TrimSpace(fmt.Sprint(payload["action_taken"]))
		}
		api.logger.Info("Automatic canary reconcile completed",
			logging.String("proposal_id", record.ID),
			logging.String("reviewer", reviewer),
			logging.String("status", record.Status),
			logging.String("action_taken", actionTaken))
	}
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

func (api *ManagementAPI) describeProposalCanaryPlan(record *configProposalRecord) (map[string]interface{}, error) {
	if record == nil || record.Config == nil {
		return nil, fmt.Errorf("proposal has no stored configuration")
	}
	if !hasProposalCanaryPlan(record) {
		return map[string]interface{}{
			"matched_services": nil,
			"matched_routes":   nil,
		}, nil
	}

	matchedServices := make([]string, 0)
	matchedRoutes := make([]string, 0)
	for _, svcCfg := range record.Config.Services {
		for _, svc := range svcCfg.Services {
			if serviceSelectedForCanary(svc, record.CanaryServices, record.CanaryRoutes) {
				matchedServices = appendUniqueString(matchedServices, strings.TrimSpace(svc.Name))
			}
			for _, route := range svc.Routes {
				if routeSelectedForCanary(svc, route, record.CanaryRoutes) {
					matchedRoutes = appendUniqueString(matchedRoutes, fmt.Sprintf("%s:%s", strings.TrimSpace(svc.Name), strings.TrimSpace(route.Path)))
				}
			}
		}
	}
	return map[string]interface{}{
		"matched_services": matchedServices,
		"matched_routes":   matchedRoutes,
	}, nil
}

func (api *ManagementAPI) buildCanaryApplyConfig(record *configProposalRecord) (*config.Config, map[string]interface{}, error) {
	if record == nil || record.Config == nil {
		return nil, nil, fmt.Errorf("proposal has no stored configuration")
	}
	if !strings.HasPrefix(record.Action, "services_") {
		return nil, nil, fmt.Errorf("canary apply is currently supported only for service proposals")
	}
	if len(record.CanaryHeaders) > 0 {
		return api.buildHeaderScopedCanaryApplyConfig(record)
	}
	if record.CanaryPercent > 0 {
		return api.buildPercentageScopedCanaryApplyConfig(record)
	}
	current := api.gateway.GetConfig()
	if current == nil {
		return nil, nil, fmt.Errorf("current gateway configuration is not available")
	}
	nextCfg, err := cloneConfig(current)
	if err != nil {
		return nil, nil, err
	}
	planServices := make([]string, 0)
	planRoutes := make([]string, 0)
	for _, selector := range record.CanaryServices {
		selector = strings.TrimSpace(selector)
		if selector != "" {
			planServices = append(planServices, selector)
		}
	}
	for _, selector := range record.CanaryRoutes {
		selector = strings.TrimSpace(selector)
		if selector != "" {
			planRoutes = append(planRoutes, selector)
		}
	}
	changedServices := make([]string, 0)
	changedRoutes := make([]map[string]interface{}, 0)

	for _, proposalSvc := range flattenServices(record.Config) {
		if !serviceSelectedForCanary(proposalSvc, planServices, planRoutes) {
			continue
		}
		changed, routes := applyCanaryServiceToConfig(nextCfg, proposalSvc, planServices, planRoutes)
		if changed {
			changedServices = append(changedServices, displayServiceName(proposalSvc))
		}
		changedRoutes = append(changedRoutes, routes...)
	}
	if len(changedServices) == 0 && len(changedRoutes) == 0 {
		return nil, nil, fmt.Errorf("canary plan did not match any services or routes in the proposal")
	}
	sort.Strings(changedServices)
	sortRouteSummaries(changedRoutes)
	summary := serviceChangeSummary(current, nextCfg)
	summary["canary"] = true
	summary["canary_services"] = planServices
	summary["canary_routes"] = planRoutes
	summary["canary_headers"] = record.CanaryHeaders
	summary["canary_changed_services"] = changedServices
	summary["canary_changed_routes"] = changedRoutes
	return nextCfg, summary, nil
}

func (api *ManagementAPI) buildHeaderScopedCanaryApplyConfig(record *configProposalRecord) (*config.Config, map[string]interface{}, error) {
	current := api.gateway.GetConfig()
	if current == nil {
		return nil, nil, fmt.Errorf("current gateway configuration is not available")
	}
	nextCfg, err := cloneConfig(current)
	if err != nil {
		return nil, nil, err
	}
	headerMatchers := parseCanaryHeaderMatchers(record.CanaryHeaders)
	if len(headerMatchers) == 0 {
		return nil, nil, fmt.Errorf("canary headers are required for header-scoped canary rollout")
	}

	planServices := normalizeQueryList(record.CanaryServices)
	planRoutes := normalizeQueryList(record.CanaryRoutes)
	changedServices := make([]string, 0)
	changedRoutes := make([]map[string]interface{}, 0)

	for _, proposalSvc := range flattenServices(record.Config) {
		if !serviceSelectedForCanary(proposalSvc, planServices, planRoutes) {
			continue
		}
		canarySvc, routes := buildHeaderScopedCanaryService(proposalSvc, planServices, planRoutes, headerMatchers)
		if len(canarySvc.Routes) == 0 {
			continue
		}
		replaceOrAppendService(nextCfg, canarySvc)
		changedServices = appendUniqueString(changedServices, displayServiceName(proposalSvc))
		changedRoutes = append(changedRoutes, routes...)
	}
	if len(changedServices) == 0 && len(changedRoutes) == 0 {
		return nil, nil, fmt.Errorf("canary plan did not match any services or routes in the proposal")
	}
	sort.Strings(changedServices)
	sortRouteSummaries(changedRoutes)
	summary := serviceChangeSummary(current, nextCfg)
	summary["canary"] = true
	summary["canary_strategy"] = "header_scoped"
	summary["canary_services"] = planServices
	summary["canary_routes"] = planRoutes
	summary["canary_headers"] = record.CanaryHeaders
	summary["canary_changed_services"] = changedServices
	summary["canary_changed_routes"] = changedRoutes
	return nextCfg, summary, nil
}

func (api *ManagementAPI) buildPercentageScopedCanaryApplyConfig(record *configProposalRecord) (*config.Config, map[string]interface{}, error) {
	current := api.gateway.GetConfig()
	if current == nil {
		return nil, nil, fmt.Errorf("current gateway configuration is not available")
	}
	nextCfg, err := cloneConfig(current)
	if err != nil {
		return nil, nil, err
	}
	planServices := normalizeQueryList(record.CanaryServices)
	planRoutes := normalizeQueryList(record.CanaryRoutes)
	changedServices := make([]string, 0)
	changedRoutes := make([]map[string]interface{}, 0)

	for _, proposalSvc := range flattenServices(record.Config) {
		if !serviceSelectedForCanary(proposalSvc, planServices, planRoutes) {
			continue
		}
		canarySvc, routes := buildPercentageScopedCanaryService(proposalSvc, planServices, planRoutes, record.CanaryPercent)
		if len(canarySvc.Routes) == 0 {
			continue
		}
		replaceOrAppendService(nextCfg, canarySvc)
		changedServices = appendUniqueString(changedServices, displayServiceName(proposalSvc))
		changedRoutes = append(changedRoutes, routes...)
	}
	if len(changedServices) == 0 && len(changedRoutes) == 0 {
		return nil, nil, fmt.Errorf("canary plan did not match any services or routes in the proposal")
	}
	sort.Strings(changedServices)
	sortRouteSummaries(changedRoutes)
	summary := serviceChangeSummary(current, nextCfg)
	summary["canary"] = true
	summary["canary_strategy"] = "percentage"
	summary["canary_services"] = planServices
	summary["canary_routes"] = planRoutes
	summary["canary_percent"] = record.CanaryPercent
	summary["canary_changed_services"] = changedServices
	summary["canary_changed_routes"] = changedRoutes
	return nextCfg, summary, nil
}

func applyCanaryServiceToConfig(cfg *config.Config, proposalSvc config.Service, canaryServices, canaryRoutes []string) (bool, []map[string]interface{}) {
	if cfg == nil {
		return false, nil
	}
	if len(cfg.Services) == 0 {
		cfg.Services = []config.ServiceConfig{{Version: 1}}
	}
	serviceIdx, existingSvc := findServiceForCanary(cfg, proposalSvc)
	targetSvc := existingSvc
	changedRoutes := make([]map[string]interface{}, 0)
	changed := false

	serviceOnly := serviceSelectedOnlyByName(proposalSvc, canaryServices, canaryRoutes)
	if serviceOnly {
		targetSvc = proposalSvc
		changed = true
		for _, route := range proposalSvc.Routes {
			changedRoutes = append(changedRoutes, routeSummary(proposalSvc, route))
		}
	} else {
		for _, proposalRoute := range proposalSvc.Routes {
			if !routeSelectedForCanary(proposalSvc, proposalRoute, canaryRoutes) {
				continue
			}
			targetSvc, changed = mergeCanaryRoute(targetSvc, proposalSvc, proposalRoute, changed)
			changedRoutes = append(changedRoutes, routeSummary(proposalSvc, proposalRoute))
		}
	}
	if !changed {
		return false, nil
	}
	if serviceIdx >= 0 {
		cfg.Services[0].Services[serviceIdx] = targetSvc
	} else {
		cfg.Services[0].Services = append(cfg.Services[0].Services, targetSvc)
	}
	return true, changedRoutes
}

func buildHeaderScopedCanaryService(proposalSvc config.Service, canaryServices, canaryRoutes []string, headerMatchers map[string]string) (config.Service, []map[string]interface{}) {
	canarySvc := proposalSvc
	canarySvc.Name = canaryServiceName(displayServiceName(proposalSvc))
	canarySvc.Routes = nil
	changedRoutes := make([]map[string]interface{}, 0)

	serviceOnly := serviceSelectedOnlyByName(proposalSvc, canaryServices, canaryRoutes)
	for _, proposalRoute := range proposalSvc.Routes {
		if !serviceOnly && !routeSelectedForCanary(proposalSvc, proposalRoute, canaryRoutes) {
			continue
		}
		clonedRoute := proposalRoute
		clonedRoute.MatchHeaders = cloneHeaderMap(headerMatchers)
		canarySvc.Routes = append(canarySvc.Routes, clonedRoute)
		changedRoutes = append(changedRoutes, routeSummary(proposalSvc, clonedRoute))
	}
	return canarySvc, changedRoutes
}

func buildPercentageScopedCanaryService(proposalSvc config.Service, canaryServices, canaryRoutes []string, percent int) (config.Service, []map[string]interface{}) {
	canarySvc := proposalSvc
	canarySvc.Name = canaryServiceName(displayServiceName(proposalSvc))
	canarySvc.Routes = nil
	changedRoutes := make([]map[string]interface{}, 0)

	serviceOnly := serviceSelectedOnlyByName(proposalSvc, canaryServices, canaryRoutes)
	for _, proposalRoute := range proposalSvc.Routes {
		if !serviceOnly && !routeSelectedForCanary(proposalSvc, proposalRoute, canaryRoutes) {
			continue
		}
		clonedRoute := proposalRoute
		clonedRoute.MatchPercent = percent
		canarySvc.Routes = append(canarySvc.Routes, clonedRoute)
		changedRoutes = append(changedRoutes, routeSummary(proposalSvc, clonedRoute))
	}
	return canarySvc, changedRoutes
}

func replaceOrAppendService(cfg *config.Config, svc config.Service) {
	if cfg == nil {
		return
	}
	if len(cfg.Services) == 0 {
		cfg.Services = []config.ServiceConfig{{Version: 1}}
	}
	for i := range cfg.Services {
		for j := range cfg.Services[i].Services {
			if strings.EqualFold(strings.TrimSpace(cfg.Services[i].Services[j].Name), strings.TrimSpace(svc.Name)) {
				cfg.Services[i].Services[j] = svc
				return
			}
		}
	}
	cfg.Services[0].Services = append(cfg.Services[0].Services, svc)
}

func canaryServiceName(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return "canary"
	}
	return name + "__canary"
}

func parseCanaryHeaderMatchers(values []string) map[string]string {
	out := make(map[string]string)
	for _, value := range values {
		parts := strings.SplitN(strings.TrimSpace(value), "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])
		if key == "" || val == "" {
			continue
		}
		out[key] = val
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func cloneHeaderMap(src map[string]string) map[string]string {
	if len(src) == 0 {
		return nil
	}
	dst := make(map[string]string, len(src))
	for key, value := range src {
		dst[key] = value
	}
	return dst
}

func findServiceForCanary(cfg *config.Config, proposalSvc config.Service) (int, config.Service) {
	for i, svc := range cfg.Services[0].Services {
		if serviceIdentity(svc) == serviceIdentity(proposalSvc) {
			return i, svc
		}
	}
	return -1, config.Service{
		Name:        proposalSvc.Name,
		Description: proposalSvc.Description,
		Host:        proposalSvc.Host,
		BasePath:    proposalSvc.BasePath,
		Tags:        append([]string(nil), proposalSvc.Tags...),
		Group:       proposalSvc.Group,
		Scopes:      append([]string(nil), proposalSvc.Scopes...),
	}
}

func serviceSelectedForCanary(svc config.Service, canaryServices, canaryRoutes []string) bool {
	return serviceSelectedOnlyByName(svc, canaryServices, canaryRoutes) || serviceHasSelectedCanaryRoute(svc, canaryRoutes)
}

func serviceSelectedOnlyByName(svc config.Service, canaryServices, canaryRoutes []string) bool {
	if len(canaryServices) == 0 {
		return false
	}
	if len(canaryRoutes) > 0 {
		return false
	}
	for _, selector := range canaryServices {
		if strings.EqualFold(strings.TrimSpace(selector), displayServiceName(svc)) {
			return true
		}
	}
	return false
}

func serviceHasSelectedCanaryRoute(svc config.Service, canaryRoutes []string) bool {
	for _, route := range svc.Routes {
		if routeSelectedForCanary(svc, route, canaryRoutes) {
			return true
		}
	}
	return false
}

func routeSelectedForCanary(svc config.Service, route config.RouterConfig, selectors []string) bool {
	if len(selectors) == 0 {
		return false
	}
	serviceName := displayServiceName(svc)
	effectivePath := svc.EffectiveRoutePath(route)
	for _, selector := range selectors {
		serviceSelector, pathSelector := parseCanaryRouteSelector(selector)
		if pathSelector == "" {
			continue
		}
		if serviceSelector != "" && !strings.EqualFold(serviceSelector, serviceName) {
			continue
		}
		if pathSelector == route.Path || pathSelector == effectivePath {
			return true
		}
	}
	return false
}

func parseCanaryRouteSelector(selector string) (string, string) {
	selector = strings.TrimSpace(selector)
	if selector == "" {
		return "", ""
	}
	if strings.HasPrefix(selector, "/") {
		return "", selector
	}
	if idx := strings.Index(selector, ":/"); idx > 0 {
		return strings.TrimSpace(selector[:idx]), strings.TrimSpace(selector[idx+1:])
	}
	return "", selector
}

func mergeCanaryRoute(targetSvc, proposalSvc config.Service, proposalRoute config.RouterConfig, alreadyChanged bool) (config.Service, bool) {
	targetSvc.Name = proposalSvc.Name
	targetSvc.Description = proposalSvc.Description
	targetSvc.Host = proposalSvc.Host
	targetSvc.BasePath = proposalSvc.BasePath
	targetSvc.Tags = append([]string(nil), proposalSvc.Tags...)
	targetSvc.Group = proposalSvc.Group
	targetSvc.Scopes = append([]string(nil), proposalSvc.Scopes...)
	if len(targetSvc.Routes) == 0 {
		targetSvc.Routes = []config.RouterConfig{}
	}
	routeID := stableRouteID(displayServiceName(proposalSvc), proposalSvc.EffectiveRoutePath(proposalRoute), proposalRoute.EffectiveMethods())
	for i, existing := range targetSvc.Routes {
		existingID := stableRouteID(displayServiceName(targetSvc), targetSvc.EffectiveRoutePath(existing), existing.EffectiveMethods())
		if existingID == routeID {
			targetSvc.Routes[i] = proposalRoute
			return targetSvc, true
		}
	}
	targetSvc.Routes = append(targetSvc.Routes, proposalRoute)
	return targetSvc, true || alreadyChanged
}

type canaryEvaluationThresholds struct {
	MinRequests   int     `json:"min_requests,omitempty"`
	MaxErrorRate  float64 `json:"max_error_rate,omitempty"`
	MaxP95Latency string  `json:"max_p95_latency,omitempty"`
}
