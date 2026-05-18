package api

import (
	"fmt"
	"github.com/bhangun/iket/pkg/config"
	coreerrors "github.com/bhangun/iket/pkg/core/errors"
	"github.com/bhangun/iket/pkg/logging"
	"net/http"
	"strings"
	"time"
)

func (api *ManagementAPI) enforceProposalSchedule(action string, notBefore time.Time) error {
	cfg := api.gateway.GetConfig()
	if cfg == nil {
		return nil
	}
	policy := cfg.Security.MutationPolicy
	if !policy.Enabled || !policy.RequireNotBeforeForHighImpactProposals || !isHighImpactMutationAction(action) {
		return nil
	}
	if notBefore.IsZero() {
		return coreerrors.New(coreerrors.CodeValidationError, "Mutation policy requires not_before for high-impact proposals")
	}
	return nil
}

func proposalMaxAge(cfg *config.Config) time.Duration {
	if cfg == nil {
		return 0
	}
	value := strings.TrimSpace(cfg.Security.MutationPolicy.MaxProposalAge)
	if value == "" {
		return 0
	}
	duration, err := time.ParseDuration(value)
	if err != nil {
		return 0
	}
	return duration
}

func proposalApprovalMaxAge(cfg *config.Config) time.Duration {
	if cfg == nil {
		return 0
	}
	value := strings.TrimSpace(cfg.Security.MutationPolicy.MaxApprovalAge)
	if value == "" {
		return 0
	}
	duration, err := time.ParseDuration(value)
	if err != nil {
		return 0
	}
	return duration
}

func (api *ManagementAPI) enforceProposalFreshness(record *configProposalRecord, now time.Time) error {
	if record == nil {
		return nil
	}
	cfg := api.gateway.GetConfig()
	if cfg == nil {
		return nil
	}
	if err := api.enforceProposalExpiration(record, now); err != nil {
		return err
	}
	if maxApprovalAge := proposalApprovalMaxAge(cfg); maxApprovalAge > 0 {
		approvalCount := proposalApprovalCount(cfg, record)
		requiredApprovers := requiredProposalApprovers(cfg, record)
		if approvalCount < requiredApprovers {
			record.Status = "pending"
			if err := saveConfigProposalRecord(record); err != nil {
				api.logger.Warn("Proposal freshness recalculated but failed to persist pending state", logging.Error(err))
			}
			return coreerrors.New(coreerrors.CodeProposalStateConflict, fmt.Sprintf("Proposal requires %d fresh approval(s) before apply; current fresh approvals: %d", requiredApprovers, approvalCount))
		}
	}
	return nil
}

func (api *ManagementAPI) enforceProposalExpiration(record *configProposalRecord, now time.Time) error {
	if record == nil {
		return nil
	}
	cfg := api.gateway.GetConfig()
	if cfg == nil {
		return nil
	}
	if maxAge := proposalMaxAge(cfg); maxAge > 0 && record.CreatedAt.Add(maxAge).Before(now) {
		record.Status = "expired"
		record.ExpiredAt = now
		record.ExpirationReason = fmt.Sprintf("proposal exceeded max age of %s", maxAge)
		if err := saveConfigProposalRecord(record); err != nil {
			api.logger.Warn("Proposal expired but failed to persist expiration state", logging.Error(err))
		}
		return coreerrors.New(coreerrors.CodeProposalStateConflict, fmt.Sprintf("Proposal expired because it exceeded max age of %s", maxAge))
	}
	return nil
}

func (api *ManagementAPI) enforceProposalBlackoutWindow(action string, now time.Time) error {
	cfg := api.gateway.GetConfig()
	if cfg == nil {
		return nil
	}
	policy := cfg.Security.MutationPolicy
	if !policy.Enabled || len(policy.BlockedApplyWindows) == 0 {
		return nil
	}
	for _, window := range policy.BlockedApplyWindows {
		if !mutationWindowApplies(action, window.Scopes) {
			continue
		}
		active, err := isWithinBlockedApplyWindow(now, window)
		if err != nil {
			return coreerrors.New(coreerrors.CodeValidationError, fmt.Sprintf("Failed to evaluate blocked apply window %q", strings.TrimSpace(window.Name))).WithError(err)
		}
		if active {
			name := strings.TrimSpace(window.Name)
			if name == "" {
				name = fmt.Sprintf("%s-%s", strings.TrimSpace(window.Start), strings.TrimSpace(window.End))
			}
			return coreerrors.New(coreerrors.CodeProposalStateConflict, fmt.Sprintf("Proposal apply is blocked by blackout window %q", name))
		}
	}
	return nil
}

func (api *ManagementAPI) enforceProposalReviewer(record *configProposalRecord, reviewer string) error {
	if record == nil {
		return nil
	}
	cfg := api.gateway.GetConfig()
	if cfg == nil {
		return nil
	}
	policy := cfg.Security.MutationPolicy
	if !policy.Enabled || !policy.RequireDifferentReviewerForProposals {
		return nil
	}
	if strings.TrimSpace(record.CreatedBy) == "" || strings.TrimSpace(reviewer) == "" {
		return nil
	}
	if strings.EqualFold(strings.TrimSpace(record.CreatedBy), strings.TrimSpace(reviewer)) {
		return coreerrors.New(coreerrors.CodePermissionDenied, "Proposal reviewer must be different from the proposer")
	}
	return nil
}

func isHighImpactMutationAction(action string) bool {
	highImpact := map[string]bool{
		"gateway_config_replace": true,
		"services_replace":       true,
		"service_delete":         true,
		"route_delete":           true,
		"route_set_enabled":      true,
		"plugin_set_enabled":     true,
		"client_remove":          true,
		"restore_revision":       true,
	}
	return highImpact[action]
}

func mutationActionScopes(action string) []string {
	scopes := make([]string, 0, 2)
	switch {
	case strings.HasPrefix(action, "gateway_config_"):
		scopes = append(scopes, "config")
	case strings.HasPrefix(action, "services_"), strings.HasPrefix(action, "service_"):
		scopes = append(scopes, "services")
	case strings.HasPrefix(action, "route_"):
		scopes = append(scopes, "routes")
	case strings.HasPrefix(action, "plugin_"):
		scopes = append(scopes, "plugins")
	case strings.HasPrefix(action, "client_"):
		scopes = append(scopes, "clients")
	case strings.HasPrefix(action, "restore_revision"):
		scopes = append(scopes, "revisions")
	}
	if isHighImpactMutationAction(action) {
		scopes = append(scopes, "high_impact")
	}
	if len(scopes) == 0 {
		return []string{"all"}
	}
	return scopes
}

func mutationPolicyApplies(action string, policy config.MutationPolicy) bool {
	if !policy.Enabled {
		return false
	}
	if len(policy.EnforcedScopes) == 0 {
		return true
	}
	actionScopes := mutationActionScopes(action)
	for _, configuredScope := range policy.EnforcedScopes {
		scope := strings.ToLower(strings.TrimSpace(configuredScope))
		if scope == "" || scope == "all" {
			return true
		}
		for _, actionScope := range actionScopes {
			if scope == actionScope {
				return true
			}
		}
	}
	return false
}

func mutationWindowApplies(action string, scopes []string) bool {
	if len(scopes) == 0 {
		return isHighImpactMutationAction(action)
	}
	return mutationPolicyApplies(action, config.MutationPolicy{
		Enabled:        true,
		EnforcedScopes: scopes,
	})
}

func isWithinBlockedApplyWindow(now time.Time, window config.MutationApplyWindow) (bool, error) {
	locationName := strings.TrimSpace(window.Timezone)
	if locationName == "" {
		locationName = "UTC"
	}
	loc, err := time.LoadLocation(locationName)
	if err != nil {
		return false, err
	}
	startMinutes, err := parseClockMinutes(window.Start)
	if err != nil {
		return false, err
	}
	endMinutes, err := parseClockMinutes(window.End)
	if err != nil {
		return false, err
	}
	localNow := now.In(loc)
	currentMinutes := localNow.Hour()*60 + localNow.Minute()
	allowedDays, err := parsePolicyWeekdays(window.Days)
	if err != nil {
		return false, err
	}
	if startMinutes < endMinutes {
		return weekdayAllowed(allowedDays, localNow.Weekday()) && currentMinutes >= startMinutes && currentMinutes < endMinutes, nil
	}
	if weekdayAllowed(allowedDays, localNow.Weekday()) && currentMinutes >= startMinutes {
		return true, nil
	}
	previousDay := localNow.Add(-24 * time.Hour).Weekday()
	return weekdayAllowed(allowedDays, previousDay) && currentMinutes < endMinutes, nil
}

func parseClockMinutes(value string) (int, error) {
	parsed, err := time.Parse("15:04", strings.TrimSpace(value))
	if err != nil {
		return 0, coreerrors.New(coreerrors.CodeValidationError, fmt.Sprintf("Invalid clock value %q", value))
	}
	return parsed.Hour()*60 + parsed.Minute(), nil
}

func parsePolicyWeekdays(days []string) (map[time.Weekday]struct{}, error) {
	if len(days) == 0 {
		return nil, nil
	}
	out := make(map[time.Weekday]struct{}, len(days))
	for _, day := range days {
		weekday, err := parsePolicyWeekday(day)
		if err != nil {
			return nil, err
		}
		out[weekday] = struct{}{}
	}
	return out, nil
}

func parsePolicyWeekday(value string) (time.Weekday, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "sun", "sunday":
		return time.Sunday, nil
	case "mon", "monday":
		return time.Monday, nil
	case "tue", "tues", "tuesday":
		return time.Tuesday, nil
	case "wed", "wednesday":
		return time.Wednesday, nil
	case "thu", "thur", "thurs", "thursday":
		return time.Thursday, nil
	case "fri", "friday":
		return time.Friday, nil
	case "sat", "saturday":
		return time.Saturday, nil
	default:
		return time.Sunday, coreerrors.New(coreerrors.CodeValidationError, fmt.Sprintf("Invalid weekday %q", value))
	}
}

func weekdayAllowed(days map[time.Weekday]struct{}, weekday time.Weekday) bool {
	if len(days) == 0 {
		return true
	}
	_, ok := days[weekday]
	return ok
}

func (api *ManagementAPI) enforceMutationPolicy(action, label, note, changeRef string) error {
	cfg := api.gateway.GetConfig()
	if cfg == nil {
		return nil
	}
	policy := cfg.Security.MutationPolicy
	if !mutationPolicyApplies(action, policy) {
		return nil
	}
	if policy.RequireLabel && strings.TrimSpace(label) == "" {
		return coreerrors.New(coreerrors.CodeValidationError, fmt.Sprintf("Mutation policy requires label for action %q", action))
	}
	if isHighImpactMutationAction(action) {
		if policy.RequireNoteForHighImpact && strings.TrimSpace(note) == "" {
			return coreerrors.New(coreerrors.CodeValidationError, fmt.Sprintf("Mutation policy requires note for high-impact action %q", action))
		}
		if policy.RequireChangeRefForHighImpact && strings.TrimSpace(changeRef) == "" {
			return coreerrors.New(coreerrors.CodeValidationError, fmt.Sprintf("Mutation policy requires change_ref for high-impact action %q", action))
		}
	}
	return nil
}

func (api *ManagementAPI) applyManagedConfigChange(cfg *config.Config, action, label, note, changeRef string, summary map[string]interface{}) error {
	if err := api.enforceMutationPolicy(action, label, note, changeRef); err != nil {
		return err
	}
	if err := api.gateway.UpdateConfig(cfg); err != nil {
		return err
	}
	revisionID, err := saveConfigRevision(action, label, note, changeRef, summary, cfg)
	if err != nil {
		api.logger.Warn("Configuration updated but failed to record revision",
			logging.String("action", action),
			logging.Error(err),
		)
		return nil
	}
	api.logger.Info("Configuration revision recorded",
		logging.String("action", action),
		logging.String("revision_id", revisionID),
	)
	return nil
}

func revisionMetadataFromRequest(r *http.Request) (string, string, string) {
	if r == nil {
		return "", "", ""
	}
	return strings.TrimSpace(r.URL.Query().Get("label")), strings.TrimSpace(r.URL.Query().Get("note")), strings.TrimSpace(r.URL.Query().Get("change_ref"))
}
