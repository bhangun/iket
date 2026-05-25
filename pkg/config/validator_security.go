package config

import (
	"fmt"
	"github.com/bhangun/iket/pkg/core/errors"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// SecurityConfigRule validates security configuration
type SecurityConfigRule struct{}

func (r *SecurityConfigRule) Validate(cfg *Config) error {
	if cfg.Security.TLS.Enabled {
		if cfg.Security.TLS.CertFile == "" {
			return errors.NewValidationError("security.tls.certFile", "certificate file is required when TLS is enabled")
		}
		if cfg.Security.TLS.KeyFile == "" {
			return errors.NewValidationError("security.tls.keyFile", "private key file is required when TLS is enabled")
		}
		if cfg.Security.TLS.Port < 0 || cfg.Security.TLS.Port > 65535 {
			return errors.NewValidationError("security.tls.port", "TLS port must be between 0 and 65535")
		}
		if cfg.Security.TLS.HTTP3Port < 0 || cfg.Security.TLS.HTTP3Port > 65535 {
			return errors.NewValidationError("security.tls.http3Port", "HTTP/3 port must be between 0 and 65535")
		}
		if cfg.Security.TLS.EnrollmentPort < 0 || cfg.Security.TLS.EnrollmentPort > 65535 {
			return errors.NewValidationError("security.tls.enrollmentPort", "enrollment TLS port must be between 0 and 65535")
		}
		if cfg.Security.TLS.EnrollmentMaxActive < 0 {
			return errors.NewValidationError("security.tls.enrollmentMaxActive", "enrollment max active must be zero or greater")
		}
	}
	if cfg.Security.TLS.HTTP3Enabled && !cfg.Security.TLS.Enabled {
		return errors.NewValidationError("security.tls.http3Enabled", "HTTP/3 requires TLS to be enabled")
	}

	if cfg.Security.EnableBasicAuth {
		if len(cfg.Security.BasicAuthUsers) == 0 {
			return errors.NewValidationError("security.basicAuthUsers", "at least one user is required when basic auth is enabled")
		}
	}

	// Validate clients map if present
	if cfg.Security.Clients != nil {
		if len(cfg.Security.Clients) == 0 {
			return errors.NewValidationError("security.clients", "at least one client must be configured if clients map is present")
		}
		for k, v := range cfg.Security.Clients {
			if k == "" || v == "" {
				return errors.NewValidationError("security.clients", "client ID and secret must not be empty")
			}
		}
	}

	if cfg.Security.MutationPolicy.RequireNoteForHighImpact && !cfg.Security.MutationPolicy.Enabled {
		return errors.NewValidationError("security.mutationPolicy.enabled", "mutation policy must be enabled before requiring notes for high-impact actions")
	}
	if cfg.Security.MutationPolicy.RequireChangeRefForHighImpact && !cfg.Security.MutationPolicy.Enabled {
		return errors.NewValidationError("security.mutationPolicy.enabled", "mutation policy must be enabled before requiring change references for high-impact actions")
	}
	if cfg.Security.MutationPolicy.RequireDifferentReviewerForProposals && !cfg.Security.MutationPolicy.Enabled {
		return errors.NewValidationError("security.mutationPolicy.enabled", "mutation policy must be enabled before requiring different proposal reviewers")
	}
	if cfg.Security.MutationPolicy.RequireNotBeforeForHighImpactProposals && !cfg.Security.MutationPolicy.Enabled {
		return errors.NewValidationError("security.mutationPolicy.enabled", "mutation policy must be enabled before requiring proposal schedule windows")
	}
	if cfg.Security.MutationPolicy.RequireVerificationForPromotedHighImpactProposals && !cfg.Security.MutationPolicy.Enabled {
		return errors.NewValidationError("security.mutationPolicy.enabled", "mutation policy must be enabled before requiring promoted proposal verification")
	}
	if cfg.Security.MutationPolicy.RequireShadowEvaluationForPromotedHighImpactProposals && !cfg.Security.MutationPolicy.Enabled {
		return errors.NewValidationError("security.mutationPolicy.enabled", "mutation policy must be enabled before requiring promoted proposal shadow evaluation")
	}
	if cfg.Security.MutationPolicy.MinShadowHealthyVerificationsForPromotedHighImpactProposals < 0 {
		return errors.NewValidationError("security.mutationPolicy.minShadowHealthyVerificationsForPromotedHighImpactProposals", "minimum shadow healthy verifications must be zero or greater")
	}
	if cfg.Security.MutationPolicy.MinShadowHealthyVerificationsForPromotedHighImpactProposals > 0 && !cfg.Security.MutationPolicy.Enabled {
		return errors.NewValidationError("security.mutationPolicy.enabled", "mutation policy must be enabled before requiring a shadow verification streak")
	}
	if strings.TrimSpace(cfg.Security.MutationPolicy.MaxProposalAge) != "" && !cfg.Security.MutationPolicy.Enabled {
		return errors.NewValidationError("security.mutationPolicy.enabled", "mutation policy must be enabled before limiting proposal age")
	}
	if strings.TrimSpace(cfg.Security.MutationPolicy.MaxApprovalAge) != "" && !cfg.Security.MutationPolicy.Enabled {
		return errors.NewValidationError("security.mutationPolicy.enabled", "mutation policy must be enabled before limiting approval age")
	}
	if len(cfg.Security.MutationPolicy.BlockedApplyWindows) > 0 && !cfg.Security.MutationPolicy.Enabled {
		return errors.NewValidationError("security.mutationPolicy.enabled", "mutation policy must be enabled before configuring blocked apply windows")
	}
	if cfg.Security.MutationPolicy.MinApproversForHighImpactProposals < 0 {
		return errors.NewValidationError("security.mutationPolicy.minApproversForHighImpactProposals", "minimum approvers must be zero or greater")
	}
	if cfg.Security.MutationPolicy.MinApproversForHighImpactProposals > 0 && !cfg.Security.MutationPolicy.Enabled {
		return errors.NewValidationError("security.mutationPolicy.enabled", "mutation policy must be enabled before requiring proposal approvers")
	}
	if strings.TrimSpace(cfg.Security.MutationPolicy.MaxProposalAge) != "" {
		if _, err := time.ParseDuration(strings.TrimSpace(cfg.Security.MutationPolicy.MaxProposalAge)); err != nil {
			return errors.NewValidationError("security.mutationPolicy.maxProposalAge", "max proposal age must use a valid duration format")
		}
	}
	if strings.TrimSpace(cfg.Security.MutationPolicy.MaxApprovalAge) != "" {
		if _, err := time.ParseDuration(strings.TrimSpace(cfg.Security.MutationPolicy.MaxApprovalAge)); err != nil {
			return errors.NewValidationError("security.mutationPolicy.maxApprovalAge", "max approval age must use a valid duration format")
		}
	}
	for _, scope := range cfg.Security.MutationPolicy.EnforcedScopes {
		switch strings.ToLower(strings.TrimSpace(scope)) {
		case "", "all", "config", "services", "routes", "plugins", "clients", "revisions", "high_impact":
		default:
			return errors.NewValidationError("security.mutationPolicy.enforcedScopes", "mutation policy scope must be one of all, config, services, routes, plugins, clients, revisions, or high_impact")
		}
	}
	for i, window := range cfg.Security.MutationPolicy.BlockedApplyWindows {
		if strings.TrimSpace(window.Start) == "" || strings.TrimSpace(window.End) == "" {
			return errors.NewValidationError(fmt.Sprintf("security.mutationPolicy.blockedApplyWindows[%d]", i), "blocked apply windows require both start and end times")
		}
		if _, err := time.Parse("15:04", strings.TrimSpace(window.Start)); err != nil {
			return errors.NewValidationError(fmt.Sprintf("security.mutationPolicy.blockedApplyWindows[%d].start", i), "start must use HH:MM 24-hour format")
		}
		if _, err := time.Parse("15:04", strings.TrimSpace(window.End)); err != nil {
			return errors.NewValidationError(fmt.Sprintf("security.mutationPolicy.blockedApplyWindows[%d].end", i), "end must use HH:MM 24-hour format")
		}
		if strings.TrimSpace(window.Start) == strings.TrimSpace(window.End) {
			return errors.NewValidationError(fmt.Sprintf("security.mutationPolicy.blockedApplyWindows[%d]", i), "blocked apply window start and end must differ")
		}
		if tz := strings.TrimSpace(window.Timezone); tz != "" {
			if _, err := time.LoadLocation(tz); err != nil {
				return errors.NewValidationError(fmt.Sprintf("security.mutationPolicy.blockedApplyWindows[%d].timezone", i), "timezone must be a valid IANA timezone")
			}
		}
		for _, day := range window.Days {
			if !isKnownPolicyWeekday(day) {
				return errors.NewValidationError(fmt.Sprintf("security.mutationPolicy.blockedApplyWindows[%d].days", i), "days must use weekday names such as mon, tue, wed, thu, fri, sat, or sun")
			}
		}
		for _, scope := range window.Scopes {
			switch strings.ToLower(strings.TrimSpace(scope)) {
			case "", "all", "config", "services", "routes", "plugins", "clients", "revisions", "high_impact":
			default:
				return errors.NewValidationError(fmt.Sprintf("security.mutationPolicy.blockedApplyWindows[%d].scopes", i), "blocked apply window scope must be one of all, config, services, routes, plugins, clients, revisions, or high_impact")
			}
		}
	}
	if err := validateProposalQueueUrgencyThresholds("security.mutationPolicy.proposalQueue.defaultUrgency", cfg.Security.MutationPolicy.ProposalQueue.DefaultUrgency); err != nil {
		return err
	}
	for environment, thresholds := range cfg.Security.MutationPolicy.ProposalQueue.EnvironmentUrgency {
		envName := strings.TrimSpace(environment)
		if envName == "" {
			return errors.NewValidationError("security.mutationPolicy.proposalQueue.environmentUrgency", "environment urgency overrides require a non-empty environment key")
		}
		if err := validateProposalQueueUrgencyThresholds(fmt.Sprintf("security.mutationPolicy.proposalQueue.environmentUrgency.%s", envName), thresholds); err != nil {
			return err
		}
	}
	if err := validateProposalQueueNotificationPolicy("security.mutationPolicy.proposalQueue.notifications", cfg.Security.MutationPolicy.ProposalQueue.Notifications); err != nil {
		return err
	}
	if err := validatePolicyAlertNotificationPolicy("security.mutationPolicy.policyAlertNotifications", cfg.Security.MutationPolicy.PolicyAlertNotifications); err != nil {
		return err
	}
	if err := validatePolicyAlertNotificationPolicy("security.mutationPolicy.limitAlertNotifications", cfg.Security.MutationPolicy.LimitAlertNotifications); err != nil {
		return err
	}
	if err := validatePolicyAlertNotificationPolicy("security.mutationPolicy.limitClassAlertNotifications", cfg.Security.MutationPolicy.LimitClassAlertNotifications); err != nil {
		return err
	}
	if err := validatePolicyAlertNotificationPolicy("security.mutationPolicy.limitClassSnoozeNotifications", cfg.Security.MutationPolicy.LimitClassSnoozeNotifications); err != nil {
		return err
	}
	for name, classConfig := range cfg.Security.LimitAlertBucketClasses {
		className := strings.TrimSpace(name)
		if className == "" {
			return errors.NewValidationError("security.limitAlertBucketClasses", "limit alert bucket classes require a non-empty name")
		}
		if err := validateLimitAlertBucketClassConfig("security.limitAlertBucketClasses."+className, classConfig); err != nil {
			return err
		}
	}
	for name, preset := range cfg.Security.LimiterClassPresets {
		presetName := strings.TrimSpace(name)
		if presetName == "" {
			return errors.NewValidationError("security.limiterClassPresets", "limiter class presets require a non-empty name")
		}
		if err := validateLimiterClassPolicyPreset("security.limiterClassPresets."+presetName, preset, cfg.Security.LimitAlertBucketClasses); err != nil {
			return err
		}
	}
	for name, preset := range cfg.Security.LimitClassDigestHiddenStrategyPolicyPresets {
		presetName := strings.TrimSpace(name)
		if presetName == "" {
			return errors.NewValidationError("security.limitClassDigestHiddenStrategyPolicyPresets", "limit class digest hidden strategy policy presets require a non-empty name")
		}
		if err := validateLimitClassDigestHiddenStrategyPolicy("security.limitClassDigestHiddenStrategyPolicyPresets."+presetName, &preset); err != nil {
			return err
		}
	}
	for name, profile := range cfg.Security.LimitClassDigestProfiles {
		profileName := strings.TrimSpace(name)
		if profileName == "" {
			return errors.NewValidationError("security.limitClassDigestProfiles", "limit class digest profiles require a non-empty name")
		}
		if err := validateNotificationWebhookLimitAlertFilters("security.limitClassDigestProfiles."+profileName, NotificationWebhook{
			MinLimitAlertSeverity:                                               profile.MinLimitAlertSeverity,
			MinLimitAlertBucketClassPriority:                                    profile.MinLimitAlertBucketClassPriority,
			LimitClassDigestTypes:                                               profile.LimitClassDigestTypes,
			LimitClassDigestSummaryOnlyTypes:                                    profile.LimitClassDigestSummaryOnlyTypes,
			LimitClassDigestMinSeverity:                                         profile.LimitClassDigestMinSeverity,
			LimitClassDigestSeverities:                                          profile.LimitClassDigestSeverities,
			LimitClassDigestMinBucketClassPriority:                              profile.LimitClassDigestMinBucketClassPriority,
			LimitClassDigestMaxBucketClasses:                                    profile.LimitClassDigestMaxBucketClasses,
			LimitClassDigestMinSummarySeverity:                                  profile.LimitClassDigestMinSummarySeverity,
			LimitClassDigestMinSummaryBucketClassPriority:                       profile.LimitClassDigestMinSummaryBucketClassPriority,
			LimitClassDigestSummarySortMode:                                     profile.LimitClassDigestSummarySortMode,
			LimitClassDigestMinSummaryCount:                                     profile.LimitClassDigestMinSummaryCount,
			LimitClassDigestOtherBucketLabel:                                    profile.LimitClassDigestOtherBucketLabel,
			LimitClassDigestOverflowReasons:                                     profile.LimitClassDigestOverflowReasons,
			LimitClassDigestOverflowReasonLabels:                                profile.LimitClassDigestOverflowReasonLabels,
			LimitClassDigestOverflowReasonGroups:                                profile.LimitClassDigestOverflowReasonGroups,
			LimitClassDigestOverflowReasonOrder:                                 profile.LimitClassDigestOverflowReasonOrder,
			LimitClassDigestMaxOverflowReasons:                                  profile.LimitClassDigestMaxOverflowReasons,
			LimitClassDigestTruncatedReasonBucketLabel:                          profile.LimitClassDigestTruncatedReasonBucketLabel,
			LimitClassDigestTruncatedReasonBucketMode:                           profile.LimitClassDigestTruncatedReasonBucketMode,
			LimitClassDigestTruncatedReasonBucketMaxReasons:                     profile.LimitClassDigestTruncatedReasonBucketMaxReasons,
			LimitClassDigestTruncatedReasonBucketReasonOrder:                    profile.LimitClassDigestTruncatedReasonBucketReasonOrder,
			LimitClassDigestTruncatedReasonBucketMinSeverity:                    profile.LimitClassDigestTruncatedReasonBucketMinSeverity,
			LimitClassDigestTruncatedReasonBucketSeverities:                     profile.LimitClassDigestTruncatedReasonBucketSeverities,
			LimitClassDigestTruncatedReasonBucketSortMode:                       profile.LimitClassDigestTruncatedReasonBucketSortMode,
			LimitClassDigestTruncatedReasonBucketDominantReasonStrategy:         profile.LimitClassDigestTruncatedReasonBucketDominantReasonStrategy,
			LimitClassDigestTruncatedReasonBucketHiddenStrategyOrder:            profile.LimitClassDigestTruncatedReasonBucketHiddenStrategyOrder,
			LimitClassDigestTruncatedReasonBucketHiddenStrategyDominantMode:     profile.LimitClassDigestTruncatedReasonBucketHiddenStrategyDominantMode,
			LimitClassDigestTruncatedReasonBucketHiddenStrategyPriorityWeight:   profile.LimitClassDigestTruncatedReasonBucketHiddenStrategyPriorityWeight,
			LimitClassDigestTruncatedReasonBucketHiddenStrategyReasonWeight:     profile.LimitClassDigestTruncatedReasonBucketHiddenStrategyReasonWeight,
			LimitClassDigestTruncatedReasonBucketHiddenStrategyItemWeight:       profile.LimitClassDigestTruncatedReasonBucketHiddenStrategyItemWeight,
			LimitClassDigestTruncatedReasonBucketHiddenStrategyPriorityCap:      profile.LimitClassDigestTruncatedReasonBucketHiddenStrategyPriorityCap,
			LimitClassDigestTruncatedReasonBucketHiddenStrategyReasonCap:        profile.LimitClassDigestTruncatedReasonBucketHiddenStrategyReasonCap,
			LimitClassDigestTruncatedReasonBucketHiddenStrategyItemCap:          profile.LimitClassDigestTruncatedReasonBucketHiddenStrategyItemCap,
			LimitClassDigestTruncatedReasonBucketHiddenStrategyMinReasons:       profile.LimitClassDigestTruncatedReasonBucketHiddenStrategyMinReasons,
			LimitClassDigestTruncatedReasonBucketHiddenStrategyMinItems:         profile.LimitClassDigestTruncatedReasonBucketHiddenStrategyMinItems,
			LimitClassDigestTruncatedReasonBucketExactSeverityPolicyPresetChain: profile.LimitClassDigestTruncatedReasonBucketExactSeverityPolicyPresetChain,
			LimitClassDigestTruncatedReasonBucketExactSeverityPolicyPreset:      profile.LimitClassDigestTruncatedReasonBucketExactSeverityPolicyPreset,
			LimitClassDigestTruncatedReasonBucketExactSeverityPolicy:            profile.LimitClassDigestTruncatedReasonBucketExactSeverityPolicy,
			LimitClassDigestTruncatedReasonBucketExactSeverityPriorityCap:       profile.LimitClassDigestTruncatedReasonBucketExactSeverityPriorityCap,
			LimitClassDigestTruncatedReasonBucketExactSeverityReasonCap:         profile.LimitClassDigestTruncatedReasonBucketExactSeverityReasonCap,
			LimitClassDigestTruncatedReasonBucketExactSeverityItemCap:           profile.LimitClassDigestTruncatedReasonBucketExactSeverityItemCap,
			LimitClassDigestTruncatedReasonBucketExactSeverityPriorityWeight:    profile.LimitClassDigestTruncatedReasonBucketExactSeverityPriorityWeight,
			LimitClassDigestTruncatedReasonBucketExactSeverityReasonWeight:      profile.LimitClassDigestTruncatedReasonBucketExactSeverityReasonWeight,
			LimitClassDigestTruncatedReasonBucketExactSeverityItemWeight:        profile.LimitClassDigestTruncatedReasonBucketExactSeverityItemWeight,
			LimitClassDigestTruncatedReasonBucketExactSeverityDominantMode:      profile.LimitClassDigestTruncatedReasonBucketExactSeverityDominantMode,
			LimitClassDigestTruncatedReasonBucketExactSeverityMinReasons:        profile.LimitClassDigestTruncatedReasonBucketExactSeverityMinReasons,
			LimitClassDigestTruncatedReasonBucketExactSeverityMinItems:          profile.LimitClassDigestTruncatedReasonBucketExactSeverityMinItems,
			LimitClassDigestTruncatedReasonBucketMinSeverityPolicyPresetChain:   profile.LimitClassDigestTruncatedReasonBucketMinSeverityPolicyPresetChain,
			LimitClassDigestTruncatedReasonBucketMinSeverityPolicyPreset:        profile.LimitClassDigestTruncatedReasonBucketMinSeverityPolicyPreset,
			LimitClassDigestTruncatedReasonBucketMinSeverityPolicy:              profile.LimitClassDigestTruncatedReasonBucketMinSeverityPolicy,
			LimitClassDigestTruncatedReasonBucketMinSeverityPriorityCap:         profile.LimitClassDigestTruncatedReasonBucketMinSeverityPriorityCap,
			LimitClassDigestTruncatedReasonBucketMinSeverityReasonCap:           profile.LimitClassDigestTruncatedReasonBucketMinSeverityReasonCap,
			LimitClassDigestTruncatedReasonBucketMinSeverityItemCap:             profile.LimitClassDigestTruncatedReasonBucketMinSeverityItemCap,
			LimitClassDigestTruncatedReasonBucketMinSeverityPriorityWeight:      profile.LimitClassDigestTruncatedReasonBucketMinSeverityPriorityWeight,
			LimitClassDigestTruncatedReasonBucketMinSeverityReasonWeight:        profile.LimitClassDigestTruncatedReasonBucketMinSeverityReasonWeight,
			LimitClassDigestTruncatedReasonBucketMinSeverityItemWeight:          profile.LimitClassDigestTruncatedReasonBucketMinSeverityItemWeight,
			LimitClassDigestTruncatedReasonBucketMinSeverityDominantMode:        profile.LimitClassDigestTruncatedReasonBucketMinSeverityDominantMode,
			LimitClassDigestTruncatedReasonBucketMinSeverityMinReasons:          profile.LimitClassDigestTruncatedReasonBucketMinSeverityMinReasons,
			LimitClassDigestTruncatedReasonBucketMinSeverityMinItems:            profile.LimitClassDigestTruncatedReasonBucketMinSeverityMinItems,
			LimitClassDigestTruncatedReasonBucketMaxReasonsPolicyPresetChain:    profile.LimitClassDigestTruncatedReasonBucketMaxReasonsPolicyPresetChain,
			LimitClassDigestTruncatedReasonBucketMaxReasonsPolicyPreset:         profile.LimitClassDigestTruncatedReasonBucketMaxReasonsPolicyPreset,
			LimitClassDigestTruncatedReasonBucketMaxReasonsPolicy:               profile.LimitClassDigestTruncatedReasonBucketMaxReasonsPolicy,
			LimitClassDigestTruncatedReasonBucketMaxReasonsPriorityCap:          profile.LimitClassDigestTruncatedReasonBucketMaxReasonsPriorityCap,
			LimitClassDigestTruncatedReasonBucketMaxReasonsReasonCap:            profile.LimitClassDigestTruncatedReasonBucketMaxReasonsReasonCap,
			LimitClassDigestTruncatedReasonBucketMaxReasonsItemCap:              profile.LimitClassDigestTruncatedReasonBucketMaxReasonsItemCap,
			LimitClassDigestTruncatedReasonBucketMaxReasonsPriorityWeight:       profile.LimitClassDigestTruncatedReasonBucketMaxReasonsPriorityWeight,
			LimitClassDigestTruncatedReasonBucketMaxReasonsReasonWeight:         profile.LimitClassDigestTruncatedReasonBucketMaxReasonsReasonWeight,
			LimitClassDigestTruncatedReasonBucketMaxReasonsItemWeight:           profile.LimitClassDigestTruncatedReasonBucketMaxReasonsItemWeight,
			LimitClassDigestTruncatedReasonBucketMaxReasonsDominantMode:         profile.LimitClassDigestTruncatedReasonBucketMaxReasonsDominantMode,
			LimitClassDigestTruncatedReasonBucketMaxReasonsMinReasons:           profile.LimitClassDigestTruncatedReasonBucketMaxReasonsMinReasons,
			LimitClassDigestTruncatedReasonBucketMaxReasonsMinItems:             profile.LimitClassDigestTruncatedReasonBucketMaxReasonsMinItems,
			LimitClassDigestMaxSummaryBucketClasses:                             profile.LimitClassDigestMaxSummaryBucketClasses,
			LimitAlertTypes:                                                     profile.LimitAlertTypes,
			LimitAlertKeyTypes:                                                  profile.LimitAlertKeyTypes,
			LimitAlertBucketClasses:                                             profile.LimitAlertBucketClasses,
			LimitAlertBucketIDRegex:                                             profile.LimitAlertBucketIDRegex,
			LimitAlertCooldown:                                                  profile.LimitAlertCooldown,
			LimitClassSnoozeExpiryCooldown:                                      profile.LimitClassSnoozeExpiryCooldown,
			LimitClassSnoozeExpiryWithin:                                        profile.LimitClassSnoozeExpiryWithin,
			LimitClassSnoozeExpiryStages:                                        profile.LimitClassSnoozeExpiryStages,
			LimitClassSnoozeEventTypes:                                          profile.LimitClassSnoozeEventTypes,
		}, cfg.Security.LimitAlertBucketClasses, cfg.Security.LimitClassDigestHiddenStrategyPolicyPresets); err != nil {
			return err
		}
	}
	for name, profile := range cfg.Security.LimitAlertProfiles {
		profileName := strings.TrimSpace(name)
		if profileName == "" {
			return errors.NewValidationError("security.limitAlertProfiles", "limit alert profiles require a non-empty name")
		}
		if err := validateNotificationWebhookLimitAlertFilters("security.limitAlertProfiles."+profileName, NotificationWebhook{
			MinLimitAlertSeverity:                                               profile.MinLimitAlertSeverity,
			MinLimitAlertBucketClassPriority:                                    profile.MinLimitAlertBucketClassPriority,
			LimitClassDigestTypes:                                               profile.LimitClassDigestTypes,
			LimitClassDigestSummaryOnlyTypes:                                    profile.LimitClassDigestSummaryOnlyTypes,
			LimitClassDigestMinSeverity:                                         profile.LimitClassDigestMinSeverity,
			LimitClassDigestSeverities:                                          profile.LimitClassDigestSeverities,
			LimitClassDigestMinBucketClassPriority:                              profile.LimitClassDigestMinBucketClassPriority,
			LimitClassDigestMaxBucketClasses:                                    profile.LimitClassDigestMaxBucketClasses,
			LimitClassDigestMinSummarySeverity:                                  profile.LimitClassDigestMinSummarySeverity,
			LimitClassDigestMinSummaryBucketClassPriority:                       profile.LimitClassDigestMinSummaryBucketClassPriority,
			LimitClassDigestSummarySortMode:                                     profile.LimitClassDigestSummarySortMode,
			LimitClassDigestMinSummaryCount:                                     profile.LimitClassDigestMinSummaryCount,
			LimitClassDigestOtherBucketLabel:                                    profile.LimitClassDigestOtherBucketLabel,
			LimitClassDigestOverflowReasons:                                     profile.LimitClassDigestOverflowReasons,
			LimitClassDigestOverflowReasonLabels:                                profile.LimitClassDigestOverflowReasonLabels,
			LimitClassDigestOverflowReasonGroups:                                profile.LimitClassDigestOverflowReasonGroups,
			LimitClassDigestOverflowReasonOrder:                                 profile.LimitClassDigestOverflowReasonOrder,
			LimitClassDigestMaxOverflowReasons:                                  profile.LimitClassDigestMaxOverflowReasons,
			LimitClassDigestTruncatedReasonBucketLabel:                          profile.LimitClassDigestTruncatedReasonBucketLabel,
			LimitClassDigestTruncatedReasonBucketMode:                           profile.LimitClassDigestTruncatedReasonBucketMode,
			LimitClassDigestTruncatedReasonBucketMaxReasons:                     profile.LimitClassDigestTruncatedReasonBucketMaxReasons,
			LimitClassDigestTruncatedReasonBucketReasonOrder:                    profile.LimitClassDigestTruncatedReasonBucketReasonOrder,
			LimitClassDigestTruncatedReasonBucketMinSeverity:                    profile.LimitClassDigestTruncatedReasonBucketMinSeverity,
			LimitClassDigestTruncatedReasonBucketSeverities:                     profile.LimitClassDigestTruncatedReasonBucketSeverities,
			LimitClassDigestTruncatedReasonBucketSortMode:                       profile.LimitClassDigestTruncatedReasonBucketSortMode,
			LimitClassDigestTruncatedReasonBucketDominantReasonStrategy:         profile.LimitClassDigestTruncatedReasonBucketDominantReasonStrategy,
			LimitClassDigestTruncatedReasonBucketHiddenStrategyOrder:            profile.LimitClassDigestTruncatedReasonBucketHiddenStrategyOrder,
			LimitClassDigestTruncatedReasonBucketHiddenStrategyDominantMode:     profile.LimitClassDigestTruncatedReasonBucketHiddenStrategyDominantMode,
			LimitClassDigestTruncatedReasonBucketHiddenStrategyPriorityWeight:   profile.LimitClassDigestTruncatedReasonBucketHiddenStrategyPriorityWeight,
			LimitClassDigestTruncatedReasonBucketHiddenStrategyReasonWeight:     profile.LimitClassDigestTruncatedReasonBucketHiddenStrategyReasonWeight,
			LimitClassDigestTruncatedReasonBucketHiddenStrategyItemWeight:       profile.LimitClassDigestTruncatedReasonBucketHiddenStrategyItemWeight,
			LimitClassDigestTruncatedReasonBucketHiddenStrategyPriorityCap:      profile.LimitClassDigestTruncatedReasonBucketHiddenStrategyPriorityCap,
			LimitClassDigestTruncatedReasonBucketHiddenStrategyReasonCap:        profile.LimitClassDigestTruncatedReasonBucketHiddenStrategyReasonCap,
			LimitClassDigestTruncatedReasonBucketHiddenStrategyItemCap:          profile.LimitClassDigestTruncatedReasonBucketHiddenStrategyItemCap,
			LimitClassDigestTruncatedReasonBucketHiddenStrategyMinReasons:       profile.LimitClassDigestTruncatedReasonBucketHiddenStrategyMinReasons,
			LimitClassDigestTruncatedReasonBucketHiddenStrategyMinItems:         profile.LimitClassDigestTruncatedReasonBucketHiddenStrategyMinItems,
			LimitClassDigestTruncatedReasonBucketExactSeverityPolicyPresetChain: profile.LimitClassDigestTruncatedReasonBucketExactSeverityPolicyPresetChain,
			LimitClassDigestTruncatedReasonBucketExactSeverityPolicyPreset:      profile.LimitClassDigestTruncatedReasonBucketExactSeverityPolicyPreset,
			LimitClassDigestTruncatedReasonBucketExactSeverityPolicy:            profile.LimitClassDigestTruncatedReasonBucketExactSeverityPolicy,
			LimitClassDigestTruncatedReasonBucketExactSeverityPriorityCap:       profile.LimitClassDigestTruncatedReasonBucketExactSeverityPriorityCap,
			LimitClassDigestTruncatedReasonBucketExactSeverityReasonCap:         profile.LimitClassDigestTruncatedReasonBucketExactSeverityReasonCap,
			LimitClassDigestTruncatedReasonBucketExactSeverityItemCap:           profile.LimitClassDigestTruncatedReasonBucketExactSeverityItemCap,
			LimitClassDigestTruncatedReasonBucketExactSeverityPriorityWeight:    profile.LimitClassDigestTruncatedReasonBucketExactSeverityPriorityWeight,
			LimitClassDigestTruncatedReasonBucketExactSeverityReasonWeight:      profile.LimitClassDigestTruncatedReasonBucketExactSeverityReasonWeight,
			LimitClassDigestTruncatedReasonBucketExactSeverityItemWeight:        profile.LimitClassDigestTruncatedReasonBucketExactSeverityItemWeight,
			LimitClassDigestTruncatedReasonBucketExactSeverityDominantMode:      profile.LimitClassDigestTruncatedReasonBucketExactSeverityDominantMode,
			LimitClassDigestTruncatedReasonBucketExactSeverityMinReasons:        profile.LimitClassDigestTruncatedReasonBucketExactSeverityMinReasons,
			LimitClassDigestTruncatedReasonBucketExactSeverityMinItems:          profile.LimitClassDigestTruncatedReasonBucketExactSeverityMinItems,
			LimitClassDigestTruncatedReasonBucketMinSeverityPolicyPresetChain:   profile.LimitClassDigestTruncatedReasonBucketMinSeverityPolicyPresetChain,
			LimitClassDigestTruncatedReasonBucketMinSeverityPolicyPreset:        profile.LimitClassDigestTruncatedReasonBucketMinSeverityPolicyPreset,
			LimitClassDigestTruncatedReasonBucketMinSeverityPolicy:              profile.LimitClassDigestTruncatedReasonBucketMinSeverityPolicy,
			LimitClassDigestTruncatedReasonBucketMinSeverityPriorityCap:         profile.LimitClassDigestTruncatedReasonBucketMinSeverityPriorityCap,
			LimitClassDigestTruncatedReasonBucketMinSeverityReasonCap:           profile.LimitClassDigestTruncatedReasonBucketMinSeverityReasonCap,
			LimitClassDigestTruncatedReasonBucketMinSeverityItemCap:             profile.LimitClassDigestTruncatedReasonBucketMinSeverityItemCap,
			LimitClassDigestTruncatedReasonBucketMinSeverityPriorityWeight:      profile.LimitClassDigestTruncatedReasonBucketMinSeverityPriorityWeight,
			LimitClassDigestTruncatedReasonBucketMinSeverityReasonWeight:        profile.LimitClassDigestTruncatedReasonBucketMinSeverityReasonWeight,
			LimitClassDigestTruncatedReasonBucketMinSeverityItemWeight:          profile.LimitClassDigestTruncatedReasonBucketMinSeverityItemWeight,
			LimitClassDigestTruncatedReasonBucketMinSeverityDominantMode:        profile.LimitClassDigestTruncatedReasonBucketMinSeverityDominantMode,
			LimitClassDigestTruncatedReasonBucketMinSeverityMinReasons:          profile.LimitClassDigestTruncatedReasonBucketMinSeverityMinReasons,
			LimitClassDigestTruncatedReasonBucketMinSeverityMinItems:            profile.LimitClassDigestTruncatedReasonBucketMinSeverityMinItems,
			LimitClassDigestTruncatedReasonBucketMaxReasonsPolicyPresetChain:    profile.LimitClassDigestTruncatedReasonBucketMaxReasonsPolicyPresetChain,
			LimitClassDigestTruncatedReasonBucketMaxReasonsPolicyPreset:         profile.LimitClassDigestTruncatedReasonBucketMaxReasonsPolicyPreset,
			LimitClassDigestTruncatedReasonBucketMaxReasonsPolicy:               profile.LimitClassDigestTruncatedReasonBucketMaxReasonsPolicy,
			LimitClassDigestTruncatedReasonBucketMaxReasonsPriorityCap:          profile.LimitClassDigestTruncatedReasonBucketMaxReasonsPriorityCap,
			LimitClassDigestTruncatedReasonBucketMaxReasonsReasonCap:            profile.LimitClassDigestTruncatedReasonBucketMaxReasonsReasonCap,
			LimitClassDigestTruncatedReasonBucketMaxReasonsItemCap:              profile.LimitClassDigestTruncatedReasonBucketMaxReasonsItemCap,
			LimitClassDigestTruncatedReasonBucketMaxReasonsPriorityWeight:       profile.LimitClassDigestTruncatedReasonBucketMaxReasonsPriorityWeight,
			LimitClassDigestTruncatedReasonBucketMaxReasonsReasonWeight:         profile.LimitClassDigestTruncatedReasonBucketMaxReasonsReasonWeight,
			LimitClassDigestTruncatedReasonBucketMaxReasonsItemWeight:           profile.LimitClassDigestTruncatedReasonBucketMaxReasonsItemWeight,
			LimitClassDigestTruncatedReasonBucketMaxReasonsDominantMode:         profile.LimitClassDigestTruncatedReasonBucketMaxReasonsDominantMode,
			LimitClassDigestTruncatedReasonBucketMaxReasonsMinReasons:           profile.LimitClassDigestTruncatedReasonBucketMaxReasonsMinReasons,
			LimitClassDigestTruncatedReasonBucketMaxReasonsMinItems:             profile.LimitClassDigestTruncatedReasonBucketMaxReasonsMinItems,
			LimitClassDigestMaxSummaryBucketClasses:                             profile.LimitClassDigestMaxSummaryBucketClasses,
			LimitAlertTypes:                                                     profile.LimitAlertTypes,
			LimitAlertKeyTypes:                                                  profile.LimitAlertKeyTypes,
			LimitAlertBucketClasses:                                             profile.LimitAlertBucketClasses,
			LimitAlertBucketIDRegex:                                             profile.LimitAlertBucketIDRegex,
			LimitAlertCooldown:                                                  profile.LimitAlertCooldown,
			LimitClassSnoozeExpiryCooldown:                                      profile.LimitClassSnoozeExpiryCooldown,
			LimitClassSnoozeExpiryWithin:                                        profile.LimitClassSnoozeExpiryWithin,
			LimitClassSnoozeExpiryStages:                                        profile.LimitClassSnoozeExpiryStages,
			LimitClassSnoozeEventTypes:                                          profile.LimitClassSnoozeEventTypes,
		}, cfg.Security.LimitAlertBucketClasses, cfg.Security.LimitClassDigestHiddenStrategyPolicyPresets); err != nil {
			return err
		}
	}
	for name, bundle := range cfg.Security.LimitClassDigestExplainBundles {
		bundleName := strings.TrimSpace(name)
		if bundleName == "" {
			return errors.NewValidationError("security.limitClassDigestExplainBundles", "limit class digest explain bundles require a non-empty name")
		}
		if len(bundle.Fields) == 0 {
			return errors.NewValidationError("security.limitClassDigestExplainBundles."+bundleName+".fields", "limit class digest explain bundles require at least one field")
		}
		for _, field := range bundle.Fields {
			if strings.TrimSpace(field) == "" {
				return errors.NewValidationError("security.limitClassDigestExplainBundles."+bundleName+".fields", "limit class digest explain bundle fields must not be empty")
			}
		}
	}
	for name, bundle := range cfg.Security.LimitClassDigestAssertionExplainBundles {
		bundleName := strings.TrimSpace(name)
		if bundleName == "" {
			return errors.NewValidationError("security.limitClassDigestAssertionExplainBundles", "limit class digest assertion explain bundles require a non-empty name")
		}
		if len(bundle.Kinds) == 0 {
			return errors.NewValidationError("security.limitClassDigestAssertionExplainBundles."+bundleName+".kinds", "limit class digest assertion explain bundles require at least one kind")
		}
		for _, kind := range bundle.Kinds {
			resolvedKind := strings.ToLower(strings.TrimSpace(kind))
			if resolvedKind == "" {
				return errors.NewValidationError("security.limitClassDigestAssertionExplainBundles."+bundleName+".kinds", "limit class digest assertion explain bundle kinds must not be empty")
			}
			if resolvedKind != "rules" && resolvedKind != "groups" {
				return errors.NewValidationError("security.limitClassDigestAssertionExplainBundles."+bundleName+".kinds", "limit class digest assertion explain bundle kinds must be rules or groups")
			}
		}
	}
	for name, bundle := range cfg.Security.LimitClassDigestAssertionGroupPresetExplainBundles {
		bundleName := strings.TrimSpace(name)
		if bundleName == "" {
			return errors.NewValidationError("security.limitClassDigestAssertionGroupPresetExplainBundles", "limit class digest assertion group preset explain bundles require a non-empty name")
		}
		if len(bundle.Presets) == 0 {
			return errors.NewValidationError("security.limitClassDigestAssertionGroupPresetExplainBundles."+bundleName+".presets", "limit class digest assertion group preset explain bundles require at least one preset")
		}
		for _, presetName := range bundle.Presets {
			resolvedName := strings.TrimSpace(presetName)
			if resolvedName == "" {
				return errors.NewValidationError("security.limitClassDigestAssertionGroupPresetExplainBundles."+bundleName+".presets", "limit class digest assertion group preset explain bundle presets must not be empty")
			}
			if _, ok := cfg.Security.LimitClassDigestAssertionGroupPresets[resolvedName]; !ok {
				return errors.NewValidationError("security.limitClassDigestAssertionGroupPresetExplainBundles."+bundleName+".presets", "limit class digest assertion group preset explain bundle presets must reference defined security.limitClassDigestAssertionGroupPresets entries")
			}
		}
	}
	for name, preset := range cfg.Security.LimitClassDigestAssertionGroupPresets {
		presetName := strings.TrimSpace(name)
		if presetName == "" {
			return errors.NewValidationError("security.limitClassDigestAssertionGroupPresets", "limit class digest assertion group presets require a non-empty name")
		}
		if err := validateLimitClassDigestAssertionGroupPreset("security.limitClassDigestAssertionGroupPresets."+presetName, preset, cfg.Security.LimitClassDigestAssertionGroupPresets); err != nil {
			return err
		}
	}
	for name, profile := range cfg.Security.LimitClassDigestAssertionExplainDiffProfiles {
		profileName := strings.TrimSpace(name)
		if profileName == "" {
			return errors.NewValidationError("security.limitClassDigestAssertionExplainDiffProfiles", "limit class digest assertion explain diff profiles require a non-empty name")
		}
		for _, bundleName := range profile.Bundles {
			resolvedName := strings.TrimSpace(bundleName)
			if resolvedName == "" {
				return errors.NewValidationError("security.limitClassDigestAssertionExplainDiffProfiles."+profileName+".bundles", "limit class digest assertion explain diff profile bundles must not contain empty values")
			}
			if _, ok := cfg.Security.LimitClassDigestAssertionExplainBundles[resolvedName]; !ok {
				return errors.NewValidationError("security.limitClassDigestAssertionExplainDiffProfiles."+profileName+".bundles", "limit class digest assertion explain diff profile bundles must reference defined security.limitClassDigestAssertionExplainBundles entries")
			}
		}
		for _, kind := range profile.Kinds {
			resolvedKind := strings.ToLower(strings.TrimSpace(kind))
			if resolvedKind == "" {
				return errors.NewValidationError("security.limitClassDigestAssertionExplainDiffProfiles."+profileName+".kinds", "limit class digest assertion explain diff profile kinds must not contain empty values")
			}
			if resolvedKind != "rules" && resolvedKind != "groups" {
				return errors.NewValidationError("security.limitClassDigestAssertionExplainDiffProfiles."+profileName+".kinds", "limit class digest assertion explain diff profile kinds must be rules or groups")
			}
		}
		for _, kind := range profile.AllowedChangedKinds {
			resolvedKind := strings.ToLower(strings.TrimSpace(kind))
			if resolvedKind == "" {
				return errors.NewValidationError("security.limitClassDigestAssertionExplainDiffProfiles."+profileName+".allowedChangedKinds", "limit class digest assertion explain diff profile allowedChangedKinds must not contain empty values")
			}
			if resolvedKind != "rules" && resolvedKind != "groups" {
				return errors.NewValidationError("security.limitClassDigestAssertionExplainDiffProfiles."+profileName+".allowedChangedKinds", "limit class digest assertion explain diff profile allowedChangedKinds must be rules or groups")
			}
		}
		for field := range profile.ExpectedFromValues {
			resolvedField := strings.ToLower(strings.TrimSpace(field))
			if resolvedField == "" {
				return errors.NewValidationError("security.limitClassDigestAssertionExplainDiffProfiles."+profileName+".expectedFromValues", "limit class digest assertion explain diff profile expectedFromValues must not contain empty kind names")
			}
			if resolvedField != "rules" && resolvedField != "groups" {
				return errors.NewValidationError("security.limitClassDigestAssertionExplainDiffProfiles."+profileName+".expectedFromValues", "limit class digest assertion explain diff profile expectedFromValues must use rules or groups as keys")
			}
		}
		for field := range profile.ExpectedToValues {
			resolvedField := strings.ToLower(strings.TrimSpace(field))
			if resolvedField == "" {
				return errors.NewValidationError("security.limitClassDigestAssertionExplainDiffProfiles."+profileName+".expectedToValues", "limit class digest assertion explain diff profile expectedToValues must not contain empty kind names")
			}
			if resolvedField != "rules" && resolvedField != "groups" {
				return errors.NewValidationError("security.limitClassDigestAssertionExplainDiffProfiles."+profileName+".expectedToValues", "limit class digest assertion explain diff profile expectedToValues must use rules or groups as keys")
			}
		}
		for field := range profile.AssertFromRules {
			resolvedField := strings.ToLower(strings.TrimSpace(field))
			if resolvedField == "" {
				return errors.NewValidationError("security.limitClassDigestAssertionExplainDiffProfiles."+profileName+".assertFromRules", "limit class digest assertion explain diff profile assertFromRules must not contain empty kind names")
			}
			if resolvedField != "rules" && resolvedField != "groups" {
				return errors.NewValidationError("security.limitClassDigestAssertionExplainDiffProfiles."+profileName+".assertFromRules", "limit class digest assertion explain diff profile assertFromRules must use rules or groups as keys")
			}
		}
		for field := range profile.AssertToRules {
			resolvedField := strings.ToLower(strings.TrimSpace(field))
			if resolvedField == "" {
				return errors.NewValidationError("security.limitClassDigestAssertionExplainDiffProfiles."+profileName+".assertToRules", "limit class digest assertion explain diff profile assertToRules must not contain empty kind names")
			}
			if resolvedField != "rules" && resolvedField != "groups" {
				return errors.NewValidationError("security.limitClassDigestAssertionExplainDiffProfiles."+profileName+".assertToRules", "limit class digest assertion explain diff profile assertToRules must use rules or groups as keys")
			}
		}
		for field := range profile.AssertFromGroups {
			resolvedField := strings.ToLower(strings.TrimSpace(field))
			if resolvedField == "" {
				return errors.NewValidationError("security.limitClassDigestAssertionExplainDiffProfiles."+profileName+".assertFromGroups", "limit class digest assertion explain diff profile assertFromGroups must not contain empty kind names")
			}
			if resolvedField != "rules" && resolvedField != "groups" {
				return errors.NewValidationError("security.limitClassDigestAssertionExplainDiffProfiles."+profileName+".assertFromGroups", "limit class digest assertion explain diff profile assertFromGroups must use rules or groups as keys")
			}
		}
		for field := range profile.AssertToGroups {
			resolvedField := strings.ToLower(strings.TrimSpace(field))
			if resolvedField == "" {
				return errors.NewValidationError("security.limitClassDigestAssertionExplainDiffProfiles."+profileName+".assertToGroups", "limit class digest assertion explain diff profile assertToGroups must not contain empty kind names")
			}
			if resolvedField != "rules" && resolvedField != "groups" {
				return errors.NewValidationError("security.limitClassDigestAssertionExplainDiffProfiles."+profileName+".assertToGroups", "limit class digest assertion explain diff profile assertToGroups must use rules or groups as keys")
			}
		}
		for field := range profile.AssertFromGroupPresets {
			resolvedField := strings.ToLower(strings.TrimSpace(field))
			if resolvedField == "" {
				return errors.NewValidationError("security.limitClassDigestAssertionExplainDiffProfiles."+profileName+".assertFromGroupPresets", "limit class digest assertion explain diff profile assertFromGroupPresets must not contain empty kind names")
			}
			if resolvedField != "rules" && resolvedField != "groups" {
				return errors.NewValidationError("security.limitClassDigestAssertionExplainDiffProfiles."+profileName+".assertFromGroupPresets", "limit class digest assertion explain diff profile assertFromGroupPresets must use rules or groups as keys")
			}
		}
		for field := range profile.AssertToGroupPresets {
			resolvedField := strings.ToLower(strings.TrimSpace(field))
			if resolvedField == "" {
				return errors.NewValidationError("security.limitClassDigestAssertionExplainDiffProfiles."+profileName+".assertToGroupPresets", "limit class digest assertion explain diff profile assertToGroupPresets must not contain empty kind names")
			}
			if resolvedField != "rules" && resolvedField != "groups" {
				return errors.NewValidationError("security.limitClassDigestAssertionExplainDiffProfiles."+profileName+".assertToGroupPresets", "limit class digest assertion explain diff profile assertToGroupPresets must use rules or groups as keys")
			}
		}
		if err := validateLimitClassDigestAssertionGroupPresetRefs("security.limitClassDigestAssertionExplainDiffProfiles."+profileName+".assertFromGroupPresets", profile.AssertFromGroupPresets, cfg.Security.LimitClassDigestAssertionGroupPresets); err != nil {
			return err
		}
		if err := validateLimitClassDigestAssertionGroupPresetRefs("security.limitClassDigestAssertionExplainDiffProfiles."+profileName+".assertToGroupPresets", profile.AssertToGroupPresets, cfg.Security.LimitClassDigestAssertionGroupPresets); err != nil {
			return err
		}
		if err := validateLimitClassDigestExplainAssertionRules("security.limitClassDigestAssertionExplainDiffProfiles."+profileName+".assertFromRules", profile.AssertFromRules); err != nil {
			return err
		}
		if err := validateLimitClassDigestExplainAssertionRules("security.limitClassDigestAssertionExplainDiffProfiles."+profileName+".assertToRules", profile.AssertToRules); err != nil {
			return err
		}
		if err := validateLimitClassDigestExplainAssertionGroups("security.limitClassDigestAssertionExplainDiffProfiles."+profileName+".assertFromGroups", profile.AssertFromGroups); err != nil {
			return err
		}
		if err := validateLimitClassDigestExplainAssertionGroups("security.limitClassDigestAssertionExplainDiffProfiles."+profileName+".assertToGroups", profile.AssertToGroups); err != nil {
			return err
		}
	}
	for name, profile := range cfg.Security.LimitClassDigestExplainDiffProfiles {
		profileName := strings.TrimSpace(name)
		if profileName == "" {
			return errors.NewValidationError("security.limitClassDigestExplainDiffProfiles", "limit class digest explain diff profiles require a non-empty name")
		}
		if strings.TrimSpace(profile.FromRole) == "" != (strings.TrimSpace(profile.ToRole) == "") {
			return errors.NewValidationError("security.limitClassDigestExplainDiffProfiles."+profileName, "limit class digest explain diff profiles must define both fromRole and toRole together")
		}
		for _, bundleName := range profile.Bundles {
			resolvedName := strings.TrimSpace(bundleName)
			if resolvedName == "" {
				return errors.NewValidationError("security.limitClassDigestExplainDiffProfiles."+profileName+".bundles", "limit class digest explain diff profile bundles must not contain empty values")
			}
			if _, ok := cfg.Security.LimitClassDigestExplainBundles[resolvedName]; !ok {
				return errors.NewValidationError("security.limitClassDigestExplainDiffProfiles."+profileName+".bundles", "limit class digest explain diff profile bundles must reference defined security.limitClassDigestExplainBundles entries")
			}
		}
		for _, field := range profile.Fields {
			if strings.TrimSpace(field) == "" {
				return errors.NewValidationError("security.limitClassDigestExplainDiffProfiles."+profileName+".fields", "limit class digest explain diff profile fields must not contain empty values")
			}
		}
		for _, field := range profile.AllowedChangedFields {
			if strings.TrimSpace(field) == "" {
				return errors.NewValidationError("security.limitClassDigestExplainDiffProfiles."+profileName+".allowedChangedFields", "limit class digest explain diff profile allowedChangedFields must not contain empty values")
			}
		}
		for field := range profile.ExpectedFromValues {
			if strings.TrimSpace(field) == "" {
				return errors.NewValidationError("security.limitClassDigestExplainDiffProfiles."+profileName+".expectedFromValues", "limit class digest explain diff profile expectedFromValues must not contain empty field names")
			}
		}
		for field := range profile.ExpectedToValues {
			if strings.TrimSpace(field) == "" {
				return errors.NewValidationError("security.limitClassDigestExplainDiffProfiles."+profileName+".expectedToValues", "limit class digest explain diff profile expectedToValues must not contain empty field names")
			}
		}
		if err := validateLimitClassDigestAssertionPresetRefs("security.limitClassDigestExplainDiffProfiles."+profileName+".assertFromPresets", profile.AssertFromPresets, cfg.Security.LimitClassDigestAssertionPresets); err != nil {
			return err
		}
		if err := validateLimitClassDigestAssertionPresetRefs("security.limitClassDigestExplainDiffProfiles."+profileName+".assertToPresets", profile.AssertToPresets, cfg.Security.LimitClassDigestAssertionPresets); err != nil {
			return err
		}
		if err := validateLimitClassDigestExplainAssertionRules("security.limitClassDigestExplainDiffProfiles."+profileName+".assertFromRules", profile.AssertFromRules); err != nil {
			return err
		}
		if err := validateLimitClassDigestExplainAssertionRules("security.limitClassDigestExplainDiffProfiles."+profileName+".assertToRules", profile.AssertToRules); err != nil {
			return err
		}
		if err := validateLimitClassDigestExplainAssertionGroups("security.limitClassDigestExplainDiffProfiles."+profileName+".assertFromGroups", profile.AssertFromGroups); err != nil {
			return err
		}
		if err := validateLimitClassDigestExplainAssertionGroups("security.limitClassDigestExplainDiffProfiles."+profileName+".assertToGroups", profile.AssertToGroups); err != nil {
			return err
		}
	}
	for name, preset := range cfg.Security.LimitClassDigestAssertionPresets {
		presetName := strings.TrimSpace(name)
		if presetName == "" {
			return errors.NewValidationError("security.limitClassDigestAssertionPresets", "limit class digest assertion presets require a non-empty name")
		}
		if err := validateLimitClassDigestAssertionPreset("security.limitClassDigestAssertionPresets."+presetName, preset, cfg.Security.LimitClassDigestAssertionPresets); err != nil {
			return err
		}
	}
	for i, webhook := range cfg.Security.NotificationWebhooks {
		if strings.TrimSpace(webhook.URL) == "" {
			return errors.NewValidationError(fmt.Sprintf("security.notificationWebhooks[%d].url", i), "notification webhook url is required")
		}
		parsed, err := url.Parse(strings.TrimSpace(webhook.URL))
		if err != nil || parsed.Scheme == "" || parsed.Host == "" {
			return errors.NewValidationError(fmt.Sprintf("security.notificationWebhooks[%d].url", i), "notification webhook url must be a valid absolute http or https URL")
		}
		scheme := strings.ToLower(strings.TrimSpace(parsed.Scheme))
		if scheme != "http" && scheme != "https" {
			return errors.NewValidationError(fmt.Sprintf("security.notificationWebhooks[%d].url", i), "notification webhook url must use http or https")
		}
		switch strings.ToLower(strings.TrimSpace(webhook.Format)) {
		case "", "generic", "slack", "teams":
		default:
			return errors.NewValidationError(fmt.Sprintf("security.notificationWebhooks[%d].format", i), "notification webhook format must be generic, slack, or teams")
		}
		if strings.TrimSpace(webhook.Timeout) != "" {
			if _, err := time.ParseDuration(strings.TrimSpace(webhook.Timeout)); err != nil {
				return errors.NewValidationError(fmt.Sprintf("security.notificationWebhooks[%d].timeout", i), "notification webhook timeout must use a valid duration format")
			}
		}
		if webhook.RetryCount < 0 {
			return errors.NewValidationError(fmt.Sprintf("security.notificationWebhooks[%d].retryCount", i), "notification webhook retryCount must be zero or greater")
		}
		if webhook.MinSLABreachCount < 0 {
			return errors.NewValidationError(fmt.Sprintf("security.notificationWebhooks[%d].minSLABreachCount", i), "notification webhook minSLABreachCount must be zero or greater")
		}
		if webhook.MinConsecutiveSLABreaches < 0 {
			return errors.NewValidationError(fmt.Sprintf("security.notificationWebhooks[%d].minConsecutiveSLABreaches", i), "notification webhook minConsecutiveSLABreaches must be zero or greater")
		}
		for _, environment := range webhook.Environments {
			if strings.TrimSpace(environment) == "" {
				return errors.NewValidationError(fmt.Sprintf("security.notificationWebhooks[%d].environments", i), "notification webhook environments must not contain empty values")
			}
		}
		if strings.TrimSpace(webhook.MinSLABreachDuration) != "" {
			if _, err := time.ParseDuration(strings.TrimSpace(webhook.MinSLABreachDuration)); err != nil {
				return errors.NewValidationError(fmt.Sprintf("security.notificationWebhooks[%d].minSLABreachDuration", i), "notification webhook minSLABreachDuration must use a valid duration format")
			}
		}
		switch strings.ToLower(strings.TrimSpace(webhook.MinSLABreachTier)) {
		case "", "warning", "elevated", "critical":
		default:
			return errors.NewValidationError(fmt.Sprintf("security.notificationWebhooks[%d].minSLABreachTier", i), "notification webhook minSLABreachTier must be warning, elevated, or critical")
		}
		if strings.TrimSpace(webhook.SLABreachCooldown) != "" {
			if _, err := time.ParseDuration(strings.TrimSpace(webhook.SLABreachCooldown)); err != nil {
				return errors.NewValidationError(fmt.Sprintf("security.notificationWebhooks[%d].slaBreachCooldown", i), "notification webhook slaBreachCooldown must use a valid duration format")
			}
		}
		if strings.TrimSpace(webhook.LimitAlertProfile) != "" {
			if _, ok := cfg.Security.LimitAlertProfiles[strings.TrimSpace(webhook.LimitAlertProfile)]; !ok {
				return errors.NewValidationError(fmt.Sprintf("security.notificationWebhooks[%d].limitAlertProfile", i), "notification webhook limitAlertProfile must reference a defined security.limitAlertProfiles entry")
			}
		}
		for _, profileName := range webhook.LimitClassDigestProfileChain {
			resolvedName := strings.TrimSpace(profileName)
			if resolvedName == "" {
				return errors.NewValidationError(fmt.Sprintf("security.notificationWebhooks[%d].limitClassDigestProfileChain", i), "notification webhook limitClassDigestProfileChain must not contain empty profile names")
			}
			if _, ok := cfg.Security.LimitClassDigestProfiles[resolvedName]; !ok {
				return errors.NewValidationError(fmt.Sprintf("security.notificationWebhooks[%d].limitClassDigestProfileChain", i), "notification webhook limitClassDigestProfileChain must reference defined security.limitClassDigestProfiles entries")
			}
		}
		if strings.TrimSpace(webhook.LimitClassDigestProfile) != "" {
			if _, ok := cfg.Security.LimitClassDigestProfiles[strings.TrimSpace(webhook.LimitClassDigestProfile)]; !ok {
				return errors.NewValidationError(fmt.Sprintf("security.notificationWebhooks[%d].limitClassDigestProfile", i), "notification webhook limitClassDigestProfile must reference a defined security.limitClassDigestProfiles entry")
			}
		}
		if err := validateNotificationWebhookLimitAlertFilters(fmt.Sprintf("security.notificationWebhooks[%d]", i), webhook, cfg.Security.LimitAlertBucketClasses, cfg.Security.LimitClassDigestHiddenStrategyPolicyPresets); err != nil {
			return err
		}
		if strings.TrimSpace(webhook.RetryBackoff) != "" {
			if _, err := time.ParseDuration(strings.TrimSpace(webhook.RetryBackoff)); err != nil {
				return errors.NewValidationError(fmt.Sprintf("security.notificationWebhooks[%d].retryBackoff", i), "notification webhook retryBackoff must use a valid duration format")
			}
		}
		if strings.TrimSpace(webhook.SignatureHeader) != "" && strings.TrimSpace(webhook.SigningSecret) == "" {
			return errors.NewValidationError(fmt.Sprintf("security.notificationWebhooks[%d].signingSecret", i), "signingSecret is required when signatureHeader is configured")
		}
		if strings.TrimSpace(webhook.TimestampHeader) != "" && strings.TrimSpace(webhook.SigningSecret) == "" {
			return errors.NewValidationError(fmt.Sprintf("security.notificationWebhooks[%d].signingSecret", i), "signingSecret is required when timestampHeader is configured")
		}
		for _, event := range webhook.Events {
			if strings.TrimSpace(event) == "" {
				return errors.NewValidationError(fmt.Sprintf("security.notificationWebhooks[%d].events", i), "notification webhook events must not be empty")
			}
		}
	}

	for _, serviceConfig := range cfg.Services {
		for _, service := range serviceConfig.Services {
			for _, route := range service.Routes {
				if route.LimitAlertPolicy == nil {
					continue
				}
				for _, bucketPolicy := range route.LimitAlertPolicy.BucketPolicies {
					if bucketClass := strings.TrimSpace(bucketPolicy.BucketClass); bucketClass != "" {
						if _, ok := cfg.Security.LimitAlertBucketClasses[bucketClass]; !ok {
							return errors.NewValidationError("services.routes.limitAlertPolicy.bucketPolicies.bucketClass", "route limit alert bucketClass must reference a defined security.limitAlertBucketClasses entry")
						}
					}
					if presetName := strings.TrimSpace(bucketPolicy.Preset); presetName != "" {
						if _, ok := cfg.Security.LimiterClassPresets[presetName]; !ok {
							return errors.NewValidationError("services.routes.limitAlertPolicy.bucketPolicies.preset", "route limit alert preset must reference a defined security.limiterClassPresets entry")
						}
					}
				}
			}
		}
	}

	return nil
}

func validateNotificationWebhookLimitAlertFilters(field string, webhook NotificationWebhook, bucketClasses map[string]LimitAlertBucketClassConfig, hiddenStrategyPolicyPresets map[string]LimitClassDigestHiddenStrategyPolicy) error {
	switch strings.ToLower(strings.TrimSpace(webhook.MinLimitAlertSeverity)) {
	case "", "warning", "elevated", "critical":
	default:
		return errors.NewValidationError(field+".minLimitAlertSeverity", "notification webhook minLimitAlertSeverity must be warning, elevated, or critical")
	}
	if webhook.MinLimitAlertBucketClassPriority < 0 {
		return errors.NewValidationError(field+".minLimitAlertBucketClassPriority", "notification webhook minLimitAlertBucketClassPriority must be zero or greater")
	}
	for _, digestType := range webhook.LimitClassDigestTypes {
		switch strings.ToLower(strings.TrimSpace(digestType)) {
		case "alert", "snooze":
		default:
			return errors.NewValidationError(field+".limitClassDigestTypes", "notification webhook limitClassDigestTypes must contain only alert or snooze")
		}
	}
	for _, digestType := range webhook.LimitClassDigestSummaryOnlyTypes {
		switch strings.ToLower(strings.TrimSpace(digestType)) {
		case "alert", "snooze":
		default:
			return errors.NewValidationError(field+".limitClassDigestSummaryOnlyTypes", "notification webhook limitClassDigestSummaryOnlyTypes must contain only alert or snooze")
		}
	}
	switch strings.ToLower(strings.TrimSpace(webhook.LimitClassDigestMinSeverity)) {
	case "", "warning", "elevated", "critical":
	default:
		return errors.NewValidationError(field+".limitClassDigestMinSeverity", "notification webhook limitClassDigestMinSeverity must be warning, elevated, or critical")
	}
	for _, severity := range webhook.LimitClassDigestSeverities {
		switch strings.ToLower(strings.TrimSpace(severity)) {
		case "warning", "elevated", "critical":
		default:
			return errors.NewValidationError(field+".limitClassDigestSeverities", "notification webhook limitClassDigestSeverities must contain only warning, elevated, or critical")
		}
	}
	if webhook.LimitClassDigestMinBucketClassPriority < 0 {
		return errors.NewValidationError(field+".limitClassDigestMinBucketClassPriority", "notification webhook limitClassDigestMinBucketClassPriority must be zero or greater")
	}
	if webhook.LimitClassDigestMaxBucketClasses < 0 {
		return errors.NewValidationError(field+".limitClassDigestMaxBucketClasses", "notification webhook limitClassDigestMaxBucketClasses must be zero or greater")
	}
	switch strings.ToLower(strings.TrimSpace(webhook.LimitClassDigestMinSummarySeverity)) {
	case "", "warning", "elevated", "critical":
	default:
		return errors.NewValidationError(field+".limitClassDigestMinSummarySeverity", "notification webhook limitClassDigestMinSummarySeverity must be warning, elevated, or critical")
	}
	switch strings.ToLower(strings.TrimSpace(webhook.LimitClassDigestSummarySortMode)) {
	case "", "priority_first", "severity_first", "count_first":
	default:
		return errors.NewValidationError(field+".limitClassDigestSummarySortMode", "notification webhook limitClassDigestSummarySortMode must be priority_first, severity_first, or count_first")
	}
	if webhook.LimitClassDigestMinSummaryBucketClassPriority < 0 {
		return errors.NewValidationError(field+".limitClassDigestMinSummaryBucketClassPriority", "notification webhook limitClassDigestMinSummaryBucketClassPriority must be zero or greater")
	}
	if webhook.LimitClassDigestMinSummaryCount < 0 {
		return errors.NewValidationError(field+".limitClassDigestMinSummaryCount", "notification webhook limitClassDigestMinSummaryCount must be zero or greater")
	}
	for _, reason := range webhook.LimitClassDigestOverflowReasons {
		switch strings.ToLower(strings.TrimSpace(reason)) {
		case "low_severity", "low_priority", "low_count", "max_summary_budget":
		default:
			return errors.NewValidationError(field+".limitClassDigestOverflowReasons", "notification webhook limitClassDigestOverflowReasons must contain only low_severity, low_priority, low_count, or max_summary_budget")
		}
	}
	for reason, label := range webhook.LimitClassDigestOverflowReasonLabels {
		switch strings.ToLower(strings.TrimSpace(reason)) {
		case "low_severity", "low_priority", "low_count", "max_summary_budget":
		default:
			return errors.NewValidationError(field+".limitClassDigestOverflowReasonLabels", "notification webhook limitClassDigestOverflowReasonLabels keys must be low_severity, low_priority, low_count, or max_summary_budget")
		}
		if strings.TrimSpace(label) == "" {
			return errors.NewValidationError(field+".limitClassDigestOverflowReasonLabels", "notification webhook limitClassDigestOverflowReasonLabels values must not be empty")
		}
	}
	for groupLabel, reasons := range webhook.LimitClassDigestOverflowReasonGroups {
		if strings.TrimSpace(groupLabel) == "" {
			return errors.NewValidationError(field+".limitClassDigestOverflowReasonGroups", "notification webhook limitClassDigestOverflowReasonGroups labels must not be empty")
		}
		if len(reasons) == 0 {
			return errors.NewValidationError(field+".limitClassDigestOverflowReasonGroups", "notification webhook limitClassDigestOverflowReasonGroups values must include at least one raw reason")
		}
		for _, reason := range reasons {
			switch strings.ToLower(strings.TrimSpace(reason)) {
			case "low_severity", "low_priority", "low_count", "max_summary_budget":
			default:
				return errors.NewValidationError(field+".limitClassDigestOverflowReasonGroups", "notification webhook limitClassDigestOverflowReasonGroups values must contain only low_severity, low_priority, low_count, or max_summary_budget")
			}
		}
	}
	for _, label := range webhook.LimitClassDigestOverflowReasonOrder {
		if strings.TrimSpace(label) == "" {
			return errors.NewValidationError(field+".limitClassDigestOverflowReasonOrder", "notification webhook limitClassDigestOverflowReasonOrder must not contain empty values")
		}
	}
	if webhook.LimitClassDigestMaxOverflowReasons < 0 {
		return errors.NewValidationError(field+".limitClassDigestMaxOverflowReasons", "notification webhook limitClassDigestMaxOverflowReasons must be zero or greater")
	}
	switch strings.ToLower(strings.TrimSpace(webhook.LimitClassDigestTruncatedReasonBucketMode)) {
	case "", "summary", "detailed":
	default:
		return errors.NewValidationError(field+".limitClassDigestTruncatedReasonBucketMode", "notification webhook limitClassDigestTruncatedReasonBucketMode must be summary or detailed")
	}
	switch strings.ToLower(strings.TrimSpace(webhook.LimitClassDigestTruncatedReasonBucketMinSeverity)) {
	case "", "warning", "elevated", "critical":
	default:
		return errors.NewValidationError(field+".limitClassDigestTruncatedReasonBucketMinSeverity", "notification webhook limitClassDigestTruncatedReasonBucketMinSeverity must be warning, elevated, or critical")
	}
	switch strings.ToLower(strings.TrimSpace(webhook.LimitClassDigestTruncatedReasonBucketSortMode)) {
	case "", "custom_order_first", "severity_first", "count_first":
	default:
		return errors.NewValidationError(field+".limitClassDigestTruncatedReasonBucketSortMode", "notification webhook limitClassDigestTruncatedReasonBucketSortMode must be custom_order_first, severity_first, or count_first")
	}
	switch strings.ToLower(strings.TrimSpace(webhook.LimitClassDigestTruncatedReasonBucketDominantReasonStrategy)) {
	case "", "default", "severity_first", "count_first":
	default:
		return errors.NewValidationError(field+".limitClassDigestTruncatedReasonBucketDominantReasonStrategy", "notification webhook limitClassDigestTruncatedReasonBucketDominantReasonStrategy must be default, severity_first, or count_first")
	}
	for _, strategy := range webhook.LimitClassDigestTruncatedReasonBucketHiddenStrategyOrder {
		switch strings.ToLower(strings.TrimSpace(strategy)) {
		case "exact_severity", "min_severity", "max_reasons":
		default:
			return errors.NewValidationError(field+".limitClassDigestTruncatedReasonBucketHiddenStrategyOrder", "notification webhook limitClassDigestTruncatedReasonBucketHiddenStrategyOrder must contain only exact_severity, min_severity, or max_reasons")
		}
	}
	switch strings.ToLower(strings.TrimSpace(webhook.LimitClassDigestTruncatedReasonBucketHiddenStrategyDominantMode)) {
	case "", "order_first", "most_hidden_reasons", "most_hidden_items", "weighted_score":
	default:
		return errors.NewValidationError(field+".limitClassDigestTruncatedReasonBucketHiddenStrategyDominantMode", "notification webhook limitClassDigestTruncatedReasonBucketHiddenStrategyDominantMode must be order_first, most_hidden_reasons, most_hidden_items, or weighted_score")
	}
	if err := validateNotificationWebhookHiddenStrategyPolicyPresetChain(field+".limitClassDigestTruncatedReasonBucketExactSeverityPolicyPresetChain", webhook.LimitClassDigestTruncatedReasonBucketExactSeverityPolicyPresetChain, hiddenStrategyPolicyPresets); err != nil {
		return err
	}
	if err := validateNotificationWebhookHiddenStrategyPolicyPreset(field+".limitClassDigestTruncatedReasonBucketExactSeverityPolicyPreset", webhook.LimitClassDigestTruncatedReasonBucketExactSeverityPolicyPreset, hiddenStrategyPolicyPresets); err != nil {
		return err
	}
	if err := validateLimitClassDigestHiddenStrategyPolicy(field+".limitClassDigestTruncatedReasonBucketExactSeverityPolicy", webhook.LimitClassDigestTruncatedReasonBucketExactSeverityPolicy); err != nil {
		return err
	}
	switch strings.ToLower(strings.TrimSpace(webhook.LimitClassDigestTruncatedReasonBucketExactSeverityDominantMode)) {
	case "", "order_first", "most_hidden_reasons", "most_hidden_items", "weighted_score":
	default:
		return errors.NewValidationError(field+".limitClassDigestTruncatedReasonBucketExactSeverityDominantMode", "notification webhook limitClassDigestTruncatedReasonBucketExactSeverityDominantMode must be order_first, most_hidden_reasons, most_hidden_items, or weighted_score")
	}
	switch strings.ToLower(strings.TrimSpace(webhook.LimitClassDigestTruncatedReasonBucketMinSeverityDominantMode)) {
	case "", "order_first", "most_hidden_reasons", "most_hidden_items", "weighted_score":
	default:
		return errors.NewValidationError(field+".limitClassDigestTruncatedReasonBucketMinSeverityDominantMode", "notification webhook limitClassDigestTruncatedReasonBucketMinSeverityDominantMode must be order_first, most_hidden_reasons, most_hidden_items, or weighted_score")
	}
	switch strings.ToLower(strings.TrimSpace(webhook.LimitClassDigestTruncatedReasonBucketMaxReasonsDominantMode)) {
	case "", "order_first", "most_hidden_reasons", "most_hidden_items", "weighted_score":
	default:
		return errors.NewValidationError(field+".limitClassDigestTruncatedReasonBucketMaxReasonsDominantMode", "notification webhook limitClassDigestTruncatedReasonBucketMaxReasonsDominantMode must be order_first, most_hidden_reasons, most_hidden_items, or weighted_score")
	}
	if webhook.LimitClassDigestTruncatedReasonBucketHiddenStrategyPriorityWeight < 0 {
		return errors.NewValidationError(field+".limitClassDigestTruncatedReasonBucketHiddenStrategyPriorityWeight", "notification webhook limitClassDigestTruncatedReasonBucketHiddenStrategyPriorityWeight must be zero or greater")
	}
	if webhook.LimitClassDigestTruncatedReasonBucketHiddenStrategyReasonWeight < 0 {
		return errors.NewValidationError(field+".limitClassDigestTruncatedReasonBucketHiddenStrategyReasonWeight", "notification webhook limitClassDigestTruncatedReasonBucketHiddenStrategyReasonWeight must be zero or greater")
	}
	if webhook.LimitClassDigestTruncatedReasonBucketHiddenStrategyItemWeight < 0 {
		return errors.NewValidationError(field+".limitClassDigestTruncatedReasonBucketHiddenStrategyItemWeight", "notification webhook limitClassDigestTruncatedReasonBucketHiddenStrategyItemWeight must be zero or greater")
	}
	if webhook.LimitClassDigestTruncatedReasonBucketHiddenStrategyPriorityCap < 0 {
		return errors.NewValidationError(field+".limitClassDigestTruncatedReasonBucketHiddenStrategyPriorityCap", "notification webhook limitClassDigestTruncatedReasonBucketHiddenStrategyPriorityCap must be zero or greater")
	}
	if webhook.LimitClassDigestTruncatedReasonBucketHiddenStrategyReasonCap < 0 {
		return errors.NewValidationError(field+".limitClassDigestTruncatedReasonBucketHiddenStrategyReasonCap", "notification webhook limitClassDigestTruncatedReasonBucketHiddenStrategyReasonCap must be zero or greater")
	}
	if webhook.LimitClassDigestTruncatedReasonBucketHiddenStrategyItemCap < 0 {
		return errors.NewValidationError(field+".limitClassDigestTruncatedReasonBucketHiddenStrategyItemCap", "notification webhook limitClassDigestTruncatedReasonBucketHiddenStrategyItemCap must be zero or greater")
	}
	if webhook.LimitClassDigestTruncatedReasonBucketHiddenStrategyMinReasons < 0 {
		return errors.NewValidationError(field+".limitClassDigestTruncatedReasonBucketHiddenStrategyMinReasons", "notification webhook limitClassDigestTruncatedReasonBucketHiddenStrategyMinReasons must be zero or greater")
	}
	if webhook.LimitClassDigestTruncatedReasonBucketHiddenStrategyMinItems < 0 {
		return errors.NewValidationError(field+".limitClassDigestTruncatedReasonBucketHiddenStrategyMinItems", "notification webhook limitClassDigestTruncatedReasonBucketHiddenStrategyMinItems must be zero or greater")
	}
	if webhook.LimitClassDigestTruncatedReasonBucketExactSeverityPriorityCap < 0 {
		return errors.NewValidationError(field+".limitClassDigestTruncatedReasonBucketExactSeverityPriorityCap", "notification webhook limitClassDigestTruncatedReasonBucketExactSeverityPriorityCap must be zero or greater")
	}
	if webhook.LimitClassDigestTruncatedReasonBucketExactSeverityReasonCap < 0 {
		return errors.NewValidationError(field+".limitClassDigestTruncatedReasonBucketExactSeverityReasonCap", "notification webhook limitClassDigestTruncatedReasonBucketExactSeverityReasonCap must be zero or greater")
	}
	if webhook.LimitClassDigestTruncatedReasonBucketExactSeverityItemCap < 0 {
		return errors.NewValidationError(field+".limitClassDigestTruncatedReasonBucketExactSeverityItemCap", "notification webhook limitClassDigestTruncatedReasonBucketExactSeverityItemCap must be zero or greater")
	}
	if webhook.LimitClassDigestTruncatedReasonBucketExactSeverityPriorityWeight < 0 {
		return errors.NewValidationError(field+".limitClassDigestTruncatedReasonBucketExactSeverityPriorityWeight", "notification webhook limitClassDigestTruncatedReasonBucketExactSeverityPriorityWeight must be zero or greater")
	}
	if webhook.LimitClassDigestTruncatedReasonBucketExactSeverityReasonWeight < 0 {
		return errors.NewValidationError(field+".limitClassDigestTruncatedReasonBucketExactSeverityReasonWeight", "notification webhook limitClassDigestTruncatedReasonBucketExactSeverityReasonWeight must be zero or greater")
	}
	if webhook.LimitClassDigestTruncatedReasonBucketExactSeverityItemWeight < 0 {
		return errors.NewValidationError(field+".limitClassDigestTruncatedReasonBucketExactSeverityItemWeight", "notification webhook limitClassDigestTruncatedReasonBucketExactSeverityItemWeight must be zero or greater")
	}
	if webhook.LimitClassDigestTruncatedReasonBucketExactSeverityMinReasons < 0 {
		return errors.NewValidationError(field+".limitClassDigestTruncatedReasonBucketExactSeverityMinReasons", "notification webhook limitClassDigestTruncatedReasonBucketExactSeverityMinReasons must be zero or greater")
	}
	if webhook.LimitClassDigestTruncatedReasonBucketExactSeverityMinItems < 0 {
		return errors.NewValidationError(field+".limitClassDigestTruncatedReasonBucketExactSeverityMinItems", "notification webhook limitClassDigestTruncatedReasonBucketExactSeverityMinItems must be zero or greater")
	}
	if err := validateNotificationWebhookHiddenStrategyPolicyPresetChain(field+".limitClassDigestTruncatedReasonBucketMinSeverityPolicyPresetChain", webhook.LimitClassDigestTruncatedReasonBucketMinSeverityPolicyPresetChain, hiddenStrategyPolicyPresets); err != nil {
		return err
	}
	if err := validateNotificationWebhookHiddenStrategyPolicyPreset(field+".limitClassDigestTruncatedReasonBucketMinSeverityPolicyPreset", webhook.LimitClassDigestTruncatedReasonBucketMinSeverityPolicyPreset, hiddenStrategyPolicyPresets); err != nil {
		return err
	}
	if err := validateLimitClassDigestHiddenStrategyPolicy(field+".limitClassDigestTruncatedReasonBucketMinSeverityPolicy", webhook.LimitClassDigestTruncatedReasonBucketMinSeverityPolicy); err != nil {
		return err
	}
	if webhook.LimitClassDigestTruncatedReasonBucketMinSeverityPriorityCap < 0 {
		return errors.NewValidationError(field+".limitClassDigestTruncatedReasonBucketMinSeverityPriorityCap", "notification webhook limitClassDigestTruncatedReasonBucketMinSeverityPriorityCap must be zero or greater")
	}
	if webhook.LimitClassDigestTruncatedReasonBucketMinSeverityReasonCap < 0 {
		return errors.NewValidationError(field+".limitClassDigestTruncatedReasonBucketMinSeverityReasonCap", "notification webhook limitClassDigestTruncatedReasonBucketMinSeverityReasonCap must be zero or greater")
	}
	if webhook.LimitClassDigestTruncatedReasonBucketMinSeverityItemCap < 0 {
		return errors.NewValidationError(field+".limitClassDigestTruncatedReasonBucketMinSeverityItemCap", "notification webhook limitClassDigestTruncatedReasonBucketMinSeverityItemCap must be zero or greater")
	}
	if webhook.LimitClassDigestTruncatedReasonBucketMinSeverityPriorityWeight < 0 {
		return errors.NewValidationError(field+".limitClassDigestTruncatedReasonBucketMinSeverityPriorityWeight", "notification webhook limitClassDigestTruncatedReasonBucketMinSeverityPriorityWeight must be zero or greater")
	}
	if webhook.LimitClassDigestTruncatedReasonBucketMinSeverityReasonWeight < 0 {
		return errors.NewValidationError(field+".limitClassDigestTruncatedReasonBucketMinSeverityReasonWeight", "notification webhook limitClassDigestTruncatedReasonBucketMinSeverityReasonWeight must be zero or greater")
	}
	if webhook.LimitClassDigestTruncatedReasonBucketMinSeverityItemWeight < 0 {
		return errors.NewValidationError(field+".limitClassDigestTruncatedReasonBucketMinSeverityItemWeight", "notification webhook limitClassDigestTruncatedReasonBucketMinSeverityItemWeight must be zero or greater")
	}
	if webhook.LimitClassDigestTruncatedReasonBucketMinSeverityMinReasons < 0 {
		return errors.NewValidationError(field+".limitClassDigestTruncatedReasonBucketMinSeverityMinReasons", "notification webhook limitClassDigestTruncatedReasonBucketMinSeverityMinReasons must be zero or greater")
	}
	if webhook.LimitClassDigestTruncatedReasonBucketMinSeverityMinItems < 0 {
		return errors.NewValidationError(field+".limitClassDigestTruncatedReasonBucketMinSeverityMinItems", "notification webhook limitClassDigestTruncatedReasonBucketMinSeverityMinItems must be zero or greater")
	}
	if err := validateNotificationWebhookHiddenStrategyPolicyPresetChain(field+".limitClassDigestTruncatedReasonBucketMaxReasonsPolicyPresetChain", webhook.LimitClassDigestTruncatedReasonBucketMaxReasonsPolicyPresetChain, hiddenStrategyPolicyPresets); err != nil {
		return err
	}
	if err := validateNotificationWebhookHiddenStrategyPolicyPreset(field+".limitClassDigestTruncatedReasonBucketMaxReasonsPolicyPreset", webhook.LimitClassDigestTruncatedReasonBucketMaxReasonsPolicyPreset, hiddenStrategyPolicyPresets); err != nil {
		return err
	}
	if err := validateLimitClassDigestHiddenStrategyPolicy(field+".limitClassDigestTruncatedReasonBucketMaxReasonsPolicy", webhook.LimitClassDigestTruncatedReasonBucketMaxReasonsPolicy); err != nil {
		return err
	}
	if webhook.LimitClassDigestTruncatedReasonBucketMaxReasonsPriorityCap < 0 {
		return errors.NewValidationError(field+".limitClassDigestTruncatedReasonBucketMaxReasonsPriorityCap", "notification webhook limitClassDigestTruncatedReasonBucketMaxReasonsPriorityCap must be zero or greater")
	}
	if webhook.LimitClassDigestTruncatedReasonBucketMaxReasonsReasonCap < 0 {
		return errors.NewValidationError(field+".limitClassDigestTruncatedReasonBucketMaxReasonsReasonCap", "notification webhook limitClassDigestTruncatedReasonBucketMaxReasonsReasonCap must be zero or greater")
	}
	if webhook.LimitClassDigestTruncatedReasonBucketMaxReasonsItemCap < 0 {
		return errors.NewValidationError(field+".limitClassDigestTruncatedReasonBucketMaxReasonsItemCap", "notification webhook limitClassDigestTruncatedReasonBucketMaxReasonsItemCap must be zero or greater")
	}
	if webhook.LimitClassDigestTruncatedReasonBucketMaxReasonsPriorityWeight < 0 {
		return errors.NewValidationError(field+".limitClassDigestTruncatedReasonBucketMaxReasonsPriorityWeight", "notification webhook limitClassDigestTruncatedReasonBucketMaxReasonsPriorityWeight must be zero or greater")
	}
	if webhook.LimitClassDigestTruncatedReasonBucketMaxReasonsReasonWeight < 0 {
		return errors.NewValidationError(field+".limitClassDigestTruncatedReasonBucketMaxReasonsReasonWeight", "notification webhook limitClassDigestTruncatedReasonBucketMaxReasonsReasonWeight must be zero or greater")
	}
	if webhook.LimitClassDigestTruncatedReasonBucketMaxReasonsItemWeight < 0 {
		return errors.NewValidationError(field+".limitClassDigestTruncatedReasonBucketMaxReasonsItemWeight", "notification webhook limitClassDigestTruncatedReasonBucketMaxReasonsItemWeight must be zero or greater")
	}
	if webhook.LimitClassDigestTruncatedReasonBucketMaxReasonsMinReasons < 0 {
		return errors.NewValidationError(field+".limitClassDigestTruncatedReasonBucketMaxReasonsMinReasons", "notification webhook limitClassDigestTruncatedReasonBucketMaxReasonsMinReasons must be zero or greater")
	}
	if webhook.LimitClassDigestTruncatedReasonBucketMaxReasonsMinItems < 0 {
		return errors.NewValidationError(field+".limitClassDigestTruncatedReasonBucketMaxReasonsMinItems", "notification webhook limitClassDigestTruncatedReasonBucketMaxReasonsMinItems must be zero or greater")
	}
	for _, severity := range webhook.LimitClassDigestTruncatedReasonBucketSeverities {
		switch strings.ToLower(strings.TrimSpace(severity)) {
		case "warning", "elevated", "critical":
		default:
			return errors.NewValidationError(field+".limitClassDigestTruncatedReasonBucketSeverities", "notification webhook limitClassDigestTruncatedReasonBucketSeverities must contain only warning, elevated, or critical")
		}
	}
	if webhook.LimitClassDigestTruncatedReasonBucketMaxReasons < 0 {
		return errors.NewValidationError(field+".limitClassDigestTruncatedReasonBucketMaxReasons", "notification webhook limitClassDigestTruncatedReasonBucketMaxReasons must be zero or greater")
	}
	for _, label := range webhook.LimitClassDigestTruncatedReasonBucketReasonOrder {
		if strings.TrimSpace(label) == "" {
			return errors.NewValidationError(field+".limitClassDigestTruncatedReasonBucketReasonOrder", "notification webhook limitClassDigestTruncatedReasonBucketReasonOrder must not contain empty values")
		}
	}
	if webhook.LimitClassDigestMaxSummaryBucketClasses < 0 {
		return errors.NewValidationError(field+".limitClassDigestMaxSummaryBucketClasses", "notification webhook limitClassDigestMaxSummaryBucketClasses must be zero or greater")
	}
	for _, limitType := range webhook.LimitAlertTypes {
		switch strings.ToLower(strings.TrimSpace(limitType)) {
		case "", "rate_limit", "concurrency_limit", "concurrency_queued", "concurrency_queue_full":
		default:
			return errors.NewValidationError(field+".limitAlertTypes", "notification webhook limitAlertTypes must contain only rate_limit, concurrency_limit, concurrency_queued, or concurrency_queue_full")
		}
	}
	for _, keyType := range webhook.LimitAlertKeyTypes {
		switch strings.ToLower(strings.TrimSpace(keyType)) {
		case "", "ip", "header", "api_key", "jwt_sub":
		default:
			return errors.NewValidationError(field+".limitAlertKeyTypes", "notification webhook limitAlertKeyTypes must contain only ip, header, api_key, or jwt_sub")
		}
	}
	for _, bucketClass := range webhook.LimitAlertBucketClasses {
		className := strings.TrimSpace(bucketClass)
		if className == "" {
			return errors.NewValidationError(field+".limitAlertBucketClasses", "notification webhook limitAlertBucketClasses must not contain empty values")
		}
		if _, ok := bucketClasses[className]; !ok {
			return errors.NewValidationError(field+".limitAlertBucketClasses", "notification webhook limitAlertBucketClasses must reference defined security.limitAlertBucketClasses entries")
		}
	}
	if strings.TrimSpace(webhook.LimitAlertBucketIDRegex) != "" {
		if _, err := regexp.Compile(strings.TrimSpace(webhook.LimitAlertBucketIDRegex)); err != nil {
			return errors.NewValidationError(field+".limitAlertBucketIDRegex", "notification webhook limitAlertBucketIDRegex must be a valid regex")
		}
	}
	if strings.TrimSpace(webhook.LimitAlertCooldown) != "" {
		if _, err := time.ParseDuration(strings.TrimSpace(webhook.LimitAlertCooldown)); err != nil {
			return errors.NewValidationError(field+".limitAlertCooldown", "notification webhook limitAlertCooldown must use a valid duration format")
		}
	}
	if strings.TrimSpace(webhook.LimitClassSnoozeExpiryCooldown) != "" {
		if _, err := time.ParseDuration(strings.TrimSpace(webhook.LimitClassSnoozeExpiryCooldown)); err != nil {
			return errors.NewValidationError(field+".limitClassSnoozeExpiryCooldown", "notification webhook limitClassSnoozeExpiryCooldown must use a valid duration format")
		}
	}
	if strings.TrimSpace(webhook.LimitClassSnoozeExpiryWithin) != "" {
		parsed, err := time.ParseDuration(strings.TrimSpace(webhook.LimitClassSnoozeExpiryWithin))
		if err != nil || parsed <= 0 {
			return errors.NewValidationError(field+".limitClassSnoozeExpiryWithin", "notification webhook limitClassSnoozeExpiryWithin must use a positive duration format")
		}
	}
	for _, stage := range webhook.LimitClassSnoozeExpiryStages {
		switch strings.ToLower(strings.TrimSpace(stage)) {
		case "warning", "elevated", "critical":
		default:
			return errors.NewValidationError(field+".limitClassSnoozeExpiryStages", "notification webhook limitClassSnoozeExpiryStages must contain only warning, elevated, or critical")
		}
	}
	for _, eventType := range webhook.LimitClassSnoozeEventTypes {
		switch strings.ToLower(strings.TrimSpace(eventType)) {
		case "digest", "expiring", "stage_changed", "resumed":
		default:
			return errors.NewValidationError(field+".limitClassSnoozeEventTypes", "notification webhook limitClassSnoozeEventTypes must contain only digest, expiring, stage_changed, or resumed")
		}
	}
	return nil
}

func validateLimitClassDigestHiddenStrategyPolicy(field string, policy *LimitClassDigestHiddenStrategyPolicy) error {
	if policy == nil {
		return nil
	}
	switch strings.ToLower(strings.TrimSpace(policy.DominantMode)) {
	case "", "order_first", "most_hidden_reasons", "most_hidden_items", "weighted_score":
	default:
		return errors.NewValidationError(field+".dominantMode", "notification webhook hidden strategy policy dominantMode must be order_first, most_hidden_reasons, most_hidden_items, or weighted_score")
	}
	if policy.MinReasons < 0 {
		return errors.NewValidationError(field+".minReasons", "notification webhook hidden strategy policy minReasons must be zero or greater")
	}
	if policy.MinItems < 0 {
		return errors.NewValidationError(field+".minItems", "notification webhook hidden strategy policy minItems must be zero or greater")
	}
	if policy.PriorityWeight < 0 {
		return errors.NewValidationError(field+".priorityWeight", "notification webhook hidden strategy policy priorityWeight must be zero or greater")
	}
	if policy.ReasonWeight < 0 {
		return errors.NewValidationError(field+".reasonWeight", "notification webhook hidden strategy policy reasonWeight must be zero or greater")
	}
	if policy.ItemWeight < 0 {
		return errors.NewValidationError(field+".itemWeight", "notification webhook hidden strategy policy itemWeight must be zero or greater")
	}
	if policy.PriorityCap < 0 {
		return errors.NewValidationError(field+".priorityCap", "notification webhook hidden strategy policy priorityCap must be zero or greater")
	}
	if policy.ReasonCap < 0 {
		return errors.NewValidationError(field+".reasonCap", "notification webhook hidden strategy policy reasonCap must be zero or greater")
	}
	if policy.ItemCap < 0 {
		return errors.NewValidationError(field+".itemCap", "notification webhook hidden strategy policy itemCap must be zero or greater")
	}
	return nil
}

func validateNotificationWebhookHiddenStrategyPolicyPreset(field, presetName string, presets map[string]LimitClassDigestHiddenStrategyPolicy) error {
	presetName = strings.TrimSpace(presetName)
	if presetName == "" {
		return nil
	}
	if _, ok := presets[presetName]; !ok {
		return errors.NewValidationError(field, "notification webhook hidden strategy policy preset must reference a defined security.limitClassDigestHiddenStrategyPolicyPresets entry")
	}
	return nil
}

func validateNotificationWebhookHiddenStrategyPolicyPresetChain(field string, presetChain []string, presets map[string]LimitClassDigestHiddenStrategyPolicy) error {
	for _, presetName := range presetChain {
		resolvedName := strings.TrimSpace(presetName)
		if resolvedName == "" {
			return errors.NewValidationError(field, "notification webhook hidden strategy policy preset chain must not contain empty preset names")
		}
		if _, ok := presets[resolvedName]; !ok {
			return errors.NewValidationError(field, "notification webhook hidden strategy policy preset chain must reference defined security.limitClassDigestHiddenStrategyPolicyPresets entries")
		}
	}
	return nil
}

func validateLimitAlertBucketClassConfig(field string, classConfig LimitAlertBucketClassConfig) error {
	if !IsBucketedLimitKeyType(classConfig.KeyType) {
		return errors.NewValidationError(field+".keyType", "limit alert bucket class keyType must be "+SupportedBucketedLimitKeyTypeValues)
	}
	if strings.TrimSpace(classConfig.BucketRegex) == "" {
		return errors.NewValidationError(field+".bucketRegex", "limit alert bucket class bucketRegex is required")
	}
	if _, err := regexp.Compile(strings.TrimSpace(classConfig.BucketRegex)); err != nil {
		return errors.NewValidationError(field+".bucketRegex", "limit alert bucket class bucketRegex must be a valid regex")
	}
	if classConfig.Priority < 0 {
		return errors.NewValidationError(field+".priority", "limit alert bucket class priority must be zero or greater")
	}
	var elevatedWithin time.Duration
	if strings.TrimSpace(classConfig.SnoozeElevatedWithin) != "" {
		parsed, err := time.ParseDuration(strings.TrimSpace(classConfig.SnoozeElevatedWithin))
		if err != nil || parsed <= 0 {
			return errors.NewValidationError(field+".snoozeElevatedWithin", "limit alert bucket class snoozeElevatedWithin must use a positive duration format")
		}
		elevatedWithin = parsed
	}
	if strings.TrimSpace(classConfig.SnoozeCriticalWithin) != "" {
		parsed, err := time.ParseDuration(strings.TrimSpace(classConfig.SnoozeCriticalWithin))
		if err != nil || parsed <= 0 {
			return errors.NewValidationError(field+".snoozeCriticalWithin", "limit alert bucket class snoozeCriticalWithin must use a positive duration format")
		}
		if elevatedWithin > 0 && parsed > elevatedWithin {
			return errors.NewValidationError(field+".snoozeCriticalWithin", "limit alert bucket class snoozeCriticalWithin must be less than or equal to snoozeElevatedWithin")
		}
	}
	for _, eventType := range classConfig.SnoozeEventTypes {
		switch strings.ToLower(strings.TrimSpace(eventType)) {
		case "expiring", "stage_changed", "resumed":
		default:
			return errors.NewValidationError(field+".snoozeEventTypes", "limit alert bucket class snoozeEventTypes must contain only expiring, stage_changed, or resumed")
		}
	}
	return nil
}

func validateLimiterClassPolicyPreset(field string, preset LimiterClassPolicyPreset, bucketClasses map[string]LimitAlertBucketClassConfig) error {
	if strings.TrimSpace(preset.BucketClass) == "" {
		return errors.NewValidationError(field+".bucketClass", "limiter class preset bucketClass is required")
	}
	classConfig, ok := bucketClasses[strings.TrimSpace(preset.BucketClass)]
	if !ok {
		return errors.NewValidationError(field+".bucketClass", "limiter class preset bucketClass must reference a defined security.limitAlertBucketClasses entry")
	}
	if preset.RateRequestsPerSecond < 0 {
		return errors.NewValidationError(field+".rateRequestsPerSecond", "limiter class preset rateRequestsPerSecond must be zero or greater")
	}
	if preset.RateBurst < 0 {
		return errors.NewValidationError(field+".rateBurst", "limiter class preset rateBurst must be zero or greater")
	}
	if preset.RateRequestsPerSecond == 0 && preset.RateBurst > 0 {
		return errors.NewValidationError(field+".rateRequestsPerSecond", "limiter class preset rateRequestsPerSecond must be positive when rateBurst is set")
	}
	if preset.RateRequestsPerSecond > 0 && preset.RateBurst == 0 {
		return errors.NewValidationError(field+".rateBurst", "limiter class preset rateBurst must be positive when rateRequestsPerSecond is set")
	}
	if preset.ConcurrencyMaxInFlight < 0 {
		return errors.NewValidationError(field+".concurrencyMaxInFlight", "limiter class preset concurrencyMaxInFlight must be zero or greater")
	}
	if preset.ConcurrencyMaxQueueDepth < 0 {
		return errors.NewValidationError(field+".concurrencyMaxQueueDepth", "limiter class preset concurrencyMaxQueueDepth must be zero or greater")
	}
	if err := validateOptionalPositiveDuration(field+".concurrencyQueueTimeout", preset.ConcurrencyQueueTimeout, "limiter class preset concurrencyQueueTimeout must use a valid positive duration format"); err != nil {
		return err
	}
	if preset.AlertMinCount < 0 {
		return errors.NewValidationError(field+".alertMinCount", "limiter class preset alertMinCount must be zero or greater")
	}
	switch strings.ToLower(strings.TrimSpace(preset.AlertMinSeverity)) {
	case "", "warning", "elevated", "critical":
	default:
		return errors.NewValidationError(field+".alertMinSeverity", "limiter class preset alertMinSeverity must be warning, elevated, or critical")
	}
	if err := validateLimitAlertTypePolicies(field+".alertLimitTypePolicies", preset.AlertLimitTypePolicies); err != nil {
		return err
	}
	if !IsBucketedLimitKeyType(classConfig.KeyType) {
		return errors.NewValidationError(field+".bucketClass", "limiter class preset bucketClass must reference a bucketed key type")
	}
	return nil
}

func validateLimitClassDigestExplainAssertionRules(field string, rules map[string][]string) error {
	for name, entries := range rules {
		resolvedName := strings.TrimSpace(name)
		if resolvedName == "" {
			return errors.NewValidationError(field, "limit class digest explain assertion rules must not contain empty field names")
		}
		for _, entry := range entries {
			resolvedEntry := strings.TrimSpace(entry)
			if resolvedEntry == "" {
				return errors.NewValidationError(field+"."+resolvedName, "limit class digest explain assertion rules must not contain empty values")
			}
			if err := validateLimitClassDigestExplainAssertionRule(field+"."+resolvedName, resolvedEntry); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateLimitClassDigestExplainAssertionGroups(field string, groups map[string][]LimitClassDigestAssertionGroup) error {
	for name, entries := range groups {
		resolvedName := strings.TrimSpace(name)
		if resolvedName == "" {
			return errors.NewValidationError(field, "limit class digest explain assertion groups must not contain empty field names")
		}
		for idx, group := range entries {
			if err := validateLimitClassDigestExplainAssertionGroup(fmt.Sprintf("%s.%s[%d]", field, resolvedName, idx), group); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateLimitClassDigestAssertionPreset(field string, preset LimitClassDigestAssertionPreset, presets map[string]LimitClassDigestAssertionPreset) error {
	for _, presetName := range preset.PresetChain {
		resolved := strings.TrimSpace(presetName)
		if resolved == "" {
			return errors.NewValidationError(field+".presetChain", "limit class digest assertion preset chains must not contain empty preset names")
		}
		if _, ok := presets[resolved]; !ok {
			return errors.NewValidationError(field+".presetChain", "limit class digest assertion preset chains must reference defined security.limitClassDigestAssertionPresets entries")
		}
	}
	if len(preset.PresetChain) == 0 && len(preset.Rules) == 0 && len(preset.Groups) == 0 {
		return errors.NewValidationError(field, "limit class digest assertion presets must include at least one presetChain entry, rule, or group")
	}
	for _, rule := range preset.Rules {
		if err := validateLimitClassDigestExplainAssertionRule(field+".rules", strings.TrimSpace(rule)); err != nil {
			return err
		}
	}
	for idx, group := range preset.Groups {
		if err := validateLimitClassDigestExplainAssertionGroup(fmt.Sprintf("%s.groups[%d]", field, idx), group); err != nil {
			return err
		}
	}
	if err := detectLimitClassDigestAssertionPresetCycle(field, strings.TrimPrefix(field, "security.limitClassDigestAssertionPresets."), presets, map[string]bool{}, map[string]bool{}); err != nil {
		return err
	}
	return nil
}

func validateLimitClassDigestAssertionGroupPreset(field string, preset LimitClassDigestAssertionGroupPreset, presets map[string]LimitClassDigestAssertionGroupPreset) error {
	for _, presetName := range preset.PresetChain {
		resolved := strings.TrimSpace(presetName)
		if resolved == "" {
			return errors.NewValidationError(field+".presetChain", "limit class digest assertion group preset chains must not contain empty preset names")
		}
		if _, ok := presets[resolved]; !ok {
			return errors.NewValidationError(field+".presetChain", "limit class digest assertion group preset chains must reference defined security.limitClassDigestAssertionGroupPresets entries")
		}
	}
	if len(preset.PresetChain) == 0 && len(preset.Groups) == 0 {
		return errors.NewValidationError(field, "limit class digest assertion group presets must include at least one presetChain entry or group")
	}
	for idx, group := range preset.Groups {
		if err := validateLimitClassDigestExplainAssertionGroup(fmt.Sprintf("%s.groups[%d]", field, idx), group); err != nil {
			return err
		}
	}
	if err := detectLimitClassDigestAssertionGroupPresetCycle(field, strings.TrimPrefix(field, "security.limitClassDigestAssertionGroupPresets."), presets, map[string]bool{}, map[string]bool{}); err != nil {
		return err
	}
	return nil
}

func detectLimitClassDigestAssertionPresetCycle(field string, current string, presets map[string]LimitClassDigestAssertionPreset, visiting map[string]bool, visited map[string]bool) error {
	if current == "" {
		return nil
	}
	if visited[current] {
		return nil
	}
	if visiting[current] {
		return errors.NewValidationError(field+".presetChain", "limit class digest assertion preset chains must not contain cycles")
	}
	preset, ok := presets[current]
	if !ok {
		return nil
	}
	visiting[current] = true
	for _, name := range preset.PresetChain {
		if err := detectLimitClassDigestAssertionPresetCycle(field, strings.TrimSpace(name), presets, visiting, visited); err != nil {
			return err
		}
	}
	delete(visiting, current)
	visited[current] = true
	return nil
}

func detectLimitClassDigestAssertionGroupPresetCycle(field string, current string, presets map[string]LimitClassDigestAssertionGroupPreset, visiting map[string]bool, visited map[string]bool) error {
	if current == "" {
		return nil
	}
	if visited[current] {
		return nil
	}
	if visiting[current] {
		return errors.NewValidationError(field+".presetChain", "limit class digest assertion group preset chains must not contain cycles")
	}
	preset, ok := presets[current]
	if !ok {
		return nil
	}
	visiting[current] = true
	for _, name := range preset.PresetChain {
		if err := detectLimitClassDigestAssertionGroupPresetCycle(field, strings.TrimSpace(name), presets, visiting, visited); err != nil {
			return err
		}
	}
	delete(visiting, current)
	visited[current] = true
	return nil
}

func validateLimitClassDigestAssertionPresetRefs(field string, refs map[string][]string, presets map[string]LimitClassDigestAssertionPreset) error {
	for name, entries := range refs {
		resolvedName := strings.TrimSpace(name)
		if resolvedName == "" {
			return errors.NewValidationError(field, "limit class digest assertion preset references must not contain empty field names")
		}
		for _, entry := range entries {
			resolvedEntry := strings.TrimSpace(entry)
			if resolvedEntry == "" {
				return errors.NewValidationError(field+"."+resolvedName, "limit class digest assertion preset references must not contain empty preset names")
			}
			if _, ok := presets[resolvedEntry]; !ok {
				return errors.NewValidationError(field+"."+resolvedName, "limit class digest assertion preset references must point to defined security.limitClassDigestAssertionPresets entries")
			}
		}
	}
	return nil
}

func validateLimitClassDigestAssertionGroupPresetRefs(field string, refs map[string][]string, presets map[string]LimitClassDigestAssertionGroupPreset) error {
	for name, entries := range refs {
		resolvedName := strings.TrimSpace(name)
		if resolvedName == "" {
			return errors.NewValidationError(field, "limit class digest assertion group preset references must not contain empty kind names")
		}
		for _, entry := range entries {
			resolvedEntry := strings.TrimSpace(entry)
			if resolvedEntry == "" {
				return errors.NewValidationError(field+"."+resolvedName, "limit class digest assertion group preset references must not contain empty preset names")
			}
			if _, ok := presets[resolvedEntry]; !ok {
				return errors.NewValidationError(field+"."+resolvedName, "limit class digest assertion group preset references must point to defined security.limitClassDigestAssertionGroupPresets entries")
			}
		}
	}
	return nil
}

func validateLimitClassDigestExplainAssertionGroup(field string, group LimitClassDigestAssertionGroup) error {
	operator := strings.ToLower(strings.TrimSpace(group.Operator))
	switch operator {
	case "allof", "anyof", "noneof":
	default:
		return errors.NewValidationError(field+".operator", "limit class digest explain assertion group operator must be allOf, anyOf, or noneOf")
	}
	if len(group.Rules) == 0 && len(group.Groups) == 0 {
		return errors.NewValidationError(field, "limit class digest explain assertion groups must include at least one rule or nested group")
	}
	for _, rule := range group.Rules {
		if err := validateLimitClassDigestExplainAssertionRule(field+".rules", strings.TrimSpace(rule)); err != nil {
			return err
		}
	}
	for idx, nested := range group.Groups {
		if err := validateLimitClassDigestExplainAssertionGroup(fmt.Sprintf("%s.groups[%d]", field, idx), nested); err != nil {
			return err
		}
	}
	return nil
}

func validateLimitClassDigestExplainAssertionRule(field string, rule string) error {
	switch {
	case rule == "exists":
	case strings.HasPrefix(rule, "contains:"),
		strings.HasPrefix(rule, "not_contains:"),
		strings.HasPrefix(rule, "regex:"),
		strings.HasPrefix(rule, "lte:"),
		strings.HasPrefix(rule, "gte:"):
		if strings.HasPrefix(rule, "regex:") {
			pattern := strings.TrimSpace(strings.TrimPrefix(rule, "regex:"))
			if pattern == "" {
				return errors.NewValidationError(field, "limit class digest explain regex assertion rules must include a pattern")
			}
			if _, err := regexp.Compile(pattern); err != nil {
				return errors.NewValidationError(field, "limit class digest explain regex assertion rules must use a valid regex")
			}
		}
	default:
		return errors.NewValidationError(field, "limit class digest explain assertion rules must be exists or start with contains:, not_contains:, regex:, lte:, or gte:")
	}
	return nil
}
