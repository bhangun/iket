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
	for name, profile := range cfg.Security.LimitAlertProfiles {
		profileName := strings.TrimSpace(name)
		if profileName == "" {
			return errors.NewValidationError("security.limitAlertProfiles", "limit alert profiles require a non-empty name")
		}
		if err := validateNotificationWebhookLimitAlertFilters("security.limitAlertProfiles."+profileName, NotificationWebhook{
			MinLimitAlertSeverity:   profile.MinLimitAlertSeverity,
			LimitAlertTypes:         profile.LimitAlertTypes,
			LimitAlertKeyTypes:      profile.LimitAlertKeyTypes,
			LimitAlertBucketClasses: profile.LimitAlertBucketClasses,
			LimitAlertBucketIDRegex: profile.LimitAlertBucketIDRegex,
			LimitAlertCooldown:      profile.LimitAlertCooldown,
		}, cfg.Security.LimitAlertBucketClasses); err != nil {
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
		if err := validateNotificationWebhookLimitAlertFilters(fmt.Sprintf("security.notificationWebhooks[%d]", i), webhook, cfg.Security.LimitAlertBucketClasses); err != nil {
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

func validateNotificationWebhookLimitAlertFilters(field string, webhook NotificationWebhook, bucketClasses map[string]LimitAlertBucketClassConfig) error {
	switch strings.ToLower(strings.TrimSpace(webhook.MinLimitAlertSeverity)) {
	case "", "warning", "elevated", "critical":
	default:
		return errors.NewValidationError(field+".minLimitAlertSeverity", "notification webhook minLimitAlertSeverity must be warning, elevated, or critical")
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
	return nil
}

func validateLimitAlertBucketClassConfig(field string, classConfig LimitAlertBucketClassConfig) error {
	switch strings.ToLower(strings.TrimSpace(classConfig.KeyType)) {
	case "ip", "header", "api_key", "jwt_sub":
	default:
		return errors.NewValidationError(field+".keyType", "limit alert bucket class keyType must be ip, header, api_key, or jwt_sub")
	}
	if strings.TrimSpace(classConfig.BucketRegex) == "" {
		return errors.NewValidationError(field+".bucketRegex", "limit alert bucket class bucketRegex is required")
	}
	if _, err := regexp.Compile(strings.TrimSpace(classConfig.BucketRegex)); err != nil {
		return errors.NewValidationError(field+".bucketRegex", "limit alert bucket class bucketRegex must be a valid regex")
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
	if strings.ToLower(strings.TrimSpace(classConfig.KeyType)) == "global" {
		return errors.NewValidationError(field+".bucketClass", "limiter class preset bucketClass must reference a bucketed key type")
	}
	return nil
}
