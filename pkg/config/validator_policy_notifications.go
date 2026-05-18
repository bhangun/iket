package config

import (
	"github.com/bhangun/iket/pkg/core/errors"
	"regexp"
	"strings"
	"time"
)

func validateProposalQueueUrgencyThresholds(field string, thresholds ProposalQueueUrgencyThresholds) error {
	readyAging, err := validateOptionalQueueThresholdDuration(field+".readyAgingAfter", thresholds.ReadyAgingAfter)
	if err != nil {
		return err
	}
	readyOverdue, err := validateOptionalQueueThresholdDuration(field+".readyOverdueAfter", thresholds.ReadyOverdueAfter)
	if err != nil {
		return err
	}
	blockedAging, err := validateOptionalQueueThresholdDuration(field+".blockedAgingAfter", thresholds.BlockedAgingAfter)
	if err != nil {
		return err
	}
	blockedOverdue, err := validateOptionalQueueThresholdDuration(field+".blockedOverdueAfter", thresholds.BlockedOverdueAfter)
	if err != nil {
		return err
	}
	if readyAging > 0 && readyOverdue > 0 && readyOverdue <= readyAging {
		return errors.NewValidationError(field, "readyOverdueAfter must be greater than readyAgingAfter")
	}
	if blockedAging > 0 && blockedOverdue > 0 && blockedOverdue <= blockedAging {
		return errors.NewValidationError(field, "blockedOverdueAfter must be greater than blockedAgingAfter")
	}
	return nil
}

func validateOptionalQueueThresholdDuration(field, value string) (time.Duration, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return 0, nil
	}
	parsed, err := time.ParseDuration(trimmed)
	if err != nil {
		return 0, errors.NewValidationError(field, "must use a valid duration format")
	}
	if parsed <= 0 {
		return 0, errors.NewValidationError(field, "must be greater than zero")
	}
	return parsed, nil
}

func validateProposalQueueNotificationPolicy(field string, policy ProposalQueueNotificationPolicy) error {
	if strings.TrimSpace(policy.Interval) != "" {
		if _, err := validateOptionalQueueThresholdDuration(field+".interval", policy.Interval); err != nil {
			return err
		}
	}
	if strings.TrimSpace(policy.MinNotificationInterval) != "" {
		if _, err := validateOptionalQueueThresholdDuration(field+".minNotificationInterval", policy.MinNotificationInterval); err != nil {
			return err
		}
	}
	for _, environment := range policy.Environments {
		if strings.TrimSpace(environment) == "" {
			return errors.NewValidationError(field+".environments", "queue notification environments must not contain empty values")
		}
	}
	return nil
}

func validatePolicyAlertNotificationPolicy(field string, policy PolicyAlertNotificationPolicy) error {
	if strings.TrimSpace(policy.Interval) != "" {
		if _, err := time.ParseDuration(strings.TrimSpace(policy.Interval)); err != nil {
			return errors.NewValidationError(field+".interval", "policy alert notification interval must use a valid duration format")
		}
	}
	if strings.TrimSpace(policy.MinNotificationInterval) != "" {
		if _, err := time.ParseDuration(strings.TrimSpace(policy.MinNotificationInterval)); err != nil {
			return errors.NewValidationError(field+".minNotificationInterval", "policy alert notification minNotificationInterval must use a valid duration format")
		}
	}
	if strings.TrimSpace(policy.Window) != "" {
		if _, err := time.ParseDuration(strings.TrimSpace(policy.Window)); err != nil {
			return errors.NewValidationError(field+".window", "policy alert notification window must use a valid duration format")
		}
	}
	if policy.MinCount < 0 {
		return errors.NewValidationError(field+".minCount", "policy alert notification minCount must be zero or greater")
	}
	switch strings.ToLower(strings.TrimSpace(policy.MinSeverity)) {
	case "", "warning", "elevated", "critical":
	default:
		return errors.NewValidationError(field+".minSeverity", "policy alert notification minSeverity must be warning, elevated, or critical")
	}
	if err := validateLimitAlertTypePolicies(field+".limitTypePolicies", policy.LimitTypePolicies); err != nil {
		return err
	}
	return nil
}

func validateRouteLimitAlertPolicy(field string, policy RouteLimitAlertPolicyConfig) error {
	if policy.MinCount < 0 {
		return errors.NewValidationError(field+".minCount", "route limit alert minCount must be zero or greater")
	}
	switch strings.ToLower(strings.TrimSpace(policy.MinSeverity)) {
	case "", "warning", "elevated", "critical":
	default:
		return errors.NewValidationError(field+".minSeverity", "route limit alert minSeverity must be warning, elevated, or critical")
	}
	switch strings.ToLower(strings.TrimSpace(policy.GroupBy)) {
	case "", "route", "bucket":
	default:
		return errors.NewValidationError(field+".groupBy", "route limit alert groupBy must be route or bucket")
	}
	if err := validateLimitAlertTypePolicies(field+".limitTypePolicies", policy.LimitTypePolicies); err != nil {
		return err
	}
	for _, bucketPolicy := range policy.BucketPolicies {
		if err := validateLimitAlertBucketPolicy(field+".bucketPolicies", bucketPolicy); err != nil {
			return err
		}
	}
	return nil
}

func validateLimitAlertBucketPolicy(field string, policy LimitAlertBucketPolicyConfig) error {
	if preset := strings.TrimSpace(policy.Preset); preset != "" {
		if strings.TrimSpace(policy.KeyType) != "" || strings.TrimSpace(policy.BucketRegex) != "" {
			return errors.NewValidationError(field+".preset", "limit alert bucket policy preset cannot be combined with keyType or bucketRegex")
		}
	}
	if bucketClass := strings.TrimSpace(policy.BucketClass); bucketClass != "" {
		if strings.TrimSpace(policy.KeyType) != "" || strings.TrimSpace(policy.BucketRegex) != "" {
			return errors.NewValidationError(field+".bucketClass", "limit alert bucket policy bucketClass cannot be combined with keyType or bucketRegex")
		}
	} else {
		if strings.TrimSpace(policy.Preset) != "" {
			goto validateThresholds
		}
		switch strings.ToLower(strings.TrimSpace(policy.KeyType)) {
		case "ip", "header", "api_key", "jwt_sub":
		default:
			return errors.NewValidationError(field+".keyType", "limit alert bucket policy keyType must be ip, header, api_key, or jwt_sub")
		}
		if strings.TrimSpace(policy.BucketRegex) == "" {
			return errors.NewValidationError(field+".bucketRegex", "limit alert bucket policy bucketRegex is required")
		}
		if _, err := regexp.Compile(strings.TrimSpace(policy.BucketRegex)); err != nil {
			return errors.NewValidationError(field+".bucketRegex", "limit alert bucket policy bucketRegex must be a valid regex")
		}
	}
validateThresholds:
	if policy.MinCount < 0 {
		return errors.NewValidationError(field+".minCount", "limit alert bucket policy minCount must be zero or greater")
	}
	switch strings.ToLower(strings.TrimSpace(policy.MinSeverity)) {
	case "", "warning", "elevated", "critical":
	default:
		return errors.NewValidationError(field+".minSeverity", "limit alert bucket policy minSeverity must be warning, elevated, or critical")
	}
	return validateLimitAlertTypePolicies(field+".limitTypePolicies", policy.LimitTypePolicies)
}

func validateLimitAlertTypePolicies(field string, policies map[string]LimitAlertTypePolicy) error {
	for limitType, thresholds := range policies {
		switch strings.ToLower(strings.TrimSpace(limitType)) {
		case "rate_limit", "concurrency_limit", "concurrency_queued", "concurrency_queue_full":
		default:
			return errors.NewValidationError(field, "limit alert type policies must contain only rate_limit, concurrency_limit, concurrency_queued, or concurrency_queue_full")
		}
		if thresholds.WarningCount < 0 || thresholds.ElevatedCount < 0 || thresholds.CriticalCount < 0 {
			return errors.NewValidationError(field, "limit alert type policy counts must be zero or greater")
		}
		warningCount := thresholds.WarningCount
		elevatedCount := thresholds.ElevatedCount
		criticalCount := thresholds.CriticalCount
		if warningCount > 0 && elevatedCount > 0 && elevatedCount < warningCount {
			return errors.NewValidationError(field, "limit alert type policy elevatedCount must be greater than or equal to warningCount")
		}
		if elevatedCount > 0 && criticalCount > 0 && criticalCount < elevatedCount {
			return errors.NewValidationError(field, "limit alert type policy criticalCount must be greater than or equal to elevatedCount")
		}
		if warningCount > 0 && criticalCount > 0 && criticalCount < warningCount {
			return errors.NewValidationError(field, "limit alert type policy criticalCount must be greater than or equal to warningCount")
		}
	}
	return nil
}

func isKnownPolicyWeekday(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "sun", "sunday", "mon", "monday", "tue", "tues", "tuesday", "wed", "wednesday", "thu", "thur", "thurs", "thursday", "fri", "friday", "sat", "saturday":
		return true
	default:
		return false
	}
}
