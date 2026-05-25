package api

import (
	"strings"
	"time"

	"github.com/bhangun/iket/pkg/config"
)

func policyAlertNotificationInterval(policy config.PolicyAlertNotificationPolicy) time.Duration {
	if parsed, err := time.ParseDuration(strings.TrimSpace(policy.Interval)); err == nil && parsed > 0 {
		return parsed
	}
	return 1 * time.Minute
}

func policyAlertNotificationMinInterval(policy config.PolicyAlertNotificationPolicy) time.Duration {
	if parsed, err := time.ParseDuration(strings.TrimSpace(policy.MinNotificationInterval)); err == nil && parsed > 0 {
		return parsed
	}
	return policyAlertNotificationInterval(policy)
}

func policyAlertNotificationWindow(policy config.PolicyAlertNotificationPolicy) time.Duration {
	if parsed, err := time.ParseDuration(strings.TrimSpace(policy.Window)); err == nil && parsed > 0 {
		return parsed
	}
	return 5 * time.Minute
}

func policyAlertNotificationMinCount(policy config.PolicyAlertNotificationPolicy) int {
	if policy.MinCount > 0 {
		return policy.MinCount
	}
	return 3
}
