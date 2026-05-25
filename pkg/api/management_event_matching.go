package api

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/bhangun/iket/pkg/config"
)

type notificationWebhookMatchRule func(config.NotificationWebhook, managementWebhookEvent) bool

type notificationWebhookScopedMatchRule struct {
	active  func(config.NotificationWebhook, managementWebhookEvent) bool
	matches func(config.NotificationWebhook, managementWebhookEvent) bool
}

var notificationWebhookMatchRules = []notificationWebhookMatchRule{
	notificationWebhookEventMatchesPayload,
	notificationWebhookEnvironmentMatchesPayload,
	notificationWebhookSLABreachMatchesPayload,
	notificationWebhookGatewayLimitAlertMatchesPayload,
}

var notificationWebhookSLABreachMatchRules = []notificationWebhookScopedMatchRule{
	{
		active: func(webhook config.NotificationWebhook, _ managementWebhookEvent) bool {
			return webhook.MinSLABreachCount > 0
		},
		matches: func(webhook config.NotificationWebhook, payload managementWebhookEvent) bool {
			return intValue(slaBreachCountFromEventData(payload.Data)) >= webhook.MinSLABreachCount
		},
	},
	{
		active: func(webhook config.NotificationWebhook, _ managementWebhookEvent) bool {
			return webhook.MinConsecutiveSLABreaches > 0
		},
		matches: func(webhook config.NotificationWebhook, payload managementWebhookEvent) bool {
			return slaBreachConsecutiveCountFromEventData(payload.Data) >= webhook.MinConsecutiveSLABreaches
		},
	},
	{
		active: func(webhook config.NotificationWebhook, _ managementWebhookEvent) bool {
			return strings.TrimSpace(webhook.MinSLABreachDuration) != ""
		},
		matches: func(webhook config.NotificationWebhook, payload managementWebhookEvent) bool {
			required, ok := parsePositiveWebhookDuration(webhook.MinSLABreachDuration)
			return ok && slaBreachAgeFromEventData(payload.Data) >= required
		},
	},
	{
		active: func(webhook config.NotificationWebhook, _ managementWebhookEvent) bool {
			return strings.TrimSpace(webhook.MinSLABreachTier) != ""
		},
		matches: func(webhook config.NotificationWebhook, payload managementWebhookEvent) bool {
			requiredTier := normalizeSLABreachTier(webhook.MinSLABreachTier)
			return requiredTier != "" && slaBreachTierRank(slaBreachTierFromEventData(payload.Data)) >= slaBreachTierRank(requiredTier)
		},
	},
}

var notificationWebhookGatewayLimitAlertMatchRules = []notificationWebhookScopedMatchRule{
	{
		active: func(webhook config.NotificationWebhook, _ managementWebhookEvent) bool {
			return len(webhook.LimitClassSnoozeEventTypes) > 0
		},
		matches: func(webhook config.NotificationWebhook, payload managementWebhookEvent) bool {
			currentSnoozeEventType := limitClassSnoozeEventType(payload.Event)
			return currentSnoozeEventType == "" || stringListContainsFold(webhook.LimitClassSnoozeEventTypes, currentSnoozeEventType)
		},
	},
	{
		active: func(webhook config.NotificationWebhook, payload managementWebhookEvent) bool {
			return notificationWebhookEventIs(payload, "gateway.limit_class_snooze_expiring") && strings.TrimSpace(webhook.LimitClassSnoozeExpiryWithin) != ""
		},
		matches: func(webhook config.NotificationWebhook, payload managementWebhookEvent) bool {
			requiredWithin, ok := parsePositiveWebhookDuration(webhook.LimitClassSnoozeExpiryWithin)
			remaining := limitClassSnoozeRemainingFromEventData(payload.Data)
			return ok && remaining > 0 && remaining <= requiredWithin
		},
	},
	{
		active: func(webhook config.NotificationWebhook, payload managementWebhookEvent) bool {
			return notificationWebhookEventIs(payload, "gateway.limit_class_snooze_expiring") && len(webhook.LimitClassSnoozeExpiryStages) > 0
		},
		matches: func(webhook config.NotificationWebhook, payload managementWebhookEvent) bool {
			return normalizedTierListContains(webhook.LimitClassSnoozeExpiryStages, limitClassSnoozeStageFromEventData(payload.Data))
		},
	},
	{
		active: func(webhook config.NotificationWebhook, _ managementWebhookEvent) bool {
			return strings.TrimSpace(webhook.MinLimitAlertSeverity) != ""
		},
		matches: func(webhook config.NotificationWebhook, payload managementWebhookEvent) bool {
			requiredSeverity := normalizeSLABreachTier(webhook.MinLimitAlertSeverity)
			return requiredSeverity != "" && slaBreachTierRank(limitAlertSeverityFromEventData(payload.Data)) >= slaBreachTierRank(requiredSeverity)
		},
	},
	{
		active: func(webhook config.NotificationWebhook, _ managementWebhookEvent) bool {
			return webhook.MinLimitAlertBucketClassPriority > 0
		},
		matches: func(webhook config.NotificationWebhook, payload managementWebhookEvent) bool {
			return limitAlertBucketClassPriorityFromEventData(payload.Data) >= webhook.MinLimitAlertBucketClassPriority
		},
	},
	{
		active: func(webhook config.NotificationWebhook, _ managementWebhookEvent) bool {
			return len(webhook.LimitAlertTypes) > 0
		},
		matches: func(webhook config.NotificationWebhook, payload managementWebhookEvent) bool {
			return stringListContainsLower(webhook.LimitAlertTypes, limitAlertTypeFromEventData(payload.Data))
		},
	},
	{
		active: func(webhook config.NotificationWebhook, _ managementWebhookEvent) bool {
			return len(webhook.LimitAlertKeyTypes) > 0
		},
		matches: func(webhook config.NotificationWebhook, payload managementWebhookEvent) bool {
			return stringListContainsLower(webhook.LimitAlertKeyTypes, limitAlertKeyTypeFromEventData(payload.Data))
		},
	},
	{
		active: func(webhook config.NotificationWebhook, _ managementWebhookEvent) bool {
			return len(webhook.LimitAlertBucketClasses) > 0
		},
		matches: func(webhook config.NotificationWebhook, payload managementWebhookEvent) bool {
			return stringListContainsFold(webhook.LimitAlertBucketClasses, limitAlertBucketClassFromEventData(payload.Data))
		},
	},
	{
		active: func(webhook config.NotificationWebhook, _ managementWebhookEvent) bool {
			return strings.TrimSpace(webhook.LimitAlertBucketIDRegex) != ""
		},
		matches: func(webhook config.NotificationWebhook, payload managementWebhookEvent) bool {
			re, err := regexp.Compile(strings.TrimSpace(webhook.LimitAlertBucketIDRegex))
			return err == nil && re.MatchString(limitAlertBucketIDFromEventData(payload.Data))
		},
	},
}

func notificationWebhookMatchesPayload(webhook config.NotificationWebhook, payload managementWebhookEvent) bool {
	for _, rule := range notificationWebhookMatchRules {
		if !rule(webhook, payload) {
			return false
		}
	}
	return true
}

func notificationWebhookEventMatchesPayload(webhook config.NotificationWebhook, payload managementWebhookEvent) bool {
	return notificationWebhookMatchesEvent(webhook, payload.Event)
}

func notificationWebhookEnvironmentMatchesPayload(webhook config.NotificationWebhook, payload managementWebhookEvent) bool {
	if len(webhook.Environments) == 0 {
		return true
	}
	return stringListContainsFold(webhook.Environments, payload.Environment)
}

func notificationWebhookSLABreachMatchesPayload(webhook config.NotificationWebhook, payload managementWebhookEvent) bool {
	if !notificationWebhookEventIs(payload, "proposal.sla_breach") {
		return true
	}
	return notificationWebhookMatchesScopedRules(webhook, payload, notificationWebhookSLABreachMatchRules)
}

func notificationWebhookGatewayLimitAlertMatchesPayload(webhook config.NotificationWebhook, payload managementWebhookEvent) bool {
	if !isGatewayLimitAlertEvent(payload.Event) {
		return true
	}
	return notificationWebhookMatchesScopedRules(webhook, payload, notificationWebhookGatewayLimitAlertMatchRules)
}

func notificationWebhookMatchesScopedRules(webhook config.NotificationWebhook, payload managementWebhookEvent, rules []notificationWebhookScopedMatchRule) bool {
	for _, rule := range rules {
		if rule.active(webhook, payload) && !rule.matches(webhook, payload) {
			return false
		}
	}
	return true
}

func notificationWebhookMatchesEvent(webhook config.NotificationWebhook, event string) bool {
	if len(webhook.Events) == 0 {
		return true
	}
	event = strings.TrimSpace(strings.ToLower(event))
	for _, candidate := range webhook.Events {
		candidate = strings.TrimSpace(strings.ToLower(candidate))
		if candidate == "" {
			continue
		}
		if candidate == "*" || candidate == event {
			return true
		}
	}
	return false
}

func notificationWebhookEventIs(payload managementWebhookEvent, event string) bool {
	return strings.EqualFold(strings.TrimSpace(payload.Event), event)
}

func stringListContainsLower(candidates []string, value string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return false
	}
	for _, candidate := range candidates {
		if strings.ToLower(strings.TrimSpace(candidate)) == value {
			return true
		}
	}
	return false
}

func stringListContainsFold(candidates []string, value string) bool {
	value = strings.TrimSpace(value)
	if value == "" {
		return false
	}
	for _, candidate := range candidates {
		if strings.EqualFold(strings.TrimSpace(candidate), value) {
			return true
		}
	}
	return false
}

func normalizedTierListContains(candidates []string, value string) bool {
	value = normalizeSLABreachTier(value)
	if value == "" {
		return false
	}
	for _, candidate := range candidates {
		if normalizeSLABreachTier(candidate) == value {
			return true
		}
	}
	return false
}

func parsePositiveWebhookDuration(value string) (time.Duration, bool) {
	duration, err := time.ParseDuration(strings.TrimSpace(value))
	return duration, err == nil && duration > 0
}

func isGatewayLimitAlertEvent(event string) bool {
	switch strings.TrimSpace(strings.ToLower(event)) {
	case "gateway.limit_alert", "gateway.limit_alert_opened", "gateway.limit_alert_stage_changed", "gateway.limit_alert_resolved",
		"gateway.limit_class_alert", "gateway.limit_class_alert_opened", "gateway.limit_class_alert_stage_changed", "gateway.limit_class_alert_resolved", "gateway.limit_class_alert_acknowledged", "gateway.limit_class_alert_snoozed",
		"gateway.limit_class_snooze_expiring", "gateway.limit_class_snooze_expiring_digest", "gateway.limit_class_snooze_stage_changed", "gateway.limit_class_snooze_resumed":
		return true
	default:
		return false
	}
}

func limitAlertSeverityFromEventData(data map[string]interface{}) string {
	return normalizeSLABreachTier(fmt.Sprint(data["severity"]))
}

func limitAlertTypeFromEventData(data map[string]interface{}) string {
	return strings.ToLower(strings.TrimSpace(fmt.Sprint(data["limit_type"])))
}

func limitAlertKeyTypeFromEventData(data map[string]interface{}) string {
	return strings.ToLower(strings.TrimSpace(fmt.Sprint(data["key_type"])))
}

func limitAlertBucketIDFromEventData(data map[string]interface{}) string {
	return strings.TrimSpace(fmt.Sprint(data["bucket_id"]))
}

func limitAlertBucketClassFromEventData(data map[string]interface{}) string {
	return strings.TrimSpace(fmt.Sprint(data["bucket_class"]))
}

func limitAlertBucketClassPriorityFromEventData(data map[string]interface{}) int {
	return intValue(data["bucket_class_priority"])
}

func limitClassSnoozeRemainingFromEventData(data map[string]interface{}) time.Duration {
	switch value := data["remaining_snooze_seconds"].(type) {
	case int:
		return time.Duration(value) * time.Second
	case int64:
		return time.Duration(value) * time.Second
	case float64:
		return time.Duration(value * float64(time.Second))
	default:
		return 0
	}
}

func limitClassSnoozeStageFromEventData(data map[string]interface{}) string {
	if stage := normalizeSLABreachTier(fmt.Sprint(data["snooze_stage"])); stage != "" {
		return stage
	}
	return normalizeSLABreachTier(fmt.Sprint(data["severity"]))
}

func limitClassSnoozeEventType(event string) string {
	switch strings.TrimSpace(strings.ToLower(event)) {
	case "gateway.limit_class_snooze_expiring_digest":
		return "digest"
	case "gateway.limit_class_snooze_expiring":
		return "expiring"
	case "gateway.limit_class_snooze_stage_changed":
		return "stage_changed"
	case "gateway.limit_class_snooze_resumed":
		return "resumed"
	default:
		return ""
	}
}
