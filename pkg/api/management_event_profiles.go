package api

import (
	"encoding/json"
	"strings"

	"github.com/bhangun/iket/pkg/config"
)

type notificationWebhookProfileApplier func(*config.NotificationWebhook, config.LimitAlertRecipientProfile)

var notificationWebhookLimitAlertProfileAppliers = []notificationWebhookProfileApplier{
	func(webhook *config.NotificationWebhook, profile config.LimitAlertRecipientProfile) {
		inheritWebhookProfileString(&webhook.MinLimitAlertSeverity, profile.MinLimitAlertSeverity)
	},
	func(webhook *config.NotificationWebhook, profile config.LimitAlertRecipientProfile) {
		inheritWebhookProfilePositiveInt(&webhook.MinLimitAlertBucketClassPriority, profile.MinLimitAlertBucketClassPriority)
	},
	func(webhook *config.NotificationWebhook, profile config.LimitAlertRecipientProfile) {
		inheritWebhookProfileString(&webhook.LimitClassDigestMinSeverity, profile.LimitClassDigestMinSeverity)
	},
	func(webhook *config.NotificationWebhook, profile config.LimitAlertRecipientProfile) {
		inheritWebhookProfileStringSlice(&webhook.LimitClassDigestTypes, profile.LimitClassDigestTypes)
	},
	func(webhook *config.NotificationWebhook, profile config.LimitAlertRecipientProfile) {
		inheritWebhookProfileStringSlice(&webhook.LimitClassDigestSummaryOnlyTypes, profile.LimitClassDigestSummaryOnlyTypes)
	},
	func(webhook *config.NotificationWebhook, profile config.LimitAlertRecipientProfile) {
		inheritWebhookProfileStringSlice(&webhook.LimitClassDigestSeverities, profile.LimitClassDigestSeverities)
	},
	func(webhook *config.NotificationWebhook, profile config.LimitAlertRecipientProfile) {
		inheritWebhookProfilePositiveInt(&webhook.LimitClassDigestMinBucketClassPriority, profile.LimitClassDigestMinBucketClassPriority)
	},
	func(webhook *config.NotificationWebhook, profile config.LimitAlertRecipientProfile) {
		inheritWebhookProfilePositiveInt(&webhook.LimitClassDigestMaxBucketClasses, profile.LimitClassDigestMaxBucketClasses)
	},
	func(webhook *config.NotificationWebhook, profile config.LimitAlertRecipientProfile) {
		inheritWebhookProfileString(&webhook.LimitClassDigestMinSummarySeverity, profile.LimitClassDigestMinSummarySeverity)
	},
	func(webhook *config.NotificationWebhook, profile config.LimitAlertRecipientProfile) {
		inheritWebhookProfileString(&webhook.LimitClassDigestSummarySortMode, profile.LimitClassDigestSummarySortMode)
	},
	func(webhook *config.NotificationWebhook, profile config.LimitAlertRecipientProfile) {
		inheritWebhookProfilePositiveInt(&webhook.LimitClassDigestMinSummaryCount, profile.LimitClassDigestMinSummaryCount)
	},
	func(webhook *config.NotificationWebhook, profile config.LimitAlertRecipientProfile) {
		inheritWebhookProfileString(&webhook.LimitClassDigestOtherBucketLabel, profile.LimitClassDigestOtherBucketLabel)
	},
	func(webhook *config.NotificationWebhook, profile config.LimitAlertRecipientProfile) {
		inheritWebhookProfileStringSlice(&webhook.LimitClassDigestOverflowReasons, profile.LimitClassDigestOverflowReasons)
	},
	func(webhook *config.NotificationWebhook, profile config.LimitAlertRecipientProfile) {
		inheritWebhookProfileStringMap(&webhook.LimitClassDigestOverflowReasonLabels, profile.LimitClassDigestOverflowReasonLabels)
	},
	func(webhook *config.NotificationWebhook, profile config.LimitAlertRecipientProfile) {
		inheritWebhookProfileStringSliceMap(&webhook.LimitClassDigestOverflowReasonGroups, profile.LimitClassDigestOverflowReasonGroups)
	},
	func(webhook *config.NotificationWebhook, profile config.LimitAlertRecipientProfile) {
		inheritWebhookProfileStringSlice(&webhook.LimitClassDigestOverflowReasonOrder, profile.LimitClassDigestOverflowReasonOrder)
	},
	func(webhook *config.NotificationWebhook, profile config.LimitAlertRecipientProfile) {
		inheritWebhookProfilePositiveInt(&webhook.LimitClassDigestMaxOverflowReasons, profile.LimitClassDigestMaxOverflowReasons)
	},
	func(webhook *config.NotificationWebhook, profile config.LimitAlertRecipientProfile) {
		inheritWebhookProfileString(&webhook.LimitClassDigestTruncatedReasonBucketLabel, profile.LimitClassDigestTruncatedReasonBucketLabel)
	},
	func(webhook *config.NotificationWebhook, profile config.LimitAlertRecipientProfile) {
		inheritWebhookProfileString(&webhook.LimitClassDigestTruncatedReasonBucketMode, profile.LimitClassDigestTruncatedReasonBucketMode)
	},
	func(webhook *config.NotificationWebhook, profile config.LimitAlertRecipientProfile) {
		inheritWebhookProfilePositiveInt(&webhook.LimitClassDigestTruncatedReasonBucketMaxReasons, profile.LimitClassDigestTruncatedReasonBucketMaxReasons)
	},
	func(webhook *config.NotificationWebhook, profile config.LimitAlertRecipientProfile) {
		inheritWebhookProfileStringSlice(&webhook.LimitClassDigestTruncatedReasonBucketReasonOrder, profile.LimitClassDigestTruncatedReasonBucketReasonOrder)
	},
	func(webhook *config.NotificationWebhook, profile config.LimitAlertRecipientProfile) {
		inheritWebhookProfileString(&webhook.LimitClassDigestTruncatedReasonBucketMinSeverity, profile.LimitClassDigestTruncatedReasonBucketMinSeverity)
	},
	func(webhook *config.NotificationWebhook, profile config.LimitAlertRecipientProfile) {
		inheritWebhookProfileStringSlice(&webhook.LimitClassDigestTruncatedReasonBucketSeverities, profile.LimitClassDigestTruncatedReasonBucketSeverities)
	},
	func(webhook *config.NotificationWebhook, profile config.LimitAlertRecipientProfile) {
		inheritWebhookProfileString(&webhook.LimitClassDigestTruncatedReasonBucketSortMode, profile.LimitClassDigestTruncatedReasonBucketSortMode)
	},
	func(webhook *config.NotificationWebhook, profile config.LimitAlertRecipientProfile) {
		inheritWebhookProfileString(&webhook.LimitClassDigestTruncatedReasonBucketDominantReasonStrategy, profile.LimitClassDigestTruncatedReasonBucketDominantReasonStrategy)
	},
	func(webhook *config.NotificationWebhook, profile config.LimitAlertRecipientProfile) {
		inheritWebhookProfileStringSlice(&webhook.LimitClassDigestTruncatedReasonBucketHiddenStrategyOrder, profile.LimitClassDigestTruncatedReasonBucketHiddenStrategyOrder)
	},
	func(webhook *config.NotificationWebhook, profile config.LimitAlertRecipientProfile) {
		inheritWebhookProfileString(&webhook.LimitClassDigestTruncatedReasonBucketHiddenStrategyDominantMode, profile.LimitClassDigestTruncatedReasonBucketHiddenStrategyDominantMode)
	},
	func(webhook *config.NotificationWebhook, profile config.LimitAlertRecipientProfile) {
		inheritWebhookProfilePositiveInt(&webhook.LimitClassDigestTruncatedReasonBucketHiddenStrategyPriorityWeight, profile.LimitClassDigestTruncatedReasonBucketHiddenStrategyPriorityWeight)
	},
	func(webhook *config.NotificationWebhook, profile config.LimitAlertRecipientProfile) {
		inheritWebhookProfilePositiveInt(&webhook.LimitClassDigestTruncatedReasonBucketHiddenStrategyReasonWeight, profile.LimitClassDigestTruncatedReasonBucketHiddenStrategyReasonWeight)
	},
	func(webhook *config.NotificationWebhook, profile config.LimitAlertRecipientProfile) {
		inheritWebhookProfilePositiveInt(&webhook.LimitClassDigestTruncatedReasonBucketHiddenStrategyItemWeight, profile.LimitClassDigestTruncatedReasonBucketHiddenStrategyItemWeight)
	},
	func(webhook *config.NotificationWebhook, profile config.LimitAlertRecipientProfile) {
		inheritWebhookProfilePositiveInt(&webhook.LimitClassDigestTruncatedReasonBucketHiddenStrategyPriorityCap, profile.LimitClassDigestTruncatedReasonBucketHiddenStrategyPriorityCap)
	},
	func(webhook *config.NotificationWebhook, profile config.LimitAlertRecipientProfile) {
		inheritWebhookProfilePositiveInt(&webhook.LimitClassDigestTruncatedReasonBucketHiddenStrategyReasonCap, profile.LimitClassDigestTruncatedReasonBucketHiddenStrategyReasonCap)
	},
	func(webhook *config.NotificationWebhook, profile config.LimitAlertRecipientProfile) {
		inheritWebhookProfilePositiveInt(&webhook.LimitClassDigestTruncatedReasonBucketHiddenStrategyItemCap, profile.LimitClassDigestTruncatedReasonBucketHiddenStrategyItemCap)
	},
	func(webhook *config.NotificationWebhook, profile config.LimitAlertRecipientProfile) {
		inheritWebhookProfilePositiveInt(&webhook.LimitClassDigestTruncatedReasonBucketHiddenStrategyMinReasons, profile.LimitClassDigestTruncatedReasonBucketHiddenStrategyMinReasons)
	},
	func(webhook *config.NotificationWebhook, profile config.LimitAlertRecipientProfile) {
		inheritWebhookProfilePositiveInt(&webhook.LimitClassDigestTruncatedReasonBucketHiddenStrategyMinItems, profile.LimitClassDigestTruncatedReasonBucketHiddenStrategyMinItems)
	},
	func(webhook *config.NotificationWebhook, profile config.LimitAlertRecipientProfile) {
		inheritWebhookProfileStringSlice(&webhook.LimitClassDigestTruncatedReasonBucketExactSeverityPolicyPresetChain, profile.LimitClassDigestTruncatedReasonBucketExactSeverityPolicyPresetChain)
	},
	func(webhook *config.NotificationWebhook, profile config.LimitAlertRecipientProfile) {
		inheritWebhookProfileString(&webhook.LimitClassDigestTruncatedReasonBucketExactSeverityPolicyPreset, profile.LimitClassDigestTruncatedReasonBucketExactSeverityPolicyPreset)
	},
	func(webhook *config.NotificationWebhook, profile config.LimitAlertRecipientProfile) {
		inheritWebhookProfileHiddenStrategyPolicy(&webhook.LimitClassDigestTruncatedReasonBucketExactSeverityPolicy, profile.LimitClassDigestTruncatedReasonBucketExactSeverityPolicy)
	},
	func(webhook *config.NotificationWebhook, profile config.LimitAlertRecipientProfile) {
		inheritWebhookProfilePositiveInt(&webhook.LimitClassDigestTruncatedReasonBucketExactSeverityPriorityCap, profile.LimitClassDigestTruncatedReasonBucketExactSeverityPriorityCap)
	},
	func(webhook *config.NotificationWebhook, profile config.LimitAlertRecipientProfile) {
		inheritWebhookProfilePositiveInt(&webhook.LimitClassDigestTruncatedReasonBucketExactSeverityReasonCap, profile.LimitClassDigestTruncatedReasonBucketExactSeverityReasonCap)
	},
	func(webhook *config.NotificationWebhook, profile config.LimitAlertRecipientProfile) {
		inheritWebhookProfilePositiveInt(&webhook.LimitClassDigestTruncatedReasonBucketExactSeverityItemCap, profile.LimitClassDigestTruncatedReasonBucketExactSeverityItemCap)
	},
	func(webhook *config.NotificationWebhook, profile config.LimitAlertRecipientProfile) {
		inheritWebhookProfilePositiveInt(&webhook.LimitClassDigestTruncatedReasonBucketExactSeverityPriorityWeight, profile.LimitClassDigestTruncatedReasonBucketExactSeverityPriorityWeight)
	},
	func(webhook *config.NotificationWebhook, profile config.LimitAlertRecipientProfile) {
		inheritWebhookProfilePositiveInt(&webhook.LimitClassDigestTruncatedReasonBucketExactSeverityReasonWeight, profile.LimitClassDigestTruncatedReasonBucketExactSeverityReasonWeight)
	},
	func(webhook *config.NotificationWebhook, profile config.LimitAlertRecipientProfile) {
		inheritWebhookProfilePositiveInt(&webhook.LimitClassDigestTruncatedReasonBucketExactSeverityItemWeight, profile.LimitClassDigestTruncatedReasonBucketExactSeverityItemWeight)
	},
	func(webhook *config.NotificationWebhook, profile config.LimitAlertRecipientProfile) {
		inheritWebhookProfileString(&webhook.LimitClassDigestTruncatedReasonBucketExactSeverityDominantMode, profile.LimitClassDigestTruncatedReasonBucketExactSeverityDominantMode)
	},
	func(webhook *config.NotificationWebhook, profile config.LimitAlertRecipientProfile) {
		inheritWebhookProfilePositiveInt(&webhook.LimitClassDigestTruncatedReasonBucketExactSeverityMinReasons, profile.LimitClassDigestTruncatedReasonBucketExactSeverityMinReasons)
	},
	func(webhook *config.NotificationWebhook, profile config.LimitAlertRecipientProfile) {
		inheritWebhookProfilePositiveInt(&webhook.LimitClassDigestTruncatedReasonBucketExactSeverityMinItems, profile.LimitClassDigestTruncatedReasonBucketExactSeverityMinItems)
	},
	func(webhook *config.NotificationWebhook, profile config.LimitAlertRecipientProfile) {
		inheritWebhookProfileStringSlice(&webhook.LimitClassDigestTruncatedReasonBucketMinSeverityPolicyPresetChain, profile.LimitClassDigestTruncatedReasonBucketMinSeverityPolicyPresetChain)
	},
	func(webhook *config.NotificationWebhook, profile config.LimitAlertRecipientProfile) {
		inheritWebhookProfileString(&webhook.LimitClassDigestTruncatedReasonBucketMinSeverityPolicyPreset, profile.LimitClassDigestTruncatedReasonBucketMinSeverityPolicyPreset)
	},
	func(webhook *config.NotificationWebhook, profile config.LimitAlertRecipientProfile) {
		inheritWebhookProfileHiddenStrategyPolicy(&webhook.LimitClassDigestTruncatedReasonBucketMinSeverityPolicy, profile.LimitClassDigestTruncatedReasonBucketMinSeverityPolicy)
	},
	func(webhook *config.NotificationWebhook, profile config.LimitAlertRecipientProfile) {
		inheritWebhookProfilePositiveInt(&webhook.LimitClassDigestTruncatedReasonBucketMinSeverityPriorityCap, profile.LimitClassDigestTruncatedReasonBucketMinSeverityPriorityCap)
	},
	func(webhook *config.NotificationWebhook, profile config.LimitAlertRecipientProfile) {
		inheritWebhookProfilePositiveInt(&webhook.LimitClassDigestTruncatedReasonBucketMinSeverityReasonCap, profile.LimitClassDigestTruncatedReasonBucketMinSeverityReasonCap)
	},
	func(webhook *config.NotificationWebhook, profile config.LimitAlertRecipientProfile) {
		inheritWebhookProfilePositiveInt(&webhook.LimitClassDigestTruncatedReasonBucketMinSeverityItemCap, profile.LimitClassDigestTruncatedReasonBucketMinSeverityItemCap)
	},
	func(webhook *config.NotificationWebhook, profile config.LimitAlertRecipientProfile) {
		inheritWebhookProfilePositiveInt(&webhook.LimitClassDigestTruncatedReasonBucketMinSeverityPriorityWeight, profile.LimitClassDigestTruncatedReasonBucketMinSeverityPriorityWeight)
	},
	func(webhook *config.NotificationWebhook, profile config.LimitAlertRecipientProfile) {
		inheritWebhookProfilePositiveInt(&webhook.LimitClassDigestTruncatedReasonBucketMinSeverityReasonWeight, profile.LimitClassDigestTruncatedReasonBucketMinSeverityReasonWeight)
	},
	func(webhook *config.NotificationWebhook, profile config.LimitAlertRecipientProfile) {
		inheritWebhookProfilePositiveInt(&webhook.LimitClassDigestTruncatedReasonBucketMinSeverityItemWeight, profile.LimitClassDigestTruncatedReasonBucketMinSeverityItemWeight)
	},
	func(webhook *config.NotificationWebhook, profile config.LimitAlertRecipientProfile) {
		inheritWebhookProfileString(&webhook.LimitClassDigestTruncatedReasonBucketMinSeverityDominantMode, profile.LimitClassDigestTruncatedReasonBucketMinSeverityDominantMode)
	},
	func(webhook *config.NotificationWebhook, profile config.LimitAlertRecipientProfile) {
		inheritWebhookProfilePositiveInt(&webhook.LimitClassDigestTruncatedReasonBucketMinSeverityMinReasons, profile.LimitClassDigestTruncatedReasonBucketMinSeverityMinReasons)
	},
	func(webhook *config.NotificationWebhook, profile config.LimitAlertRecipientProfile) {
		inheritWebhookProfilePositiveInt(&webhook.LimitClassDigestTruncatedReasonBucketMinSeverityMinItems, profile.LimitClassDigestTruncatedReasonBucketMinSeverityMinItems)
	},
	func(webhook *config.NotificationWebhook, profile config.LimitAlertRecipientProfile) {
		inheritWebhookProfileStringSlice(&webhook.LimitClassDigestTruncatedReasonBucketMaxReasonsPolicyPresetChain, profile.LimitClassDigestTruncatedReasonBucketMaxReasonsPolicyPresetChain)
	},
	func(webhook *config.NotificationWebhook, profile config.LimitAlertRecipientProfile) {
		inheritWebhookProfileString(&webhook.LimitClassDigestTruncatedReasonBucketMaxReasonsPolicyPreset, profile.LimitClassDigestTruncatedReasonBucketMaxReasonsPolicyPreset)
	},
	func(webhook *config.NotificationWebhook, profile config.LimitAlertRecipientProfile) {
		inheritWebhookProfileHiddenStrategyPolicy(&webhook.LimitClassDigestTruncatedReasonBucketMaxReasonsPolicy, profile.LimitClassDigestTruncatedReasonBucketMaxReasonsPolicy)
	},
	func(webhook *config.NotificationWebhook, profile config.LimitAlertRecipientProfile) {
		inheritWebhookProfilePositiveInt(&webhook.LimitClassDigestTruncatedReasonBucketMaxReasonsPriorityCap, profile.LimitClassDigestTruncatedReasonBucketMaxReasonsPriorityCap)
	},
	func(webhook *config.NotificationWebhook, profile config.LimitAlertRecipientProfile) {
		inheritWebhookProfilePositiveInt(&webhook.LimitClassDigestTruncatedReasonBucketMaxReasonsReasonCap, profile.LimitClassDigestTruncatedReasonBucketMaxReasonsReasonCap)
	},
	func(webhook *config.NotificationWebhook, profile config.LimitAlertRecipientProfile) {
		inheritWebhookProfilePositiveInt(&webhook.LimitClassDigestTruncatedReasonBucketMaxReasonsItemCap, profile.LimitClassDigestTruncatedReasonBucketMaxReasonsItemCap)
	},
	func(webhook *config.NotificationWebhook, profile config.LimitAlertRecipientProfile) {
		inheritWebhookProfilePositiveInt(&webhook.LimitClassDigestTruncatedReasonBucketMaxReasonsPriorityWeight, profile.LimitClassDigestTruncatedReasonBucketMaxReasonsPriorityWeight)
	},
	func(webhook *config.NotificationWebhook, profile config.LimitAlertRecipientProfile) {
		inheritWebhookProfilePositiveInt(&webhook.LimitClassDigestTruncatedReasonBucketMaxReasonsReasonWeight, profile.LimitClassDigestTruncatedReasonBucketMaxReasonsReasonWeight)
	},
	func(webhook *config.NotificationWebhook, profile config.LimitAlertRecipientProfile) {
		inheritWebhookProfilePositiveInt(&webhook.LimitClassDigestTruncatedReasonBucketMaxReasonsItemWeight, profile.LimitClassDigestTruncatedReasonBucketMaxReasonsItemWeight)
	},
	func(webhook *config.NotificationWebhook, profile config.LimitAlertRecipientProfile) {
		inheritWebhookProfileString(&webhook.LimitClassDigestTruncatedReasonBucketMaxReasonsDominantMode, profile.LimitClassDigestTruncatedReasonBucketMaxReasonsDominantMode)
	},
	func(webhook *config.NotificationWebhook, profile config.LimitAlertRecipientProfile) {
		inheritWebhookProfilePositiveInt(&webhook.LimitClassDigestTruncatedReasonBucketMaxReasonsMinReasons, profile.LimitClassDigestTruncatedReasonBucketMaxReasonsMinReasons)
	},
	func(webhook *config.NotificationWebhook, profile config.LimitAlertRecipientProfile) {
		inheritWebhookProfilePositiveInt(&webhook.LimitClassDigestTruncatedReasonBucketMaxReasonsMinItems, profile.LimitClassDigestTruncatedReasonBucketMaxReasonsMinItems)
	},
	func(webhook *config.NotificationWebhook, profile config.LimitAlertRecipientProfile) {
		inheritWebhookProfilePositiveInt(&webhook.LimitClassDigestMinSummaryBucketClassPriority, profile.LimitClassDigestMinSummaryBucketClassPriority)
	},
	func(webhook *config.NotificationWebhook, profile config.LimitAlertRecipientProfile) {
		inheritWebhookProfilePositiveInt(&webhook.LimitClassDigestMaxSummaryBucketClasses, profile.LimitClassDigestMaxSummaryBucketClasses)
	},
	func(webhook *config.NotificationWebhook, profile config.LimitAlertRecipientProfile) {
		inheritWebhookProfileStringSlice(&webhook.LimitAlertTypes, profile.LimitAlertTypes)
	},
	func(webhook *config.NotificationWebhook, profile config.LimitAlertRecipientProfile) {
		inheritWebhookProfileStringSlice(&webhook.LimitAlertKeyTypes, profile.LimitAlertKeyTypes)
	},
	func(webhook *config.NotificationWebhook, profile config.LimitAlertRecipientProfile) {
		inheritWebhookProfileStringSlice(&webhook.LimitAlertBucketClasses, profile.LimitAlertBucketClasses)
	},
	func(webhook *config.NotificationWebhook, profile config.LimitAlertRecipientProfile) {
		inheritWebhookProfileString(&webhook.LimitAlertBucketIDRegex, profile.LimitAlertBucketIDRegex)
	},
	func(webhook *config.NotificationWebhook, profile config.LimitAlertRecipientProfile) {
		inheritWebhookProfileString(&webhook.LimitAlertCooldown, profile.LimitAlertCooldown)
	},
	func(webhook *config.NotificationWebhook, profile config.LimitAlertRecipientProfile) {
		inheritWebhookProfileString(&webhook.LimitClassSnoozeExpiryCooldown, profile.LimitClassSnoozeExpiryCooldown)
	},
	func(webhook *config.NotificationWebhook, profile config.LimitAlertRecipientProfile) {
		inheritWebhookProfileString(&webhook.LimitClassSnoozeExpiryWithin, profile.LimitClassSnoozeExpiryWithin)
	},
	func(webhook *config.NotificationWebhook, profile config.LimitAlertRecipientProfile) {
		inheritWebhookProfileStringSlice(&webhook.LimitClassSnoozeExpiryStages, profile.LimitClassSnoozeExpiryStages)
	},
	func(webhook *config.NotificationWebhook, profile config.LimitAlertRecipientProfile) {
		inheritWebhookProfileStringSlice(&webhook.LimitClassSnoozeEventTypes, profile.LimitClassSnoozeEventTypes)
	},
}

func effectiveNotificationWebhookLimitAlertProfile(webhook config.NotificationWebhook, profiles map[string]config.LimitAlertRecipientProfile) config.NotificationWebhook {
	profile, ok := notificationWebhookLimitAlertProfile(webhook, profiles)
	if !ok {
		return webhook
	}
	for _, apply := range notificationWebhookLimitAlertProfileAppliers {
		apply(&webhook, profile)
	}
	return webhook
}

func effectiveNotificationWebhookLimitClassDigestProfile(webhook config.NotificationWebhook, profiles map[string]config.LimitAlertRecipientProfile) config.NotificationWebhook {
	if len(webhook.LimitClassDigestProfileChain) == 0 && strings.TrimSpace(webhook.LimitClassDigestProfile) == "" {
		return webhook
	}
	merged := config.LimitAlertRecipientProfile{}
	for _, profileName := range webhook.LimitClassDigestProfileChain {
		profile, ok := profiles[strings.TrimSpace(profileName)]
		if !ok {
			continue
		}
		merged = mergedLimitClassDigestRecipientProfile(merged, profile)
	}
	if profileName := strings.TrimSpace(webhook.LimitClassDigestProfile); profileName != "" {
		if profile, ok := profiles[profileName]; ok {
			merged = mergedLimitClassDigestRecipientProfile(merged, profile)
		}
	}
	for _, apply := range notificationWebhookLimitAlertProfileAppliers {
		apply(&webhook, merged)
	}
	return webhook
}

func resolveNotificationWebhookHiddenStrategyPolicyPresets(webhook config.NotificationWebhook, presets map[string]config.LimitClassDigestHiddenStrategyPolicy) config.NotificationWebhook {
	webhook.LimitClassDigestTruncatedReasonBucketExactSeverityPolicy = resolvedNotificationWebhookHiddenStrategyPolicy(
		webhook.LimitClassDigestTruncatedReasonBucketExactSeverityPolicy,
		webhook.LimitClassDigestTruncatedReasonBucketExactSeverityPolicyPresetChain,
		webhook.LimitClassDigestTruncatedReasonBucketExactSeverityPolicyPreset,
		presets,
	)
	webhook.LimitClassDigestTruncatedReasonBucketMinSeverityPolicy = resolvedNotificationWebhookHiddenStrategyPolicy(
		webhook.LimitClassDigestTruncatedReasonBucketMinSeverityPolicy,
		webhook.LimitClassDigestTruncatedReasonBucketMinSeverityPolicyPresetChain,
		webhook.LimitClassDigestTruncatedReasonBucketMinSeverityPolicyPreset,
		presets,
	)
	webhook.LimitClassDigestTruncatedReasonBucketMaxReasonsPolicy = resolvedNotificationWebhookHiddenStrategyPolicy(
		webhook.LimitClassDigestTruncatedReasonBucketMaxReasonsPolicy,
		webhook.LimitClassDigestTruncatedReasonBucketMaxReasonsPolicyPresetChain,
		webhook.LimitClassDigestTruncatedReasonBucketMaxReasonsPolicyPreset,
		presets,
	)
	return webhook
}

func notificationWebhookLimitAlertProfile(webhook config.NotificationWebhook, profiles map[string]config.LimitAlertRecipientProfile) (config.LimitAlertRecipientProfile, bool) {
	profileName := strings.TrimSpace(webhook.LimitAlertProfile)
	if profileName == "" {
		return config.LimitAlertRecipientProfile{}, false
	}
	profile, ok := profiles[profileName]
	return profile, ok
}

func inheritWebhookProfileString(target *string, fallback string) {
	if strings.TrimSpace(*target) == "" {
		*target = fallback
	}
}

func inheritWebhookProfilePositiveInt(target *int, fallback int) {
	if *target <= 0 {
		*target = fallback
	}
}

func inheritWebhookProfileStringSlice(target *[]string, fallback []string) {
	if len(*target) == 0 && len(fallback) > 0 {
		*target = append([]string(nil), fallback...)
	}
}

func inheritWebhookProfileStringMap(target *map[string]string, fallback map[string]string) {
	if len(*target) == 0 && len(fallback) > 0 {
		cloned := make(map[string]string, len(fallback))
		for key, value := range fallback {
			cloned[key] = value
		}
		*target = cloned
	}
}

func inheritWebhookProfileStringSliceMap(target *map[string][]string, fallback map[string][]string) {
	if len(*target) == 0 && len(fallback) > 0 {
		cloned := make(map[string][]string, len(fallback))
		for key, values := range fallback {
			cloned[key] = append([]string(nil), values...)
		}
		*target = cloned
	}
}

func inheritWebhookProfileHiddenStrategyPolicy(target **config.LimitClassDigestHiddenStrategyPolicy, fallback *config.LimitClassDigestHiddenStrategyPolicy) {
	if *target != nil || fallback == nil {
		return
	}
	cloned := *fallback
	*target = &cloned
}

func mergedLimitClassDigestRecipientProfile(base config.LimitAlertRecipientProfile, overlay config.LimitAlertRecipientProfile) config.LimitAlertRecipientProfile {
	mergedWebhook := notificationWebhookFromLimitAlertRecipientProfile(overlay)
	for _, apply := range notificationWebhookLimitAlertProfileAppliers {
		apply(&mergedWebhook, base)
	}
	return limitAlertRecipientProfileFromNotificationWebhook(mergedWebhook)
}

func notificationWebhookFromLimitAlertRecipientProfile(profile config.LimitAlertRecipientProfile) config.NotificationWebhook {
	var webhook config.NotificationWebhook
	bytes, err := json.Marshal(profile)
	if err != nil {
		return webhook
	}
	_ = json.Unmarshal(bytes, &webhook)
	return webhook
}

func limitAlertRecipientProfileFromNotificationWebhook(webhook config.NotificationWebhook) config.LimitAlertRecipientProfile {
	var profile config.LimitAlertRecipientProfile
	bytes, err := json.Marshal(webhook)
	if err != nil {
		return profile
	}
	_ = json.Unmarshal(bytes, &profile)
	return profile
}

func resolvedNotificationWebhookHiddenStrategyPolicy(policy *config.LimitClassDigestHiddenStrategyPolicy, presetChain []string, presetName string, presets map[string]config.LimitClassDigestHiddenStrategyPolicy) *config.LimitClassDigestHiddenStrategyPolicy {
	var resolved *config.LimitClassDigestHiddenStrategyPolicy
	for _, chainPresetName := range presetChain {
		preset, ok := resolvedHiddenStrategyPolicyPreset(chainPresetName, presets)
		if !ok {
			continue
		}
		resolved = mergedLimitClassDigestHiddenStrategyPolicy(resolved, &preset)
	}
	if preset, ok := resolvedHiddenStrategyPolicyPreset(presetName, presets); ok {
		resolved = mergedLimitClassDigestHiddenStrategyPolicy(resolved, &preset)
	}
	if policy != nil {
		resolved = mergedLimitClassDigestHiddenStrategyPolicy(resolved, policy)
	}
	return resolved
}

func resolvedHiddenStrategyPolicyPreset(name string, presets map[string]config.LimitClassDigestHiddenStrategyPolicy) (config.LimitClassDigestHiddenStrategyPolicy, bool) {
	name = strings.TrimSpace(name)
	if name == "" {
		return config.LimitClassDigestHiddenStrategyPolicy{}, false
	}
	preset, ok := presets[name]
	return preset, ok
}

func mergedLimitClassDigestHiddenStrategyPolicy(base *config.LimitClassDigestHiddenStrategyPolicy, overlay *config.LimitClassDigestHiddenStrategyPolicy) *config.LimitClassDigestHiddenStrategyPolicy {
	if base == nil && overlay == nil {
		return nil
	}
	var merged config.LimitClassDigestHiddenStrategyPolicy
	if base != nil {
		merged = *base
	}
	if overlay == nil {
		return &merged
	}
	if value := strings.TrimSpace(overlay.DominantMode); value != "" {
		merged.DominantMode = value
	}
	if overlay.MinReasons > 0 {
		merged.MinReasons = overlay.MinReasons
	}
	if overlay.MinItems > 0 {
		merged.MinItems = overlay.MinItems
	}
	if overlay.PriorityWeight > 0 {
		merged.PriorityWeight = overlay.PriorityWeight
	}
	if overlay.ReasonWeight > 0 {
		merged.ReasonWeight = overlay.ReasonWeight
	}
	if overlay.ItemWeight > 0 {
		merged.ItemWeight = overlay.ItemWeight
	}
	if overlay.PriorityCap > 0 {
		merged.PriorityCap = overlay.PriorityCap
	}
	if overlay.ReasonCap > 0 {
		merged.ReasonCap = overlay.ReasonCap
	}
	if overlay.ItemCap > 0 {
		merged.ItemCap = overlay.ItemCap
	}
	return &merged
}
