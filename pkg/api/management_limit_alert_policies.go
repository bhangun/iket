package api

import (
	"regexp"
	"strings"

	"github.com/bhangun/iket/pkg/config"
	"github.com/bhangun/iket/pkg/core/gateway"
)

func applyLimitAlertPolicies(summary gateway.RouteLimitAlertSummary, policy config.PolicyAlertNotificationPolicy, cfg *config.Config) gateway.RouteLimitAlertSummary {
	filtered := gateway.RouteLimitAlertSummary{
		Window:        summary.Window,
		WindowSeconds: summary.WindowSeconds,
		MinCount:      summary.MinCount,
		BySeverity:    map[string]int{"warning": 0, "elevated": 0, "critical": 0},
	}
	for _, alert := range summary.Alerts {
		alert = classifyRouteLimitAlert(cfg, alert)
		routePolicy, bucketPolicy := routeLimitAlertPolicyForAlert(cfg, alert)
		updated, include := applyLimitAlertPolicy(alert, summary.MinCount, policy, routePolicy, bucketPolicy)
		if !include {
			continue
		}
		filtered.Alerts = append(filtered.Alerts, updated)
		filtered.BySeverity[updated.Severity]++
	}
	filtered.TotalAlerts = len(filtered.Alerts)
	return filtered
}

func filterLimitAlertSummaryBySeverity(summary gateway.RouteLimitAlertSummary, minSeverity string) gateway.RouteLimitAlertSummary {
	minRank := slaBreachTierRank(minSeverity)
	if minRank <= 0 {
		return summary
	}
	filtered := gateway.RouteLimitAlertSummary{
		Window:        summary.Window,
		WindowSeconds: summary.WindowSeconds,
		MinCount:      summary.MinCount,
		BySeverity:    map[string]int{"warning": 0, "elevated": 0, "critical": 0},
	}
	for _, alert := range summary.Alerts {
		if slaBreachTierRank(alert.Severity) < minRank {
			continue
		}
		filtered.Alerts = append(filtered.Alerts, alert)
		filtered.BySeverity[alert.Severity]++
	}
	filtered.TotalAlerts = len(filtered.Alerts)
	return filtered
}

func classifyRouteLimitAlerts(cfg *config.Config, alerts []gateway.RouteLimitAlert) []gateway.RouteLimitAlert {
	if cfg == nil || len(alerts) == 0 {
		return alerts
	}
	classified := make([]gateway.RouteLimitAlert, 0, len(alerts))
	for _, alert := range alerts {
		classified = append(classified, classifyRouteLimitAlert(cfg, alert))
	}
	return classified
}

func classifyRouteLimitAlert(cfg *config.Config, alert gateway.RouteLimitAlert) gateway.RouteLimitAlert {
	if cfg == nil {
		return alert
	}
	alert.BucketClass = gateway.ResolveLimiterBucketClass(cfg, alert.KeyType, alert.RawBucketKey)
	return alert
}

func effectiveLimitAlertEvaluationMinCount(defaultMinCount int, cfg *config.Config, policy config.PolicyAlertNotificationPolicy) int {
	minCount := defaultMinCount
	if minCount <= 0 {
		minCount = 3
	}
	if policy.MinCount > 0 && policy.MinCount < minCount {
		minCount = policy.MinCount
	}
	for _, thresholds := range policy.LimitTypePolicies {
		if thresholds.WarningCount > 0 && thresholds.WarningCount < minCount {
			minCount = thresholds.WarningCount
		}
	}
	if cfg == nil {
		return minCount
	}
	for _, serviceConfig := range cfg.Services {
		for _, service := range serviceConfig.Services {
			for _, route := range service.Routes {
				if route.LimitAlertPolicy == nil {
					continue
				}
				if route.LimitAlertPolicy.MinCount > 0 && route.LimitAlertPolicy.MinCount < minCount {
					minCount = route.LimitAlertPolicy.MinCount
				}
				for _, thresholds := range route.LimitAlertPolicy.LimitTypePolicies {
					if thresholds.WarningCount > 0 && thresholds.WarningCount < minCount {
						minCount = thresholds.WarningCount
					}
				}
				for _, bucketPolicy := range route.LimitAlertPolicy.BucketPolicies {
					if bucketPolicy.MinCount > 0 && bucketPolicy.MinCount < minCount {
						minCount = bucketPolicy.MinCount
					}
					for _, thresholds := range bucketPolicy.LimitTypePolicies {
						if thresholds.WarningCount > 0 && thresholds.WarningCount < minCount {
							minCount = thresholds.WarningCount
						}
					}
				}
			}
		}
	}
	return minCount
}

func applyLimitAlertPolicy(alert gateway.RouteLimitAlert, defaultMinCount int, global config.PolicyAlertNotificationPolicy, routePolicy *config.RouteLimitAlertPolicyConfig, bucketPolicy *config.LimitAlertBucketPolicyConfig) (gateway.RouteLimitAlert, bool) {
	minCount := defaultMinCount
	if routePolicy != nil && routePolicy.MinCount > 0 {
		minCount = routePolicy.MinCount
	}
	policies := global.LimitTypePolicies
	minSeverity := normalizeSLABreachTier(global.MinSeverity)
	if routePolicy != nil {
		if len(routePolicy.LimitTypePolicies) > 0 {
			policies = routePolicy.LimitTypePolicies
		}
		if override := normalizeSLABreachTier(routePolicy.MinSeverity); override != "" {
			minSeverity = override
		}
	}
	if bucketPolicy != nil {
		if bucketPolicy.MinCount > 0 {
			minCount = bucketPolicy.MinCount
		}
		if len(bucketPolicy.LimitTypePolicies) > 0 {
			policies = bucketPolicy.LimitTypePolicies
		}
		if override := normalizeSLABreachTier(bucketPolicy.MinSeverity); override != "" {
			minSeverity = override
		}
	}
	limitType := strings.ToLower(strings.TrimSpace(alert.LimitType))
	policy, ok := policies[limitType]

	warningThreshold := minCount
	if warningThreshold <= 0 {
		warningThreshold = 3
	}
	if ok && policy.WarningCount > 0 {
		warningThreshold = policy.WarningCount
	}
	elevatedThreshold := limitAlertMaxInt(warningThreshold*2, 6)
	if limitType == "concurrency_queue_full" {
		elevatedThreshold = warningThreshold
	}
	if ok && policy.ElevatedCount > 0 {
		elevatedThreshold = policy.ElevatedCount
	}
	criticalThreshold := limitAlertMaxInt(warningThreshold*4, 12)
	if ok && policy.CriticalCount > 0 {
		criticalThreshold = policy.CriticalCount
	}
	if alert.Count < warningThreshold {
		return alert, false
	}

	severity := "warning"
	if alert.Count >= criticalThreshold {
		severity = "critical"
	} else if alert.Count >= elevatedThreshold {
		severity = "elevated"
	}
	if minSeverity != "" && slaBreachTierRank(minSeverity) > slaBreachTierRank(severity) {
		severity = minSeverity
	}
	alert.Severity = severity
	return alert, true
}

func routeLimitAlertPolicyForAlert(cfg *config.Config, alert gateway.RouteLimitAlert) (*config.RouteLimitAlertPolicyConfig, *config.LimitAlertBucketPolicyConfig) {
	if cfg == nil {
		return nil, nil
	}
	serviceName := strings.TrimSpace(alert.ServiceName)
	routePath := strings.TrimSpace(alert.RoutePath)
	for _, serviceConfig := range cfg.Services {
		for _, service := range serviceConfig.Services {
			if strings.TrimSpace(service.Name) != serviceName {
				continue
			}
			for _, route := range service.Routes {
				if strings.TrimSpace(service.EffectiveRoutePath(route)) == routePath && route.LimitAlertPolicy != nil {
					return route.LimitAlertPolicy, matchingLimitAlertBucketPolicy(cfg, route.LimitAlertPolicy, alert)
				}
			}
		}
	}
	return nil, nil
}

func matchingLimitAlertBucketPolicy(cfg *config.Config, routePolicy *config.RouteLimitAlertPolicyConfig, alert gateway.RouteLimitAlert) *config.LimitAlertBucketPolicyConfig {
	if routePolicy == nil || len(routePolicy.BucketPolicies) == 0 {
		return nil
	}
	for i := range routePolicy.BucketPolicies {
		effectivePolicy := effectiveLimitAlertBucketPolicyForMatch(cfg, routePolicy.BucketPolicies[i])
		policy := &effectivePolicy
		if bucketClass := strings.TrimSpace(policy.BucketClass); bucketClass != "" {
			if strings.EqualFold(bucketClass, strings.TrimSpace(alert.BucketClass)) {
				return policy
			}
			continue
		}
		keyType := strings.ToLower(strings.TrimSpace(alert.KeyType))
		bucketKey := strings.TrimSpace(alert.RawBucketKey)
		if keyType == "" || bucketKey == "" {
			continue
		}
		if strings.ToLower(strings.TrimSpace(policy.KeyType)) != keyType {
			continue
		}
		re, err := regexp.Compile(strings.TrimSpace(policy.BucketRegex))
		if err != nil {
			continue
		}
		if re.MatchString(bucketKey) {
			return policy
		}
	}
	return nil
}

func effectiveLimitAlertBucketPolicyForMatch(cfg *config.Config, policy config.LimitAlertBucketPolicyConfig) config.LimitAlertBucketPolicyConfig {
	if strings.TrimSpace(policy.Preset) == "" {
		return policy
	}
	if cfg == nil {
		return policy
	}
	preset, ok := cfg.Security.LimiterClassPresets[strings.TrimSpace(policy.Preset)]
	if !ok {
		return policy
	}
	if strings.TrimSpace(policy.BucketClass) == "" {
		policy.BucketClass = preset.BucketClass
	}
	if policy.MinCount == 0 {
		policy.MinCount = preset.AlertMinCount
	}
	if strings.TrimSpace(policy.MinSeverity) == "" {
		policy.MinSeverity = preset.AlertMinSeverity
	}
	if len(policy.LimitTypePolicies) == 0 && len(preset.AlertLimitTypePolicies) > 0 {
		policy.LimitTypePolicies = copyLimitAlertTypePolicies(preset.AlertLimitTypePolicies)
	}
	return policy
}

func copyLimitAlertTypePolicies(src map[string]config.LimitAlertTypePolicy) map[string]config.LimitAlertTypePolicy {
	if len(src) == 0 {
		return nil
	}
	dst := make(map[string]config.LimitAlertTypePolicy, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

func limitAlertMaxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
