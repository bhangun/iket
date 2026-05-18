package api

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/bhangun/iket/pkg/config"
	"github.com/bhangun/iket/pkg/core/gateway"
	"regexp"
	"strings"
	"time"
)

func (api *ManagementAPI) reconcileGatewayLimitAlertNotifications(now time.Time) {
	cfg := api.gateway.GetConfig()
	if cfg == nil {
		return
	}
	policy := cfg.Security.MutationPolicy.LimitAlertNotifications
	if !policy.Enabled {
		return
	}
	interval := policyAlertNotificationInterval(policy)
	minInterval := policyAlertNotificationMinInterval(policy)
	window := policyAlertNotificationWindow(policy)
	minCount := policyAlertNotificationMinCount(policy)
	minSeverity := normalizeSLABreachTier(policy.MinSeverity)

	api.queueDigestNotifyMu.Lock()
	lastSent := api.lastLimitAlertNotificationAt
	lastChecksum := api.lastLimitAlertNotificationChecksum
	api.queueDigestNotifyMu.Unlock()
	if !lastSent.IsZero() && now.Sub(lastSent) < interval {
		return
	}

	evaluationMinCount := effectiveLimitAlertEvaluationMinCount(minCount, cfg, policy)
	summary := api.gateway.RouteLimitAlertSummaryAt(now, window, evaluationMinCount)
	summary.Window = window.String()
	summary = applyLimitAlertPolicies(summary, policy, cfg)
	summary = filterLimitAlertSummaryBySeverity(summary, minSeverity)
	openedEvents, stageChangedEvents, resolvedEvents := api.updateGatewayLimitAlertIncidentState(summary.Alerts, now)
	if summary.TotalAlerts == 0 {
		for _, event := range resolvedEvents {
			api.emitManagementEvent(event)
		}
		api.queueDigestNotifyMu.Lock()
		api.lastLimitAlertNotificationAt = now
		api.lastLimitAlertNotificationChecksum = ""
		api.queueDigestNotifyMu.Unlock()
		return
	}

	checksum := proposalQueueDigestChecksum(map[string]interface{}{
		"window":         summary.Window,
		"window_seconds": summary.WindowSeconds,
		"min_count":      summary.MinCount,
		"by_severity":    summary.BySeverity,
		"alerts":         summary.Alerts,
	})
	if policy.OnlyOnChange && checksum != "" && checksum == lastChecksum {
		return
	}
	if !lastSent.IsZero() && now.Sub(lastSent) < minInterval {
		return
	}

	api.emitManagementEvent(managementWebhookEvent{
		Event:      "gateway.limit_alert_digest",
		OccurredAt: now,
		Data: map[string]interface{}{
			"window":         summary.Window,
			"window_seconds": summary.WindowSeconds,
			"min_count":      summary.MinCount,
			"min_severity":   minSeverity,
			"total_alerts":   summary.TotalAlerts,
			"by_severity":    summary.BySeverity,
			"alerts":         summary.Alerts,
		},
	})
	for _, event := range openedEvents {
		api.emitManagementEvent(event)
	}
	for _, event := range stageChangedEvents {
		api.emitManagementEvent(event)
	}
	for _, event := range resolvedEvents {
		api.emitManagementEvent(event)
	}
	for _, alert := range summary.Alerts {
		api.emitManagementEvent(managementWebhookEvent{
			Event:      "gateway.limit_alert",
			OccurredAt: now,
			Data: map[string]interface{}{
				"window":                summary.Window,
				"window_seconds":        summary.WindowSeconds,
				"min_count":             summary.MinCount,
				"severity":              alert.Severity,
				"service_name":          alert.ServiceName,
				"route_path":            alert.RoutePath,
				"limit_type":            alert.LimitType,
				"key_type":              alert.KeyType,
				"bucket_id":             alert.BucketID,
				"bucket_class":          alert.BucketClass,
				"count":                 alert.Count,
				"queued_admissions":     alert.QueuedAdmissions,
				"queue_full_rejections": alert.QueueFullRejections,
				"average_queue_wait_ms": alert.AverageQueueWaitMs,
				"max_queue_wait_ms":     alert.MaxQueueWaitMs,
				"since":                 alert.Since,
			},
		})
	}

	api.queueDigestNotifyMu.Lock()
	api.lastLimitAlertNotificationAt = now
	api.lastLimitAlertNotificationChecksum = checksum
	api.queueDigestNotifyMu.Unlock()
}

func (api *ManagementAPI) autoNotifyGatewayLimitAlerts() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		api.reconcileGatewayLimitAlertNotifications(time.Now().UTC())
	}
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

func (api *ManagementAPI) updateGatewayLimitAlertIncidentState(alerts []gateway.RouteLimitAlert, now time.Time) ([]managementWebhookEvent, []managementWebhookEvent, []managementWebhookEvent) {
	current := make(map[string]gateway.RouteLimitAlert, len(alerts))
	for _, alert := range alerts {
		current[gatewayLimitAlertIncidentKey(alert)] = alert
	}

	api.queueDigestNotifyMu.Lock()
	defer api.queueDigestNotifyMu.Unlock()

	opened := make([]managementWebhookEvent, 0)
	stageChanged := make([]managementWebhookEvent, 0)
	resolved := make([]managementWebhookEvent, 0)

	for key, alert := range current {
		state, ok := api.limitAlertIncidentState[key]
		if !ok || strings.TrimSpace(state.IncidentID) == "" {
			state = gatewayLimitAlertIncidentState{
				IncidentID:  fmt.Sprintf("lal-%s-%s", now.UTC().Format("20060102-150405.000000000"), shortLimitAlertIncidentSuffix(key)),
				Severity:    strings.TrimSpace(alert.Severity),
				ServiceName: strings.TrimSpace(alert.ServiceName),
				RoutePath:   strings.TrimSpace(alert.RoutePath),
				LimitType:   strings.TrimSpace(alert.LimitType),
				KeyType:     strings.TrimSpace(alert.KeyType),
				BucketID:    strings.TrimSpace(alert.BucketID),
				BucketClass: strings.TrimSpace(alert.BucketClass),
				FirstSeenAt: now,
				LastSeenAt:  now,
				LastCount:   alert.Count,
			}
			api.limitAlertIncidentState[key] = state
			opened = append(opened, managementWebhookEvent{
				Event:      "gateway.limit_alert_opened",
				OccurredAt: now,
				Data:       buildGatewayLimitAlertIncidentData(state, alert, now),
			})
			continue
		}

		previousSeverity := state.Severity
		state.LastSeenAt = now
		state.LastCount = alert.Count
		if slaBreachTierRank(alert.Severity) > slaBreachTierRank(previousSeverity) {
			state.Severity = strings.TrimSpace(alert.Severity)
			api.limitAlertIncidentState[key] = state
			data := buildGatewayLimitAlertIncidentData(state, alert, now)
			data["previous_severity"] = previousSeverity
			stageChanged = append(stageChanged, managementWebhookEvent{
				Event:      "gateway.limit_alert_stage_changed",
				OccurredAt: now,
				Data:       data,
			})
			continue
		}
		api.limitAlertIncidentState[key] = state
	}

	for key, state := range api.limitAlertIncidentState {
		if _, ok := current[key]; ok {
			continue
		}
		resolved = append(resolved, managementWebhookEvent{
			Event:      "gateway.limit_alert_resolved",
			OccurredAt: now,
			Data: buildGatewayLimitAlertIncidentData(state, gateway.RouteLimitAlert{
				Severity:    state.Severity,
				ServiceName: state.ServiceName,
				RoutePath:   state.RoutePath,
				LimitType:   state.LimitType,
				KeyType:     state.KeyType,
				BucketID:    state.BucketID,
				BucketClass: state.BucketClass,
				Count:       state.LastCount,
			}, now),
		})
		delete(api.limitAlertIncidentState, key)
	}

	return opened, stageChanged, resolved
}

func gatewayLimitAlertIncidentKey(alert gateway.RouteLimitAlert) string {
	return strings.TrimSpace(alert.ServiceName) + "|" + strings.TrimSpace(alert.RoutePath) + "|" + strings.TrimSpace(alert.LimitType) + "|" + strings.TrimSpace(alert.BucketID)
}

func shortLimitAlertIncidentSuffix(key string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(key)))
	return hex.EncodeToString(sum[:4])
}

func buildGatewayLimitAlertIncidentData(state gatewayLimitAlertIncidentState, alert gateway.RouteLimitAlert, now time.Time) map[string]interface{} {
	age := 0.0
	if !state.FirstSeenAt.IsZero() {
		age = now.Sub(state.FirstSeenAt).Seconds()
		if age < 0 {
			age = 0
		}
	}
	severity := strings.TrimSpace(alert.Severity)
	if severity == "" {
		severity = strings.TrimSpace(state.Severity)
	}
	count := alert.Count
	if count <= 0 {
		count = state.LastCount
	}
	return map[string]interface{}{
		"incident_id":           strings.TrimSpace(state.IncidentID),
		"severity":              severity,
		"service_name":          strings.TrimSpace(state.ServiceName),
		"route_path":            strings.TrimSpace(state.RoutePath),
		"limit_type":            strings.TrimSpace(state.LimitType),
		"key_type":              strings.TrimSpace(alert.KeyType),
		"bucket_id":             strings.TrimSpace(alert.BucketID),
		"bucket_class":          strings.TrimSpace(alert.BucketClass),
		"count":                 count,
		"queued_admissions":     alert.QueuedAdmissions,
		"queue_full_rejections": alert.QueueFullRejections,
		"average_queue_wait_ms": alert.AverageQueueWaitMs,
		"max_queue_wait_ms":     alert.MaxQueueWaitMs,
		"first_seen_at":         state.FirstSeenAt,
		"last_seen_at":          state.LastSeenAt,
		"incident_age_seconds":  age,
	}
}
