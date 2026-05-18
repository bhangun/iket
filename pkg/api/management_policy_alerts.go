package api

import (
	"fmt"
	"github.com/bhangun/iket/pkg/core/gateway"
	"net/http"
	"net/url"
	"strings"
	"time"
)

func (api *ManagementAPI) reconcileProposalQueueDigestNotifications(now time.Time) {
	cfg := api.gateway.GetConfig()
	if cfg == nil {
		return
	}
	policy := cfg.Security.MutationPolicy.ProposalQueue.Notifications
	if !policy.Enabled {
		return
	}
	interval := proposalQueueDigestNotificationInterval(policy)
	minInterval := proposalQueueDigestNotificationMinInterval(policy)
	environments := append([]string(nil), policy.Environments...)
	if len(environments) == 0 {
		environments = []string{""}
	}
	for _, environment := range environments {
		key := proposalQueueDigestNotificationKey(environment)
		api.queueDigestNotifyMu.Lock()
		lastSent := api.lastQueueDigestNotificationAt[key]
		lastChecksum := api.lastQueueDigestNotificationChecksum[key]
		api.queueDigestNotifyMu.Unlock()
		if !lastSent.IsZero() && now.Sub(lastSent) < interval {
			continue
		}
		req := &http.Request{Method: http.MethodGet, URL: &url.URL{}}
		query := req.URL.Query()
		if strings.TrimSpace(environment) != "" {
			query.Set("environment", strings.TrimSpace(environment))
		}
		req.URL.RawQuery = query.Encode()
		snapshot, statusCode, err := api.buildProposalQueueSnapshot(req)
		if err != nil || statusCode != http.StatusOK {
			continue
		}
		digest := buildProposalQueueDigestEventData(snapshot)
		checksum := proposalQueueDigestChecksum(digest)
		if policy.OnlyOnChange && checksum != "" && checksum == lastChecksum {
			continue
		}
		if !lastSent.IsZero() && now.Sub(lastSent) < minInterval {
			continue
		}
		slaBreachCount := 0
		if attention, ok := digest["attention_required"].(map[string]interface{}); ok {
			slaBreachCount = intValue(attention["sla_breach_count"])
		}
		slaState, resolvedState, previousState := api.updateProposalQueueSLABreachState(key, now, slaBreachCount)
		if policy.OnlyOnSLABreach && slaBreachCount == 0 {
			if resolvedState == nil {
				continue
			}
		}
		payload := managementWebhookEvent{
			Event:       "proposal.digest",
			OccurredAt:  now,
			Environment: strings.TrimSpace(environment),
			Data:        digest,
		}
		api.emitManagementEvent(payload)
		if slaBreachCount > 0 {
			slaStateData := buildProposalQueueSLABreachStateData(slaState, now)
			previousTier := ""
			if previousState != nil {
				previousTier = proposalQueueSLABreachTierAt(*previousState, now)
			}
			currentTier := strings.TrimSpace(fmt.Sprint(slaStateData["tier"]))
			if previousTier != currentTier {
				api.emitManagementEvent(managementWebhookEvent{
					Event:       "proposal.sla_stage_changed",
					OccurredAt:  now,
					Environment: strings.TrimSpace(environment),
					Data: map[string]interface{}{
						"queue_summary":        digest["queue_summary"],
						"sla_breach_state":     slaStateData,
						"incident_id":          slaStateData["incident_id"],
						"previous_stage":       previousTier,
						"current_stage":        currentTier,
						"triggered_from_event": "proposal.digest",
					},
				})
			}
			api.emitManagementEvent(managementWebhookEvent{
				Event:       "proposal.sla_breach",
				OccurredAt:  now,
				Environment: strings.TrimSpace(environment),
				Data: map[string]interface{}{
					"queue_summary":        digest["queue_summary"],
					"attention_required":   digest["attention_required"],
					"top_sla_breaches":     digest["top_sla_breaches"],
					"sla_breach_state":     slaStateData,
					"sla_breach_tier":      slaStateData["tier"],
					"triggered_from_event": "proposal.digest",
				},
			})
		} else if resolvedState != nil {
			resolvedStateData := buildProposalQueueSLABreachStateData(*resolvedState, now)
			api.emitManagementEvent(managementWebhookEvent{
				Event:       "proposal.sla_resolved",
				OccurredAt:  now,
				Environment: strings.TrimSpace(environment),
				Data: map[string]interface{}{
					"queue_summary":       digest["queue_summary"],
					"resolved_sla_state":  resolvedStateData,
					"incident_id":         resolvedStateData["incident_id"],
					"resolved_from_event": "proposal.digest",
				},
			})
		}
		api.queueDigestNotifyMu.Lock()
		api.lastQueueDigestNotificationAt[key] = now
		api.lastQueueDigestNotificationChecksum[key] = checksum
		api.queueDigestNotifyMu.Unlock()
	}
}

func (api *ManagementAPI) reconcileGatewayPolicyAlertNotifications(now time.Time) {
	cfg := api.gateway.GetConfig()
	if cfg == nil {
		return
	}
	policy := cfg.Security.MutationPolicy.PolicyAlertNotifications
	if !policy.Enabled {
		return
	}
	interval := policyAlertNotificationInterval(policy)
	minInterval := policyAlertNotificationMinInterval(policy)
	window := policyAlertNotificationWindow(policy)
	minCount := policyAlertNotificationMinCount(policy)
	minSeverity := normalizeSLABreachTier(policy.MinSeverity)

	api.queueDigestNotifyMu.Lock()
	lastSent := api.lastPolicyAlertNotificationAt
	lastChecksum := api.lastPolicyAlertNotificationChecksum
	api.queueDigestNotifyMu.Unlock()
	if !lastSent.IsZero() && now.Sub(lastSent) < interval {
		return
	}

	summary := api.gateway.PolicyAlertSummaryAt(now, window, minCount)
	summary.Window = window.String()
	summary = filterPolicyAlertSummaryBySeverity(summary, minSeverity)
	openedEvents, stageChangedEvents, resolvedEvents := api.updateGatewayPolicyAlertIncidentState(summary.Alerts, now)
	if summary.TotalAlerts == 0 {
		for _, event := range resolvedEvents {
			api.emitManagementEvent(event)
		}
		api.queueDigestNotifyMu.Lock()
		api.lastPolicyAlertNotificationAt = now
		api.lastPolicyAlertNotificationChecksum = ""
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
		Event:      "gateway.policy_alert_digest",
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

	api.queueDigestNotifyMu.Lock()
	api.lastPolicyAlertNotificationAt = now
	api.lastPolicyAlertNotificationChecksum = checksum
	api.queueDigestNotifyMu.Unlock()
}

func (api *ManagementAPI) updateGatewayPolicyAlertIncidentState(alerts []gateway.PolicyAlert, now time.Time) ([]managementWebhookEvent, []managementWebhookEvent, []managementWebhookEvent) {
	current := make(map[string]gateway.PolicyAlert, len(alerts))
	for _, alert := range alerts {
		current[gatewayPolicyAlertIncidentKey(alert)] = alert
	}

	api.queueDigestNotifyMu.Lock()
	defer api.queueDigestNotifyMu.Unlock()

	opened := make([]managementWebhookEvent, 0)
	stageChanged := make([]managementWebhookEvent, 0)
	resolved := make([]managementWebhookEvent, 0)

	for key, alert := range current {
		state, ok := api.policyAlertIncidentState[key]
		if !ok || strings.TrimSpace(state.IncidentID) == "" {
			state = gatewayPolicyAlertIncidentState{
				IncidentID:  fmt.Sprintf("pal-%s", now.UTC().Format("20060102-150405.000000000")),
				Severity:    strings.TrimSpace(alert.Severity),
				ServiceName: strings.TrimSpace(alert.ServiceName),
				RoutePath:   strings.TrimSpace(alert.RoutePath),
				Reason:      strings.TrimSpace(alert.Reason),
				FirstSeenAt: now,
				LastSeenAt:  now,
				LastCount:   alert.Count,
			}
			api.policyAlertIncidentState[key] = state
			opened = append(opened, managementWebhookEvent{
				Event:      "gateway.policy_alert_opened",
				OccurredAt: now,
				Data:       buildGatewayPolicyAlertIncidentData(state, alert.Count, alert.Severity, now),
			})
			continue
		}

		previousSeverity := state.Severity
		state.LastSeenAt = now
		state.LastCount = alert.Count
		if slaBreachTierRank(alert.Severity) > slaBreachTierRank(previousSeverity) {
			state.Severity = strings.TrimSpace(alert.Severity)
			api.policyAlertIncidentState[key] = state
			data := buildGatewayPolicyAlertIncidentData(state, alert.Count, alert.Severity, now)
			data["previous_severity"] = previousSeverity
			stageChanged = append(stageChanged, managementWebhookEvent{
				Event:      "gateway.policy_alert_stage_changed",
				OccurredAt: now,
				Data:       data,
			})
			continue
		}
		api.policyAlertIncidentState[key] = state
	}

	for key, state := range api.policyAlertIncidentState {
		if _, ok := current[key]; ok {
			continue
		}
		resolved = append(resolved, managementWebhookEvent{
			Event:      "gateway.policy_alert_resolved",
			OccurredAt: now,
			Data:       buildGatewayPolicyAlertIncidentData(state, state.LastCount, state.Severity, now),
		})
		delete(api.policyAlertIncidentState, key)
	}

	return opened, stageChanged, resolved
}
