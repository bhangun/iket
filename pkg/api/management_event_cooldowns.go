package api

import (
	"fmt"
	"strings"

	"github.com/bhangun/iket/pkg/config"
)

type notificationWebhookCooldownScope struct {
	key           string
	cooldownValue string
	tier          string
}

func (api *ManagementAPI) notificationWebhookCooldownAllowsDelivery(webhook config.NotificationWebhook, payload managementWebhookEvent) bool {
	scope, ok := notificationWebhookCooldownScopeFor(webhook, payload)
	if !ok {
		return true
	}
	cooldown, ok := parsePositiveWebhookDuration(scope.cooldownValue)
	if !ok {
		return true
	}

	state, ok := api.notificationWebhookEscalationState(scope.key)
	if !ok || state.LastSentAt.IsZero() {
		return true
	}
	if notificationWebhookCooldownEscalated(scope.tier, state.LastTier) {
		return true
	}
	return payload.OccurredAt.Sub(state.LastSentAt) >= cooldown
}

func (api *ManagementAPI) recordNotificationWebhookDelivery(webhook config.NotificationWebhook, payload managementWebhookEvent) {
	scope, ok := notificationWebhookCooldownScopeFor(webhook, payload)
	if !ok {
		return
	}
	api.recordNotificationWebhookEscalationState(scope.key, proposalQueueSLABreachEscalationState{
		LastSentAt: payload.OccurredAt,
		LastTier:   scope.tier,
	})
}

func notificationWebhookCooldownScopeFor(webhook config.NotificationWebhook, payload managementWebhookEvent) (notificationWebhookCooldownScope, bool) {
	switch {
	case notificationWebhookEventIs(payload, "proposal.sla_breach"):
		return notificationWebhookCooldownScope{
			key:           proposalQueueSLABreachEscalationKey(webhook, payload.Environment),
			cooldownValue: webhook.SLABreachCooldown,
			tier:          slaBreachTierFromEventData(payload.Data),
		}, true
	case notificationWebhookEventIs(payload, "gateway.limit_alert"), notificationWebhookEventIs(payload, "gateway.limit_class_alert"):
		return notificationWebhookCooldownScope{
			key:           gatewayLimitAlertEscalationKey(webhook, payload),
			cooldownValue: webhook.LimitAlertCooldown,
			tier:          limitAlertSeverityFromEventData(payload.Data),
		}, true
	case notificationWebhookEventIs(payload, "gateway.limit_class_snooze_expiring"):
		return notificationWebhookCooldownScope{
			key:           gatewayLimitAlertEscalationKey(webhook, payload),
			cooldownValue: webhook.LimitClassSnoozeExpiryCooldown,
		}, true
	default:
		return notificationWebhookCooldownScope{}, false
	}
}

func notificationWebhookCooldownEscalated(currentTier, previousTier string) bool {
	if strings.TrimSpace(currentTier) == "" {
		return false
	}
	return slaBreachTierRank(currentTier) > slaBreachTierRank(previousTier)
}

func (api *ManagementAPI) notificationWebhookEscalationState(key string) (proposalQueueSLABreachEscalationState, bool) {
	api.queueDigestNotifyMu.Lock()
	defer api.queueDigestNotifyMu.Unlock()
	state, ok := api.slaBreachEscalationState[key]
	return state, ok
}

func (api *ManagementAPI) recordNotificationWebhookEscalationState(key string, state proposalQueueSLABreachEscalationState) {
	api.queueDigestNotifyMu.Lock()
	defer api.queueDigestNotifyMu.Unlock()
	api.slaBreachEscalationState[key] = state
}

func gatewayLimitAlertEscalationKey(webhook config.NotificationWebhook, payload managementWebhookEvent) string {
	webhookID := notificationWebhookIdentity(webhook)
	bucketIdentifier := strings.TrimSpace(fmt.Sprint(payload.Data["bucket_id"]))
	if bucketIdentifier == "" {
		bucketIdentifier = strings.TrimSpace(fmt.Sprint(payload.Data["bucket_class"]))
	}
	return webhookID + "||" + strings.TrimSpace(fmt.Sprint(payload.Data["service_name"])) + "|" + strings.TrimSpace(fmt.Sprint(payload.Data["route_path"])) + "|" + strings.TrimSpace(fmt.Sprint(payload.Data["limit_type"])) + "|" + bucketIdentifier
}

func proposalQueueSLABreachEscalationKey(webhook config.NotificationWebhook, environment string) string {
	return notificationWebhookIdentity(webhook) + "||" + proposalQueueDigestNotificationKey(environment)
}

func notificationWebhookIdentity(webhook config.NotificationWebhook) string {
	webhookID := strings.TrimSpace(webhook.Name)
	if webhookID == "" {
		webhookID = strings.TrimSpace(webhook.URL)
	}
	return webhookID
}
