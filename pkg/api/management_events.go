package api

import (
	"strings"
	"time"

	"github.com/bhangun/iket/pkg/logging"
)

func (api *ManagementAPI) emitProposalEvent(event string, record *configProposalRecord, data map[string]interface{}) {
	payload := managementWebhookEvent{
		Event:      strings.TrimSpace(event),
		OccurredAt: time.Now().UTC(),
		Data:       data,
	}
	if record != nil {
		payload.ProposalID = record.ID
		payload.Action = record.Action
		payload.Status = record.Status
		payload.Environment = record.Environment
		payload.Reviewer = record.ReviewedBy
		payload.ReviewNote = record.ReviewNote
		payload.Label = record.Label
		payload.Note = record.Note
		payload.ChangeRef = record.ChangeRef
	}
	api.emitManagementEvent(payload)
}

func (api *ManagementAPI) emitManagementEvent(payload managementWebhookEvent) int {
	cfg := api.gateway.GetConfig()
	if cfg == nil || len(cfg.Security.NotificationWebhooks) == 0 {
		return 0
	}
	payload.Event = strings.TrimSpace(payload.Event)
	if payload.OccurredAt.IsZero() {
		payload.OccurredAt = time.Now().UTC()
	}
	delivered := 0
	for _, webhook := range cfg.Security.NotificationWebhooks {
		webhook = effectiveNotificationWebhookLimitAlertProfile(webhook, cfg.Security.LimitAlertProfiles)
		webhook = effectiveNotificationWebhookLimitClassDigestProfile(webhook, cfg.Security.LimitClassDigestProfiles)
		webhook = resolveNotificationWebhookHiddenStrategyPolicyPresets(webhook, cfg.Security.LimitClassDigestHiddenStrategyPolicyPresets)
		if !notificationWebhookMatchesPayload(webhook, payload) {
			continue
		}
		if !api.notificationWebhookCooldownAllowsDelivery(webhook, payload) {
			continue
		}
		shapedPayload := api.notificationWebhookPayloadForReceiver(webhook, payload)
		if _, err := api.postNotificationWebhook(webhook, shapedPayload, ""); err != nil {
			api.logger.Warn("Failed to deliver notification webhook",
				logging.String("event", shapedPayload.Event),
				logging.String("webhook", webhook.URL),
				logging.Error(err))
			continue
		}
		api.recordNotificationWebhookDelivery(webhook, payload)
		delivered++
	}
	return delivered
}
