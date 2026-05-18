package api

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/bhangun/iket/pkg/config"
	"github.com/bhangun/iket/pkg/logging"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
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
		if !notificationWebhookMatchesPayload(webhook, payload) {
			continue
		}
		if !api.notificationWebhookCooldownAllowsDelivery(webhook, payload) {
			continue
		}
		if _, err := api.postNotificationWebhook(webhook, payload, ""); err != nil {
			api.logger.Warn("Failed to deliver notification webhook",
				logging.String("event", payload.Event),
				logging.String("webhook", webhook.URL),
				logging.Error(err))
			continue
		}
		api.recordNotificationWebhookDelivery(webhook, payload)
		delivered++
	}
	return delivered
}

func notificationWebhookMatchesPayload(webhook config.NotificationWebhook, payload managementWebhookEvent) bool {
	if !notificationWebhookMatchesEvent(webhook, payload.Event) {
		return false
	}
	if len(webhook.Environments) > 0 {
		eventEnv := strings.ToLower(strings.TrimSpace(payload.Environment))
		matched := false
		for _, environment := range webhook.Environments {
			if strings.ToLower(strings.TrimSpace(environment)) == eventEnv && eventEnv != "" {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	if webhook.MinSLABreachCount > 0 && strings.EqualFold(strings.TrimSpace(payload.Event), "proposal.sla_breach") {
		if intValue(slaBreachCountFromEventData(payload.Data)) < webhook.MinSLABreachCount {
			return false
		}
	}
	if webhook.MinConsecutiveSLABreaches > 0 && strings.EqualFold(strings.TrimSpace(payload.Event), "proposal.sla_breach") {
		if slaBreachConsecutiveCountFromEventData(payload.Data) < webhook.MinConsecutiveSLABreaches {
			return false
		}
	}
	if strings.TrimSpace(webhook.MinSLABreachDuration) != "" && strings.EqualFold(strings.TrimSpace(payload.Event), "proposal.sla_breach") {
		required, err := time.ParseDuration(strings.TrimSpace(webhook.MinSLABreachDuration))
		if err != nil || required <= 0 {
			return false
		}
		if slaBreachAgeFromEventData(payload.Data) < required {
			return false
		}
	}
	if strings.TrimSpace(webhook.MinSLABreachTier) != "" && strings.EqualFold(strings.TrimSpace(payload.Event), "proposal.sla_breach") {
		requiredTier := normalizeSLABreachTier(webhook.MinSLABreachTier)
		if requiredTier == "" {
			return false
		}
		if slaBreachTierRank(slaBreachTierFromEventData(payload.Data)) < slaBreachTierRank(requiredTier) {
			return false
		}
	}
	if isGatewayLimitAlertEvent(payload.Event) {
		if strings.TrimSpace(webhook.MinLimitAlertSeverity) != "" {
			requiredSeverity := normalizeSLABreachTier(webhook.MinLimitAlertSeverity)
			if requiredSeverity == "" {
				return false
			}
			if slaBreachTierRank(limitAlertSeverityFromEventData(payload.Data)) < slaBreachTierRank(requiredSeverity) {
				return false
			}
		}
		if len(webhook.LimitAlertTypes) > 0 {
			currentType := strings.ToLower(strings.TrimSpace(limitAlertTypeFromEventData(payload.Data)))
			matched := false
			for _, limitType := range webhook.LimitAlertTypes {
				if strings.ToLower(strings.TrimSpace(limitType)) == currentType && currentType != "" {
					matched = true
					break
				}
			}
			if !matched {
				return false
			}
		}
		if len(webhook.LimitAlertKeyTypes) > 0 {
			currentKeyType := strings.ToLower(strings.TrimSpace(limitAlertKeyTypeFromEventData(payload.Data)))
			matched := false
			for _, keyType := range webhook.LimitAlertKeyTypes {
				if strings.ToLower(strings.TrimSpace(keyType)) == currentKeyType && currentKeyType != "" {
					matched = true
					break
				}
			}
			if !matched {
				return false
			}
		}
		if len(webhook.LimitAlertBucketClasses) > 0 {
			currentBucketClass := strings.TrimSpace(limitAlertBucketClassFromEventData(payload.Data))
			matched := false
			for _, bucketClass := range webhook.LimitAlertBucketClasses {
				if strings.EqualFold(strings.TrimSpace(bucketClass), currentBucketClass) && currentBucketClass != "" {
					matched = true
					break
				}
			}
			if !matched {
				return false
			}
		}
		if pattern := strings.TrimSpace(webhook.LimitAlertBucketIDRegex); pattern != "" {
			re, err := regexp.Compile(pattern)
			if err != nil {
				return false
			}
			if !re.MatchString(limitAlertBucketIDFromEventData(payload.Data)) {
				return false
			}
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

func (api *ManagementAPI) notificationWebhookCooldownAllowsDelivery(webhook config.NotificationWebhook, payload managementWebhookEvent) bool {
	if !strings.EqualFold(strings.TrimSpace(payload.Event), "proposal.sla_breach") {
		if !strings.EqualFold(strings.TrimSpace(payload.Event), "gateway.limit_alert") && !strings.EqualFold(strings.TrimSpace(payload.Event), "gateway.limit_class_alert") {
			return true
		}
		cooldownValue := strings.TrimSpace(webhook.LimitAlertCooldown)
		if cooldownValue == "" {
			return true
		}
		cooldown, err := time.ParseDuration(cooldownValue)
		if err != nil || cooldown <= 0 {
			return true
		}
		key := gatewayLimitAlertEscalationKey(webhook, payload)
		currentSeverity := limitAlertSeverityFromEventData(payload.Data)
		api.queueDigestNotifyMu.Lock()
		defer api.queueDigestNotifyMu.Unlock()
		state, ok := api.slaBreachEscalationState[key]
		if !ok || state.LastSentAt.IsZero() {
			return true
		}
		if slaBreachTierRank(currentSeverity) > slaBreachTierRank(state.LastTier) {
			return true
		}
		return payload.OccurredAt.Sub(state.LastSentAt) >= cooldown
	}
	cooldownValue := strings.TrimSpace(webhook.SLABreachCooldown)
	if cooldownValue == "" {
		return true
	}
	cooldown, err := time.ParseDuration(cooldownValue)
	if err != nil || cooldown <= 0 {
		return true
	}
	key := proposalQueueSLABreachEscalationKey(webhook, payload.Environment)
	currentTier := slaBreachTierFromEventData(payload.Data)
	api.queueDigestNotifyMu.Lock()
	defer api.queueDigestNotifyMu.Unlock()
	state, ok := api.slaBreachEscalationState[key]
	if !ok || state.LastSentAt.IsZero() {
		return true
	}
	if slaBreachTierRank(currentTier) > slaBreachTierRank(state.LastTier) {
		return true
	}
	return payload.OccurredAt.Sub(state.LastSentAt) >= cooldown
}

func (api *ManagementAPI) recordNotificationWebhookDelivery(webhook config.NotificationWebhook, payload managementWebhookEvent) {
	if !strings.EqualFold(strings.TrimSpace(payload.Event), "proposal.sla_breach") {
		if !strings.EqualFold(strings.TrimSpace(payload.Event), "gateway.limit_alert") && !strings.EqualFold(strings.TrimSpace(payload.Event), "gateway.limit_class_alert") {
			return
		}
		key := gatewayLimitAlertEscalationKey(webhook, payload)
		api.queueDigestNotifyMu.Lock()
		defer api.queueDigestNotifyMu.Unlock()
		api.slaBreachEscalationState[key] = proposalQueueSLABreachEscalationState{
			LastSentAt: payload.OccurredAt,
			LastTier:   limitAlertSeverityFromEventData(payload.Data),
		}
		return
	}
	key := proposalQueueSLABreachEscalationKey(webhook, payload.Environment)
	api.queueDigestNotifyMu.Lock()
	defer api.queueDigestNotifyMu.Unlock()
	api.slaBreachEscalationState[key] = proposalQueueSLABreachEscalationState{
		LastSentAt: payload.OccurredAt,
		LastTier:   slaBreachTierFromEventData(payload.Data),
	}
}

func isGatewayLimitAlertEvent(event string) bool {
	switch strings.TrimSpace(strings.ToLower(event)) {
	case "gateway.limit_alert", "gateway.limit_alert_opened", "gateway.limit_alert_stage_changed", "gateway.limit_alert_resolved",
		"gateway.limit_class_alert", "gateway.limit_class_alert_opened", "gateway.limit_class_alert_stage_changed", "gateway.limit_class_alert_resolved":
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

func gatewayLimitAlertEscalationKey(webhook config.NotificationWebhook, payload managementWebhookEvent) string {
	webhookID := strings.TrimSpace(webhook.Name)
	if webhookID == "" {
		webhookID = strings.TrimSpace(webhook.URL)
	}
	bucketIdentifier := strings.TrimSpace(fmt.Sprint(payload.Data["bucket_id"]))
	if bucketIdentifier == "" {
		bucketIdentifier = strings.TrimSpace(fmt.Sprint(payload.Data["bucket_class"]))
	}
	return webhookID + "||" + strings.TrimSpace(fmt.Sprint(payload.Data["service_name"])) + "|" + strings.TrimSpace(fmt.Sprint(payload.Data["route_path"])) + "|" + strings.TrimSpace(fmt.Sprint(payload.Data["limit_type"])) + "|" + bucketIdentifier
}

func proposalQueueSLABreachEscalationKey(webhook config.NotificationWebhook, environment string) string {
	webhookID := strings.TrimSpace(webhook.Name)
	if webhookID == "" {
		webhookID = strings.TrimSpace(webhook.URL)
	}
	return webhookID + "||" + proposalQueueDigestNotificationKey(environment)
}

func effectiveNotificationWebhookLimitAlertProfile(webhook config.NotificationWebhook, profiles map[string]config.LimitAlertRecipientProfile) config.NotificationWebhook {
	profileName := strings.TrimSpace(webhook.LimitAlertProfile)
	if profileName == "" {
		return webhook
	}
	profile, ok := profiles[profileName]
	if !ok {
		return webhook
	}
	if strings.TrimSpace(webhook.MinLimitAlertSeverity) == "" {
		webhook.MinLimitAlertSeverity = profile.MinLimitAlertSeverity
	}
	if len(webhook.LimitAlertTypes) == 0 {
		webhook.LimitAlertTypes = append([]string(nil), profile.LimitAlertTypes...)
	}
	if len(webhook.LimitAlertKeyTypes) == 0 {
		webhook.LimitAlertKeyTypes = append([]string(nil), profile.LimitAlertKeyTypes...)
	}
	if len(webhook.LimitAlertBucketClasses) == 0 {
		webhook.LimitAlertBucketClasses = append([]string(nil), profile.LimitAlertBucketClasses...)
	}
	if strings.TrimSpace(webhook.LimitAlertBucketIDRegex) == "" {
		webhook.LimitAlertBucketIDRegex = profile.LimitAlertBucketIDRegex
	}
	if strings.TrimSpace(webhook.LimitAlertCooldown) == "" {
		webhook.LimitAlertCooldown = profile.LimitAlertCooldown
	}
	return webhook
}

func slaBreachCountFromEventData(data map[string]interface{}) interface{} {
	if attention, ok := data["attention_required"].(map[string]interface{}); ok {
		if count, ok := attention["sla_breach_count"]; ok {
			return count
		}
	}
	if count, ok := data["sla_breach_count"]; ok {
		return count
	}
	return 0
}

func slaBreachConsecutiveCountFromEventData(data map[string]interface{}) int {
	if state, ok := data["sla_breach_state"].(map[string]interface{}); ok {
		return intValue(state["consecutive_breaches"])
	}
	return 0
}

func slaBreachAgeFromEventData(data map[string]interface{}) time.Duration {
	if state, ok := data["sla_breach_state"].(map[string]interface{}); ok {
		switch value := state["breach_age_seconds"].(type) {
		case int:
			return time.Duration(value) * time.Second
		case int64:
			return time.Duration(value) * time.Second
		case float64:
			return time.Duration(value * float64(time.Second))
		}
	}
	return 0
}

func slaBreachTierFromEventData(data map[string]interface{}) string {
	if state, ok := data["sla_breach_state"].(map[string]interface{}); ok {
		if tier, ok := state["tier"]; ok {
			return normalizeSLABreachTier(fmt.Sprint(tier))
		}
	}
	if tier, ok := data["sla_breach_tier"]; ok {
		return normalizeSLABreachTier(fmt.Sprint(tier))
	}
	return ""
}

func normalizeSLABreachTier(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "warning", "elevated", "critical":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return ""
	}
}

func slaBreachTierRank(tier string) int {
	switch normalizeSLABreachTier(tier) {
	case "warning":
		return 1
	case "elevated":
		return 2
	case "critical":
		return 3
	default:
		return 0
	}
}

func (api *ManagementAPI) postNotificationWebhook(webhook config.NotificationWebhook, payload managementWebhookEvent, replayOf string) (*notificationDeliveryRecord, error) {
	record := notificationDeliveryRecord{
		ID:            fmt.Sprintf("ntf-%s", time.Now().UTC().Format("20060102-150405.000000000")),
		Event:         strings.TrimSpace(payload.Event),
		ProposalID:    strings.TrimSpace(payload.ProposalID),
		WebhookName:   strings.TrimSpace(webhook.Name),
		WebhookURL:    strings.TrimSpace(webhook.URL),
		WebhookFormat: strings.TrimSpace(webhook.Format),
		OccurredAt:    payload.OccurredAt,
		Webhook:       webhook,
		Payload:       payload,
		ReplayOf:      strings.TrimSpace(replayOf),
	}
	attempts := webhook.RetryCount + 1
	if attempts < 1 {
		attempts = 1
	}
	backoff := time.Second
	if value := strings.TrimSpace(webhook.RetryBackoff); value != "" {
		if parsed, err := time.ParseDuration(value); err == nil && parsed > 0 {
			backoff = parsed
		}
	}
	var lastErr error
	for attempt := 1; attempt <= attempts; attempt++ {
		statusCode, err := executeNotificationWebhook(webhook, payload)
		record.Attempts = attempt
		record.LastStatusCode = statusCode
		record.DeliveredAt = time.Now().UTC()
		if err == nil {
			record.Success = true
			record.LastError = ""
			break
		}
		lastErr = err
		record.LastError = err.Error()
		if attempt < attempts && backoff > 0 {
			time.Sleep(backoff)
		}
	}
	if err := saveNotificationDeliveryRecord(record); err != nil {
		api.logger.Warn("Failed to persist notification delivery record",
			logging.String("event", record.Event),
			logging.String("delivery_id", record.ID),
			logging.Error(err))
	}
	if !record.Success {
		return &record, lastErr
	}
	return &record, nil
}

func executeNotificationWebhook(webhook config.NotificationWebhook, payload managementWebhookEvent) (int, error) {
	bodyPayload := buildNotificationWebhookPayload(webhook, payload)
	body, err := json.Marshal(bodyPayload)
	if err != nil {
		return 0, err
	}
	timeout := 5 * time.Second
	if value := strings.TrimSpace(webhook.Timeout); value != "" {
		if parsed, err := time.ParseDuration(value); err == nil && parsed > 0 {
			timeout = parsed
		}
	}
	client := &http.Client{Timeout: timeout}
	if strings.EqualFold(parsedScheme(webhook.URL), "https") && webhook.InsecureSkipVerify {
		client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
		}
	}
	req, err := http.NewRequest("POST", webhook.URL, bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Iket-Event", payload.Event)
	if secret := strings.TrimSpace(webhook.SigningSecret); secret != "" {
		timestamp := time.Now().UTC().Format(time.RFC3339)
		timestampHeader := strings.TrimSpace(webhook.TimestampHeader)
		if timestampHeader == "" {
			timestampHeader = "X-Iket-Timestamp"
		}
		signatureHeader := strings.TrimSpace(webhook.SignatureHeader)
		if signatureHeader == "" {
			signatureHeader = "X-Iket-Signature"
		}
		req.Header.Set(timestampHeader, timestamp)
		req.Header.Set(signatureHeader, signNotificationWebhook(secret, timestamp, body))
	}
	for key, value := range webhook.Headers {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		req.Header.Set(key, value)
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return resp.StatusCode, fmt.Errorf("webhook responded with status %d", resp.StatusCode)
	}
	return resp.StatusCode, nil
}

func signNotificationWebhook(secret, timestamp string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(timestamp))
	mac.Write([]byte("."))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

func buildNotificationWebhookPayload(webhook config.NotificationWebhook, payload managementWebhookEvent) interface{} {
	switch strings.ToLower(strings.TrimSpace(webhook.Format)) {
	case "slack":
		return map[string]interface{}{
			"text": buildNotificationWebhookText(payload),
		}
	case "teams":
		return map[string]interface{}{
			"@type":      "MessageCard",
			"@context":   "https://schema.org/extensions",
			"summary":    buildNotificationWebhookSummary(payload),
			"themeColor": notificationWebhookThemeColor(payload.Event),
			"title":      buildNotificationWebhookSummary(payload),
			"sections": []map[string]interface{}{
				{
					"text": buildNotificationWebhookText(payload),
				},
			},
		}
	default:
		return payload
	}
}

func buildNotificationWebhookSummary(payload managementWebhookEvent) string {
	summary := strings.TrimSpace(payload.Event)
	if payload.ProposalID != "" {
		summary += " " + payload.ProposalID
	}
	if payload.Environment != "" {
		summary += " (" + payload.Environment + ")"
	}
	return strings.TrimSpace(summary)
}

func buildNotificationWebhookText(payload managementWebhookEvent) string {
	parts := []string{strings.TrimSpace(payload.Event)}
	if payload.ProposalID != "" {
		parts = append(parts, "proposal="+payload.ProposalID)
	}
	if payload.Status != "" {
		parts = append(parts, "status="+payload.Status)
	}
	if payload.Environment != "" {
		parts = append(parts, "env="+payload.Environment)
	}
	if payload.Reviewer != "" {
		parts = append(parts, "reviewer="+payload.Reviewer)
	}
	if payload.ChangeRef != "" {
		parts = append(parts, "change_ref="+payload.ChangeRef)
	}
	return strings.Join(parts, " | ")
}

func notificationWebhookThemeColor(event string) string {
	switch strings.TrimSpace(strings.ToLower(event)) {
	case "proposal.canary_aborted", "proposal.rejected":
		return "d32f2f"
	case "proposal.canary_started", "proposal.canary_advanced", "proposal.promoted":
		return "1976d2"
	default:
		return "2e7d32"
	}
}

func parsedScheme(rawURL string) string {
	parsed, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return ""
	}
	return parsed.Scheme
}

type managementWebhookEvent struct {
	Event       string                 `json:"event"`
	OccurredAt  time.Time              `json:"occurred_at"`
	ProposalID  string                 `json:"proposal_id,omitempty"`
	Action      string                 `json:"action,omitempty"`
	Status      string                 `json:"status,omitempty"`
	Environment string                 `json:"environment,omitempty"`
	Reviewer    string                 `json:"reviewer,omitempty"`
	ReviewNote  string                 `json:"review_note,omitempty"`
	Label       string                 `json:"label,omitempty"`
	Note        string                 `json:"note,omitempty"`
	ChangeRef   string                 `json:"change_ref,omitempty"`
	Data        map[string]interface{} `json:"data,omitempty"`
}

type proposalQueueSLABreachState struct {
	IncidentID          string
	ConsecutiveBreaches int
	FirstBreachedAt     time.Time
	LastBreachedAt      time.Time
}

type proposalQueueSLABreachEscalationState struct {
	LastSentAt time.Time
	LastTier   string
}

type gatewayPolicyAlertIncidentState struct {
	IncidentID  string
	Severity    string
	ServiceName string
	RoutePath   string
	Reason      string
	FirstSeenAt time.Time
	LastSeenAt  time.Time
	LastCount   int
}

type gatewayLimitAlertIncidentState struct {
	IncidentID  string
	Severity    string
	ServiceName string
	RoutePath   string
	LimitType   string
	KeyType     string
	BucketID    string
	BucketClass string
	FirstSeenAt time.Time
	LastSeenAt  time.Time
	LastCount   int
}

type gatewayLimitClassAlertIncidentState struct {
	IncidentID  string
	Severity    string
	ServiceName string
	RoutePath   string
	LimitType   string
	KeyType     string
	BucketClass string
	FirstSeenAt time.Time
	LastSeenAt  time.Time
	LastCount   int
}

type notificationDeliveryRecord struct {
	ID             string                     `json:"id"`
	Event          string                     `json:"event"`
	ProposalID     string                     `json:"proposal_id,omitempty"`
	WebhookName    string                     `json:"webhook_name,omitempty"`
	WebhookURL     string                     `json:"webhook_url"`
	WebhookFormat  string                     `json:"webhook_format,omitempty"`
	OccurredAt     time.Time                  `json:"occurred_at"`
	DeliveredAt    time.Time                  `json:"delivered_at"`
	Success        bool                       `json:"success"`
	Attempts       int                        `json:"attempts"`
	LastStatusCode int                        `json:"last_status_code,omitempty"`
	LastError      string                     `json:"last_error,omitempty"`
	ReplayOf       string                     `json:"replay_of,omitempty"`
	Webhook        config.NotificationWebhook `json:"webhook"`
	Payload        managementWebhookEvent     `json:"payload"`
}
