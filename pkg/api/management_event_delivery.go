package api

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/bhangun/iket/pkg/config"
	"github.com/bhangun/iket/pkg/logging"
)

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
	attempts := notificationWebhookAttempts(webhook)
	backoff := notificationWebhookRetryBackoff(webhook)
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

func notificationWebhookAttempts(webhook config.NotificationWebhook) int {
	attempts := webhook.RetryCount + 1
	if attempts < 1 {
		return 1
	}
	return attempts
}

func notificationWebhookRetryBackoff(webhook config.NotificationWebhook) time.Duration {
	if value := strings.TrimSpace(webhook.RetryBackoff); value != "" {
		if parsed, err := time.ParseDuration(value); err == nil && parsed > 0 {
			return parsed
		}
	}
	return time.Second
}

func executeNotificationWebhook(webhook config.NotificationWebhook, payload managementWebhookEvent) (int, error) {
	bodyPayload := buildNotificationWebhookPayload(webhook, payload)
	body, err := json.Marshal(bodyPayload)
	if err != nil {
		return 0, err
	}
	client := notificationWebhookHTTPClient(webhook)
	req, err := newNotificationWebhookRequest(webhook, payload, body)
	if err != nil {
		return 0, err
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

func notificationWebhookHTTPClient(webhook config.NotificationWebhook) *http.Client {
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
	return client
}

func newNotificationWebhookRequest(webhook config.NotificationWebhook, payload managementWebhookEvent, body []byte) (*http.Request, error) {
	req, err := http.NewRequest("POST", webhook.URL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Iket-Event", payload.Event)
	setNotificationWebhookSignatureHeaders(req, webhook, body)
	for key, value := range webhook.Headers {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		req.Header.Set(key, value)
	}
	return req, nil
}

func setNotificationWebhookSignatureHeaders(req *http.Request, webhook config.NotificationWebhook, body []byte) {
	secret := strings.TrimSpace(webhook.SigningSecret)
	if secret == "" {
		return
	}
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
