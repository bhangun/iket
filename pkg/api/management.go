package api

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"crypto/tls"
	"github.com/bhangun/iket/pkg/config"
	"github.com/bhangun/iket/pkg/logging"

	"github.com/bhangun/iket/pkg/core/gateway"
	"github.com/bhangun/iket/pkg/plugin"

	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
)

// ManagementAPI provides REST endpoints for gateway management
type ManagementAPI struct {
	gateway    *gateway.Gateway
	logger     *logging.Logger
	registry   *plugin.Registry
	mu         sync.RWMutex
	startedAt  time.Time
	lastReload time.Time

	// WebSocket upgrader
	upgrader websocket.Upgrader

	// Real-time update channels
	statusSubscribers  map[*websocket.Conn]bool
	metricsSubscribers map[*websocket.Conn]bool
	logsSubscribers    map[*websocket.Conn]bool
	subscriberMu       sync.RWMutex

	queueDigestNotifyMu                 sync.Mutex
	lastQueueDigestNotificationAt       map[string]time.Time
	lastQueueDigestNotificationChecksum map[string]string
	queueDigestSLABreachState           map[string]proposalQueueSLABreachState
	slaBreachEscalationState            map[string]proposalQueueSLABreachEscalationState
	lastPolicyAlertNotificationAt       time.Time
	lastPolicyAlertNotificationChecksum string
	policyAlertIncidentState            map[string]gatewayPolicyAlertIncidentState
}

const defaultProposalCanaryAutoReconcileInterval = 30 * time.Second

// NewManagementAPI creates a new management API instance
func NewManagementAPI(gateway *gateway.Gateway, logger *logging.Logger, registry *plugin.Registry) *ManagementAPI {
	api := &ManagementAPI{
		gateway:    gateway,
		logger:     logger,
		registry:   registry,
		startedAt:  time.Now(),
		lastReload: time.Now(),
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool {
				return true // Allow all origins for now
			},
		},
		statusSubscribers:                   make(map[*websocket.Conn]bool),
		metricsSubscribers:                  make(map[*websocket.Conn]bool),
		logsSubscribers:                     make(map[*websocket.Conn]bool),
		lastQueueDigestNotificationAt:       make(map[string]time.Time),
		lastQueueDigestNotificationChecksum: make(map[string]string),
		queueDigestSLABreachState:           make(map[string]proposalQueueSLABreachState),
		slaBreachEscalationState:            make(map[string]proposalQueueSLABreachEscalationState),
		policyAlertIncidentState:            make(map[string]gatewayPolicyAlertIncidentState),
	}

	// Start real-time update goroutines
	go api.broadcastStatusUpdates()
	go api.broadcastMetricsUpdates()
	go api.autoReconcileCanaries()
	go api.autoNotifyProposalQueueDigests()
	go api.autoNotifyGatewayPolicyAlerts()

	return api
}

// RegisterRoutes registers all management API routes
func (api *ManagementAPI) RegisterRoutes(router *mux.Router) {
	// API v1 routes
	v1 := router.PathPrefix("/api/v1").Subrouter()

	// Add CORS middleware for management API
	v1.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

			if r.Method == "OPTIONS" {
				w.WriteHeader(http.StatusOK)
				return
			}

			next.ServeHTTP(w, r)
		})
	})

	// Gateway management
	v1.HandleFunc("/gateway/status", api.getGatewayStatus).Methods("GET")
	v1.HandleFunc("/gateway/config", api.getGatewayConfig).Methods("GET")
	v1.HandleFunc("/gateway/config", api.updateGatewayConfig).Methods("PUT")
	v1.HandleFunc("/gateway/config/self-test", api.selfTestGatewayConfig).Methods("GET")
	v1.HandleFunc("/gateway/reload", api.reloadGateway).Methods("POST")
	v1.HandleFunc("/gateway/metrics", api.getGatewayMetrics).Methods("GET")
	v1.HandleFunc("/gateway/backends", api.getGatewayBackends).Methods("GET")
	v1.HandleFunc("/gateway/policy-hits", api.getGatewayPolicyHits).Methods("GET")
	v1.HandleFunc("/gateway/policy-alerts", api.getGatewayPolicyAlerts).Methods("GET")
	v1.HandleFunc("/gateway/policy-alerts/notify", api.notifyGatewayPolicyAlerts).Methods("POST")
	v1.HandleFunc("/gateway/shadow-report", api.getGatewayShadowReport).Methods("GET")
	v1.HandleFunc("/gateway/shadow-evaluate", api.getGatewayShadowEvaluation).Methods("GET")

	// Plugin management
	v1.HandleFunc("/plugins", api.listPlugins).Methods("GET")
	v1.HandleFunc("/plugins/{name}", api.getPluginDetails).Methods("GET")
	v1.HandleFunc("/plugins/{name}/config", api.updatePluginConfig).Methods("PUT")
	v1.HandleFunc("/plugins/{name}/enable", api.enablePlugin).Methods("POST")
	v1.HandleFunc("/plugins/{name}/disable", api.disablePlugin).Methods("POST")
	v1.HandleFunc("/plugins/{name}/health", api.getPluginHealth).Methods("GET")
	v1.HandleFunc("/plugins/{name}/status", api.getPluginStatus).Methods("GET")

	// Route management
	v1.HandleFunc("/routes", api.listRoutes).Methods("GET")
	v1.HandleFunc("/routes", api.createRoute).Methods("POST")
	v1.HandleFunc("/routes/{id}", api.getRouteDetails).Methods("GET")
	v1.HandleFunc("/routes/{id}", api.updateRoute).Methods("PUT")
	v1.HandleFunc("/routes/{id}", api.deleteRoute).Methods("DELETE")
	v1.HandleFunc("/routes/{id}/enable", api.enableRoute).Methods("POST")
	v1.HandleFunc("/routes/{id}/disable", api.disableRoute).Methods("POST")

	// Monitoring & logs
	v1.HandleFunc("/logs", api.getLogs).Methods("GET")
	v1.HandleFunc("/logs/stream", api.streamLogs).Methods("GET")
	v1.HandleFunc("/metrics/system", api.getSystemMetrics).Methods("GET")

	// WebSocket endpoints
	v1.HandleFunc("/ws/status", api.wsStatus).Methods("GET")
	v1.HandleFunc("/ws/metrics", api.wsMetrics).Methods("GET")
	v1.HandleFunc("/ws/logs", api.wsLogs).Methods("GET")

	// Certificate management
	v1.HandleFunc("/certificates", api.listCertificates).Methods("GET")
	v1.HandleFunc("/certificates", api.uploadCertificate).Methods("POST")
	v1.HandleFunc("/certificates/{id}", api.deleteCertificate).Methods("DELETE")
	v1.HandleFunc("/enrollment/tokens", api.createEnrollmentToken).Methods("POST")
	v1.HandleFunc("/enrollment/tokens", api.listEnrollmentTokens).Methods("GET")
	v1.HandleFunc("/enrollment/tokens/{id}", api.revokeEnrollmentToken).Methods("DELETE")

	// Backup & restore
	v1.HandleFunc("/backup", api.createBackup).Methods("POST")
	v1.HandleFunc("/backup", api.listBackups).Methods("GET")
	v1.HandleFunc("/backup/{id}/restore", api.restoreBackup).Methods("POST")
	v1.HandleFunc("/revisions", api.listRevisions).Methods("GET")
	v1.HandleFunc("/revisions/diff", api.diffRevisions).Methods("GET")
	v1.HandleFunc("/revisions/{id}", api.getRevision).Methods("GET")
	v1.HandleFunc("/revisions/{id}/restore", api.restoreRevision).Methods("POST")
	v1.HandleFunc("/proposals", api.listProposals).Methods("GET")
	v1.HandleFunc("/proposals/queue", api.getProposalQueue).Methods("GET")
	v1.HandleFunc("/proposals/queue/blocked-report", api.getBlockedProposalQueueReport).Methods("GET")
	v1.HandleFunc("/proposals/queue/notify-digest", api.notifyProposalQueueDigest).Methods("POST")
	v1.HandleFunc("/proposals/queue/approve-ready", api.approveReadyProposalQueue).Methods("POST")
	v1.HandleFunc("/proposals/queue/apply-ready", api.applyReadyProposalQueue).Methods("POST")
	v1.HandleFunc("/proposals/{id}", api.getProposal).Methods("GET")
	v1.HandleFunc("/proposals/{id}/verify", api.verifyProposal).Methods("GET")
	v1.HandleFunc("/proposals/{id}/readiness", api.getProposalReadiness).Methods("GET")
	v1.HandleFunc("/proposals/{id}/explain-blocked", api.explainBlockedProposal).Methods("GET")
	v1.HandleFunc("/proposals/{id}/canary", api.getProposalCanaryStatus).Methods("GET")
	v1.HandleFunc("/proposals/{id}/canary/evaluate", api.evaluateProposalCanary).Methods("GET")
	v1.HandleFunc("/proposals/{id}/canary/advance", api.advanceProposalCanary).Methods("POST")
	v1.HandleFunc("/proposals/{id}/canary/reconcile", api.reconcileProposalCanary).Methods("POST")
	v1.HandleFunc("/proposals/{id}/canary/expand", api.expandProposalCanary).Methods("POST")
	v1.HandleFunc("/proposals/{id}/canary/complete", api.completeProposalCanary).Methods("POST")
	v1.HandleFunc("/proposals/{id}/approve", api.approveProposal).Methods("POST")
	v1.HandleFunc("/proposals/{id}/apply", api.applyProposal).Methods("POST")
	v1.HandleFunc("/proposals/{id}/promote", api.promoteProposal).Methods("POST")
	v1.HandleFunc("/proposals/{id}/reject", api.rejectProposal).Methods("POST")
	v1.HandleFunc("/notifications/deliveries", api.listNotificationDeliveries).Methods("GET")
	v1.HandleFunc("/notifications/deliveries/{id}", api.getNotificationDelivery).Methods("GET")
	v1.HandleFunc("/notifications/deliveries/{id}/replay", api.replayNotificationDelivery).Methods("POST")
	v1.HandleFunc("/notifications/deliveries/replay-failed", api.replayFailedNotificationDeliveries).Methods("POST")

	// Service management
	v1.HandleFunc("/services", api.getServices).Methods("GET")
	v1.HandleFunc("/services", api.createService).Methods("POST")
	v1.HandleFunc("/services/{name}", api.updateService).Methods("PUT")
	v1.HandleFunc("/services/{name}", api.deleteService).Methods("DELETE")

	// Client management
	v1.HandleFunc("/clients", api.listClients).Methods("GET")
	v1.HandleFunc("/clients", api.addClient).Methods("POST")
	v1.HandleFunc("/clients/{key}", api.removeClient).Methods("DELETE")
}

func (api *ManagementAPI) RegisterEnrollmentRoutes(router *mux.Router) {
	v1 := router.PathPrefix("/api/v1").Subrouter()
	v1.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
			if r.Method == "OPTIONS" {
				w.WriteHeader(http.StatusOK)
				return
			}
			next.ServeHTTP(w, r)
		})
	})
	v1.HandleFunc("/enroll", api.enrollClientCertificate).Methods("POST")
}

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
		return true
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

func proposalQueueSLABreachEscalationKey(webhook config.NotificationWebhook, environment string) string {
	webhookID := strings.TrimSpace(webhook.Name)
	if webhookID == "" {
		webhookID = strings.TrimSpace(webhook.URL)
	}
	return webhookID + "||" + proposalQueueDigestNotificationKey(environment)
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

// Response structures
type APIResponse struct {
	Success bool        `json:"success"`
	Message string      `json:"message,omitempty"`
	Data    interface{} `json:"data,omitempty"`
}

type ErrorResponse struct {
	Error ErrorDetails `json:"error"`
}

type ErrorDetails struct {
	Code    string                 `json:"code"`
	Message string                 `json:"message"`
	Details map[string]interface{} `json:"details,omitempty"`
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

// Gateway Status Response
type GatewayStatus struct {
	Status            string    `json:"status"`
	Uptime            string    `json:"uptime"`
	Version           string    `json:"version"`
	StartTime         time.Time `json:"start_time"`
	ConfigLoaded      bool      `json:"config_loaded"`
	LastReload        time.Time `json:"last_reload"`
	ActiveConnections int       `json:"active_connections"`
	TotalRequests     int64     `json:"total_requests"`
	ErrorCount        int       `json:"error_count"`
}

// Gateway Metrics Response
type GatewayMetrics struct {
	Requests struct {
		Total         int64   `json:"total"`
		Successful    int64   `json:"successful"`
		Failed        int64   `json:"failed"`
		RatePerMinute float64 `json:"rate_per_minute"`
	} `json:"requests"`
	ResponseTimes struct {
		Average float64 `json:"average"`
		P95     float64 `json:"p95"`
		P99     float64 `json:"p99"`
	} `json:"response_times"`
	Errors struct {
		FourXX int `json:"4xx"`
		FiveXX int `json:"5xx"`
	} `json:"errors"`
	Connections struct {
		Active int   `json:"active"`
		Total  int64 `json:"total"`
	} `json:"connections"`
}

type ConfigSelfTestRoute struct {
	RouteName   string            `json:"route_name"`
	ServiceName string            `json:"service_name"`
	RoutePath   string            `json:"route_path"`
	RequestPath string            `json:"request_path"`
	Matched     bool              `json:"matched"`
	RouteVars   map[string]string `json:"route_vars,omitempty"`
	ProxiedPath string            `json:"proxied_path,omitempty"`
	Destination string            `json:"destination,omitempty"`
	StripPath   bool              `json:"strip_path"`
	URLPattern  string            `json:"url_pattern,omitempty"`
	Enabled     bool              `json:"enabled"`
}

// Plugin Response
type PluginInfo struct {
	Name    string            `json:"name"`
	Type    string            `json:"type"`
	Enabled bool              `json:"enabled"`
	Status  string            `json:"status"`
	Tags    map[string]string `json:"tags"`
}

// Route Response
type RouteInfo struct {
	ID          string                 `json:"id"`
	Path        string                 `json:"path"`
	Destination string                 `json:"destination"`
	Methods     []string               `json:"methods"`
	RequireAuth bool                   `json:"require_auth"`
	Timeout     int                    `json:"timeout"`
	StripPath   bool                   `json:"strip_path"`
	Enabled     bool                   `json:"enabled"`
	Stats       map[string]interface{} `json:"stats"`
}

// Handler implementations
func (api *ManagementAPI) getGatewayStatus(w http.ResponseWriter, r *http.Request) {
	clientIP := gateway.GetClientIP(r)
	api.logger.Info("gateway/status requested",
		logging.String("client_ip", clientIP),
		logging.String("path", r.URL.Path),
	)

	api.mu.RLock()
	defer api.mu.RUnlock()

	// Get gateway config for status info
	_ = api.gateway.GetConfig()

	status := GatewayStatus{
		Status:            "running",
		Uptime:            time.Since(api.startedAt).Round(time.Second).String(),
		Version:           api.gateway.Version(),
		StartTime:         api.startedAt,
		ConfigLoaded:      api.gateway.GetConfig() != nil,
		LastReload:        api.lastReload,
		ActiveConnections: 0,
		TotalRequests:     int64(len(api.logger.RecentLogs(2000, ""))),
		ErrorCount:        len(api.logger.RecentLogs(2000, "error")),
	}

	api.writeJSON(w, status)
}

func (api *ManagementAPI) getGatewayConfig(w http.ResponseWriter, r *http.Request) {
	api.mu.RLock()
	defer api.mu.RUnlock()

	cfg := api.gateway.GetConfig()
	if cfg == nil {
		api.writeError(w, "Configuration not available", http.StatusInternalServerError)
		return
	}

	// Redact sensitive information
	redactedConfig := *cfg
	if redactedConfig.Security.Jwt.Secret != "" {
		redactedConfig.Security.Jwt.Secret = "REDACTED"
	}
	redactedConfig.Security.BasicAuthUsers = nil

	api.writeJSON(w, redactedConfig)
}

func (api *ManagementAPI) selfTestGatewayConfig(w http.ResponseWriter, r *http.Request) {
	api.mu.RLock()
	defer api.mu.RUnlock()

	cfg := api.gateway.GetConfig()
	if cfg == nil {
		api.writeError(w, "Configuration not available", http.StatusInternalServerError)
		return
	}

	samplePath := r.URL.Query().Get("path")
	if samplePath == "" {
		samplePath = "/example"
	}
	sampleMethod := strings.ToUpper(r.URL.Query().Get("method"))
	if sampleMethod == "" {
		sampleMethod = http.MethodGet
	}

	results := make([]ConfigSelfTestRoute, 0)
	for _, serviceConfig := range cfg.Services {
		for _, service := range serviceConfig.Services {
			for _, rawRoute := range service.Routes {
				route := rawRoute
				route.Path = service.EffectiveRoutePath(rawRoute)
				route.Methods = rawRoute.EffectiveMethods()

				result := ConfigSelfTestRoute{
					RouteName:   route.Name,
					ServiceName: service.Name,
					RoutePath:   route.Path,
					RequestPath: samplePath,
					StripPath:   route.StripPath,
					Enabled:     route.IsEnabled(),
					Destination: service.Host,
				}
				if result.RouteName == "" {
					result.RouteName = route.Path
				}
				if len(route.Backends) > 0 {
					result.URLPattern = route.Backends[0].URLPattern
				}

				vars, matched := gateway.MatchRouteTemplate(route, sampleMethod, samplePath, nil)
				result.Matched = matched
				if matched {
					result.RouteVars = vars
					proxiedPath, err := gateway.ComputeProxiedPath(&service, route, samplePath, vars)
					if err != nil {
						api.writeError(w, fmt.Sprintf("Failed to compute proxied path for route %s: %v", route.Path, err), http.StatusInternalServerError)
						return
					}
					result.ProxiedPath = proxiedPath
				}

				results = append(results, result)
			}
		}
	}

	api.writeJSON(w, map[string]interface{}{
		"sample_method": sampleMethod,
		"sample_path":   samplePath,
		"routes":        results,
	})
}

func (api *ManagementAPI) updateGatewayConfig(w http.ResponseWriter, r *http.Request) {
	strategy := r.URL.Query().Get("strategy")
	if strategy == "" {
		strategy = "replace"
	}
	dryRun := r.URL.Query().Get("dry_run") == "true"
	proposalOnly := r.URL.Query().Get("proposal") == "true"

	var input map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		api.writeError(w, "Invalid configuration format", http.StatusBadRequest)
		return
	}

	api.mu.Lock()
	defer api.mu.Unlock()

	currentCfg := api.gateway.GetConfig()
	// Create a copy for simulation to avoid modifying the live config if it's a dry run
	simCfg := *currentCfg

	if strategy == "merge" {
		currentMap := make(map[string]interface{})
		currentJSON, _ := json.Marshal(simCfg)
		json.Unmarshal(currentJSON, &currentMap)

		api.deepMerge(currentMap, input)

		mergedJSON, _ := json.Marshal(currentMap)
		if err := json.Unmarshal(mergedJSON, &simCfg); err != nil {
			api.writeError(w, "Failed to merge configuration", http.StatusInternalServerError)
			return
		}
	} else {
		newJSON, _ := json.Marshal(input)
		if err := json.Unmarshal(newJSON, &simCfg); err != nil {
			api.writeError(w, "Invalid configuration", http.StatusBadRequest)
			return
		}
	}

	// Validate configuration
	if err := simCfg.Validate(); err != nil {
		api.writeError(w, fmt.Sprintf("Invalid configuration: %v", err), http.StatusBadRequest)
		return
	}

	summary := configChangeSummary(currentCfg, &simCfg)

	if dryRun {
		response := APIResponse{
			Success: true,
			Message: fmt.Sprintf("[DRY RUN] Configuration is valid and %s-ready", strategy),
			Data: map[string]interface{}{
				"strategy": strategy,
				"dry_run":  true,
				"summary":  summary,
			},
		}
		api.writeJSON(w, response)
		return
	}

	label, note, changeRef := revisionMetadataFromRequest(r)
	if proposalOnly {
		notBefore, err := proposalNotBeforeFromRequest(r)
		if err != nil {
			api.writeError(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := api.enforceProposalSchedule("gateway_config_"+strategy, notBefore); err != nil {
			api.writeError(w, err.Error(), http.StatusBadRequest)
			return
		}
		proposalID, err := saveConfigProposal("gateway_config_"+strategy, strategy, proposalProposerFromRequest(r), proposalEnvironmentFromRequest(r), "", "", nil, nil, nil, 0, nil, 0, 0, "", false, "", "", label, note, changeRef, notBefore, requiredProposalApprovers(api.gateway.GetConfig(), &configProposalRecord{Action: "gateway_config_" + strategy}), summary, &simCfg)
		if err != nil {
			api.writeError(w, fmt.Sprintf("Failed to create proposal: %v", err), http.StatusInternalServerError)
			return
		}
		api.writeJSON(w, APIResponse{
			Success: true,
			Message: "Configuration proposal created successfully",
			Data: map[string]interface{}{
				"proposal_id":     proposalID,
				"strategy":        strategy,
				"environment":     proposalEnvironmentFromRequest(r),
				"not_before":      notBefore,
				"canary_services": proposalCanaryServicesFromRequest(r, nil),
				"canary_routes":   proposalCanaryRoutesFromRequest(r, nil),
				"canary_headers":  proposalCanaryHeadersFromRequest(r, nil),
				"canary_percent":  0,
				"summary":         summary,
			},
		})
		return
	}

	if err := api.applyManagedConfigChange(&simCfg, "gateway_config_"+strategy, label, note, changeRef, summary); err != nil {
		api.writeError(w, "Failed to update configuration", http.StatusInternalServerError)
		return
	}

	response := APIResponse{
		Success: true,
		Message: fmt.Sprintf("Configuration updated successfully using %s strategy", strategy),
		Data: map[string]interface{}{
			"reload_required": true,
			"summary":         summary,
		},
	}
	api.writeJSON(w, response)
}

func (api *ManagementAPI) deepMerge(dst, src map[string]interface{}) {
	for k, v := range src {
		if srcMap, ok := v.(map[string]interface{}); ok {
			if dstMap, ok := dst[k].(map[string]interface{}); ok {
				api.deepMerge(dstMap, srcMap)
				continue
			}
		}
		dst[k] = v
	}
}

func (api *ManagementAPI) reloadGateway(w http.ResponseWriter, r *http.Request) {
	if err := api.gateway.ReloadConfig(); err != nil {
		api.writeError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	api.lastReload = time.Now()

	response := APIResponse{
		Success: true,
		Message: "Configuration reloaded successfully",
		Data: map[string]interface{}{
			"timestamp": time.Now(),
		},
	}
	api.writeJSON(w, response)
}

func (api *ManagementAPI) getGatewayMetrics(w http.ResponseWriter, r *http.Request) {
	metrics := GatewayMetrics{}
	allLogs := api.logger.RecentLogs(2000, "")
	errorLogs := api.logger.RecentLogs(2000, "error")
	warnLogs := api.logger.RecentLogs(2000, "warn")

	metrics.Requests.Total = int64(len(allLogs))
	metrics.Requests.Successful = metrics.Requests.Total - int64(len(errorLogs))
	metrics.Requests.Failed = int64(len(errorLogs))
	metrics.Requests.RatePerMinute = float64(len(allLogs))

	metrics.ResponseTimes.Average = 0
	metrics.ResponseTimes.P95 = 0
	metrics.ResponseTimes.P99 = 0

	metrics.Errors.FourXX = len(warnLogs)
	metrics.Errors.FiveXX = len(errorLogs)

	metrics.Connections.Active = 0
	metrics.Connections.Total = metrics.Requests.Total

	api.writeJSON(w, metrics)
}

func (api *ManagementAPI) getGatewayBackends(w http.ResponseWriter, r *http.Request) {
	backends := api.gateway.BackendStatuses()
	api.writeJSON(w, map[string]interface{}{
		"backends": backends,
		"total":    len(backends),
	})
}

func (api *ManagementAPI) getGatewayPolicyHits(w http.ResponseWriter, r *http.Request) {
	summary := api.gateway.PolicyHitSummary()
	window := 5 * time.Minute
	windowSource := "5m"
	if raw := strings.TrimSpace(r.URL.Query().Get("window")); raw != "" {
		if parsed, err := time.ParseDuration(raw); err == nil && parsed > 0 {
			window = parsed
			windowSource = raw
		}
	}
	recent := api.gateway.PolicyHitWindowSummary(window)
	recent.Window = windowSource
	api.writeJSON(w, map[string]interface{}{
		"total":         summary.Total,
		"updated_at":    summary.UpdatedAt,
		"reasons":       summary.Reasons,
		"routes":        summary.Routes,
		"recent_window": recent,
	})
}

func (api *ManagementAPI) getGatewayPolicyAlerts(w http.ResponseWriter, r *http.Request) {
	window, windowSource, minCount := parseGatewayPolicyAlertQuery(r)
	summary := api.gateway.PolicyAlertSummary(window, minCount)
	summary.Window = windowSource
	api.writeJSON(w, summary)
}

func (api *ManagementAPI) notifyGatewayPolicyAlerts(w http.ResponseWriter, r *http.Request) {
	window, windowSource, minCount := parseGatewayPolicyAlertQuery(r)
	summary := api.gateway.PolicyAlertSummary(window, minCount)
	summary.Window = windowSource

	digestPayload := managementWebhookEvent{
		Event:      "gateway.policy_alert_digest",
		OccurredAt: time.Now().UTC(),
		Data: map[string]interface{}{
			"window":         summary.Window,
			"window_seconds": summary.WindowSeconds,
			"min_count":      summary.MinCount,
			"total_alerts":   summary.TotalAlerts,
			"by_severity":    summary.BySeverity,
			"alerts":         summary.Alerts,
		},
	}
	digestDeliveries := api.emitManagementEvent(digestPayload)

	alertDeliveries := 0
	for _, alert := range summary.Alerts {
		alertDeliveries += api.emitManagementEvent(managementWebhookEvent{
			Event:      "gateway.policy_alert",
			OccurredAt: time.Now().UTC(),
			Data: map[string]interface{}{
				"window":         summary.Window,
				"window_seconds": summary.WindowSeconds,
				"min_count":      summary.MinCount,
				"severity":       alert.Severity,
				"service_name":   alert.ServiceName,
				"route_path":     alert.RoutePath,
				"reason":         alert.Reason,
				"count":          alert.Count,
				"since":          alert.Since,
			},
		})
	}

	api.writeJSON(w, map[string]interface{}{
		"window":            summary.Window,
		"min_count":         summary.MinCount,
		"total_alerts":      summary.TotalAlerts,
		"digest_deliveries": digestDeliveries,
		"alert_deliveries":  alertDeliveries,
		"alerts":            summary.Alerts,
	})
}

func parseGatewayPolicyAlertQuery(r *http.Request) (time.Duration, string, int) {
	window := 5 * time.Minute
	windowSource := "5m"
	if raw := strings.TrimSpace(r.URL.Query().Get("window")); raw != "" {
		if parsed, err := time.ParseDuration(raw); err == nil && parsed > 0 {
			window = parsed
			windowSource = raw
		}
	}
	minCount := 3
	if raw := strings.TrimSpace(r.URL.Query().Get("min_count")); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil && parsed > 0 {
			minCount = parsed
		}
	}
	return window, windowSource, minCount
}

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

func filterPolicyAlertSummaryBySeverity(summary gateway.PolicyAlertSummary, minSeverity string) gateway.PolicyAlertSummary {
	minRank := slaBreachTierRank(minSeverity)
	if minRank <= 0 {
		return summary
	}
	filtered := gateway.PolicyAlertSummary{
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

func gatewayPolicyAlertIncidentKey(alert gateway.PolicyAlert) string {
	return strings.TrimSpace(alert.ServiceName) + "|" + strings.TrimSpace(alert.RoutePath) + "|" + strings.TrimSpace(alert.Reason)
}

func buildGatewayPolicyAlertIncidentData(state gatewayPolicyAlertIncidentState, count int, severity string, now time.Time) map[string]interface{} {
	if count <= 0 {
		count = state.LastCount
	}
	if strings.TrimSpace(severity) == "" {
		severity = state.Severity
	}
	age := 0.0
	if !state.FirstSeenAt.IsZero() {
		age = now.Sub(state.FirstSeenAt).Seconds()
		if age < 0 {
			age = 0
		}
	}
	return map[string]interface{}{
		"incident_id":          strings.TrimSpace(state.IncidentID),
		"severity":             strings.TrimSpace(severity),
		"service_name":         strings.TrimSpace(state.ServiceName),
		"route_path":           strings.TrimSpace(state.RoutePath),
		"reason":               strings.TrimSpace(state.Reason),
		"count":                count,
		"first_seen_at":        state.FirstSeenAt,
		"last_seen_at":         state.LastSeenAt,
		"incident_age_seconds": age,
	}
}

func (api *ManagementAPI) getGatewayShadowReport(w http.ResponseWriter, r *http.Request) {
	summaries := api.gateway.ShadowRouteSummaries()
	api.writeJSON(w, map[string]interface{}{
		"routes": summaries,
		"total":  len(summaries),
	})
}

func (api *ManagementAPI) getGatewayShadowEvaluation(w http.ResponseWriter, r *http.Request) {
	evaluations := api.gateway.ShadowRouteEvaluations()
	healthy := 0
	failed := 0
	withPolicy := 0
	for _, evaluation := range evaluations {
		if evaluation.PolicyConfigured {
			withPolicy++
		}
		if evaluation.Healthy {
			healthy++
		} else {
			failed++
		}
	}
	api.writeJSON(w, map[string]interface{}{
		"routes":      evaluations,
		"total":       len(evaluations),
		"with_policy": withPolicy,
		"healthy":     healthy,
		"failed":      failed,
		"all_healthy": failed == 0,
	})
}

// ListPlugins returns the list of registered plugin names.
func (m *ManagementAPI) ListPlugins() []string {
	return m.registry.List() // assuming Registry has a List() method
}

func (api *ManagementAPI) listPlugins(w http.ResponseWriter, r *http.Request) {
	plugins := api.registry.List()
	pluginInfos := make([]PluginInfo, 0, len(plugins))

	for _, name := range plugins {
		plugin, err := api.registry.Get(name)
		if err != nil {
			continue
		}

		info := PluginInfo{
			Name:    name,
			Type:    "unknown",
			Enabled: api.pluginEnabled(name),
			Status:  "healthy",
			Tags:    make(map[string]string),
		}

		// Get plugin type if available
		if typedPlugin, ok := plugin.(interface{ Type() string }); ok {
			info.Type = typedPlugin.Type()
		}

		// Get plugin tags if available
		if taggedPlugin, ok := plugin.(interface{ Tags() map[string]string }); ok {
			info.Tags = taggedPlugin.Tags()
		}

		// Check health if available
		if healthChecker, ok := plugin.(interface{ Health() error }); ok {
			if err := healthChecker.Health(); err != nil {
				info.Status = "unhealthy"
			}
		}

		pluginInfos = append(pluginInfos, info)
	}

	response := map[string]interface{}{
		"plugins": pluginInfos,
	}
	api.writeJSON(w, response)
}

func (api *ManagementAPI) getPluginDetails(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	pluginName := vars["name"]

	plugin, err := api.registry.Get(pluginName)
	if err != nil {
		api.writeError(w, "Plugin not found", http.StatusNotFound)
		return
	}

	details := map[string]interface{}{
		"name":    pluginName,
		"type":    "unknown",
		"enabled": api.pluginEnabled(pluginName),
		"status":  "healthy",
	}

	// Get plugin type
	if typedPlugin, ok := plugin.(interface{ Type() string }); ok {
		details["type"] = typedPlugin.Type()
	}

	// Get plugin tags
	if taggedPlugin, ok := plugin.(interface{ Tags() map[string]string }); ok {
		details["tags"] = taggedPlugin.Tags()
	}

	// Get health status
	if healthChecker, ok := plugin.(interface{ Health() error }); ok {
		if err := healthChecker.Health(); err != nil {
			details["status"] = "unhealthy"
			details["health"] = map[string]interface{}{
				"status":  "unhealthy",
				"message": err.Error(),
			}
		} else {
			details["health"] = map[string]interface{}{
				"status":  "healthy",
				"message": "Plugin is functioning normally",
			}
		}
	}

	// Get status
	if statusReporter, ok := plugin.(interface{ Status() string }); ok {
		details["status_message"] = statusReporter.Status()
	}

	api.writeJSON(w, details)
}

func (api *ManagementAPI) updatePluginConfig(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	pluginName := vars["name"]
	dryRun := r.URL.Query().Get("dry_run") == "true"

	var config map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&config); err != nil {
		api.writeError(w, "Invalid configuration format", http.StatusBadRequest)
		return
	}

	plugin, err := api.registry.Get(pluginName)
	if err != nil {
		api.writeError(w, "Plugin not found", http.StatusNotFound)
		return
	}

	cfg := api.gateway.GetConfig()
	if cfg == nil {
		api.writeError(w, "Configuration not available", http.StatusInternalServerError)
		return
	}
	simCfg, err := cloneConfig(cfg)
	if err != nil {
		api.writeError(w, "Failed to prepare configuration update", http.StatusInternalServerError)
		return
	}
	currentPluginCfg := simCfg.Plugins[pluginName]
	simCfg.SetPluginConfig(pluginName, config)
	summary := map[string]interface{}{
		"plugin": pluginName,
		"summary": map[string]interface{}{
			"changed_fields": collectChangedPaths("", currentPluginCfg, config),
		},
	}

	if dryRun {
		api.writeJSON(w, map[string]interface{}{
			"success": true,
			"dry_run": true,
			"message": "[DRY RUN] Plugin configuration is valid and ready to apply",
			"data":    summary,
		})
		return
	}

	// Reload plugin with new configuration
	if err := plugin.Initialize(config); err != nil {
		api.writeError(w, "Failed to update plugin configuration", http.StatusInternalServerError)
		return
	}
	label, note, changeRef := revisionMetadataFromRequest(r)
	if err := api.applyManagedConfigChange(simCfg, "plugin_config_update", label, note, changeRef, summary); err != nil {
		api.writeError(w, "Failed to persist plugin configuration", http.StatusInternalServerError)
		return
	}

	response := APIResponse{
		Success: true,
		Message: "Plugin configuration updated",
		Data:    summary,
	}
	api.writeJSON(w, response)
}

func (api *ManagementAPI) enablePlugin(w http.ResponseWriter, r *http.Request) {
	pluginName := mux.Vars(r)["name"]
	if err := api.setPluginEnabled(r, pluginName, true); err != nil {
		api.writeError(w, err.Error(), http.StatusBadRequest)
		return
	}

	response := APIResponse{
		Success: true,
		Message: "Plugin enabled successfully",
	}
	api.writeJSON(w, response)
}

func (api *ManagementAPI) disablePlugin(w http.ResponseWriter, r *http.Request) {
	pluginName := mux.Vars(r)["name"]
	if err := api.setPluginEnabled(r, pluginName, false); err != nil {
		api.writeError(w, err.Error(), http.StatusBadRequest)
		return
	}

	response := APIResponse{
		Success: true,
		Message: "Plugin disabled successfully",
	}
	api.writeJSON(w, response)
}

func (api *ManagementAPI) getPluginHealth(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	pluginName := vars["name"]

	plugin, err := api.registry.Get(pluginName)
	if err != nil {
		api.writeError(w, "Plugin not found", http.StatusNotFound)
		return
	}

	healthChecker, ok := plugin.(interface{ Health() error })
	if !ok {
		api.writeError(w, "Plugin does not support health checks", http.StatusNotImplemented)
		return
	}

	err = healthChecker.Health()
	health := map[string]interface{}{
		"status":     "healthy",
		"last_check": time.Now(),
		"message":    "Plugin is functioning normally",
	}

	if err != nil {
		health["status"] = "unhealthy"
		health["message"] = err.Error()
	}

	api.writeJSON(w, health)
}

func (api *ManagementAPI) getPluginStatus(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	pluginName := vars["name"]

	plugin, err := api.registry.Get(pluginName)
	if err != nil {
		api.writeError(w, "Plugin not found", http.StatusNotFound)
		return
	}

	statusReporter, ok := plugin.(interface{ Status() string })
	if !ok {
		api.writeError(w, "Plugin does not support status reporting", http.StatusNotImplemented)
		return
	}

	status := map[string]interface{}{
		"status":      statusReporter.Status(),
		"enabled":     api.pluginEnabled(pluginName),
		"last_update": time.Now(),
	}

	api.writeJSON(w, status)
}

func (api *ManagementAPI) listRoutes(w http.ResponseWriter, r *http.Request) {
	cfg := api.gateway.GetConfig()
	if cfg == nil {
		api.writeError(w, "Configuration not available", http.StatusInternalServerError)
		return
	}

	records := api.routeRecords(cfg)
	routeInfos := make([]RouteInfo, 0, len(records))
	for _, record := range records {
		routeInfos = append(routeInfos, api.routeInfoFromRecord(record))
	}
	response := map[string]interface{}{
		"routes": routeInfos,
	}
	api.writeJSON(w, response)
}

func (api *ManagementAPI) getRouteDetails(w http.ResponseWriter, r *http.Request) {
	record, err := api.findRouteRecord(api.gateway.GetConfig(), mux.Vars(r)["id"])
	if err != nil {
		api.writeError(w, err.Error(), http.StatusNotFound)
		return
	}
	api.writeJSON(w, map[string]interface{}{
		"id":           record.ID,
		"service_name": record.Service.Name,
		"path":         record.EffectivePath,
		"raw_path":     record.Route.Path,
		"destination":  record.Service.Host,
		"methods":      record.Route.EffectiveMethods(),
		"require_auth": record.Route.RequireAuth,
		"require_jwt":  record.Route.RequireJwt,
		"strip_path":   record.Route.StripPath,
		"enabled":      record.Route.IsEnabled(),
		"backend":      record.Route.Backends,
		"scopes":       record.Route.Scopes,
		"roles":        record.Route.Roles,
		"headers":      record.Route.Headers,
	})
}

func (api *ManagementAPI) createRoute(w http.ResponseWriter, r *http.Request) {
	dryRun := r.URL.Query().Get("dry_run") == "true"
	var req struct {
		ServiceName string              `json:"service_name"`
		Route       config.RouterConfig `json:"route"`
		Path        string              `json:"path"`
		Method      string              `json:"method"`
		Methods     []string            `json:"methods"`
		RequireAuth bool                `json:"requireAuth"`
		StripPath   bool                `json:"stripPath"`
		RequireJwt  bool                `json:"requireJwt"`
		Enabled     *bool               `json:"enabled"`
		Backends    []config.Backend    `json:"backend"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.writeError(w, "Invalid route configuration", http.StatusBadRequest)
		return
	}
	cfg := api.gateway.GetConfig()
	simCfg, err := cloneConfig(cfg)
	if err != nil {
		api.writeError(w, "Failed to prepare configuration update", http.StatusInternalServerError)
		return
	}
	routeConfig := req.Route
	if routeConfig.Path == "" {
		routeConfig.Path = req.Path
		routeConfig.Method = req.Method
		routeConfig.Methods = req.Methods
		routeConfig.RequireAuth = req.RequireAuth
		routeConfig.StripPath = req.StripPath
		routeConfig.RequireJwt = req.RequireJwt
		routeConfig.Enabled = req.Enabled
		routeConfig.Backends = req.Backends
	}
	if routeConfig.Enabled == nil {
		routeConfig.Enabled = config.NewBool(true)
	}
	if routeConfig.Path == "" || req.ServiceName == "" {
		api.writeError(w, "service_name and route.path are required", http.StatusBadRequest)
		return
	}
	service, err := findServiceByName(simCfg, req.ServiceName)
	if err != nil {
		api.writeError(w, err.Error(), http.StatusNotFound)
		return
	}
	for _, existing := range service.Routes {
		if existing.Path == routeConfig.Path && sameMethods(existing.EffectiveMethods(), routeConfig.EffectiveMethods()) {
			api.writeError(w, "Route already exists", http.StatusConflict)
			return
		}
	}
	service.Routes = append(service.Routes, routeConfig)
	summary := routeChangeSummary(nil, &routeConfig, *service)

	if dryRun {
		api.writeJSON(w, map[string]interface{}{
			"success": true,
			"dry_run": true,
			"message": "[DRY RUN] Route is valid and ready to create",
			"data": map[string]interface{}{
				"summary": summary,
			},
		})
		return
	}
	label, note, changeRef := revisionMetadataFromRequest(r)
	if err := api.applyManagedConfigChange(simCfg, "route_create", label, note, changeRef, map[string]interface{}{"summary": summary}); err != nil {
		api.writeError(w, "Failed to create route", http.StatusInternalServerError)
		return
	}
	record, _ := api.findRouteByServicePathMethod(api.gateway.GetConfig(), req.ServiceName, routeConfig.Path, routeConfig.EffectiveMethods())

	response := APIResponse{
		Success: true,
		Message: "Route created successfully",
		Data: map[string]interface{}{
			"route_id": record.ID,
			"summary":  summary,
		},
	}
	api.writeJSON(w, response)
}

func getIP(r *http.Request) string {
	// Common proxy headers
	hdrs := []string{
		"X-Forwarded-For",
		"X-Real-Ip",
		"Proxy-Client-IP",
		"WL-Proxy-Client-IP",
	}

	for _, h := range hdrs {
		v := r.Header.Get(h)
		if v == "" {
			continue
		}
		parts := strings.Split(v, ",")
		if len(parts) > 0 {
			ip := strings.TrimSpace(parts[0])
			if ip != "" {
				return ip
			}
		}
	}

	// fallback
	if host, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr)); err == nil {
		return host
	}
	return r.RemoteAddr
}

func (api *ManagementAPI) updateRoute(w http.ResponseWriter, r *http.Request) {
	dryRun := r.URL.Query().Get("dry_run") == "true"
	var raw map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&raw); err != nil {
		api.writeError(w, "Invalid update data", http.StatusBadRequest)
		return
	}
	updateBytes, _ := json.Marshal(raw)
	var updates config.RouterConfig
	if err := json.Unmarshal(updateBytes, &updates); err != nil {
		api.writeError(w, "Invalid update data", http.StatusBadRequest)
		return
	}
	cfg := api.gateway.GetConfig()
	record, err := api.findRouteRecord(cfg, mux.Vars(r)["id"])
	if err != nil {
		api.writeError(w, err.Error(), http.StatusNotFound)
		return
	}
	simCfg, err := cloneConfig(cfg)
	if err != nil {
		api.writeError(w, "Failed to prepare configuration update", http.StatusInternalServerError)
		return
	}
	svc := &simCfg.Services[record.ServiceConfigIndex].Services[record.ServiceIndex]
	updatedRoute := svc.Routes[record.RouteIndex]
	previousRoute := updatedRoute
	mergeRouteUpdate(&updatedRoute, updates)
	applyRouteRawUpdate(&updatedRoute, raw)
	svc.Routes[record.RouteIndex] = updatedRoute
	summary := routeChangeSummary(&previousRoute, &updatedRoute, *svc)

	if dryRun {
		api.writeJSON(w, map[string]interface{}{
			"success": true,
			"dry_run": true,
			"message": "[DRY RUN] Route update is valid and ready to apply",
			"data": map[string]interface{}{
				"route_id": record.ID,
				"summary":  summary,
			},
		})
		return
	}
	label, note, changeRef := revisionMetadataFromRequest(r)
	if err := api.applyManagedConfigChange(simCfg, "route_update", label, note, changeRef, map[string]interface{}{"route_id": record.ID, "summary": summary}); err != nil {
		api.writeError(w, "Failed to update route", http.StatusInternalServerError)
		return
	}

	response := APIResponse{
		Success: true,
		Message: "Route updated successfully",
		Data: map[string]interface{}{
			"route_id": record.ID,
			"summary":  summary,
		},
	}
	api.writeJSON(w, response)
}

func (api *ManagementAPI) deleteRoute(w http.ResponseWriter, r *http.Request) {
	cfg := api.gateway.GetConfig()
	record, err := api.findRouteRecord(cfg, mux.Vars(r)["id"])
	if err != nil {
		api.writeError(w, err.Error(), http.StatusNotFound)
		return
	}
	simCfg, err := cloneConfig(cfg)
	if err != nil {
		api.writeError(w, "Failed to prepare configuration update", http.StatusInternalServerError)
		return
	}
	svc := &simCfg.Services[record.ServiceConfigIndex].Services[record.ServiceIndex]
	svc.Routes = append(svc.Routes[:record.RouteIndex], svc.Routes[record.RouteIndex+1:]...)
	label, note, changeRef := revisionMetadataFromRequest(r)
	if err := api.applyManagedConfigChange(simCfg, "route_delete", label, note, changeRef, map[string]interface{}{"route_id": record.ID}); err != nil {
		api.writeError(w, "Failed to delete route", http.StatusInternalServerError)
		return
	}

	response := APIResponse{
		Success: true,
		Message: "Route deleted successfully",
	}
	api.writeJSON(w, response)
}

func (api *ManagementAPI) enableRoute(w http.ResponseWriter, r *http.Request) {
	if err := api.setRouteEnabled(r, mux.Vars(r)["id"], true); err != nil {
		api.writeError(w, err.Error(), http.StatusNotFound)
		return
	}

	response := APIResponse{
		Success: true,
		Message: "Route enabled successfully",
	}
	api.writeJSON(w, response)
}

func (api *ManagementAPI) disableRoute(w http.ResponseWriter, r *http.Request) {
	if err := api.setRouteEnabled(r, mux.Vars(r)["id"], false); err != nil {
		api.writeError(w, err.Error(), http.StatusNotFound)
		return
	}

	response := APIResponse{
		Success: true,
		Message: "Route disabled successfully",
	}
	api.writeJSON(w, response)
}

func (api *ManagementAPI) getLogs(w http.ResponseWriter, r *http.Request) {
	limit := 100
	if raw := r.URL.Query().Get("limit"); raw != "" {
		fmt.Sscanf(raw, "%d", &limit)
	}
	level := r.URL.Query().Get("level")
	serviceName := r.URL.Query().Get("service")
	routeName := r.URL.Query().Get("route")
	requestID := r.URL.Query().Get("request_id")

	logs := filterLogEntries(api.logger.RecentLogs(2000, level), serviceName, routeName, requestID)
	if limit > 0 && len(logs) > limit {
		logs = logs[len(logs)-limit:]
	}
	response := map[string]interface{}{
		"logs":     logs,
		"total":    len(logs),
		"has_more": false,
	}
	api.writeJSON(w, response)
}

func (api *ManagementAPI) streamLogs(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	flusher, ok := w.(http.Flusher)
	if !ok {
		api.writeError(w, "Streaming not supported", http.StatusInternalServerError)
		return
	}

	fmt.Fprintf(w, "event: connected\ndata: {\"message\":\"Connected to log stream\"}\n\n")
	flusher.Flush()

	level := r.URL.Query().Get("level")
	serviceName := r.URL.Query().Get("service")
	routeName := r.URL.Query().Get("route")
	requestID := r.URL.Query().Get("request_id")
	backlog := 20
	if raw := r.URL.Query().Get("backlog"); raw != "" {
		fmt.Sscanf(raw, "%d", &backlog)
	}
	backlogEntries := filterLogEntries(api.logger.RecentLogs(2000, level), serviceName, routeName, requestID)
	if backlog > 0 && len(backlogEntries) > backlog {
		backlogEntries = backlogEntries[len(backlogEntries)-backlog:]
	}
	for _, entry := range backlogEntries {
		data, _ := json.Marshal(entry)
		fmt.Fprintf(w, "event: log\ndata: %s\n\n", data)
	}
	flusher.Flush()

	ch := api.logger.SubscribeLogs()
	defer api.logger.UnsubscribeLogs(ch)

	for {
		select {
		case <-r.Context().Done():
			return
		case entry := <-ch:
			if !logEntryMatches(entry, serviceName, routeName, requestID) {
				continue
			}
			data, _ := json.Marshal(entry)
			fmt.Fprintf(w, "event: log\ndata: %s\n\n", data)
			flusher.Flush()
		}
	}
}

func filterLogEntries(entries []logging.LogEntry, serviceName, routeName, requestID string) []logging.LogEntry {
	if serviceName == "" && routeName == "" && requestID == "" {
		return entries
	}
	filtered := make([]logging.LogEntry, 0, len(entries))
	for _, entry := range entries {
		if logEntryMatches(entry, serviceName, routeName, requestID) {
			filtered = append(filtered, entry)
		}
	}
	return filtered
}

func logEntryMatches(entry logging.LogEntry, serviceName, routeName, requestID string) bool {
	if serviceName != "" && fieldString(entry.Fields, "service_name") != serviceName {
		return false
	}
	if routeName != "" && fieldString(entry.Fields, "route_name") != routeName {
		return false
	}
	if requestID != "" && fieldString(entry.Fields, "request_id") != requestID {
		return false
	}
	return true
}

func fieldString(fields map[string]interface{}, key string) string {
	if len(fields) == 0 {
		return ""
	}
	if value, ok := fields[key]; ok {
		return fmt.Sprint(value)
	}
	return ""
}

func (api *ManagementAPI) getSystemMetrics(w http.ResponseWriter, r *http.Request) {
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	metrics := map[string]interface{}{
		"process": map[string]interface{}{
			"goroutines": runtime.NumGoroutine(),
			"cpus":       runtime.NumCPU(),
		},
		"memory": map[string]interface{}{
			"alloc_mb":      mem.Alloc / 1024 / 1024,
			"sys_mb":        mem.Sys / 1024 / 1024,
			"heap_alloc_mb": mem.HeapAlloc / 1024 / 1024,
		},
		"storage": map[string]interface{}{
			"admin_dir": adminDataDir(),
		},
	}

	api.writeJSON(w, metrics)
}

// WebSocket handlers

func (api *ManagementAPI) wsStatus(w http.ResponseWriter, r *http.Request) {
	conn, err := api.upgrader.Upgrade(w, r, nil)
	if err != nil {
		api.logger.Error("Failed to upgrade WebSocket connection", err)
		return
	}
	defer conn.Close()

	// Register subscriber
	api.subscriberMu.Lock()
	api.statusSubscribers[conn] = true
	api.subscriberMu.Unlock()

	// Remove subscriber when connection closes
	defer func() {
		api.subscriberMu.Lock()
		delete(api.statusSubscribers, conn)
		api.subscriberMu.Unlock()
	}()

	// Keep connection alive
	for {
		_, _, err := conn.ReadMessage()
		if err != nil {
			break
		}
	}
}

func (api *ManagementAPI) wsMetrics(w http.ResponseWriter, r *http.Request) {
	conn, err := api.upgrader.Upgrade(w, r, nil)
	if err != nil {
		api.logger.Error("Failed to upgrade WebSocket connection", err)
		return
	}
	defer conn.Close()

	// Register subscriber
	api.subscriberMu.Lock()
	api.metricsSubscribers[conn] = true
	api.subscriberMu.Unlock()

	// Remove subscriber when connection closes
	defer func() {
		api.subscriberMu.Lock()
		delete(api.metricsSubscribers, conn)
		api.subscriberMu.Unlock()
	}()

	// Keep connection alive
	for {
		_, _, err := conn.ReadMessage()
		if err != nil {
			break
		}
	}
}

func (api *ManagementAPI) wsLogs(w http.ResponseWriter, r *http.Request) {
	conn, err := api.upgrader.Upgrade(w, r, nil)
	if err != nil {
		api.logger.Error("Failed to upgrade WebSocket connection", err)
		return
	}
	defer conn.Close()

	level := r.URL.Query().Get("level")
	ch := api.logger.SubscribeLogs()
	defer api.logger.UnsubscribeLogs(ch)

	for _, entry := range api.logger.RecentLogs(20, level) {
		if err := conn.WriteJSON(entry); err != nil {
			return
		}
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	}()

	for {
		select {
		case <-done:
			return
		case entry := <-ch:
			if level != "" && !strings.EqualFold(entry.Level, level) {
				continue
			}
			if err := conn.WriteJSON(entry); err != nil {
				return
			}
		}
	}
}

// Real-time update broadcasters

func (api *ManagementAPI) broadcastStatusUpdates() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		status := map[string]interface{}{
			"type": "status_update",
			"data": map[string]interface{}{
				"status":             "running",
				"active_connections": 42,
				"total_requests":     15420,
			},
		}

		api.broadcastToSubscribers(api.statusSubscribers, status)
	}
}

func (api *ManagementAPI) broadcastMetricsUpdates() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		metrics := map[string]interface{}{
			"type": "metrics_update",
			"data": map[string]interface{}{
				"requests_per_minute": 120.0,
				"avg_response_time":   45.2,
				"error_rate":          0.26,
			},
		}

		api.broadcastToSubscribers(api.metricsSubscribers, metrics)
	}
}

func (api *ManagementAPI) broadcastToSubscribers(subscribers map[*websocket.Conn]bool, message interface{}) {
	data, err := json.Marshal(message)
	if err != nil {
		api.logger.Error("Failed to marshal message", err)
		return
	}

	api.subscriberMu.RLock()
	defer api.subscriberMu.RUnlock()

	for conn := range subscribers {
		err := conn.WriteMessage(websocket.TextMessage, data)
		if err != nil {
			api.logger.Error("Failed to send message to subscriber", err)
			// Remove failed connection
			delete(subscribers, conn)
			conn.Close()
		}
	}
}

// Certificate management (placeholder implementations)

func (api *ManagementAPI) listCertificates(w http.ResponseWriter, r *http.Request) {
	certificates, err := loadManagedCertificates()
	if err != nil {
		api.writeError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"certificates": certificates,
	}
	api.writeJSON(w, response)
}

func (api *ManagementAPI) uploadCertificate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name    string `json:"name"`
		Type    string `json:"type"`
		CertPEM string `json:"cert_pem"`
		KeyPEM  string `json:"key_pem"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.writeError(w, "Invalid certificate payload", http.StatusBadRequest)
		return
	}
	meta, err := saveManagedCertificate(req.Name, req.Type, req.CertPEM, req.KeyPEM)
	if err != nil {
		api.writeError(w, err.Error(), http.StatusBadRequest)
		return
	}

	response := APIResponse{
		Success: true,
		Message: "Certificate uploaded successfully",
		Data: map[string]interface{}{
			"certificate_id": meta["id"],
		},
	}
	api.writeJSON(w, response)
}

func (api *ManagementAPI) createEnrollmentToken(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name      string `json:"name"`
		TTLMinute int    `json:"ttl_minutes"`
		ServerURL string `json:"server_url"`
		EnrollURL string `json:"enroll_url"`
		ClientCN  string `json:"client_cn"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.writeError(w, "Invalid enrollment token payload", http.StatusBadRequest)
		return
	}

	if strings.TrimSpace(req.Name) == "" {
		req.Name = "iket-cli"
	}
	if req.TTLMinute <= 0 {
		req.TTLMinute = 15
	}
	if req.TTLMinute > 1440 {
		api.writeError(w, "ttl_minutes must be between 1 and 1440", http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(req.ClientCN) == "" {
		req.ClientCN = sanitizedClientCommonName(req.Name)
	}

	existing, err := listEnrollmentTokenRecords()
	if err != nil {
		api.writeError(w, "Failed to inspect enrollment tokens", http.StatusInternalServerError)
		return
	}
	activeCount := 0
	now := time.Now().UTC()
	for _, record := range existing {
		if isActiveEnrollmentToken(record, now) {
			activeCount++
		}
	}
	maxActive := api.gateway.GetConfig().Security.TLS.EffectiveEnrollmentMaxActive()
	if activeCount >= maxActive {
		api.writeError(w, fmt.Sprintf("active enrollment token limit reached (%d)", maxActive), http.StatusConflict)
		return
	}

	caKey, caCert, caPEM, err := loadEnrollmentCA(api.gateway.GetConfig().Security.TLS)
	if err != nil {
		api.writeError(w, err.Error(), http.StatusBadRequest)
		return
	}
	_ = caKey
	_ = caCert

	id, err := randomHex(6)
	if err != nil {
		api.writeError(w, "Failed to generate enrollment token", http.StatusInternalServerError)
		return
	}
	secret, err := randomHex(16)
	if err != nil {
		api.writeError(w, "Failed to generate enrollment token", http.StatusInternalServerError)
		return
	}

	record := enrollmentTokenRecord{
		ID:        id,
		Name:      req.Name,
		TokenHash: hashEnrollmentSecret(secret),
		CreatedAt: time.Now().UTC(),
		ExpiresAt: time.Now().UTC().Add(time.Duration(req.TTLMinute) * time.Minute),
		ServerURL: strings.TrimSpace(req.ServerURL),
		EnrollURL: strings.TrimSpace(req.EnrollURL),
		ClientCN:  req.ClientCN,
	}
	if err := saveEnrollmentTokenRecord(record); err != nil {
		api.writeError(w, "Failed to persist enrollment token", http.StatusInternalServerError)
		return
	}

	api.logger.Info("Enrollment token created",
		logging.String("event", "enrollment_token_created"),
		logging.String("token_id", id),
		logging.String("token_name", req.Name),
		logging.String("client_cn", req.ClientCN),
		logging.String("client_ip", gateway.GetClientIP(r)),
		logging.Int("ttl_minutes", req.TTLMinute),
		logging.Int("active_tokens", activeCount+1),
	)

	api.writeJSON(w, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"id":         id,
			"name":       req.Name,
			"token":      id + "." + secret,
			"expires_at": record.ExpiresAt,
			"server_url": record.ServerURL,
			"enroll_url": record.EnrollURL,
			"client_cn":  record.ClientCN,
			"ca_pem":     string(caPEM),
		},
	})
}

func (api *ManagementAPI) enrollClientCertificate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token     string `json:"token"`
		Name      string `json:"name"`
		CSRPEM    string `json:"csr_pem"`
		ServerURL string `json:"server_url"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.writeError(w, "Invalid enrollment request", http.StatusBadRequest)
		return
	}

	id, secret, err := parseEnrollmentToken(req.Token)
	if err != nil {
		api.writeError(w, err.Error(), http.StatusBadRequest)
		return
	}
	record, err := loadEnrollmentTokenRecord(id)
	if err != nil {
		api.writeError(w, err.Error(), http.StatusNotFound)
		return
	}
	if record.TokenHash != hashEnrollmentSecret(secret) {
		api.writeError(w, "Invalid enrollment token", http.StatusUnauthorized)
		return
	}
	if !record.UsedAt.IsZero() {
		api.writeError(w, "Enrollment token has already been used", http.StatusConflict)
		return
	}
	if time.Now().UTC().After(record.ExpiresAt) {
		api.writeError(w, "Enrollment token has expired", http.StatusUnauthorized)
		return
	}
	if strings.TrimSpace(req.CSRPEM) == "" {
		api.writeError(w, "csr_pem is required", http.StatusBadRequest)
		return
	}

	caKey, caCert, caPEM, err := loadEnrollmentCA(api.gateway.GetConfig().Security.TLS)
	if err != nil {
		api.writeError(w, err.Error(), http.StatusBadRequest)
		return
	}

	commonName := record.ClientCN
	if commonName == "" {
		commonName = sanitizedClientCommonName(firstNonEmpty(req.Name, record.Name, "iket-cli"))
	}
	certPEM, cert, err := signEnrollmentCSR([]byte(req.CSRPEM), commonName, caKey, caCert)
	if err != nil {
		api.writeError(w, fmt.Sprintf("Failed to sign CSR: %v", err), http.StatusBadRequest)
		return
	}

	record.UsedAt = time.Now().UTC()
	if strings.TrimSpace(req.ServerURL) != "" {
		record.ServerURL = strings.TrimSpace(req.ServerURL)
	}
	if err := saveEnrollmentTokenRecord(*record); err != nil {
		api.writeError(w, "Failed to finalize enrollment token", http.StatusInternalServerError)
		return
	}

	api.logger.Info("Enrollment token redeemed",
		logging.String("event", "enrollment_token_redeemed"),
		logging.String("token_id", record.ID),
		logging.String("token_name", record.Name),
		logging.String("client_cn", commonName),
		logging.String("client_ip", gateway.GetClientIP(r)),
	)

	api.writeJSON(w, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"cert_pem":    string(certPEM),
			"ca_pem":      string(caPEM),
			"server_url":  record.ServerURL,
			"subject":     cert.Subject.String(),
			"valid_until": cert.NotAfter,
		},
	})
}

func (api *ManagementAPI) listEnrollmentTokens(w http.ResponseWriter, r *http.Request) {
	records, err := listEnrollmentTokenRecords()
	if err != nil {
		api.writeError(w, "Failed to list enrollment tokens", http.StatusInternalServerError)
		return
	}
	now := time.Now().UTC()
	items := make([]map[string]interface{}, 0, len(records))
	activeCount := 0
	for _, record := range records {
		active := isActiveEnrollmentToken(record, now)
		if active {
			activeCount++
		}
		items = append(items, map[string]interface{}{
			"id":         record.ID,
			"name":       record.Name,
			"created_at": record.CreatedAt,
			"expires_at": record.ExpiresAt,
			"used_at":    record.UsedAt,
			"server_url": record.ServerURL,
			"enroll_url": record.EnrollURL,
			"client_cn":  record.ClientCN,
			"active":     active,
		})
	}
	api.writeJSON(w, map[string]interface{}{
		"tokens":             items,
		"active_count":       activeCount,
		"max_active_allowed": api.gateway.GetConfig().Security.TLS.EffectiveEnrollmentMaxActive(),
	})
}

func (api *ManagementAPI) revokeEnrollmentToken(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	record, err := loadEnrollmentTokenRecord(id)
	if err != nil {
		api.writeError(w, err.Error(), http.StatusNotFound)
		return
	}
	if err := deleteEnrollmentTokenRecord(id); err != nil {
		api.writeError(w, "Failed to revoke enrollment token", http.StatusInternalServerError)
		return
	}

	api.logger.Info("Enrollment token revoked",
		logging.String("event", "enrollment_token_revoked"),
		logging.String("token_id", id),
		logging.String("token_name", record.Name),
		logging.String("client_ip", gateway.GetClientIP(r)),
	)

	api.writeJSON(w, APIResponse{
		Success: true,
		Message: "Enrollment token revoked",
		Data: map[string]interface{}{
			"id":   id,
			"name": record.Name,
		},
	})
}

func (api *ManagementAPI) deleteCertificate(w http.ResponseWriter, r *http.Request) {
	if err := deleteManagedCertificate(mux.Vars(r)["id"]); err != nil {
		api.writeError(w, err.Error(), http.StatusNotFound)
		return
	}

	response := APIResponse{
		Success: true,
		Message: "Certificate deleted successfully",
	}
	api.writeJSON(w, response)
}

// Backup & restore (placeholder implementations)

func (api *ManagementAPI) createBackup(w http.ResponseWriter, r *http.Request) {
	backupID, filePath, size, err := createConfigBackup(api.gateway.GetConfig())
	if err != nil {
		api.writeError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	response := APIResponse{
		Success: true,
		Message: "Backup created successfully",
		Data: map[string]interface{}{
			"backup_id":  backupID,
			"filename":   filepath.Base(filePath),
			"size_bytes": size,
			"created_at": time.Now(),
		},
	}
	api.writeJSON(w, response)
}

func (api *ManagementAPI) listBackups(w http.ResponseWriter, r *http.Request) {
	backups, err := listConfigBackups()
	if err != nil {
		api.writeError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"backups": backups,
	}
	api.writeJSON(w, response)
}

func (api *ManagementAPI) restoreBackup(w http.ResponseWriter, r *http.Request) {
	if err := restoreConfigBackup(api.gateway, mux.Vars(r)["id"]); err != nil {
		api.writeError(w, err.Error(), http.StatusNotFound)
		return
	}
	api.lastReload = time.Now()

	response := APIResponse{
		Success: true,
		Message: "Backup restored successfully",
		Data: map[string]interface{}{
			"restart_required": true,
		},
	}
	api.writeJSON(w, response)
}

func (api *ManagementAPI) listRevisions(w http.ResponseWriter, r *http.Request) {
	revisions, err := listConfigRevisions()
	if err != nil {
		api.writeError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	api.writeJSON(w, map[string]interface{}{
		"revisions": revisions,
	})
}

func (api *ManagementAPI) getRevision(w http.ResponseWriter, r *http.Request) {
	record, err := loadConfigRevision(mux.Vars(r)["id"])
	if err != nil {
		api.writeError(w, err.Error(), http.StatusNotFound)
		return
	}
	serviceCount := 0
	routeCount := 0
	if record.Config != nil {
		for _, svcCfg := range record.Config.Services {
			serviceCount += len(svcCfg.Services)
			for _, svc := range svcCfg.Services {
				routeCount += len(svc.Routes)
			}
		}
	}
	api.writeJSON(w, map[string]interface{}{
		"id":            record.ID,
		"action":        record.Action,
		"label":         record.Label,
		"note":          record.Note,
		"change_ref":    record.ChangeRef,
		"created_at":    record.CreatedAt,
		"summary":       record.Summary,
		"service_count": serviceCount,
		"route_count":   routeCount,
		"config":        record.Config,
	})
}

func (api *ManagementAPI) diffRevisions(w http.ResponseWriter, r *http.Request) {
	fromID := strings.TrimSpace(r.URL.Query().Get("from"))
	toID := strings.TrimSpace(r.URL.Query().Get("to"))
	if fromID == "" || toID == "" {
		api.writeError(w, "from and to query parameters are required", http.StatusBadRequest)
		return
	}

	fromCfg, fromMeta, err := api.resolveRevisionConfig(fromID)
	if err != nil {
		api.writeError(w, err.Error(), http.StatusNotFound)
		return
	}
	toCfg, toMeta, err := api.resolveRevisionConfig(toID)
	if err != nil {
		api.writeError(w, err.Error(), http.StatusNotFound)
		return
	}

	api.writeJSON(w, map[string]interface{}{
		"from": map[string]interface{}{
			"id":         fromID,
			"source":     fromMeta["source"],
			"action":     fromMeta["action"],
			"label":      fromMeta["label"],
			"note":       fromMeta["note"],
			"change_ref": fromMeta["change_ref"],
			"created_at": fromMeta["created_at"],
		},
		"to": map[string]interface{}{
			"id":         toID,
			"source":     toMeta["source"],
			"action":     toMeta["action"],
			"label":      toMeta["label"],
			"note":       toMeta["note"],
			"change_ref": toMeta["change_ref"],
			"created_at": toMeta["created_at"],
		},
		"config_summary":  configChangeSummary(fromCfg, toCfg),
		"service_summary": serviceChangeSummary(fromCfg, toCfg),
	})
}

func (api *ManagementAPI) restoreRevision(w http.ResponseWriter, r *http.Request) {
	record, err := loadConfigRevision(mux.Vars(r)["id"])
	if err != nil {
		api.writeError(w, err.Error(), http.StatusNotFound)
		return
	}
	if record.Config == nil {
		api.writeError(w, "revision has no stored configuration", http.StatusInternalServerError)
		return
	}
	summary := map[string]interface{}{
		"restored_from_revision": record.ID,
		"original_action":        record.Action,
	}
	label, note, changeRef := revisionMetadataFromRequest(r)
	if err := api.applyManagedConfigChange(record.Config, "restore_revision", label, note, changeRef, summary); err != nil {
		api.writeError(w, fmt.Sprintf("Failed to restore revision: %v", err), http.StatusInternalServerError)
		return
	}
	api.writeJSON(w, APIResponse{
		Success: true,
		Message: "Revision restored successfully",
		Data: map[string]interface{}{
			"revision_id": record.ID,
			"summary":     summary,
		},
	})
}

func (api *ManagementAPI) listProposals(w http.ResponseWriter, r *http.Request) {
	proposals, err := listConfigProposals()
	if err != nil {
		api.writeError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	for _, proposal := range proposals {
		id, _ := proposal["id"].(string)
		if id == "" {
			continue
		}
		record, err := loadConfigProposal(id)
		if err != nil {
			continue
		}
		proposal["approval_count"] = proposalApprovalCount(api.gateway.GetConfig(), record)
		proposal["required_approvals"] = requiredProposalApprovers(api.gateway.GetConfig(), record)
	}
	api.writeJSON(w, map[string]interface{}{
		"proposals": proposals,
	})
}

func (api *ManagementAPI) getProposalQueue(w http.ResponseWriter, r *http.Request) {
	response, statusCode, err := api.buildProposalQueueSnapshot(r)
	if err != nil {
		api.writeError(w, err.Error(), statusCode)
		return
	}
	api.writeJSON(w, response)
}

func (api *ManagementAPI) buildProposalQueueSnapshot(r *http.Request) (map[string]interface{}, int, error) {
	cfg := api.gateway.GetConfig()
	proposals, err := listConfigProposals()
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}

	query := r.URL.Query()
	filterEnv := strings.TrimSpace(query.Get("environment"))
	filterStatus := strings.TrimSpace(query.Get("status"))
	filterReady := strings.TrimSpace(query.Get("ready"))
	filterNextAction := strings.TrimSpace(query.Get("next_action"))
	filterUrgency := strings.TrimSpace(query.Get("urgency"))
	if filterUrgency != "" && !isValidProposalQueueUrgency(filterUrgency) {
		return nil, http.StatusBadRequest, fmt.Errorf("urgency filter must be fresh, aging, or overdue")
	}
	limit := 0
	if rawLimit := strings.TrimSpace(query.Get("limit")); rawLimit != "" {
		parsed, err := strconv.Atoi(rawLimit)
		if err != nil || parsed <= 0 {
			return nil, http.StatusBadRequest, fmt.Errorf("limit must be a positive integer")
		}
		limit = parsed
	}
	readyFilterEnabled := false
	readyFilterValue := false
	if filterReady != "" {
		readyFilterValue, err = strconv.ParseBool(filterReady)
		if err != nil {
			return nil, http.StatusBadRequest, fmt.Errorf("ready filter must be true or false")
		}
		readyFilterEnabled = true
	}

	queue := make([]map[string]interface{}, 0, len(proposals))
	readyCount := 0
	blockedCount := 0
	needsApprovalCount := 0
	needsScheduleCount := 0
	needsVerificationCount := 0
	byEnvironment := map[string]int{}
	byStatus := map[string]int{}
	byNextAction := map[string]int{}
	byUrgency := map[string]int{}
	slaBreachesByEnvironment := map[string]int{}
	oldestBlockedAgeSeconds := int64(0)
	oldestBlockedID := ""
	oldestReadyAgeSeconds := int64(0)
	oldestReadyID := ""
	oldestOverdueAgeSeconds := int64(0)
	oldestOverdueID := ""
	slaBreachCount := 0
	highestPriorityScore := -1
	highestPriorityID := ""
	highestPriorityReason := ""
	now := time.Now().UTC()

	for _, proposal := range proposals {
		id, _ := proposal["id"].(string)
		if strings.TrimSpace(id) == "" {
			continue
		}
		record, err := loadConfigProposal(id)
		if err != nil {
			continue
		}
		readiness, err := api.buildProposalReadiness(record)
		if err != nil {
			continue
		}
		ready, _ := readiness["ready_for_apply"].(bool)
		blockers, _ := readiness["blockers"].([]string)
		if filterEnv != "" && record.Environment != filterEnv {
			continue
		}
		if filterStatus != "" && record.Status != filterStatus {
			continue
		}
		if readyFilterEnabled && ready != readyFilterValue {
			continue
		}
		nextAction, needsApproval, needsSchedule, needsVerification := queueNextAction(record, readiness, blockers)
		if filterNextAction != "" && nextAction != filterNextAction {
			continue
		}
		ageSeconds := int64(now.Sub(record.CreatedAt).Seconds())
		readySince, readyAgeSeconds := queueReadySince(record, readiness)
		urgencyThresholds := resolveProposalQueueUrgencyThresholds(cfg, record.Environment)
		urgency := queueUrgency(urgencyThresholds, ready, ageSeconds, readyAgeSeconds)
		if filterUrgency != "" && urgency != filterUrgency {
			continue
		}
		slaBreached := urgency == "overdue"
		slaAgeSeconds := ageSeconds
		slaTarget := "blocked_overdue_after"
		slaThresholdSeconds := int64(urgencyThresholds.blockedOverdueAfter.Seconds())
		if ready {
			slaAgeSeconds = readyAgeSeconds
			slaTarget = "ready_overdue_after"
			slaThresholdSeconds = int64(urgencyThresholds.readyOverdueAfter.Seconds())
		}
		priorityScore, priorityReason := queuePriority(record, readiness, blockers, nextAction, ageSeconds, readyAgeSeconds)

		queue = append(queue, map[string]interface{}{
			"id":                    record.ID,
			"action":                record.Action,
			"status":                record.Status,
			"environment":           record.Environment,
			"promoted_from":         record.PromotedFrom,
			"label":                 record.Label,
			"change_ref":            record.ChangeRef,
			"created_by":            record.CreatedBy,
			"created_at":            record.CreatedAt,
			"approval_count":        readiness["approval_count"],
			"required_approvals":    readiness["required_approvals"],
			"ready_for_apply":       ready,
			"needs_approval":        needsApproval,
			"needs_schedule":        needsSchedule,
			"needs_verification":    needsVerification,
			"next_action":           nextAction,
			"urgency":               urgency,
			"sla_breached":          slaBreached,
			"sla_target":            slaTarget,
			"sla_age_seconds":       slaAgeSeconds,
			"sla_threshold_seconds": slaThresholdSeconds,
			"age_seconds":           ageSeconds,
			"ready_since":           readySince,
			"ready_age_seconds":     readyAgeSeconds,
			"priority_score":        priorityScore,
			"priority_reason":       priorityReason,
			"blocker_count":         len(blockers),
			"blockers":              blockers,
			"readiness":             readiness,
		})
		if ready {
			readyCount++
			if oldestReadyID == "" || readyAgeSeconds > oldestReadyAgeSeconds {
				oldestReadyAgeSeconds = readyAgeSeconds
				oldestReadyID = record.ID
			}
		} else {
			blockedCount++
			if oldestBlockedID == "" || ageSeconds > oldestBlockedAgeSeconds {
				oldestBlockedAgeSeconds = ageSeconds
				oldestBlockedID = record.ID
			}
		}
		envKey := strings.TrimSpace(record.Environment)
		if envKey == "" {
			envKey = "default"
		}
		if urgency == "overdue" {
			slaBreachCount++
			comparisonAge := ageSeconds
			if ready {
				comparisonAge = readyAgeSeconds
			}
			if oldestOverdueID == "" || comparisonAge > oldestOverdueAgeSeconds {
				oldestOverdueAgeSeconds = comparisonAge
				oldestOverdueID = record.ID
			}
			slaBreachesByEnvironment[envKey]++
		}
		if needsApproval {
			needsApprovalCount++
		}
		if needsSchedule {
			needsScheduleCount++
		}
		if needsVerification {
			needsVerificationCount++
		}
		if priorityScore > highestPriorityScore {
			highestPriorityScore = priorityScore
			highestPriorityID = record.ID
			highestPriorityReason = priorityReason
		}
		byEnvironment[envKey]++
		statusKey := strings.TrimSpace(record.Status)
		if statusKey == "" {
			statusKey = "unknown"
		}
		byStatus[statusKey]++
		nextActionKey := strings.TrimSpace(nextAction)
		if nextActionKey == "" {
			nextActionKey = "unknown"
		}
		byNextAction[nextActionKey]++
		byUrgency[urgency]++
	}

	sort.SliceStable(queue, func(i, j int) bool {
		iPriority, _ := queue[i]["priority_score"].(int)
		jPriority, _ := queue[j]["priority_score"].(int)
		if iPriority != jPriority {
			return iPriority > jPriority
		}
		iReady, _ := queue[i]["ready_for_apply"].(bool)
		jReady, _ := queue[j]["ready_for_apply"].(bool)
		if iReady != jReady {
			return iReady && !jReady
		}

		iCreated, _ := queue[i]["created_at"].(time.Time)
		jCreated, _ := queue[j]["created_at"].(time.Time)
		if !iCreated.Equal(jCreated) {
			return iCreated.Before(jCreated)
		}

		iID, _ := queue[i]["id"].(string)
		jID, _ := queue[j]["id"].(string)
		return iID < jID
	})
	if limit > 0 && len(queue) > limit {
		queue = queue[:limit]
	}

	return map[string]interface{}{
		"queue": queue,
		"summary": map[string]interface{}{
			"total":                       len(queue),
			"ready_count":                 readyCount,
			"blocked_count":               blockedCount,
			"needs_approval_count":        needsApprovalCount,
			"needs_schedule_count":        needsScheduleCount,
			"needs_verification_count":    needsVerificationCount,
			"by_environment":              byEnvironment,
			"by_status":                   byStatus,
			"by_next_action":              byNextAction,
			"by_urgency":                  byUrgency,
			"sla_breach_count":            slaBreachCount,
			"sla_breaches_by_environment": slaBreachesByEnvironment,
			"oldest_blocked": map[string]interface{}{
				"proposal_id": oldestBlockedID,
				"age_seconds": oldestBlockedAgeSeconds,
			},
			"oldest_ready": map[string]interface{}{
				"proposal_id":       oldestReadyID,
				"ready_age_seconds": oldestReadyAgeSeconds,
			},
			"oldest_overdue": map[string]interface{}{
				"proposal_id": oldestOverdueID,
				"age_seconds": oldestOverdueAgeSeconds,
			},
			"oldest_sla_breach": map[string]interface{}{
				"proposal_id": oldestOverdueID,
				"age_seconds": oldestOverdueAgeSeconds,
			},
			"highest_priority": map[string]interface{}{
				"proposal_id": highestPriorityID,
				"score":       highestPriorityScore,
				"reason":      highestPriorityReason,
			},
			"filters": map[string]interface{}{
				"environment": filterEnv,
				"status":      filterStatus,
				"next_action": filterNextAction,
				"urgency":     filterUrgency,
				"ready": func() interface{} {
					if readyFilterEnabled {
						return readyFilterValue
					}
					return nil
				}(),
			},
		},
	}, http.StatusOK, nil
}

func (api *ManagementAPI) applyReadyProposalQueue(w http.ResponseWriter, r *http.Request) {
	cfg := api.gateway.GetConfig()
	dryRun := r.URL.Query().Get("dry_run") == "true"
	reviewer := strings.TrimSpace(r.URL.Query().Get("reviewer"))
	reviewNote := strings.TrimSpace(r.URL.Query().Get("review_note"))
	filterEnv := strings.TrimSpace(r.URL.Query().Get("environment"))
	filterStatus := strings.TrimSpace(r.URL.Query().Get("status"))
	filterNextAction := strings.TrimSpace(r.URL.Query().Get("next_action"))
	filterUrgency := strings.TrimSpace(r.URL.Query().Get("urgency"))
	if filterNextAction != "" && filterNextAction != "apply" {
		api.writeError(w, "next_action filter for apply-ready must be apply", http.StatusBadRequest)
		return
	}
	if filterUrgency != "" && !isValidProposalQueueUrgency(filterUrgency) {
		api.writeError(w, "urgency filter must be fresh, aging, or overdue", http.StatusBadRequest)
		return
	}
	limit := 0
	if rawLimit := strings.TrimSpace(r.URL.Query().Get("limit")); rawLimit != "" {
		parsed, err := strconv.Atoi(rawLimit)
		if err != nil || parsed <= 0 {
			api.writeError(w, "limit must be a positive integer", http.StatusBadRequest)
			return
		}
		limit = parsed
	}
	if !dryRun && reviewer == "" {
		api.writeError(w, "reviewer is required to apply ready proposals", http.StatusBadRequest)
		return
	}

	proposals, err := listConfigProposals()
	if err != nil {
		api.writeError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	type readyCandidate struct {
		record          *configProposalRecord
		readySince      time.Time
		readyAgeSeconds int64
	}
	candidates := make([]readyCandidate, 0)
	for _, proposal := range proposals {
		id, _ := proposal["id"].(string)
		if strings.TrimSpace(id) == "" {
			continue
		}
		record, err := loadConfigProposal(id)
		if err != nil {
			continue
		}
		if filterEnv != "" && record.Environment != filterEnv {
			continue
		}
		if filterStatus != "" && record.Status != filterStatus {
			continue
		}
		readiness, err := api.buildProposalReadiness(record)
		if err != nil {
			continue
		}
		if ready, _ := readiness["ready_for_apply"].(bool); !ready {
			continue
		}
		readySince, readyAgeSeconds := queueReadySince(record, readiness)
		urgency := queueUrgency(resolveProposalQueueUrgencyThresholds(cfg, record.Environment), true, int64(time.Now().UTC().Sub(record.CreatedAt).Seconds()), readyAgeSeconds)
		if filterUrgency != "" && urgency != filterUrgency {
			continue
		}
		candidates = append(candidates, readyCandidate{
			record:          record,
			readySince:      readySince,
			readyAgeSeconds: readyAgeSeconds,
		})
	}

	sort.SliceStable(candidates, func(i, j int) bool {
		if !candidates[i].readySince.Equal(candidates[j].readySince) {
			return candidates[i].readySince.Before(candidates[j].readySince)
		}
		return candidates[i].record.ID < candidates[j].record.ID
	})
	if limit > 0 && len(candidates) > limit {
		candidates = candidates[:limit]
	}

	resultItems := make([]map[string]interface{}, 0, len(candidates))
	if dryRun {
		for _, candidate := range candidates {
			resultItems = append(resultItems, map[string]interface{}{
				"proposal_id":       candidate.record.ID,
				"status":            candidate.record.Status,
				"environment":       candidate.record.Environment,
				"ready_since":       candidate.readySince,
				"ready_age_seconds": candidate.readyAgeSeconds,
				"would_apply":       true,
			})
		}
		api.writeJSON(w, APIResponse{
			Success: true,
			Message: "Ready proposal batch apply preview generated successfully",
			Data: map[string]interface{}{
				"dry_run":         true,
				"candidate_count": len(resultItems),
				"filters": map[string]interface{}{
					"environment": filterEnv,
					"status":      filterStatus,
					"next_action": "apply",
					"urgency":     filterUrgency,
				},
				"results": resultItems,
			},
		})
		return
	}

	label, note, changeRef := revisionMetadataFromRequest(r)
	appliedCount := 0
	failedCount := 0
	for _, candidate := range candidates {
		result, statusCode, err := api.applyProposalRecord(candidate.record, reviewer, reviewNote, label, note, changeRef)
		if err != nil {
			failedCount++
			resultItems = append(resultItems, map[string]interface{}{
				"proposal_id": candidate.record.ID,
				"success":     false,
				"status_code": statusCode,
				"error":       err.Error(),
			})
			continue
		}
		appliedCount++
		entry := map[string]interface{}{
			"proposal_id": candidate.record.ID,
			"success":     true,
		}
		for k, v := range result {
			entry[k] = v
		}
		resultItems = append(resultItems, entry)
	}

	api.writeJSON(w, APIResponse{
		Success: failedCount == 0,
		Message: "Ready proposal batch apply completed",
		Data: map[string]interface{}{
			"dry_run":         false,
			"candidate_count": len(candidates),
			"applied_count":   appliedCount,
			"failed_count":    failedCount,
			"filters": map[string]interface{}{
				"environment": filterEnv,
				"status":      filterStatus,
				"next_action": "apply",
				"urgency":     filterUrgency,
			},
			"results": resultItems,
		},
	})
}

func (api *ManagementAPI) notifyProposalQueueDigest(w http.ResponseWriter, r *http.Request) {
	queueSnapshot, statusCode, err := api.buildProposalQueueSnapshot(r)
	if err != nil {
		api.writeError(w, err.Error(), statusCode)
		return
	}
	digestData := buildProposalQueueDigestEventData(queueSnapshot)
	payload := managementWebhookEvent{
		Event:       "proposal.digest",
		OccurredAt:  time.Now().UTC(),
		Environment: strings.TrimSpace(fmt.Sprint(digestData["environment"])),
		Data:        digestData,
	}
	deliveredEvents := make([]map[string]interface{}, 0, 2)
	digestDeliveries := api.emitManagementEvent(payload)
	deliveredEvents = append(deliveredEvents, map[string]interface{}{
		"event":      payload.Event,
		"deliveries": digestDeliveries,
	})
	slaBreachCount := 0
	if attention, ok := digestData["attention_required"].(map[string]interface{}); ok {
		switch value := attention["sla_breach_count"].(type) {
		case int:
			slaBreachCount = value
		case float64:
			slaBreachCount = int(value)
		}
	}
	queueKey := proposalQueueDigestNotificationKey(strings.TrimSpace(fmt.Sprint(digestData["environment"])))
	slaState, resolvedState, previousState := api.updateProposalQueueSLABreachState(queueKey, payload.OccurredAt, slaBreachCount)
	if slaBreachCount > 0 {
		slaStateData := buildProposalQueueSLABreachStateData(slaState, payload.OccurredAt)
		previousTier := ""
		if previousState != nil {
			previousTier = proposalQueueSLABreachTierAt(*previousState, payload.OccurredAt)
		}
		currentTier := strings.TrimSpace(fmt.Sprint(slaStateData["tier"]))
		if previousTier != currentTier {
			stagePayload := managementWebhookEvent{
				Event:       "proposal.sla_stage_changed",
				OccurredAt:  time.Now().UTC(),
				Environment: strings.TrimSpace(fmt.Sprint(digestData["environment"])),
				Data: map[string]interface{}{
					"queue_summary":        digestData["queue_summary"],
					"sla_breach_state":     slaStateData,
					"incident_id":          slaStateData["incident_id"],
					"previous_stage":       previousTier,
					"current_stage":        currentTier,
					"triggered_from_event": "proposal.digest",
				},
			}
			stageDeliveries := api.emitManagementEvent(stagePayload)
			deliveredEvents = append(deliveredEvents, map[string]interface{}{
				"event":      stagePayload.Event,
				"deliveries": stageDeliveries,
			})
		}
		slaPayload := managementWebhookEvent{
			Event:       "proposal.sla_breach",
			OccurredAt:  time.Now().UTC(),
			Environment: strings.TrimSpace(fmt.Sprint(digestData["environment"])),
			Data: map[string]interface{}{
				"queue_summary":        digestData["queue_summary"],
				"attention_required":   digestData["attention_required"],
				"top_sla_breaches":     digestData["top_sla_breaches"],
				"sla_breach_state":     slaStateData,
				"sla_breach_tier":      slaStateData["tier"],
				"triggered_from_event": "proposal.digest",
			},
		}
		slaDeliveries := api.emitManagementEvent(slaPayload)
		deliveredEvents = append(deliveredEvents, map[string]interface{}{
			"event":      slaPayload.Event,
			"deliveries": slaDeliveries,
		})
	} else if resolvedState != nil {
		resolvedStateData := buildProposalQueueSLABreachStateData(*resolvedState, payload.OccurredAt)
		resolvedPayload := managementWebhookEvent{
			Event:       "proposal.sla_resolved",
			OccurredAt:  time.Now().UTC(),
			Environment: strings.TrimSpace(fmt.Sprint(digestData["environment"])),
			Data: map[string]interface{}{
				"queue_summary":       digestData["queue_summary"],
				"resolved_sla_state":  resolvedStateData,
				"incident_id":         resolvedStateData["incident_id"],
				"resolved_from_event": "proposal.digest",
			},
		}
		resolvedDeliveries := api.emitManagementEvent(resolvedPayload)
		deliveredEvents = append(deliveredEvents, map[string]interface{}{
			"event":      resolvedPayload.Event,
			"deliveries": resolvedDeliveries,
		})
	}
	api.writeJSON(w, APIResponse{
		Success: true,
		Message: "Proposal queue digest notifications emitted",
		Data: map[string]interface{}{
			"events": deliveredEvents,
			"digest": digestData,
		},
	})
}

func (api *ManagementAPI) approveReadyProposalQueue(w http.ResponseWriter, r *http.Request) {
	cfg := api.gateway.GetConfig()
	dryRun := r.URL.Query().Get("dry_run") == "true"
	reviewer := strings.TrimSpace(r.URL.Query().Get("reviewer"))
	reviewNote := strings.TrimSpace(r.URL.Query().Get("review_note"))
	filterEnv := strings.TrimSpace(r.URL.Query().Get("environment"))
	filterStatus := strings.TrimSpace(r.URL.Query().Get("status"))
	filterNextAction := strings.TrimSpace(r.URL.Query().Get("next_action"))
	if filterNextAction != "" && filterNextAction != "needs_approval" {
		api.writeError(w, "next_action filter for approve-ready must be needs_approval", http.StatusBadRequest)
		return
	}
	filterUrgency := strings.TrimSpace(r.URL.Query().Get("urgency"))
	if filterUrgency != "" && !isValidProposalQueueUrgency(filterUrgency) {
		api.writeError(w, "urgency filter must be fresh, aging, or overdue", http.StatusBadRequest)
		return
	}
	limit := 0
	if rawLimit := strings.TrimSpace(r.URL.Query().Get("limit")); rawLimit != "" {
		parsed, err := strconv.Atoi(rawLimit)
		if err != nil || parsed <= 0 {
			api.writeError(w, "limit must be a positive integer", http.StatusBadRequest)
			return
		}
		limit = parsed
	}
	if !dryRun && reviewer == "" {
		api.writeError(w, "reviewer is required to approve ready proposals", http.StatusBadRequest)
		return
	}

	proposals, err := listConfigProposals()
	if err != nil {
		api.writeError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	type approvalCandidate struct {
		record     *configProposalRecord
		nextAction string
		createdAt  time.Time
	}
	candidates := make([]approvalCandidate, 0)
	for _, proposal := range proposals {
		id, _ := proposal["id"].(string)
		if strings.TrimSpace(id) == "" {
			continue
		}
		record, err := loadConfigProposal(id)
		if err != nil {
			continue
		}
		if filterEnv != "" && record.Environment != filterEnv {
			continue
		}
		if filterStatus != "" && record.Status != filterStatus {
			continue
		}
		readiness, err := api.buildProposalReadiness(record)
		if err != nil {
			continue
		}
		if ready, _ := readiness["ready_for_apply"].(bool); ready {
			continue
		}
		blockers, _ := readiness["blockers"].([]string)
		nextAction, needsApproval, _, _ := queueNextAction(record, readiness, blockers)
		if !needsApproval {
			continue
		}
		urgency := queueUrgency(resolveProposalQueueUrgencyThresholds(cfg, record.Environment), false, int64(time.Now().UTC().Sub(record.CreatedAt).Seconds()), 0)
		if filterUrgency != "" && urgency != filterUrgency {
			continue
		}
		candidates = append(candidates, approvalCandidate{
			record:     record,
			nextAction: nextAction,
			createdAt:  record.CreatedAt,
		})
	}

	sort.SliceStable(candidates, func(i, j int) bool {
		if !candidates[i].createdAt.Equal(candidates[j].createdAt) {
			return candidates[i].createdAt.Before(candidates[j].createdAt)
		}
		return candidates[i].record.ID < candidates[j].record.ID
	})
	if limit > 0 && len(candidates) > limit {
		candidates = candidates[:limit]
	}

	resultItems := make([]map[string]interface{}, 0, len(candidates))
	if dryRun {
		for _, candidate := range candidates {
			resultItems = append(resultItems, map[string]interface{}{
				"proposal_id":   candidate.record.ID,
				"status":        candidate.record.Status,
				"environment":   candidate.record.Environment,
				"would_approve": true,
			})
		}
		api.writeJSON(w, APIResponse{
			Success: true,
			Message: "Ready proposal batch approval preview generated successfully",
			Data: map[string]interface{}{
				"dry_run":         true,
				"candidate_count": len(resultItems),
				"filters": map[string]interface{}{
					"environment": filterEnv,
					"status":      filterStatus,
					"next_action": "needs_approval",
					"urgency":     filterUrgency,
				},
				"results": resultItems,
			},
		})
		return
	}

	approvedCount := 0
	failedCount := 0
	for _, candidate := range candidates {
		result, statusCode, err := api.approveProposalRecord(candidate.record, reviewer, reviewNote)
		if err != nil {
			failedCount++
			resultItems = append(resultItems, map[string]interface{}{
				"proposal_id": candidate.record.ID,
				"success":     false,
				"status_code": statusCode,
				"error":       err.Error(),
			})
			continue
		}
		approvedCount++
		entry := map[string]interface{}{
			"proposal_id": candidate.record.ID,
			"success":     true,
		}
		for k, v := range result {
			entry[k] = v
		}
		resultItems = append(resultItems, entry)
	}

	api.writeJSON(w, APIResponse{
		Success: failedCount == 0,
		Message: "Ready proposal batch approval completed",
		Data: map[string]interface{}{
			"dry_run":         false,
			"candidate_count": len(candidates),
			"approved_count":  approvedCount,
			"failed_count":    failedCount,
			"filters": map[string]interface{}{
				"environment": filterEnv,
				"status":      filterStatus,
				"next_action": "needs_approval",
				"urgency":     filterUrgency,
			},
			"results": resultItems,
		},
	})
}

func (api *ManagementAPI) getBlockedProposalQueueReport(w http.ResponseWriter, r *http.Request) {
	proposals, err := listConfigProposals()
	if err != nil {
		api.writeError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	filterEnv := strings.TrimSpace(r.URL.Query().Get("environment"))
	filterStatus := strings.TrimSpace(r.URL.Query().Get("status"))
	type blockerSummary struct {
		Reason      string   `json:"reason"`
		Count       int      `json:"count"`
		ProposalIDs []string `json:"proposal_ids"`
	}

	index := map[string]*blockerSummary{}
	blockedProposalIDs := make([]string, 0)
	byAction := map[string]int{}

	for _, proposal := range proposals {
		id, _ := proposal["id"].(string)
		if strings.TrimSpace(id) == "" {
			continue
		}
		record, err := loadConfigProposal(id)
		if err != nil {
			continue
		}
		if filterEnv != "" && record.Environment != filterEnv {
			continue
		}
		if filterStatus != "" && record.Status != filterStatus {
			continue
		}
		readiness, err := api.buildProposalReadiness(record)
		if err != nil {
			continue
		}
		if ready, _ := readiness["ready_for_apply"].(bool); ready {
			continue
		}
		blockers, _ := readiness["blockers"].([]string)
		if len(blockers) == 0 {
			continue
		}
		blockedProposalIDs = append(blockedProposalIDs, record.ID)
		actionKey := strings.TrimSpace(record.Action)
		if actionKey == "" {
			actionKey = "unknown"
		}
		byAction[actionKey]++
		for _, blocker := range blockers {
			summary := index[blocker]
			if summary == nil {
				summary = &blockerSummary{Reason: blocker}
				index[blocker] = summary
			}
			summary.Count++
			summary.ProposalIDs = append(summary.ProposalIDs, record.ID)
		}
	}

	summaries := make([]blockerSummary, 0, len(index))
	for _, summary := range index {
		summaries = append(summaries, *summary)
	}
	sort.SliceStable(summaries, func(i, j int) bool {
		if summaries[i].Count != summaries[j].Count {
			return summaries[i].Count > summaries[j].Count
		}
		return summaries[i].Reason < summaries[j].Reason
	})

	api.writeJSON(w, map[string]interface{}{
		"blocked_proposal_count": len(blockedProposalIDs),
		"blocked_proposal_ids":   blockedProposalIDs,
		"blockers":               summaries,
		"by_action":              byAction,
		"filters": map[string]interface{}{
			"environment": filterEnv,
			"status":      filterStatus,
		},
	})
}

func buildProposalQueueDigestEventData(queueSnapshot map[string]interface{}) map[string]interface{} {
	queueItems, _ := queueSnapshot["queue"].([]map[string]interface{})
	if queueItems == nil {
		if genericQueue, ok := queueSnapshot["queue"].([]interface{}); ok {
			queueItems = make([]map[string]interface{}, 0, len(genericQueue))
			for _, item := range genericQueue {
				if entry, ok := item.(map[string]interface{}); ok {
					queueItems = append(queueItems, entry)
				}
			}
		}
	}
	summary, _ := queueSnapshot["summary"].(map[string]interface{})
	topReady := make([]map[string]interface{}, 0)
	topBlocked := make([]map[string]interface{}, 0)
	topSLABreaches := make([]map[string]interface{}, 0)
	blockerCounts := map[string]int{}
	blockerProposalIDs := map[string][]string{}
	environments := map[string]int{}
	for _, item := range queueItems {
		proposalID := strings.TrimSpace(fmt.Sprint(item["id"]))
		environment := strings.TrimSpace(fmt.Sprint(item["environment"]))
		if environment != "" {
			environments[environment]++
		}
		entry := map[string]interface{}{
			"proposal_id":           proposalID,
			"environment":           environment,
			"next_action":           item["next_action"],
			"urgency":               item["urgency"],
			"priority_score":        item["priority_score"],
			"priority_reason":       item["priority_reason"],
			"sla_breached":          item["sla_breached"],
			"sla_age_seconds":       item["sla_age_seconds"],
			"sla_threshold_seconds": item["sla_threshold_seconds"],
		}
		if breached, _ := item["sla_breached"].(bool); breached {
			topSLABreaches = append(topSLABreaches, entry)
		}
		if ready, _ := item["ready_for_apply"].(bool); ready {
			entry["ready_age_seconds"] = item["ready_age_seconds"]
			topReady = append(topReady, entry)
			continue
		}
		if blockers, ok := item["blockers"].([]string); ok {
			if len(blockers) > 0 {
				entry["primary_blocker"] = blockers[0]
			}
			for _, blocker := range blockers {
				blockerCounts[blocker]++
				blockerProposalIDs[blocker] = append(blockerProposalIDs[blocker], proposalID)
			}
		} else if blockers, ok := item["blockers"].([]interface{}); ok {
			for i, raw := range blockers {
				blocker := strings.TrimSpace(fmt.Sprint(raw))
				if blocker == "" {
					continue
				}
				if i == 0 {
					entry["primary_blocker"] = blocker
				}
				blockerCounts[blocker]++
				blockerProposalIDs[blocker] = append(blockerProposalIDs[blocker], proposalID)
			}
		}
		entry["blocker_count"] = item["blocker_count"]
		topBlocked = append(topBlocked, entry)
	}
	sort.SliceStable(topReady, func(i, j int) bool {
		return int64Value(topReady[i]["ready_age_seconds"]) > int64Value(topReady[j]["ready_age_seconds"])
	})
	sort.SliceStable(topBlocked, func(i, j int) bool {
		return intValue(topBlocked[i]["priority_score"]) > intValue(topBlocked[j]["priority_score"])
	})
	sort.SliceStable(topSLABreaches, func(i, j int) bool {
		return int64Value(topSLABreaches[i]["sla_age_seconds"]) > int64Value(topSLABreaches[j]["sla_age_seconds"])
	})
	if len(topReady) > 5 {
		topReady = topReady[:5]
	}
	if len(topBlocked) > 5 {
		topBlocked = topBlocked[:5]
	}
	if len(topSLABreaches) > 5 {
		topSLABreaches = topSLABreaches[:5]
	}
	topBlockers := make([]map[string]interface{}, 0, len(blockerCounts))
	for reason, count := range blockerCounts {
		topBlockers = append(topBlockers, map[string]interface{}{
			"reason":       reason,
			"count":        count,
			"proposal_ids": blockerProposalIDs[reason],
		})
	}
	sort.SliceStable(topBlockers, func(i, j int) bool {
		if intValue(topBlockers[i]["count"]) != intValue(topBlockers[j]["count"]) {
			return intValue(topBlockers[i]["count"]) > intValue(topBlockers[j]["count"])
		}
		return strings.TrimSpace(fmt.Sprint(topBlockers[i]["reason"])) < strings.TrimSpace(fmt.Sprint(topBlockers[j]["reason"]))
	})
	if len(topBlockers) > 5 {
		topBlockers = topBlockers[:5]
	}
	environment := ""
	if len(environments) == 1 {
		for key := range environments {
			environment = key
		}
	}
	return map[string]interface{}{
		"generated_at":     time.Now().UTC(),
		"environment":      environment,
		"queue_summary":    summary,
		"top_ready":        topReady,
		"top_blocked":      topBlocked,
		"top_blockers":     topBlockers,
		"top_sla_breaches": topSLABreaches,
		"attention_required": map[string]interface{}{
			"sla_breach_count": func() interface{} {
				if summary != nil && summary["sla_breach_count"] != nil {
					return summary["sla_breach_count"]
				}
				return len(topSLABreaches)
			}(),
			"sla_breaches_by_environment": func() interface{} {
				if summary != nil && summary["sla_breaches_by_environment"] != nil {
					return summary["sla_breaches_by_environment"]
				}
				return map[string]int{}
			}(),
			"oldest_sla_breach": func() interface{} {
				if summary != nil && summary["oldest_sla_breach"] != nil {
					return summary["oldest_sla_breach"]
				}
				return map[string]interface{}{}
			}(),
		},
	}
}

func proposalQueueDigestNotificationInterval(policy config.ProposalQueueNotificationPolicy) time.Duration {
	if parsed, ok := parseProposalQueueUrgencyThreshold(strings.TrimSpace(policy.Interval)); ok {
		return parsed
	}
	return 15 * time.Minute
}

func proposalQueueDigestNotificationMinInterval(policy config.ProposalQueueNotificationPolicy) time.Duration {
	if parsed, ok := parseProposalQueueUrgencyThreshold(strings.TrimSpace(policy.MinNotificationInterval)); ok {
		return parsed
	}
	return 5 * time.Minute
}

func proposalQueueDigestNotificationKey(environment string) string {
	environment = strings.TrimSpace(environment)
	if environment == "" {
		return "all"
	}
	return environment
}

func proposalQueueDigestChecksum(digest map[string]interface{}) string {
	payload := map[string]interface{}{
		"queue_summary":      digest["queue_summary"],
		"attention_required": digest["attention_required"],
		"top_sla_breaches":   digest["top_sla_breaches"],
		"top_blockers":       digest["top_blockers"],
		"environment":        digest["environment"],
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func (api *ManagementAPI) updateProposalQueueSLABreachState(key string, now time.Time, slaBreachCount int) (proposalQueueSLABreachState, *proposalQueueSLABreachState, *proposalQueueSLABreachState) {
	api.queueDigestNotifyMu.Lock()
	defer api.queueDigestNotifyMu.Unlock()
	if slaBreachCount <= 0 {
		if existing, ok := api.queueDigestSLABreachState[key]; ok {
			delete(api.queueDigestSLABreachState, key)
			api.clearProposalQueueSLABreachEscalationStateLocked(key)
			return proposalQueueSLABreachState{}, &existing, nil
		}
		delete(api.queueDigestSLABreachState, key)
		api.clearProposalQueueSLABreachEscalationStateLocked(key)
		return proposalQueueSLABreachState{}, nil, nil
	}
	state := api.queueDigestSLABreachState[key]
	var previous *proposalQueueSLABreachState
	if strings.TrimSpace(state.IncidentID) != "" {
		copyState := state
		previous = &copyState
	}
	if strings.TrimSpace(state.IncidentID) == "" {
		state.IncidentID = fmt.Sprintf("sla-%s", now.UTC().Format("20060102-150405.000000000"))
	}
	if state.FirstBreachedAt.IsZero() {
		state.FirstBreachedAt = now
	}
	state.ConsecutiveBreaches++
	state.LastBreachedAt = now
	api.queueDigestSLABreachState[key] = state
	return state, nil, previous
}

func (api *ManagementAPI) clearProposalQueueSLABreachEscalationStateLocked(queueKey string) {
	suffix := "||" + queueKey
	for key := range api.slaBreachEscalationState {
		if strings.HasSuffix(key, suffix) {
			delete(api.slaBreachEscalationState, key)
		}
	}
}

func (api *ManagementAPI) currentProposalQueueSLABreachState(key string) proposalQueueSLABreachState {
	api.queueDigestNotifyMu.Lock()
	defer api.queueDigestNotifyMu.Unlock()
	return api.queueDigestSLABreachState[key]
}

func buildProposalQueueSLABreachStateData(state proposalQueueSLABreachState, now time.Time) map[string]interface{} {
	age := 0.0
	if !state.FirstBreachedAt.IsZero() {
		age = now.Sub(state.FirstBreachedAt).Seconds()
		if age < 0 {
			age = 0
		}
	}
	return map[string]interface{}{
		"incident_id":          state.IncidentID,
		"consecutive_breaches": state.ConsecutiveBreaches,
		"first_breached_at":    state.FirstBreachedAt,
		"last_breached_at":     state.LastBreachedAt,
		"breach_age_seconds":   age,
		"tier":                 classifyProposalQueueSLABreachTier(state, age),
	}
}

func classifyProposalQueueSLABreachTier(state proposalQueueSLABreachState, breachAgeSeconds float64) string {
	if state.ConsecutiveBreaches >= 3 || breachAgeSeconds >= 15*60 {
		return "critical"
	}
	if state.ConsecutiveBreaches >= 2 || breachAgeSeconds >= 5*60 {
		return "elevated"
	}
	return "warning"
}

func proposalQueueSLABreachTierAt(state proposalQueueSLABreachState, now time.Time) string {
	if strings.TrimSpace(state.IncidentID) == "" {
		return ""
	}
	age := 0.0
	if !state.FirstBreachedAt.IsZero() {
		age = now.Sub(state.FirstBreachedAt).Seconds()
		if age < 0 {
			age = 0
		}
	}
	return classifyProposalQueueSLABreachTier(state, age)
}

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

func intValue(value interface{}) int {
	switch v := value.(type) {
	case int:
		return v
	case int64:
		return int(v)
	case float64:
		return int(v)
	default:
		return 0
	}
}

func int64Value(value interface{}) int64 {
	switch v := value.(type) {
	case int64:
		return v
	case int:
		return int64(v)
	case float64:
		return int64(v)
	default:
		return 0
	}
}

func queuePriority(record *configProposalRecord, readiness map[string]interface{}, blockers []string, nextAction string, ageSeconds, readyAgeSeconds int64) (int, string) {
	score := 0
	reason := "general_backlog"
	if ready, _ := readiness["ready_for_apply"].(bool); ready {
		score = 50 + int(minInt64(readyAgeSeconds/3600, 24))
		reason = "ready_to_apply"
		if readyAgeSeconds >= 4*3600 {
			score += 10
			reason = "ready_and_aging"
		}
		return score, reason
	}
	switch nextAction {
	case "needs_verification":
		score = 95
		reason = "verification_blocked"
	case "needs_approval":
		score = 90
		reason = "approval_blocked"
	case "wait_for_window", "wait_for_schedule":
		score = 30
		reason = "waiting_for_window"
	case "expired":
		score = 80
		reason = "expired"
	default:
		score = 70
		reason = "blocked"
	}
	score += int(minInt64(ageSeconds/3600, 24))
	if len(blockers) >= 3 {
		score += 5
	}
	return score, reason
}

type proposalQueueUrgencyThresholds struct {
	readyAgingAfter     time.Duration
	readyOverdueAfter   time.Duration
	blockedAgingAfter   time.Duration
	blockedOverdueAfter time.Duration
}

func queueUrgency(thresholds proposalQueueUrgencyThresholds, ready bool, ageSeconds, readyAgeSeconds int64) string {
	if ready {
		switch {
		case readyAgeSeconds >= int64(thresholds.readyOverdueAfter.Seconds()):
			return "overdue"
		case readyAgeSeconds >= int64(thresholds.readyAgingAfter.Seconds()):
			return "aging"
		default:
			return "fresh"
		}
	}
	switch {
	case ageSeconds >= int64(thresholds.blockedOverdueAfter.Seconds()):
		return "overdue"
	case ageSeconds >= int64(thresholds.blockedAgingAfter.Seconds()):
		return "aging"
	default:
		return "fresh"
	}
}

func isValidProposalQueueUrgency(value string) bool {
	switch strings.TrimSpace(value) {
	case "fresh", "aging", "overdue":
		return true
	default:
		return false
	}
}

func resolveProposalQueueUrgencyThresholds(cfg *config.Config, environment string) proposalQueueUrgencyThresholds {
	resolved := proposalQueueUrgencyThresholds{
		readyAgingAfter:     time.Hour,
		readyOverdueAfter:   4 * time.Hour,
		blockedAgingAfter:   4 * time.Hour,
		blockedOverdueAfter: 24 * time.Hour,
	}
	if cfg == nil {
		return resolved
	}
	applyProposalQueueUrgencyThresholdOverrides(&resolved, cfg.Security.MutationPolicy.ProposalQueue.DefaultUrgency)
	envKey := strings.TrimSpace(environment)
	if envKey != "" {
		if override, ok := cfg.Security.MutationPolicy.ProposalQueue.EnvironmentUrgency[envKey]; ok {
			applyProposalQueueUrgencyThresholdOverrides(&resolved, override)
		}
	}
	return resolved
}

func applyProposalQueueUrgencyThresholdOverrides(target *proposalQueueUrgencyThresholds, override config.ProposalQueueUrgencyThresholds) {
	if target == nil {
		return
	}
	if parsed, ok := parseProposalQueueUrgencyThreshold(override.ReadyAgingAfter); ok {
		target.readyAgingAfter = parsed
	}
	if parsed, ok := parseProposalQueueUrgencyThreshold(override.ReadyOverdueAfter); ok {
		target.readyOverdueAfter = parsed
	}
	if parsed, ok := parseProposalQueueUrgencyThreshold(override.BlockedAgingAfter); ok {
		target.blockedAgingAfter = parsed
	}
	if parsed, ok := parseProposalQueueUrgencyThreshold(override.BlockedOverdueAfter); ok {
		target.blockedOverdueAfter = parsed
	}
}

func parseProposalQueueUrgencyThreshold(value string) (time.Duration, bool) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return 0, false
	}
	parsed, err := time.ParseDuration(trimmed)
	if err != nil || parsed <= 0 {
		return 0, false
	}
	return parsed, true
}

func minInt64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}

func queueExplanation(nextAction, primaryBlocker string) string {
	switch nextAction {
	case "needs_approval":
		return "proposal is blocked on approvals"
	case "needs_verification":
		return "proposal is blocked on verification or policy checks"
	case "wait_for_schedule":
		return "proposal is waiting for its not-before schedule"
	case "wait_for_window":
		return "proposal is blocked by a blackout or maintenance window"
	case "expired":
		return "proposal can no longer be applied because it expired"
	case "apply":
		return "proposal is ready to apply"
	default:
		if strings.TrimSpace(primaryBlocker) != "" {
			return primaryBlocker
		}
		return "proposal has unresolved blockers"
	}
}

func queueNextAction(record *configProposalRecord, readiness map[string]interface{}, blockers []string) (string, bool, bool, bool) {
	if ready, _ := readiness["ready_for_apply"].(bool); ready {
		return "apply", false, false, false
	}
	approvalCount, _ := readiness["approval_count"].(int)
	requiredApprovals, _ := readiness["required_approvals"].(int)
	if approvalCount < requiredApprovals {
		return "needs_approval", true, false, false
	}
	if notBeforeReady, _ := readiness["not_before_ready"].(bool); !notBeforeReady {
		return "wait_for_schedule", false, true, false
	}
	if verificationReady, _ := readiness["verification_ready"].(bool); !verificationReady {
		return "needs_verification", false, false, true
	}
	if !record.ExpiredAt.IsZero() {
		return "expired", false, false, false
	}
	for _, blocker := range blockers {
		if strings.Contains(strings.ToLower(blocker), "blackout") {
			return "wait_for_window", false, true, false
		}
	}
	return "resolve_blockers", false, false, false
}

func queueReadySince(record *configProposalRecord, readiness map[string]interface{}) (time.Time, int64) {
	if ready, _ := readiness["ready_for_apply"].(bool); !ready {
		return time.Time{}, 0
	}
	readySince := record.CreatedAt
	if !record.ReviewedAt.IsZero() && record.ReviewedAt.After(readySince) {
		readySince = record.ReviewedAt
	}
	if !record.NotBefore.IsZero() && record.NotBefore.After(readySince) {
		readySince = record.NotBefore
	}
	if verification, _ := readiness["verification"].(map[string]interface{}); verification != nil {
		if shadowVerification, _ := verification["shadow_verification"].(map[string]interface{}); shadowVerification != nil {
			if shadowReady, _ := shadowVerification["shadow_ready"].(bool); shadowReady {
				if shadowReadyAt, _ := shadowVerification["shadow_ready_at"].(time.Time); !shadowReadyAt.IsZero() && shadowReadyAt.After(readySince) {
					readySince = shadowReadyAt
				}
			}
		}
	}
	return readySince, int64(time.Since(readySince).Seconds())
}

func (api *ManagementAPI) getProposal(w http.ResponseWriter, r *http.Request) {
	record, err := loadConfigProposal(mux.Vars(r)["id"])
	if err != nil {
		api.writeError(w, err.Error(), http.StatusNotFound)
		return
	}
	serviceCount := 0
	routeCount := 0
	if record.Config != nil {
		for _, svcCfg := range record.Config.Services {
			serviceCount += len(svcCfg.Services)
			for _, svc := range svcCfg.Services {
				routeCount += len(svc.Routes)
			}
		}
	}
	api.writeJSON(w, map[string]interface{}{
		"id":                     record.ID,
		"action":                 record.Action,
		"status":                 record.Status,
		"created_by":             record.CreatedBy,
		"environment":            record.Environment,
		"promoted_from":          record.PromotedFrom,
		"config_hash":            record.ConfigHash,
		"source_config_hash":     record.SourceConfigHash,
		"canary_services":        record.CanaryServices,
		"canary_routes":          record.CanaryRoutes,
		"canary_headers":         record.CanaryHeaders,
		"canary_percent":         record.CanaryPercent,
		"canary_steps":           record.CanarySteps,
		"canary_min_requests":    record.CanaryMinRequests,
		"canary_max_error_rate":  record.CanaryMaxErrorRate,
		"canary_max_p95_latency": record.CanaryMaxP95Latency,
		"canary_auto":            record.CanaryAutoReconcile,
		"canary_auto_interval":   record.CanaryAutoInterval,
		"canary_auto_reviewer":   record.CanaryAutoReviewer,
		"canary_last_reconciled": record.CanaryLastReconciled,
		"canary_next_reconcile":  record.CanaryNextReconcile,
		"label":                  record.Label,
		"note":                   record.Note,
		"change_ref":             record.ChangeRef,
		"strategy":               record.Strategy,
		"created_at":             record.CreatedAt,
		"not_before":             record.NotBefore,
		"reviewed_at":            record.ReviewedAt,
		"applied_at":             record.AppliedAt,
		"reviewed_by":            record.ReviewedBy,
		"review_note":            record.ReviewNote,
		"expired_at":             record.ExpiredAt,
		"expiration_reason":      record.ExpirationReason,
		"approval_count":         proposalApprovalCount(api.gateway.GetConfig(), record),
		"required_approvals":     requiredProposalApprovers(api.gateway.GetConfig(), record),
		"approvals":              record.Approvals,
		"summary":                record.Summary,
		"service_count":          serviceCount,
		"route_count":            routeCount,
		"revision_id":            record.RevisionID,
		"config":                 record.Config,
	})
}

func (api *ManagementAPI) approveProposal(w http.ResponseWriter, r *http.Request) {
	record, err := loadConfigProposal(mux.Vars(r)["id"])
	if err != nil {
		api.writeError(w, err.Error(), http.StatusNotFound)
		return
	}
	reviewer, reviewNote := proposalReviewMetadataFromRequest(r, record)
	result, statusCode, err := api.approveProposalRecord(record, reviewer, reviewNote)
	if err != nil {
		api.writeError(w, err.Error(), statusCode)
		return
	}
	api.writeJSON(w, APIResponse{
		Success: true,
		Message: "Proposal approval recorded successfully",
		Data:    result,
	})
}

func (api *ManagementAPI) approveProposalRecord(record *configProposalRecord, reviewer, reviewNote string) (map[string]interface{}, int, error) {
	if record.Status == "rejected" || record.Status == "applied" {
		return nil, http.StatusConflict, fmt.Errorf("proposal is already %s", record.Status)
	}
	if strings.TrimSpace(reviewer) == "" {
		return nil, http.StatusBadRequest, fmt.Errorf("reviewer is required to approve a proposal")
	}
	if err := api.enforceProposalReviewer(record, reviewer); err != nil {
		return nil, http.StatusForbidden, err
	}
	if err := api.enforceProposalExpiration(record, time.Now().UTC()); err != nil {
		return nil, http.StatusConflict, err
	}
	upsertProposalApproval(record, reviewer, reviewNote)
	record.ReviewedAt = time.Now().UTC()
	record.ReviewedBy = reviewer
	record.ReviewNote = reviewNote
	record.Status = proposalStatusAfterApproval(api.gateway.GetConfig(), record)
	if err := saveConfigProposalRecord(record); err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("Failed to approve proposal: %v", err)
	}
	result := map[string]interface{}{
		"proposal_id":    record.ID,
		"status":         record.Status,
		"approval_count": proposalApprovalCount(api.gateway.GetConfig(), record),
		"required_count": requiredProposalApprovers(api.gateway.GetConfig(), record),
	}
	api.emitProposalEvent("proposal.approved", record, map[string]interface{}{
		"approval_count": result["approval_count"],
		"required_count": result["required_count"],
	})
	return result, http.StatusOK, nil
}

func (api *ManagementAPI) verifyProposal(w http.ResponseWriter, r *http.Request) {
	record, err := loadConfigProposal(mux.Vars(r)["id"])
	if err != nil {
		api.writeError(w, err.Error(), http.StatusNotFound)
		return
	}
	if record.Config == nil {
		api.writeError(w, "proposal has no stored configuration", http.StatusInternalServerError)
		return
	}
	result, err := api.buildProposalVerification(record)
	if err != nil {
		api.writeError(w, fmt.Sprintf("failed to verify proposal: %v", err), http.StatusInternalServerError)
		return
	}
	if err := api.observeProposalShadowVerification(record, result); err != nil {
		api.writeError(w, fmt.Sprintf("failed to persist proposal shadow verification: %v", err), http.StatusInternalServerError)
		return
	}
	api.markProposalShadowReady(record, result)
	api.writeJSON(w, result)
}

func (api *ManagementAPI) getProposalReadiness(w http.ResponseWriter, r *http.Request) {
	record, err := loadConfigProposal(mux.Vars(r)["id"])
	if err != nil {
		api.writeError(w, err.Error(), http.StatusNotFound)
		return
	}
	result, err := api.buildProposalReadiness(record)
	if err != nil {
		api.writeError(w, fmt.Sprintf("failed to evaluate proposal readiness: %v", err), http.StatusInternalServerError)
		return
	}
	api.writeJSON(w, result)
}

func (api *ManagementAPI) explainBlockedProposal(w http.ResponseWriter, r *http.Request) {
	record, err := loadConfigProposal(mux.Vars(r)["id"])
	if err != nil {
		api.writeError(w, err.Error(), http.StatusNotFound)
		return
	}
	readiness, err := api.buildProposalReadiness(record)
	if err != nil {
		api.writeError(w, fmt.Sprintf("failed to explain blocked proposal: %v", err), http.StatusInternalServerError)
		return
	}
	if ready, _ := readiness["ready_for_apply"].(bool); ready {
		api.writeJSON(w, map[string]interface{}{
			"proposal_id":     record.ID,
			"ready_for_apply": true,
			"explanation":     "proposal is ready to apply",
			"next_action":     "apply",
			"readiness":       readiness,
		})
		return
	}
	blockers, _ := readiness["blockers"].([]string)
	nextAction, needsApproval, needsSchedule, needsVerification := queueNextAction(record, readiness, blockers)
	primary := ""
	if len(blockers) > 0 {
		primary = blockers[0]
	}
	api.writeJSON(w, map[string]interface{}{
		"proposal_id":        record.ID,
		"ready_for_apply":    false,
		"next_action":        nextAction,
		"primary_blocker":    primary,
		"needs_approval":     needsApproval,
		"needs_schedule":     needsSchedule,
		"needs_verification": needsVerification,
		"blocker_count":      len(blockers),
		"blockers":           blockers,
		"explanation":        queueExplanation(nextAction, primary),
		"readiness":          readiness,
	})
}

func (api *ManagementAPI) getProposalCanaryStatus(w http.ResponseWriter, r *http.Request) {
	record, err := loadConfigProposal(mux.Vars(r)["id"])
	if err != nil {
		api.writeError(w, err.Error(), http.StatusNotFound)
		return
	}
	if !hasProposalCanaryPlan(record) && record.Status != "canary_active" {
		api.writeError(w, "proposal does not have an active canary rollout", http.StatusBadRequest)
		return
	}
	planSummary, err := api.describeProposalCanaryPlan(record)
	if err != nil {
		api.writeError(w, fmt.Sprintf("Failed to inspect canary rollout: %v", err), http.StatusBadRequest)
		return
	}
	verification, err := api.buildProposalVerification(record)
	if err != nil {
		api.writeError(w, fmt.Sprintf("Failed to verify proposal: %v", err), http.StatusInternalServerError)
		return
	}
	evaluation, err := api.buildProposalCanaryEvaluation(record)
	if err != nil {
		evaluation = map[string]interface{}{
			"healthy": false,
			"reasons": []string{err.Error()},
		}
	}
	api.writeJSON(w, APIResponse{
		Success: true,
		Message: "Proposal canary status retrieved successfully",
		Data: map[string]interface{}{
			"proposal_id":            record.ID,
			"status":                 record.Status,
			"environment":            record.Environment,
			"promoted_from":          record.PromotedFrom,
			"canary_services":        record.CanaryServices,
			"canary_routes":          record.CanaryRoutes,
			"canary_headers":         record.CanaryHeaders,
			"canary_percent":         record.CanaryPercent,
			"canary_steps":           record.CanarySteps,
			"canary_min_requests":    record.CanaryMinRequests,
			"canary_max_error_rate":  record.CanaryMaxErrorRate,
			"canary_max_p95_latency": record.CanaryMaxP95Latency,
			"canary_auto":            record.CanaryAutoReconcile,
			"canary_auto_interval":   record.CanaryAutoInterval,
			"canary_auto_reviewer":   record.CanaryAutoReviewer,
			"canary_last_reconciled": record.CanaryLastReconciled,
			"canary_next_reconcile":  record.CanaryNextReconcile,
			"approval_count":         proposalApprovalCount(api.gateway.GetConfig(), record),
			"required_approvals":     requiredProposalApprovers(api.gateway.GetConfig(), record),
			"plan_summary":           planSummary,
			"verification":           verification,
			"evaluation":             evaluation,
		},
	})
}

func (api *ManagementAPI) applyProposal(w http.ResponseWriter, r *http.Request) {
	record, err := loadConfigProposal(mux.Vars(r)["id"])
	if err != nil {
		api.writeError(w, err.Error(), http.StatusNotFound)
		return
	}
	reviewer, reviewNote := proposalReviewMetadataFromRequest(r, record)
	label, note, changeRef := proposalMetadataFromRequest(r, record)
	result, statusCode, err := api.applyProposalRecord(record, reviewer, reviewNote, label, note, changeRef)
	if err != nil {
		api.writeError(w, err.Error(), statusCode)
		return
	}
	api.writeJSON(w, APIResponse{
		Success: true,
		Message: proposalApplyMessage(record),
		Data:    result,
	})
}

func (api *ManagementAPI) applyProposalRecord(record *configProposalRecord, reviewer, reviewNote, label, note, changeRef string) (map[string]interface{}, int, error) {
	if record.Status != "pending" && record.Status != "approved" {
		return nil, http.StatusConflict, fmt.Errorf("proposal is already %s", record.Status)
	}
	if record.Config == nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("proposal has no stored configuration")
	}
	if strings.TrimSpace(reviewer) == "" {
		return nil, http.StatusBadRequest, fmt.Errorf("reviewer is required to apply a proposal")
	}
	if err := api.enforceProposalReviewer(record, reviewer); err != nil {
		return nil, http.StatusForbidden, err
	}
	now := time.Now().UTC()
	if err := api.enforceProposalExpiration(record, now); err != nil {
		return nil, http.StatusConflict, err
	}
	upsertProposalApproval(record, reviewer, reviewNote)
	requiredApprovers := requiredProposalApprovers(api.gateway.GetConfig(), record)
	if proposalApprovalCount(api.gateway.GetConfig(), record) < requiredApprovers {
		record.Status = proposalStatusAfterApproval(api.gateway.GetConfig(), record)
		if err := saveConfigProposalRecord(record); err != nil {
			api.logger.Warn("Proposal approval recorded but failed to persist before apply gate", logging.Error(err))
		}
		return nil, http.StatusConflict, fmt.Errorf("proposal requires %d approval(s) before apply; current fresh approvals: %d", requiredApprovers, proposalApprovalCount(api.gateway.GetConfig(), record))
	}
	if err := api.enforceProposalFreshness(record, now); err != nil {
		return nil, http.StatusConflict, err
	}
	if err := api.enforceProposalVerification(record); err != nil {
		return nil, http.StatusConflict, err
	}
	if !record.NotBefore.IsZero() && now.Before(record.NotBefore) {
		record.Status = proposalStatusAfterApproval(api.gateway.GetConfig(), record)
		if err := saveConfigProposalRecord(record); err != nil {
			api.logger.Warn("Proposal approval recorded but failed to persist before not_before gate", logging.Error(err))
		}
		return nil, http.StatusConflict, fmt.Errorf("proposal cannot be applied before %s", record.NotBefore.Format(time.RFC3339))
	}
	if err := api.enforceProposalBlackoutWindow(record.Action, now); err != nil {
		record.Status = proposalStatusAfterApproval(api.gateway.GetConfig(), record)
		if errSave := saveConfigProposalRecord(record); errSave != nil {
			api.logger.Warn("Proposal approval recorded but failed to persist before blackout gate", logging.Error(errSave))
		}
		return nil, http.StatusConflict, err
	}
	applyCfg := record.Config
	applySummary := record.Summary
	if hasProposalCanaryPlan(record) {
		baselineCfg, cloneErr := cloneConfig(api.gateway.GetConfig())
		if cloneErr != nil {
			return nil, http.StatusInternalServerError, fmt.Errorf("Failed to capture canary baseline config: %v", cloneErr)
		}
		record.CanaryBaselineConfig = baselineCfg
		applyCfg, applySummary, cloneErr = api.buildCanaryApplyConfig(record)
		if cloneErr != nil {
			return nil, http.StatusBadRequest, fmt.Errorf("Failed to build canary apply config: %v", cloneErr)
		}
	}
	if err := api.applyManagedConfigChange(applyCfg, record.Action, label, note, changeRef, applySummary); err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("Failed to apply proposal: %v", err)
	}
	if hasProposalCanaryPlan(record) {
		record.Status = "canary_active"
		scheduleNextProposalCanaryReconcile(record, now)
	} else {
		record.Status = "applied"
		record.CanaryNextReconcile = time.Time{}
	}
	record.ReviewedAt = now
	record.AppliedAt = record.ReviewedAt
	record.ReviewedBy = reviewer
	record.ReviewNote = reviewNote
	revisions, err := listConfigRevisions()
	if err == nil && len(revisions) > 0 {
		if latest, ok := revisions[0]["id"].(string); ok {
			record.RevisionID = latest
		}
	}
	if err := saveConfigProposalRecord(record); err != nil {
		api.logger.Warn("Proposal applied but failed to update proposal record", logging.Error(err))
	}
	result := map[string]interface{}{
		"proposal_id":    record.ID,
		"status":         record.Status,
		"revision_id":    record.RevisionID,
		"reviewed_by":    record.ReviewedBy,
		"review_note":    record.ReviewNote,
		"approval_count": proposalApprovalCount(api.gateway.GetConfig(), record),
		"summary":        applySummary,
	}
	if hasProposalCanaryPlan(record) {
		api.emitProposalEvent("proposal.canary_started", record, map[string]interface{}{
			"revision_id":    record.RevisionID,
			"summary":        applySummary,
			"canary_percent": record.CanaryPercent,
			"canary_steps":   record.CanarySteps,
		})
	} else {
		api.emitProposalEvent("proposal.applied", record, map[string]interface{}{
			"revision_id": record.RevisionID,
			"summary":     applySummary,
		})
	}
	return result, http.StatusOK, nil
}

func (api *ManagementAPI) expandProposalCanary(w http.ResponseWriter, r *http.Request) {
	record, err := loadConfigProposal(mux.Vars(r)["id"])
	if err != nil {
		api.writeError(w, err.Error(), http.StatusNotFound)
		return
	}
	if record.Config == nil {
		api.writeError(w, "proposal has no stored configuration", http.StatusInternalServerError)
		return
	}
	if record.Status != "pending" && record.Status != "approved" && record.Status != "canary_active" {
		api.writeError(w, fmt.Sprintf("proposal cannot expand canary because it is %s", record.Status), http.StatusConflict)
		return
	}
	record.CanaryServices = mergeNormalizedLists(record.CanaryServices, normalizeQueryList(r.URL.Query()["canary_service"]))
	record.CanaryRoutes = mergeNormalizedLists(record.CanaryRoutes, normalizeQueryList(r.URL.Query()["canary_route"]))
	canaryPercent, err := proposalCanaryPercentFromRequest(r, record)
	if err != nil {
		api.writeError(w, err.Error(), http.StatusBadRequest)
		return
	}
	record.CanaryPercent = canaryPercent
	canarySteps, err := proposalCanaryStepsFromRequest(r, record)
	if err != nil {
		api.writeError(w, err.Error(), http.StatusBadRequest)
		return
	}
	record.CanarySteps = canarySteps
	canaryMinRequests, err := proposalCanaryMinRequestsFromRequest(r, record)
	if err != nil {
		api.writeError(w, err.Error(), http.StatusBadRequest)
		return
	}
	record.CanaryMinRequests = canaryMinRequests
	canaryMaxErrorRate, err := proposalCanaryMaxErrorRateFromRequest(r, record)
	if err != nil {
		api.writeError(w, err.Error(), http.StatusBadRequest)
		return
	}
	record.CanaryMaxErrorRate = canaryMaxErrorRate
	canaryMaxP95Latency, err := proposalCanaryMaxP95LatencyFromRequest(r, record)
	if err != nil {
		api.writeError(w, err.Error(), http.StatusBadRequest)
		return
	}
	record.CanaryMaxP95Latency = canaryMaxP95Latency
	canaryAutoReconcile, err := proposalCanaryAutoReconcileFromRequest(r, record)
	if err != nil {
		api.writeError(w, err.Error(), http.StatusBadRequest)
		return
	}
	record.CanaryAutoReconcile = canaryAutoReconcile
	canaryAutoInterval, err := proposalCanaryAutoIntervalFromRequest(r, record)
	if err != nil {
		api.writeError(w, err.Error(), http.StatusBadRequest)
		return
	}
	record.CanaryAutoInterval = canaryAutoInterval
	record.CanaryAutoReviewer = proposalCanaryAutoReviewerFromRequest(r, record)
	if len(record.CanaryServices) == 0 && len(record.CanaryRoutes) == 0 {
		api.writeError(w, "at least one canary_service or canary_route is required", http.StatusBadRequest)
		return
	}

	if record.Status != "canary_active" {
		if err := saveConfigProposalRecord(record); err != nil {
			api.writeError(w, fmt.Sprintf("Failed to update proposal canary plan: %v", err), http.StatusInternalServerError)
			return
		}
		planSummary, err := api.describeProposalCanaryPlan(record)
		if err != nil {
			api.writeError(w, fmt.Sprintf("Failed to inspect canary rollout: %v", err), http.StatusBadRequest)
			return
		}
		api.writeJSON(w, APIResponse{
			Success: true,
			Message: "Proposal canary plan updated successfully",
			Data: map[string]interface{}{
				"proposal_id":            record.ID,
				"status":                 record.Status,
				"canary_services":        record.CanaryServices,
				"canary_routes":          record.CanaryRoutes,
				"canary_percent":         record.CanaryPercent,
				"canary_min_requests":    record.CanaryMinRequests,
				"canary_max_error_rate":  record.CanaryMaxErrorRate,
				"canary_max_p95_latency": record.CanaryMaxP95Latency,
				"canary_auto":            record.CanaryAutoReconcile,
				"canary_auto_interval":   record.CanaryAutoInterval,
				"canary_auto_reviewer":   record.CanaryAutoReviewer,
				"approval_count":         proposalApprovalCount(api.gateway.GetConfig(), record),
				"required_approvals":     requiredProposalApprovers(api.gateway.GetConfig(), record),
				"plan_summary":           planSummary,
			},
		})
		return
	}

	reviewer, reviewNote := proposalReviewMetadataFromRequest(r, record)
	if strings.TrimSpace(reviewer) == "" {
		api.writeError(w, "reviewer is required to expand an active canary rollout", http.StatusBadRequest)
		return
	}
	if err := api.enforceProposalReviewer(record, reviewer); err != nil {
		api.writeError(w, err.Error(), http.StatusForbidden)
		return
	}
	now := time.Now().UTC()
	if err := api.enforceProposalExpiration(record, now); err != nil {
		api.writeError(w, err.Error(), http.StatusConflict)
		return
	}
	if err := api.enforceProposalFreshness(record, now); err != nil {
		api.writeError(w, err.Error(), http.StatusConflict)
		return
	}
	if err := api.enforceProposalVerification(record); err != nil {
		api.writeError(w, err.Error(), http.StatusConflict)
		return
	}
	if err := api.enforceProposalCanaryEvaluation(record); err != nil {
		revisionID, rollbackErr := api.rollbackProposalCanary(record, reviewer, reviewNote, err.Error())
		if rollbackErr != nil {
			api.writeError(w, fmt.Sprintf("%s; automatic rollback also failed: %v", err.Error(), rollbackErr), http.StatusConflict)
			return
		}
		api.writeJSON(w, APIResponse{
			Success: false,
			Message: "Canary guard failed and rollback was applied",
			Data: map[string]interface{}{
				"proposal_id":     record.ID,
				"status":          record.Status,
				"revision_id":     revisionID,
				"rollback":        true,
				"rollback_reason": err.Error(),
			},
		})
		return
	}
	if err := api.enforceProposalBlackoutWindow(record.Action, now); err != nil {
		api.writeError(w, err.Error(), http.StatusConflict)
		return
	}
	label, note, changeRef := proposalMetadataFromRequest(r, record)
	applyCfg, applySummary, err := api.buildCanaryApplyConfig(record)
	if err != nil {
		api.writeError(w, fmt.Sprintf("Failed to build expanded canary config: %v", err), http.StatusBadRequest)
		return
	}
	if err := api.applyManagedConfigChange(applyCfg, record.Action, label, note, changeRef, applySummary); err != nil {
		api.writeError(w, fmt.Sprintf("Failed to expand canary rollout: %v", err), http.StatusInternalServerError)
		return
	}
	record.ReviewedAt = now
	record.ReviewedBy = reviewer
	record.ReviewNote = reviewNote
	scheduleNextProposalCanaryReconcile(record, now)
	revisions, err := listConfigRevisions()
	if err == nil && len(revisions) > 0 {
		if latest, ok := revisions[0]["id"].(string); ok {
			record.RevisionID = latest
		}
	}
	if err := saveConfigProposalRecord(record); err != nil {
		api.logger.Warn("Canary expansion applied but failed to update proposal record", logging.Error(err))
	}
	api.writeJSON(w, APIResponse{
		Success: true,
		Message: "Proposal canary rollout expanded successfully",
		Data: map[string]interface{}{
			"proposal_id":            record.ID,
			"status":                 record.Status,
			"reviewed_by":            record.ReviewedBy,
			"review_note":            record.ReviewNote,
			"canary_services":        record.CanaryServices,
			"canary_routes":          record.CanaryRoutes,
			"canary_headers":         record.CanaryHeaders,
			"canary_percent":         record.CanaryPercent,
			"canary_steps":           record.CanarySteps,
			"canary_min_requests":    record.CanaryMinRequests,
			"canary_max_error_rate":  record.CanaryMaxErrorRate,
			"canary_max_p95_latency": record.CanaryMaxP95Latency,
			"canary_auto":            record.CanaryAutoReconcile,
			"canary_auto_interval":   record.CanaryAutoInterval,
			"canary_auto_reviewer":   record.CanaryAutoReviewer,
			"canary_last_reconciled": record.CanaryLastReconciled,
			"canary_next_reconcile":  record.CanaryNextReconcile,
			"revision_id":            record.RevisionID,
			"summary":                applySummary,
		},
	})
}

func (api *ManagementAPI) completeProposalCanary(w http.ResponseWriter, r *http.Request) {
	record, err := loadConfigProposal(mux.Vars(r)["id"])
	if err != nil {
		api.writeError(w, err.Error(), http.StatusNotFound)
		return
	}
	if record.Config == nil {
		api.writeError(w, "proposal has no stored configuration", http.StatusInternalServerError)
		return
	}
	if record.Status != "canary_active" {
		api.writeError(w, fmt.Sprintf("proposal canary is not active; current status is %s", record.Status), http.StatusConflict)
		return
	}
	reviewer, reviewNote := proposalReviewMetadataFromRequest(r, record)
	if strings.TrimSpace(reviewer) == "" {
		api.writeError(w, "reviewer is required to complete an active canary rollout", http.StatusBadRequest)
		return
	}
	if err := api.enforceProposalReviewer(record, reviewer); err != nil {
		api.writeError(w, err.Error(), http.StatusForbidden)
		return
	}
	now := time.Now().UTC()
	if err := api.enforceProposalExpiration(record, now); err != nil {
		api.writeError(w, err.Error(), http.StatusConflict)
		return
	}
	if err := api.enforceProposalFreshness(record, now); err != nil {
		api.writeError(w, err.Error(), http.StatusConflict)
		return
	}
	if err := api.enforceProposalVerification(record); err != nil {
		api.writeError(w, err.Error(), http.StatusConflict)
		return
	}
	if err := api.enforceProposalCanaryEvaluation(record); err != nil {
		revisionID, rollbackErr := api.rollbackProposalCanary(record, reviewer, reviewNote, err.Error())
		if rollbackErr != nil {
			api.writeError(w, fmt.Sprintf("%s; automatic rollback also failed: %v", err.Error(), rollbackErr), http.StatusConflict)
			return
		}
		api.writeJSON(w, APIResponse{
			Success: false,
			Message: "Canary guard failed and rollback was applied",
			Data: map[string]interface{}{
				"proposal_id":     record.ID,
				"status":          record.Status,
				"revision_id":     revisionID,
				"rollback":        true,
				"rollback_reason": err.Error(),
			},
		})
		return
	}
	if err := api.enforceProposalBlackoutWindow(record.Action, now); err != nil {
		api.writeError(w, err.Error(), http.StatusConflict)
		return
	}
	label, note, changeRef := proposalMetadataFromRequest(r, record)
	if err := api.applyManagedConfigChange(record.Config, record.Action, label, note, changeRef, record.Summary); err != nil {
		api.writeError(w, fmt.Sprintf("Failed to complete canary rollout: %v", err), http.StatusInternalServerError)
		return
	}
	record.Status = "applied"
	record.ReviewedAt = now
	record.AppliedAt = now
	record.ReviewedBy = reviewer
	record.ReviewNote = reviewNote
	revisions, err := listConfigRevisions()
	if err == nil && len(revisions) > 0 {
		if latest, ok := revisions[0]["id"].(string); ok {
			record.RevisionID = latest
		}
	}
	if err := saveConfigProposalRecord(record); err != nil {
		api.logger.Warn("Canary completion applied but failed to update proposal record", logging.Error(err))
	}
	api.writeJSON(w, APIResponse{
		Success: true,
		Message: "Proposal canary rollout completed successfully",
		Data: map[string]interface{}{
			"proposal_id": record.ID,
			"status":      record.Status,
			"revision_id": record.RevisionID,
			"reviewed_by": record.ReviewedBy,
			"review_note": record.ReviewNote,
			"summary":     record.Summary,
		},
	})
}

func (api *ManagementAPI) promoteProposal(w http.ResponseWriter, r *http.Request) {
	record, err := loadConfigProposal(mux.Vars(r)["id"])
	if err != nil {
		api.writeError(w, err.Error(), http.StatusNotFound)
		return
	}
	if record.Config == nil {
		api.writeError(w, "proposal has no stored configuration", http.StatusInternalServerError)
		return
	}
	if record.Status == "rejected" || record.Status == "expired" {
		api.writeError(w, fmt.Sprintf("proposal cannot be promoted because it is %s", record.Status), http.StatusConflict)
		return
	}
	environment := proposalEnvironmentFromRequest(r)
	if environment == "" {
		api.writeError(w, "environment is required to promote a proposal", http.StatusBadRequest)
		return
	}
	notBefore, err := proposalNotBeforeFromRequest(r)
	if err != nil {
		api.writeError(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := api.enforceProposalSchedule(record.Action, notBefore); err != nil {
		api.writeError(w, err.Error(), http.StatusBadRequest)
		return
	}
	label, note, changeRef := proposalMetadataFromRequest(r, record)
	proposer := proposalProposerFromRequest(r)
	if proposer == "" {
		proposer = record.CreatedBy
	}
	clonedCfg, err := cloneConfig(record.Config)
	if err != nil {
		api.writeError(w, fmt.Sprintf("Failed to clone promoted proposal: %v", err), http.StatusInternalServerError)
		return
	}
	canaryPercent, err := proposalCanaryPercentFromRequest(r, record)
	if err != nil {
		api.writeError(w, err.Error(), http.StatusBadRequest)
		return
	}
	canarySteps, err := proposalCanaryStepsFromRequest(r, record)
	if err != nil {
		api.writeError(w, err.Error(), http.StatusBadRequest)
		return
	}
	canaryMinRequests, err := proposalCanaryMinRequestsFromRequest(r, record)
	if err != nil {
		api.writeError(w, err.Error(), http.StatusBadRequest)
		return
	}
	canaryMaxErrorRate, err := proposalCanaryMaxErrorRateFromRequest(r, record)
	if err != nil {
		api.writeError(w, err.Error(), http.StatusBadRequest)
		return
	}
	canaryMaxP95Latency, err := proposalCanaryMaxP95LatencyFromRequest(r, record)
	if err != nil {
		api.writeError(w, err.Error(), http.StatusBadRequest)
		return
	}
	canaryAutoReconcile, err := proposalCanaryAutoReconcileFromRequest(r, record)
	if err != nil {
		api.writeError(w, err.Error(), http.StatusBadRequest)
		return
	}
	canaryAutoInterval, err := proposalCanaryAutoIntervalFromRequest(r, record)
	if err != nil {
		api.writeError(w, err.Error(), http.StatusBadRequest)
		return
	}
	canaryAutoReviewer := proposalCanaryAutoReviewerFromRequest(r, record)
	promotedID, err := saveConfigProposal(record.Action, record.Strategy, proposer, environment, record.ID, record.ConfigHash, proposalCanaryServicesFromRequest(r, record), proposalCanaryRoutesFromRequest(r, record), proposalCanaryHeadersFromRequest(r, record), canaryPercent, canarySteps, canaryMinRequests, canaryMaxErrorRate, canaryMaxP95Latency, canaryAutoReconcile, canaryAutoInterval, canaryAutoReviewer, label, note, changeRef, notBefore, requiredProposalApprovers(api.gateway.GetConfig(), record), record.Summary, clonedCfg)
	if err != nil {
		api.writeError(w, fmt.Sprintf("Failed to promote proposal: %v", err), http.StatusInternalServerError)
		return
	}
	api.writeJSON(w, APIResponse{
		Success: true,
		Message: "Proposal promoted successfully",
		Data: map[string]interface{}{
			"proposal_id":            promotedID,
			"promoted_from":          record.ID,
			"environment":            environment,
			"not_before":             notBefore,
			"canary_services":        proposalCanaryServicesFromRequest(r, record),
			"canary_routes":          proposalCanaryRoutesFromRequest(r, record),
			"canary_headers":         proposalCanaryHeadersFromRequest(r, record),
			"canary_percent":         canaryPercent,
			"canary_steps":           canarySteps,
			"canary_min_requests":    canaryMinRequests,
			"canary_max_error_rate":  canaryMaxErrorRate,
			"canary_max_p95_latency": canaryMaxP95Latency,
			"canary_auto":            canaryAutoReconcile,
			"canary_auto_interval":   canaryAutoInterval,
			"canary_auto_reviewer":   canaryAutoReviewer,
			"required_count":         requiredProposalApprovers(api.gateway.GetConfig(), record),
		},
	})
	api.emitProposalEvent("proposal.promoted", record, map[string]interface{}{
		"promoted_proposal_id": promotedID,
		"environment":          environment,
		"not_before":           notBefore,
	})
}

func (api *ManagementAPI) rejectProposal(w http.ResponseWriter, r *http.Request) {
	record, err := loadConfigProposal(mux.Vars(r)["id"])
	if err != nil {
		api.writeError(w, err.Error(), http.StatusNotFound)
		return
	}
	if record.Status != "pending" {
		api.writeError(w, fmt.Sprintf("proposal is already %s", record.Status), http.StatusConflict)
		return
	}
	reviewer, reviewNote := proposalReviewMetadataFromRequest(r, record)
	if strings.TrimSpace(reviewer) == "" {
		api.writeError(w, "reviewer is required to reject a proposal", http.StatusBadRequest)
		return
	}
	if err := api.enforceProposalReviewer(record, reviewer); err != nil {
		api.writeError(w, err.Error(), http.StatusForbidden)
		return
	}
	record.Status = "rejected"
	record.ReviewedAt = time.Now().UTC()
	record.ReviewedBy = reviewer
	record.ReviewNote = reviewNote
	if err := saveConfigProposalRecord(record); err != nil {
		api.writeError(w, fmt.Sprintf("Failed to reject proposal: %v", err), http.StatusInternalServerError)
		return
	}
	api.writeJSON(w, APIResponse{
		Success: true,
		Message: "Proposal rejected successfully",
		Data: map[string]interface{}{
			"proposal_id": record.ID,
			"status":      record.Status,
			"reviewed_by": record.ReviewedBy,
			"review_note": record.ReviewNote,
		},
	})
	api.emitProposalEvent("proposal.rejected", record, map[string]interface{}{
		"reviewed_by": record.ReviewedBy,
		"review_note": record.ReviewNote,
	})
}

func (api *ManagementAPI) listNotificationDeliveries(w http.ResponseWriter, r *http.Request) {
	records, err := listNotificationDeliveryRecords()
	if err != nil {
		api.writeError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	records = filterNotificationDeliveryRecords(
		records,
		r.URL.Query().Get("event"),
		r.URL.Query().Get("proposal_id"),
		r.URL.Query().Get("webhook"),
		r.URL.Query().Get("success"),
	)
	api.writeJSON(w, map[string]interface{}{
		"deliveries": records,
		"total":      len(records),
	})
}

func (api *ManagementAPI) getNotificationDelivery(w http.ResponseWriter, r *http.Request) {
	record, err := loadNotificationDeliveryRecord(mux.Vars(r)["id"])
	if err != nil {
		api.writeError(w, err.Error(), http.StatusNotFound)
		return
	}
	api.writeJSON(w, record)
}

func (api *ManagementAPI) replayNotificationDelivery(w http.ResponseWriter, r *http.Request) {
	record, err := loadNotificationDeliveryRecord(mux.Vars(r)["id"])
	if err != nil {
		api.writeError(w, err.Error(), http.StatusNotFound)
		return
	}
	replayed, replayErr := api.postNotificationWebhook(record.Webhook, record.Payload, record.ID)
	if replayErr != nil {
		api.writeError(w, fmt.Sprintf("Failed to replay notification delivery: %v", replayErr), http.StatusBadGateway)
		return
	}
	api.writeJSON(w, APIResponse{
		Success: true,
		Message: "Notification delivery replayed successfully",
		Data: map[string]interface{}{
			"source_delivery_id": record.ID,
			"delivery_id":        replayed.ID,
			"event":              replayed.Event,
			"attempts":           replayed.Attempts,
			"last_status_code":   replayed.LastStatusCode,
			"delivered_at":       replayed.DeliveredAt,
		},
	})
}

func (api *ManagementAPI) replayFailedNotificationDeliveries(w http.ResponseWriter, r *http.Request) {
	records, err := listNotificationDeliveryRecords()
	if err != nil {
		api.writeError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	records = filterNotificationDeliveryRecords(
		records,
		r.URL.Query().Get("event"),
		r.URL.Query().Get("proposal_id"),
		r.URL.Query().Get("webhook"),
		"false",
	)
	limit := 0
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		if parsed, parseErr := strconv.Atoi(raw); parseErr != nil || parsed < 0 {
			api.writeError(w, "limit must be zero or greater", http.StatusBadRequest)
			return
		} else {
			limit = parsed
		}
	}
	replayed := make([]map[string]interface{}, 0)
	for _, item := range records {
		if limit > 0 && len(replayed) >= limit {
			break
		}
		id, _ := item["id"].(string)
		if strings.TrimSpace(id) == "" {
			continue
		}
		record, err := loadNotificationDeliveryRecord(id)
		if err != nil {
			continue
		}
		newRecord, replayErr := api.postNotificationWebhook(record.Webhook, record.Payload, record.ID)
		if replayErr != nil {
			replayed = append(replayed, map[string]interface{}{
				"source_delivery_id": record.ID,
				"event":              record.Event,
				"success":            false,
				"error":              replayErr.Error(),
			})
			continue
		}
		replayed = append(replayed, map[string]interface{}{
			"source_delivery_id": record.ID,
			"delivery_id":        newRecord.ID,
			"event":              newRecord.Event,
			"success":            true,
			"attempts":           newRecord.Attempts,
			"last_status_code":   newRecord.LastStatusCode,
		})
	}
	api.writeJSON(w, APIResponse{
		Success: true,
		Message: "Failed notification deliveries replayed",
		Data: map[string]interface{}{
			"matched":  len(records),
			"replayed": replayed,
		},
	})
}

// Helper methods

func (api *ManagementAPI) writeJSON(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

type routeRecord struct {
	ID                 string
	ServiceConfigIndex int
	ServiceIndex       int
	RouteIndex         int
	Service            config.Service
	Route              config.RouterConfig
	EffectivePath      string
}

func cloneConfig(cfg *config.Config) (*config.Config, error) {
	data, err := json.Marshal(cfg)
	if err != nil {
		return nil, err
	}
	var cloned config.Config
	if err := json.Unmarshal(data, &cloned); err != nil {
		return nil, err
	}
	return &cloned, nil
}

func configFingerprint(cfg *config.Config) (string, error) {
	data, err := json.Marshal(cfg)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

func (api *ManagementAPI) buildProposalVerification(record *configProposalRecord) (map[string]interface{}, error) {
	configHash, err := configFingerprint(record.Config)
	if err != nil {
		return nil, err
	}
	result := map[string]interface{}{
		"proposal_id":            record.ID,
		"environment":            record.Environment,
		"promoted_from":          record.PromotedFrom,
		"config_hash":            record.ConfigHash,
		"computed_hash":          configHash,
		"canary_services":        record.CanaryServices,
		"canary_routes":          record.CanaryRoutes,
		"canary_headers":         record.CanaryHeaders,
		"canary_percent":         record.CanaryPercent,
		"canary_steps":           record.CanarySteps,
		"canary_min_requests":    record.CanaryMinRequests,
		"canary_max_error_rate":  record.CanaryMaxErrorRate,
		"canary_max_p95_latency": record.CanaryMaxP95Latency,
		"integrity_ok":           strings.TrimSpace(record.ConfigHash) == "" || strings.EqualFold(strings.TrimSpace(record.ConfigHash), configHash),
		"source_verified":        false,
		"matches_source":         false,
		"matches_current":        false,
		"current_summary":        map[string]interface{}{},
		"current_services":       map[string]interface{}{},
	}

	liveCfg := api.gateway.GetConfig()
	if liveCfg != nil {
		liveHash, err := configFingerprint(liveCfg)
		if err == nil {
			result["current_hash"] = liveHash
			result["matches_current"] = strings.EqualFold(liveHash, configHash)
		}
		result["current_summary"] = configChangeSummary(record.Config, liveCfg)
		result["current_services"] = serviceChangeSummary(record.Config, liveCfg)
	}

	shadowVerification, err := api.buildProposalShadowVerification(record)
	if err != nil {
		return nil, err
	}
	result["shadow_verification"] = shadowVerification

	if strings.TrimSpace(record.PromotedFrom) == "" {
		return result, nil
	}

	sourceRecord, err := loadConfigProposal(strings.TrimSpace(record.PromotedFrom))
	if err != nil {
		result["source_error"] = err.Error()
		return result, nil
	}
	if sourceRecord.Config == nil {
		result["source_error"] = "source proposal has no stored configuration"
		return result, nil
	}
	sourceHash := strings.TrimSpace(sourceRecord.ConfigHash)
	if sourceHash == "" {
		sourceHash, err = configFingerprint(sourceRecord.Config)
		if err != nil {
			return nil, err
		}
	}
	expectedSourceHash := strings.TrimSpace(record.SourceConfigHash)
	if expectedSourceHash == "" {
		expectedSourceHash = sourceHash
	}
	result["source_verified"] = true
	result["source_hash"] = sourceHash
	result["expected_source_hash"] = expectedSourceHash
	result["matches_source"] = strings.EqualFold(expectedSourceHash, configHash)
	result["source_summary"] = configChangeSummary(sourceRecord.Config, record.Config)
	result["source_services"] = serviceChangeSummary(sourceRecord.Config, record.Config)
	return result, nil
}

func (api *ManagementAPI) evaluateProposalCanary(w http.ResponseWriter, r *http.Request) {
	record, err := loadConfigProposal(mux.Vars(r)["id"])
	if err != nil {
		api.writeError(w, err.Error(), http.StatusNotFound)
		return
	}
	evaluation, err := api.buildProposalCanaryEvaluation(record)
	if err != nil {
		api.writeError(w, fmt.Sprintf("Failed to evaluate canary rollout: %v", err), http.StatusBadRequest)
		return
	}
	api.writeJSON(w, APIResponse{
		Success: true,
		Message: "Proposal canary evaluation completed successfully",
		Data:    evaluation,
	})
}

func (api *ManagementAPI) advanceProposalCanary(w http.ResponseWriter, r *http.Request) {
	record, err := loadConfigProposal(mux.Vars(r)["id"])
	if err != nil {
		api.writeError(w, err.Error(), http.StatusNotFound)
		return
	}
	if record.Config == nil {
		api.writeError(w, "proposal has no stored configuration", http.StatusInternalServerError)
		return
	}
	if record.Status != "canary_active" {
		api.writeError(w, fmt.Sprintf("proposal canary is not active; current status is %s", record.Status), http.StatusConflict)
		return
	}
	reviewer, reviewNote := proposalReviewMetadataFromRequest(r, record)
	if strings.TrimSpace(reviewer) == "" {
		api.writeError(w, "reviewer is required to advance an active canary rollout", http.StatusBadRequest)
		return
	}
	if err := api.enforceProposalReviewer(record, reviewer); err != nil {
		api.writeError(w, err.Error(), http.StatusForbidden)
		return
	}
	now := time.Now().UTC()
	if err := api.enforceProposalExpiration(record, now); err != nil {
		api.writeError(w, err.Error(), http.StatusConflict)
		return
	}
	if err := api.enforceProposalFreshness(record, now); err != nil {
		api.writeError(w, err.Error(), http.StatusConflict)
		return
	}
	if err := api.enforceProposalVerification(record); err != nil {
		api.writeError(w, err.Error(), http.StatusConflict)
		return
	}
	if err := api.enforceProposalCanaryEvaluation(record); err != nil {
		api.writeProposalCanaryRollbackOrError(w, record, reviewer, reviewNote, err)
		return
	}
	if err := api.enforceProposalBlackoutWindow(record.Action, now); err != nil {
		api.writeError(w, err.Error(), http.StatusConflict)
		return
	}

	nextPercent, complete, err := nextCanaryAdvanceStep(record)
	if err != nil {
		api.writeError(w, err.Error(), http.StatusBadRequest)
		return
	}
	if complete {
		label, note, changeRef := proposalMetadataFromRequest(r, record)
		data, err := api.performProposalCanaryCompletion(record, reviewer, reviewNote, label, note, changeRef, now)
		if err != nil {
			api.writeError(w, fmt.Sprintf("Failed to complete canary rollout: %v", err), http.StatusInternalServerError)
			return
		}
		api.writeJSON(w, APIResponse{
			Success: true,
			Message: "Proposal canary rollout completed successfully",
			Data:    data,
		})
		return
	}
	label, note, changeRef := proposalMetadataFromRequest(r, record)
	data, err := api.performProposalCanaryAdvance(record, reviewer, reviewNote, label, note, changeRef, now, nextPercent)
	if err != nil {
		api.writeError(w, fmt.Sprintf("Failed to advance canary rollout: %v", err), http.StatusInternalServerError)
		return
	}
	api.writeJSON(w, APIResponse{
		Success: true,
		Message: "Proposal canary rollout advanced successfully",
		Data:    data,
	})
}

func (api *ManagementAPI) reconcileProposalCanary(w http.ResponseWriter, r *http.Request) {
	record, err := loadConfigProposal(mux.Vars(r)["id"])
	if err != nil {
		api.writeError(w, err.Error(), http.StatusNotFound)
		return
	}
	if record.Config == nil {
		api.writeError(w, "proposal has no stored configuration", http.StatusInternalServerError)
		return
	}
	if record.Status != "canary_active" {
		api.writeError(w, fmt.Sprintf("proposal canary is not active; current status is %s", record.Status), http.StatusConflict)
		return
	}
	reviewer, reviewNote := proposalReviewMetadataFromRequest(r, record)
	if strings.TrimSpace(reviewer) == "" {
		api.writeError(w, "reviewer is required to reconcile an active canary rollout", http.StatusBadRequest)
		return
	}
	if err := api.enforceProposalReviewer(record, reviewer); err != nil {
		api.writeError(w, err.Error(), http.StatusForbidden)
		return
	}
	now := time.Now().UTC()
	if err := api.enforceProposalExpiration(record, now); err != nil {
		api.writeError(w, err.Error(), http.StatusConflict)
		return
	}
	if err := api.enforceProposalFreshness(record, now); err != nil {
		api.writeError(w, err.Error(), http.StatusConflict)
		return
	}
	if err := api.enforceProposalVerification(record); err != nil {
		api.writeError(w, err.Error(), http.StatusConflict)
		return
	}
	if err := api.enforceProposalBlackoutWindow(record.Action, now); err != nil {
		api.writeError(w, err.Error(), http.StatusConflict)
		return
	}
	label, note, changeRef := proposalMetadataFromRequest(r, record)
	data, err := api.performProposalCanaryReconcile(record, reviewer, reviewNote, label, note, changeRef, now)
	if err != nil {
		api.writeError(w, fmt.Sprintf("Failed to reconcile canary rollout: %v", err), http.StatusInternalServerError)
		return
	}
	success, _ := data["success"].(bool)
	message, _ := data["message"].(string)
	api.writeJSON(w, APIResponse{
		Success: success,
		Message: message,
		Data:    data["data"],
	})
}

func (api *ManagementAPI) performProposalCanaryReconcile(record *configProposalRecord, reviewer, reviewNote, label, note, changeRef string, now time.Time) (map[string]interface{}, error) {
	evaluation, err := api.buildProposalCanaryEvaluation(record)
	if err != nil {
		return nil, fmt.Errorf("evaluate canary rollout: %w", err)
	}
	if healthy, _ := evaluation["healthy"].(bool); !healthy {
		record.CanaryLastReconciled = now
		record.CanaryNextReconcile = time.Time{}
		revisionID, rollbackErr := api.rollbackProposalCanary(record, reviewer, reviewNote, canaryEvaluationReasons(evaluation))
		if rollbackErr != nil {
			return nil, fmt.Errorf("%s; automatic rollback also failed: %v", canaryEvaluationReasons(evaluation), rollbackErr)
		}
		return map[string]interface{}{
			"success": false,
			"message": "Canary reconcile detected unhealthy metrics and rollback was applied",
			"data": map[string]interface{}{
				"proposal_id":     record.ID,
				"status":          record.Status,
				"revision_id":     revisionID,
				"rollback":        true,
				"action_taken":    "rollback",
				"rollback_reason": canaryEvaluationReasons(evaluation),
				"evaluation":      evaluation,
			},
		}, nil
	}

	nextPercent, complete, stepErr := nextCanaryAdvanceStep(record)
	if stepErr != nil {
		complete = true
	}
	if complete || record.CanaryPercent <= 0 {
		data, err := api.performProposalCanaryCompletion(record, reviewer, reviewNote, label, note, changeRef, now)
		if err != nil {
			return nil, fmt.Errorf("complete canary rollout: %w", err)
		}
		data["action_taken"] = "complete"
		data["evaluation"] = evaluation
		return map[string]interface{}{
			"success": true,
			"message": "Proposal canary reconcile completed the rollout successfully",
			"data":    data,
		}, nil
	}

	data, err := api.performProposalCanaryAdvance(record, reviewer, reviewNote, label, note, changeRef, now, nextPercent)
	if err != nil {
		return nil, fmt.Errorf("advance canary rollout: %w", err)
	}
	data["action_taken"] = "advance"
	data["evaluation"] = evaluation
	return map[string]interface{}{
		"success": true,
		"message": "Proposal canary reconcile advanced the rollout successfully",
		"data":    data,
	}, nil
}

func (api *ManagementAPI) buildProposalCanaryEvaluation(record *configProposalRecord) (map[string]interface{}, error) {
	if record == nil {
		return nil, fmt.Errorf("proposal not found")
	}
	if !hasProposalCanaryPlan(record) && record.Status != "canary_active" {
		return nil, fmt.Errorf("proposal does not have a canary rollout")
	}
	services, routes, err := proposalCanaryMetricTargets(record)
	if err != nil {
		return nil, err
	}
	logs := filterCanaryLogEntries(api.logger.RecentLogs(2000, ""), services, routes)
	requests := 0
	failed := 0
	durations := make([]time.Duration, 0, len(logs))
	for _, entry := range logs {
		status, ok := fieldInt(entry.Fields, "status_code")
		if !ok {
			continue
		}
		requests++
		if status >= 500 {
			failed++
		}
		if duration, ok := fieldDuration(entry.Fields, "duration"); ok {
			durations = append(durations, duration)
		}
	}
	avg := averageDuration(durations)
	p95 := percentileDuration(durations, 95)
	p99 := percentileDuration(durations, 99)
	errorRate := 0.0
	if requests > 0 {
		errorRate = float64(failed) / float64(requests)
	}

	thresholds := canaryEvaluationThresholds{
		MinRequests:   record.CanaryMinRequests,
		MaxErrorRate:  record.CanaryMaxErrorRate,
		MaxP95Latency: strings.TrimSpace(record.CanaryMaxP95Latency),
	}
	healthy := true
	reasons := make([]string, 0)
	if thresholds.MinRequests > 0 && requests < thresholds.MinRequests {
		healthy = false
		reasons = append(reasons, fmt.Sprintf("canary observed %d request(s), below minimum %d", requests, thresholds.MinRequests))
	}
	if thresholds.MaxErrorRate > 0 && errorRate > thresholds.MaxErrorRate {
		healthy = false
		reasons = append(reasons, fmt.Sprintf("canary error rate %.4f exceeded limit %.4f", errorRate, thresholds.MaxErrorRate))
	}
	if thresholds.MaxP95Latency != "" {
		limit, _ := time.ParseDuration(thresholds.MaxP95Latency)
		if limit > 0 && p95 > limit {
			healthy = false
			reasons = append(reasons, fmt.Sprintf("canary p95 latency %s exceeded limit %s", p95, limit))
		}
	}
	if len(reasons) == 0 {
		reasons = append(reasons, "canary metrics are within configured thresholds")
	}

	return map[string]interface{}{
		"proposal_id":       record.ID,
		"status":            record.Status,
		"environment":       record.Environment,
		"canary_services":   record.CanaryServices,
		"canary_routes":     record.CanaryRoutes,
		"canary_headers":    record.CanaryHeaders,
		"canary_percent":    record.CanaryPercent,
		"canary_steps":      record.CanarySteps,
		"target_services":   services,
		"target_routes":     routes,
		"thresholds":        thresholds,
		"requests":          requests,
		"failed_requests":   failed,
		"error_rate":        errorRate,
		"average_latency":   avg.String(),
		"p95_latency":       p95.String(),
		"p99_latency":       p99.String(),
		"healthy":           healthy,
		"reasons":           reasons,
		"evaluation_window": "recent_logs_2000",
	}, nil
}

func proposalCanaryMetricTargets(record *configProposalRecord) ([]string, []string, error) {
	if record == nil || record.Config == nil {
		return nil, nil, fmt.Errorf("proposal has no stored configuration")
	}
	planServices := normalizeQueryList(record.CanaryServices)
	planRoutes := normalizeQueryList(record.CanaryRoutes)
	targetServices := make([]string, 0)
	targetRoutes := make([]string, 0)
	for _, svcCfg := range record.Config.Services {
		for _, svc := range svcCfg.Services {
			if !serviceSelectedForCanary(svc, planServices, planRoutes) {
				continue
			}
			serviceName := displayServiceName(svc)
			if len(record.CanaryHeaders) > 0 || record.CanaryPercent > 0 {
				serviceName = canaryServiceName(serviceName)
			}
			targetServices = appendUniqueString(targetServices, serviceName)
			serviceOnly := serviceSelectedOnlyByName(svc, planServices, planRoutes)
			for _, route := range svc.Routes {
				if serviceOnly || routeSelectedForCanary(svc, route, planRoutes) {
					targetRoutes = appendUniqueString(targetRoutes, strings.TrimSpace(route.Path))
				}
			}
		}
	}
	if len(targetServices) == 0 && len(targetRoutes) == 0 {
		return nil, nil, fmt.Errorf("canary plan did not match any proposal services or routes")
	}
	sort.Strings(targetServices)
	sort.Strings(targetRoutes)
	return targetServices, targetRoutes, nil
}

func filterCanaryLogEntries(entries []logging.LogEntry, serviceNames, routeNames []string) []logging.LogEntry {
	if len(entries) == 0 {
		return nil
	}
	serviceSet := make(map[string]struct{}, len(serviceNames))
	for _, name := range serviceNames {
		name = strings.TrimSpace(name)
		if name != "" {
			serviceSet[name] = struct{}{}
		}
	}
	routeSet := make(map[string]struct{}, len(routeNames))
	for _, name := range routeNames {
		name = strings.TrimSpace(name)
		if name != "" {
			routeSet[name] = struct{}{}
		}
	}
	filtered := make([]logging.LogEntry, 0, len(entries))
	for _, entry := range entries {
		serviceName := fieldString(entry.Fields, "service_name")
		routeName := fieldString(entry.Fields, "route_name")
		_, serviceMatch := serviceSet[serviceName]
		_, routeMatch := routeSet[routeName]
		if serviceMatch || routeMatch {
			filtered = append(filtered, entry)
		}
	}
	return filtered
}

func fieldInt(fields map[string]interface{}, key string) (int, bool) {
	if fields == nil {
		return 0, false
	}
	value, ok := fields[key]
	if !ok || value == nil {
		return 0, false
	}
	switch v := value.(type) {
	case int:
		return v, true
	case int64:
		return int(v), true
	case float64:
		return int(v), true
	case json.Number:
		i, err := v.Int64()
		return int(i), err == nil
	case string:
		i, err := strconv.Atoi(strings.TrimSpace(v))
		return i, err == nil
	default:
		return 0, false
	}
}

func fieldDuration(fields map[string]interface{}, key string) (time.Duration, bool) {
	if fields == nil {
		return 0, false
	}
	value, ok := fields[key]
	if !ok || value == nil {
		return 0, false
	}
	switch v := value.(type) {
	case string:
		d, err := time.ParseDuration(strings.TrimSpace(v))
		return d, err == nil
	case time.Duration:
		return v, true
	case float64:
		return time.Duration(v * float64(time.Second)), true
	default:
		return 0, false
	}
}

func averageDuration(values []time.Duration) time.Duration {
	if len(values) == 0 {
		return 0
	}
	var total time.Duration
	for _, value := range values {
		total += value
	}
	return total / time.Duration(len(values))
}

func percentileDuration(values []time.Duration, percentile int) time.Duration {
	if len(values) == 0 {
		return 0
	}
	sorted := append([]time.Duration(nil), values...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	if percentile <= 0 {
		return sorted[0]
	}
	if percentile >= 100 {
		return sorted[len(sorted)-1]
	}
	index := (len(sorted)*percentile + 99) / 100
	if index <= 0 {
		index = 1
	}
	if index > len(sorted) {
		index = len(sorted)
	}
	return sorted[index-1]
}

func nextCanaryAdvanceStep(record *configProposalRecord) (nextPercent int, complete bool, err error) {
	if record == nil {
		return 0, false, fmt.Errorf("proposal not found")
	}
	if len(record.CanarySteps) == 0 {
		return 0, false, fmt.Errorf("proposal does not define any canary steps")
	}
	steps := append([]int(nil), record.CanarySteps...)
	sort.Ints(steps)
	current := record.CanaryPercent
	for _, step := range steps {
		if step > current {
			if step >= 100 {
				return 100, true, nil
			}
			return step, false, nil
		}
	}
	if current > 0 && current < 100 {
		return 100, true, nil
	}
	return 0, false, fmt.Errorf("no further canary steps remain")
}

func (api *ManagementAPI) performProposalCanaryAdvance(record *configProposalRecord, reviewer, reviewNote, label, note, changeRef string, now time.Time, nextPercent int) (map[string]interface{}, error) {
	record.CanaryPercent = nextPercent
	applyCfg, applySummary, err := api.buildCanaryApplyConfig(record)
	if err != nil {
		return nil, fmt.Errorf("build advanced canary config: %w", err)
	}
	if err := api.applyManagedConfigChange(applyCfg, record.Action, label, note, changeRef, applySummary); err != nil {
		return nil, err
	}
	record.ReviewedAt = now
	record.ReviewedBy = reviewer
	record.ReviewNote = reviewNote
	scheduleNextProposalCanaryReconcile(record, now)
	revisions, err := listConfigRevisions()
	if err == nil && len(revisions) > 0 {
		if latest, ok := revisions[0]["id"].(string); ok {
			record.RevisionID = latest
		}
	}
	if err := saveConfigProposalRecord(record); err != nil {
		api.logger.Warn("Canary advance applied but failed to update proposal record", logging.Error(err))
	}
	result := map[string]interface{}{
		"proposal_id":            record.ID,
		"status":                 record.Status,
		"reviewed_by":            record.ReviewedBy,
		"review_note":            record.ReviewNote,
		"canary_percent":         record.CanaryPercent,
		"canary_steps":           record.CanarySteps,
		"canary_auto":            record.CanaryAutoReconcile,
		"canary_auto_interval":   record.CanaryAutoInterval,
		"canary_auto_reviewer":   record.CanaryAutoReviewer,
		"canary_last_reconciled": record.CanaryLastReconciled,
		"canary_next_reconcile":  record.CanaryNextReconcile,
		"revision_id":            record.RevisionID,
		"summary":                applySummary,
	}
	api.emitProposalEvent("proposal.canary_advanced", record, result)
	return result, nil
}

func (api *ManagementAPI) performProposalCanaryCompletion(record *configProposalRecord, reviewer, reviewNote, label, note, changeRef string, now time.Time) (map[string]interface{}, error) {
	if err := api.applyManagedConfigChange(record.Config, record.Action, label, note, changeRef, record.Summary); err != nil {
		return nil, err
	}
	record.Status = "applied"
	record.ReviewedAt = now
	record.AppliedAt = now
	record.ReviewedBy = reviewer
	record.ReviewNote = reviewNote
	scheduleNextProposalCanaryReconcile(record, now)
	revisions, err := listConfigRevisions()
	if err == nil && len(revisions) > 0 {
		if latest, ok := revisions[0]["id"].(string); ok {
			record.RevisionID = latest
		}
	}
	if err := saveConfigProposalRecord(record); err != nil {
		api.logger.Warn("Canary completion applied but failed to update proposal record", logging.Error(err))
	}
	result := map[string]interface{}{
		"proposal_id":            record.ID,
		"status":                 record.Status,
		"revision_id":            record.RevisionID,
		"reviewed_by":            record.ReviewedBy,
		"review_note":            record.ReviewNote,
		"canary_last_reconciled": record.CanaryLastReconciled,
		"canary_next_reconcile":  record.CanaryNextReconcile,
		"summary":                record.Summary,
	}
	api.emitProposalEvent("proposal.canary_completed", record, result)
	return result, nil
}

func (api *ManagementAPI) enforceProposalVerification(record *configProposalRecord) error {
	if record == nil {
		return nil
	}
	cfg := api.gateway.GetConfig()
	if cfg == nil {
		return nil
	}
	policy := cfg.Security.MutationPolicy
	if !policy.Enabled || !policy.RequireVerificationForPromotedHighImpactProposals {
		return nil
	}
	if !isHighImpactMutationAction(record.Action) || strings.TrimSpace(record.PromotedFrom) == "" {
		return nil
	}
	result, err := api.buildProposalVerification(record)
	if err != nil {
		return fmt.Errorf("failed to verify promoted proposal: %w", err)
	}
	if integrityOK, _ := result["integrity_ok"].(bool); !integrityOK {
		return fmt.Errorf("promoted proposal failed integrity verification")
	}
	if sourceVerified, _ := result["source_verified"].(bool); !sourceVerified {
		return fmt.Errorf("promoted proposal source could not be verified")
	}
	if matchesSource, _ := result["matches_source"].(bool); !matchesSource {
		return fmt.Errorf("promoted proposal no longer matches its source proposal")
	}
	if policy.RequireShadowEvaluationForPromotedHighImpactProposals {
		shadowVerification, _ := result["shadow_verification"].(map[string]interface{})
		if checked, _ := shadowVerification["checked"].(bool); checked {
			if allHealthy, _ := shadowVerification["all_healthy"].(bool); !allHealthy {
				if err := api.observeProposalShadowVerification(record, result); err != nil {
					return fmt.Errorf("failed to persist proposal shadow verification: %w", err)
				}
				return fmt.Errorf("promoted proposal failed shadow evaluation")
			}
		}
	}
	if err := api.observeProposalShadowVerification(record, result); err != nil {
		return fmt.Errorf("failed to persist proposal shadow verification: %w", err)
	}
	api.markProposalShadowReady(record, result)
	if policy.MinShadowHealthyVerificationsForPromotedHighImpactProposals > 0 {
		shadowVerification, _ := result["shadow_verification"].(map[string]interface{})
		if checked, _ := shadowVerification["checked"].(bool); checked && record.ShadowVerificationPasses < policy.MinShadowHealthyVerificationsForPromotedHighImpactProposals {
			return fmt.Errorf("promoted proposal requires %d consecutive healthy shadow verifications; current streak: %d", policy.MinShadowHealthyVerificationsForPromotedHighImpactProposals, record.ShadowVerificationPasses)
		}
	}
	return nil
}

func (api *ManagementAPI) buildProposalShadowVerification(record *configProposalRecord) (map[string]interface{}, error) {
	healthyStreak := 0
	lastVerifiedAt := time.Time{}
	lastHealthy := false
	shadowReady := false
	shadowReadyAt := time.Time{}
	if record != nil {
		healthyStreak = record.ShadowVerificationPasses
		lastVerifiedAt = record.ShadowLastVerifiedAt
		lastHealthy = record.ShadowLastHealthy
		shadowReady = record.ShadowReady
		shadowReadyAt = record.ShadowReadyAt
	}
	result := map[string]interface{}{
		"checked":          false,
		"all_healthy":      true,
		"matched_routes":   []gateway.ShadowRouteEvaluation{},
		"failed_routes":    []gateway.ShadowRouteEvaluation{},
		"expected_routes":  0,
		"healthy_streak":   healthyStreak,
		"last_verified_at": lastVerifiedAt,
		"last_healthy":     lastHealthy,
		"shadow_ready":     shadowReady,
		"shadow_ready_at":  shadowReadyAt,
	}
	if record == nil || record.Config == nil {
		return result, nil
	}
	expected := proposalShadowPolicyRouteKeys(record)
	if len(expected) == 0 {
		return result, nil
	}
	result["checked"] = true
	result["expected_routes"] = len(expected)
	evaluations := api.gateway.ShadowRouteEvaluations()
	index := make(map[string]gateway.ShadowRouteEvaluation, len(evaluations))
	for _, evaluation := range evaluations {
		index[evaluation.ServiceName+"|"+evaluation.RoutePath] = evaluation
	}
	matched := make([]gateway.ShadowRouteEvaluation, 0, len(expected))
	failed := make([]gateway.ShadowRouteEvaluation, 0)
	keys := make([]string, 0, len(expected))
	for key := range expected {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		evaluation, ok := index[key]
		if !ok {
			serviceName, routePath := splitShadowRouteKey(key)
			evaluation = gateway.ShadowRouteEvaluation{
				ShadowRouteSummary: gateway.ShadowRouteSummary{
					ServiceName: serviceName,
					RoutePath:   routePath,
				},
				PolicyConfigured: true,
				Healthy:          false,
				Reasons:          []string{"shadow route evaluation is not available yet"},
			}
		}
		matched = append(matched, evaluation)
		if !evaluation.Healthy {
			failed = append(failed, evaluation)
		}
	}
	result["matched_routes"] = matched
	result["failed_routes"] = failed
	result["all_healthy"] = len(failed) == 0
	return result, nil
}

func (api *ManagementAPI) buildProposalReadiness(record *configProposalRecord) (map[string]interface{}, error) {
	if record == nil {
		return nil, fmt.Errorf("proposal is required")
	}
	now := time.Now().UTC()
	approvalCount := proposalApprovalCount(api.gateway.GetConfig(), record)
	requiredApprovals := requiredProposalApprovers(api.gateway.GetConfig(), record)
	verification, err := api.buildProposalVerification(record)
	if err != nil {
		return nil, err
	}
	blockers := make([]string, 0)
	statusEligible := record.Status == "pending" || record.Status == "approved"
	if !statusEligible {
		blockers = append(blockers, fmt.Sprintf("proposal status %q is not eligible for apply", record.Status))
	}
	if approvalCount < requiredApprovals {
		blockers = append(blockers, fmt.Sprintf("requires %d approval(s); current fresh approvals: %d", requiredApprovals, approvalCount))
	}
	recordClone := *record
	if err := api.enforceProposalExpiration(&recordClone, now); err != nil {
		blockers = append(blockers, err.Error())
	}
	recordClone = *record
	if err := api.enforceProposalFreshness(&recordClone, now); err != nil {
		blockers = append(blockers, err.Error())
	}
	notBeforeReady := record.NotBefore.IsZero() || !now.Before(record.NotBefore)
	if !notBeforeReady {
		blockers = append(blockers, fmt.Sprintf("proposal cannot be applied before %s", record.NotBefore.Format(time.RFC3339)))
	}
	blackoutBlocked := false
	if err := api.enforceProposalBlackoutWindow(record.Action, now); err != nil {
		blackoutBlocked = true
		blockers = append(blockers, err.Error())
	}
	verificationReady, verificationBlockers := api.proposalVerificationReadiness(record, verification)
	blockers = append(blockers, verificationBlockers...)
	shadowVerification, _ := verification["shadow_verification"].(map[string]interface{})
	shadowReady, _ := shadowVerification["shadow_ready"].(bool)
	return map[string]interface{}{
		"proposal_id":        record.ID,
		"status":             record.Status,
		"environment":        record.Environment,
		"promoted_from":      record.PromotedFrom,
		"ready_for_apply":    len(blockers) == 0,
		"status_eligible":    statusEligible,
		"approval_count":     approvalCount,
		"required_approvals": requiredApprovals,
		"not_before":         record.NotBefore,
		"not_before_ready":   notBeforeReady,
		"blackout_blocked":   blackoutBlocked,
		"verification_ready": verificationReady,
		"shadow_ready":       shadowReady,
		"verification":       verification,
		"blockers":           blockers,
		"evaluated_at":       now,
	}, nil
}

func (api *ManagementAPI) proposalVerificationReadiness(record *configProposalRecord, result map[string]interface{}) (bool, []string) {
	blockers := make([]string, 0)
	if record == nil {
		return false, []string{"proposal is required"}
	}
	cfg := api.gateway.GetConfig()
	if cfg == nil {
		return true, blockers
	}
	policy := cfg.Security.MutationPolicy
	if !policy.Enabled || !policy.RequireVerificationForPromotedHighImpactProposals {
		return true, blockers
	}
	if !isHighImpactMutationAction(record.Action) || strings.TrimSpace(record.PromotedFrom) == "" {
		return true, blockers
	}
	if integrityOK, _ := result["integrity_ok"].(bool); !integrityOK {
		blockers = append(blockers, "promoted proposal failed integrity verification")
	}
	if sourceVerified, _ := result["source_verified"].(bool); !sourceVerified {
		blockers = append(blockers, "promoted proposal source could not be verified")
	}
	if matchesSource, _ := result["matches_source"].(bool); !matchesSource {
		blockers = append(blockers, "promoted proposal no longer matches its source proposal")
	}
	shadowVerification, _ := result["shadow_verification"].(map[string]interface{})
	if policy.RequireShadowEvaluationForPromotedHighImpactProposals {
		if checked, _ := shadowVerification["checked"].(bool); checked {
			if allHealthy, _ := shadowVerification["all_healthy"].(bool); !allHealthy {
				blockers = append(blockers, "promoted proposal failed shadow evaluation")
			}
		}
	}
	if policy.MinShadowHealthyVerificationsForPromotedHighImpactProposals > 0 {
		if checked, _ := shadowVerification["checked"].(bool); checked && record.ShadowVerificationPasses < policy.MinShadowHealthyVerificationsForPromotedHighImpactProposals {
			blockers = append(blockers, fmt.Sprintf("promoted proposal requires %d consecutive healthy shadow verifications; current streak: %d", policy.MinShadowHealthyVerificationsForPromotedHighImpactProposals, record.ShadowVerificationPasses))
		}
	}
	return len(blockers) == 0, blockers
}

func (api *ManagementAPI) observeProposalShadowVerification(record *configProposalRecord, result map[string]interface{}) error {
	if record == nil {
		return nil
	}
	shadowVerification, _ := result["shadow_verification"].(map[string]interface{})
	if len(shadowVerification) == 0 {
		return nil
	}
	checked, _ := shadowVerification["checked"].(bool)
	if !checked {
		return nil
	}
	allHealthy, _ := shadowVerification["all_healthy"].(bool)
	record.ShadowLastVerifiedAt = time.Now().UTC()
	record.ShadowLastHealthy = allHealthy
	if allHealthy {
		record.ShadowVerificationPasses++
	} else {
		record.ShadowVerificationPasses = 0
	}
	shadowVerification["healthy_streak"] = record.ShadowVerificationPasses
	shadowVerification["last_verified_at"] = record.ShadowLastVerifiedAt
	shadowVerification["last_healthy"] = record.ShadowLastHealthy
	shadowVerification["shadow_ready"] = record.ShadowReady
	shadowVerification["shadow_ready_at"] = record.ShadowReadyAt
	return saveConfigProposalRecord(record)
}

func (api *ManagementAPI) markProposalShadowReady(record *configProposalRecord, result map[string]interface{}) {
	if record == nil {
		return
	}
	shadowVerification, _ := result["shadow_verification"].(map[string]interface{})
	if len(shadowVerification) == 0 {
		return
	}
	checked, _ := shadowVerification["checked"].(bool)
	if !checked {
		return
	}
	cfg := api.gateway.GetConfig()
	if cfg == nil {
		return
	}
	required := cfg.Security.MutationPolicy.MinShadowHealthyVerificationsForPromotedHighImpactProposals
	if required <= 0 {
		required = 1
	}
	allHealthy, _ := shadowVerification["all_healthy"].(bool)
	readyNow := allHealthy && record.ShadowVerificationPasses >= required
	if readyNow && !record.ShadowReady {
		record.ShadowReady = true
		record.ShadowReadyAt = time.Now().UTC()
		shadowVerification["shadow_ready"] = true
		shadowVerification["shadow_ready_at"] = record.ShadowReadyAt
		if err := saveConfigProposalRecord(record); err == nil {
			api.emitProposalEvent("proposal.shadow_ready", record, map[string]interface{}{
				"healthy_streak":  record.ShadowVerificationPasses,
				"required_streak": required,
				"shadow_ready_at": record.ShadowReadyAt,
			})
		}
		return
	}
	if !readyNow && record.ShadowReady {
		record.ShadowReady = false
		record.ShadowReadyAt = time.Time{}
		shadowVerification["shadow_ready"] = false
		shadowVerification["shadow_ready_at"] = record.ShadowReadyAt
		_ = saveConfigProposalRecord(record)
	}
}

func proposalShadowPolicyRouteKeys(record *configProposalRecord) map[string]struct{} {
	keys := make(map[string]struct{})
	if record == nil || record.Config == nil {
		return keys
	}
	planServices := normalizeQueryList(record.CanaryServices)
	planRoutes := normalizeQueryList(record.CanaryRoutes)
	for _, svc := range flattenServices(record.Config) {
		serviceSelected := serviceSelectedForCanary(svc, planServices, planRoutes)
		serviceOnly := serviceSelectedOnlyByName(svc, planServices, planRoutes)
		for _, route := range svc.Routes {
			if !proposalShadowPolicyConfigured(route) {
				continue
			}
			if len(planServices) > 0 || len(planRoutes) > 0 {
				if !serviceSelected {
					continue
				}
				if !serviceOnly && !routeSelectedForCanary(svc, route, planRoutes) {
					continue
				}
			}
			keys[displayServiceName(svc)+"|"+route.Path] = struct{}{}
		}
	}
	return keys
}

func proposalShadowPolicyConfigured(route config.RouterConfig) bool {
	return route.ShadowMinRequests > 0 || route.ShadowMaxErrorRate > 0 || strings.TrimSpace(route.ShadowMaxLatencyDelta) != ""
}

func splitShadowRouteKey(key string) (string, string) {
	parts := strings.SplitN(key, "|", 2)
	if len(parts) != 2 {
		return key, ""
	}
	return parts[0], parts[1]
}

func (api *ManagementAPI) enforceProposalCanaryEvaluation(record *configProposalRecord) error {
	if record == nil || !hasCanaryMetricThresholds(record) {
		return nil
	}
	evaluation, err := api.buildProposalCanaryEvaluation(record)
	if err != nil {
		return fmt.Errorf("failed to evaluate canary metrics: %w", err)
	}
	if healthy, _ := evaluation["healthy"].(bool); healthy {
		return nil
	}
	reasons, _ := evaluation["reasons"].([]string)
	if len(reasons) == 0 {
		if values, ok := evaluation["reasons"].([]interface{}); ok {
			for _, value := range values {
				if text := strings.TrimSpace(fmt.Sprint(value)); text != "" {
					reasons = append(reasons, text)
				}
			}
		}
	}
	if len(reasons) == 0 {
		return fmt.Errorf("canary rollout failed configured metric thresholds")
	}
	return fmt.Errorf("canary rollout failed configured metric thresholds: %s", strings.Join(reasons, "; "))
}

func (api *ManagementAPI) writeProposalCanaryRollbackOrError(w http.ResponseWriter, record *configProposalRecord, reviewer, reviewNote string, evalErr error) {
	revisionID, rollbackErr := api.rollbackProposalCanary(record, reviewer, reviewNote, evalErr.Error())
	if rollbackErr != nil {
		api.writeError(w, fmt.Sprintf("%s; automatic rollback also failed: %v", evalErr.Error(), rollbackErr), http.StatusConflict)
		return
	}
	api.writeJSON(w, APIResponse{
		Success: false,
		Message: "Canary guard failed and rollback was applied",
		Data: map[string]interface{}{
			"proposal_id":     record.ID,
			"status":          record.Status,
			"revision_id":     revisionID,
			"rollback":        true,
			"rollback_reason": evalErr.Error(),
		},
	})
}

func canaryEvaluationReasons(evaluation map[string]interface{}) string {
	reasons, _ := evaluation["reasons"].([]string)
	if len(reasons) == 0 {
		if values, ok := evaluation["reasons"].([]interface{}); ok {
			for _, value := range values {
				if text := strings.TrimSpace(fmt.Sprint(value)); text != "" {
					reasons = append(reasons, text)
				}
			}
		}
	}
	if len(reasons) == 0 {
		return "canary rollout failed configured metric thresholds"
	}
	return strings.Join(reasons, "; ")
}

func (api *ManagementAPI) rollbackProposalCanary(record *configProposalRecord, reviewer, reviewNote, reason string) (string, error) {
	if record == nil || record.CanaryBaselineConfig == nil {
		return "", fmt.Errorf("canary baseline configuration is not available for rollback")
	}
	summary := map[string]interface{}{
		"canary_rollback": true,
		"proposal_id":     record.ID,
		"reason":          strings.TrimSpace(reason),
	}
	if err := api.applyManagedConfigChange(record.CanaryBaselineConfig, "rollback_canary", "canary-rollback", reason, record.ChangeRef, summary); err != nil {
		return "", err
	}
	record.Status = "canary_aborted"
	record.ReviewedAt = time.Now().UTC()
	record.ReviewedBy = reviewer
	record.ReviewNote = reviewNote
	record.CanaryNextReconcile = time.Time{}
	revisions, err := listConfigRevisions()
	if err == nil && len(revisions) > 0 {
		if latest, ok := revisions[0]["id"].(string); ok {
			record.RevisionID = latest
		}
	}
	if err := saveConfigProposalRecord(record); err != nil {
		api.logger.Warn("Canary rollback applied but failed to update proposal record", logging.Error(err))
	}
	api.emitProposalEvent("proposal.canary_aborted", record, map[string]interface{}{
		"revision_id":     record.RevisionID,
		"rollback_reason": strings.TrimSpace(reason),
	})
	return record.RevisionID, nil
}

func hasCanaryMetricThresholds(record *configProposalRecord) bool {
	if record == nil {
		return false
	}
	return record.CanaryMinRequests > 0 || record.CanaryMaxErrorRate > 0 || strings.TrimSpace(record.CanaryMaxP95Latency) != ""
}

func proposalCanaryAutoInterval(record *configProposalRecord) time.Duration {
	if record == nil || !record.CanaryAutoReconcile {
		return 0
	}
	value := strings.TrimSpace(record.CanaryAutoInterval)
	if value == "" {
		return defaultProposalCanaryAutoReconcileInterval
	}
	interval, err := time.ParseDuration(value)
	if err != nil || interval <= 0 {
		return defaultProposalCanaryAutoReconcileInterval
	}
	return interval
}

func proposalCanaryAutoReviewer(record *configProposalRecord) string {
	if record == nil {
		return ""
	}
	if reviewer := strings.TrimSpace(record.CanaryAutoReviewer); reviewer != "" {
		return reviewer
	}
	if reviewer := strings.TrimSpace(record.ReviewedBy); reviewer != "" {
		return reviewer
	}
	if reviewer := strings.TrimSpace(record.CreatedBy); reviewer != "" {
		return reviewer
	}
	return "canary-controller"
}

func scheduleNextProposalCanaryReconcile(record *configProposalRecord, now time.Time) {
	if record == nil {
		return
	}
	record.CanaryLastReconciled = now
	if record.Status == "canary_active" && record.CanaryAutoReconcile {
		record.CanaryNextReconcile = now.Add(proposalCanaryAutoInterval(record))
		return
	}
	record.CanaryNextReconcile = time.Time{}
}

func (api *ManagementAPI) autoReconcileCanaries() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		api.reconcileAutoCanaries(time.Now().UTC())
	}
}

func (api *ManagementAPI) autoNotifyProposalQueueDigests() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		api.reconcileProposalQueueDigestNotifications(time.Now().UTC())
	}
}

func (api *ManagementAPI) autoNotifyGatewayPolicyAlerts() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		api.reconcileGatewayPolicyAlertNotifications(time.Now().UTC())
	}
}

func (api *ManagementAPI) reconcileAutoCanaries(now time.Time) {
	proposals, err := listConfigProposals()
	if err != nil {
		return
	}
	for _, proposal := range proposals {
		id, _ := proposal["id"].(string)
		if strings.TrimSpace(id) == "" {
			continue
		}
		record, err := loadConfigProposal(id)
		if err != nil || record == nil {
			continue
		}
		if record.Status != "canary_active" || !record.CanaryAutoReconcile {
			continue
		}
		if !record.CanaryNextReconcile.IsZero() && now.Before(record.CanaryNextReconcile) {
			continue
		}
		reviewer := proposalCanaryAutoReviewer(record)
		data, err := api.performProposalCanaryReconcile(record, reviewer, "Automatic canary reconcile", record.Label, record.Note, record.ChangeRef, now)
		if err != nil {
			api.logger.Warn("Automatic canary reconcile failed",
				logging.String("proposal_id", record.ID),
				logging.String("reviewer", reviewer),
				logging.Error(err))
			continue
		}
		actionTaken := ""
		if payload, ok := data["data"].(map[string]interface{}); ok {
			actionTaken = strings.TrimSpace(fmt.Sprint(payload["action_taken"]))
		}
		api.logger.Info("Automatic canary reconcile completed",
			logging.String("proposal_id", record.ID),
			logging.String("reviewer", reviewer),
			logging.String("status", record.Status),
			logging.String("action_taken", actionTaken))
	}
}

func configChangeSummary(currentCfg, nextCfg *config.Config) map[string]interface{} {
	currentMap := make(map[string]interface{})
	nextMap := make(map[string]interface{})
	if data, err := json.Marshal(currentCfg); err == nil {
		_ = json.Unmarshal(data, &currentMap)
	}
	if data, err := json.Marshal(nextCfg); err == nil {
		_ = json.Unmarshal(data, &nextMap)
	}

	paths := collectChangedPaths("", currentMap, nextMap)
	topSections := make([]string, 0)
	seen := make(map[string]struct{})
	for _, path := range paths {
		section := path
		if idx := strings.Index(section, "."); idx >= 0 {
			section = section[:idx]
		}
		if _, ok := seen[section]; ok {
			continue
		}
		seen[section] = struct{}{}
		topSections = append(topSections, section)
	}
	sort.Strings(topSections)

	return map[string]interface{}{
		"changed_count":    len(paths),
		"changed_fields":   paths,
		"changed_sections": topSections,
	}
}

func collectChangedPaths(prefix string, current, next interface{}) []string {
	if reflect.DeepEqual(current, next) {
		return nil
	}

	currentMap, currentOK := current.(map[string]interface{})
	nextMap, nextOK := next.(map[string]interface{})
	if currentOK && nextOK {
		keys := make([]string, 0, len(currentMap)+len(nextMap))
		seen := make(map[string]struct{}, len(currentMap)+len(nextMap))
		for key := range currentMap {
			seen[key] = struct{}{}
			keys = append(keys, key)
		}
		for key := range nextMap {
			if _, ok := seen[key]; ok {
				continue
			}
			keys = append(keys, key)
		}
		sort.Strings(keys)

		paths := make([]string, 0)
		for _, key := range keys {
			normalizedKey := normalizeDiffKey(key)
			childPrefix := normalizedKey
			if prefix != "" {
				childPrefix = prefix + "." + normalizedKey
			}
			paths = append(paths, collectChangedPaths(childPrefix, currentMap[key], nextMap[key])...)
		}
		return paths
	}

	if prefix == "" {
		return []string{"<root>"}
	}
	return []string{prefix}
}

func normalizeDiffKey(key string) string {
	if key == "" {
		return key
	}
	return strings.ToLower(key[:1]) + key[1:]
}

func serviceChangeSummary(currentCfg, nextCfg *config.Config) map[string]interface{} {
	currentServices := flattenServices(currentCfg)
	nextServices := flattenServices(nextCfg)

	addedServices := make([]string, 0)
	removedServices := make([]string, 0)
	updatedServices := make([]string, 0)
	addedRoutes := make([]map[string]interface{}, 0)
	removedRoutes := make([]map[string]interface{}, 0)
	updatedRoutes := make([]map[string]interface{}, 0)

	currentIndex := make(map[string]config.Service, len(currentServices))
	nextIndex := make(map[string]config.Service, len(nextServices))
	for _, svc := range currentServices {
		currentIndex[serviceIdentity(svc)] = svc
	}
	for _, svc := range nextServices {
		nextIndex[serviceIdentity(svc)] = svc
	}

	for key, nextSvc := range nextIndex {
		currentSvc, exists := currentIndex[key]
		if !exists {
			addedServices = append(addedServices, displayServiceName(nextSvc))
			for _, route := range nextSvc.Routes {
				addedRoutes = append(addedRoutes, routeSummary(nextSvc, route))
			}
			continue
		}

		if serviceMetaChanged(currentSvc, nextSvc) {
			updatedServices = append(updatedServices, displayServiceName(nextSvc))
		}

		currentRoutes := routeSummaryIndex(currentSvc)
		nextRoutes := routeSummaryIndex(nextSvc)
		for routeKey, nextRoute := range nextRoutes {
			currentRoute, routeExists := currentRoutes[routeKey]
			if !routeExists {
				addedRoutes = append(addedRoutes, routeSummary(nextSvc, nextRoute))
				continue
			}
			if !reflect.DeepEqual(currentRoute, nextRoute) {
				updatedRoutes = append(updatedRoutes, routeSummary(nextSvc, nextRoute))
			}
		}
		for routeKey, currentRoute := range currentRoutes {
			if _, routeExists := nextRoutes[routeKey]; !routeExists {
				removedRoutes = append(removedRoutes, routeSummary(currentSvc, currentRoute))
			}
		}
	}

	for key, currentSvc := range currentIndex {
		if _, exists := nextIndex[key]; exists {
			continue
		}
		removedServices = append(removedServices, displayServiceName(currentSvc))
		for _, route := range currentSvc.Routes {
			removedRoutes = append(removedRoutes, routeSummary(currentSvc, route))
		}
	}

	sort.Strings(addedServices)
	sort.Strings(removedServices)
	sort.Strings(updatedServices)
	sortRouteSummaries(addedRoutes)
	sortRouteSummaries(removedRoutes)
	sortRouteSummaries(updatedRoutes)

	return map[string]interface{}{
		"added_services":   addedServices,
		"removed_services": removedServices,
		"updated_services": updatedServices,
		"added_routes":     addedRoutes,
		"removed_routes":   removedRoutes,
		"updated_routes":   updatedRoutes,
	}
}

func hasProposalCanaryPlan(record *configProposalRecord) bool {
	return record != nil && (len(record.CanaryServices) > 0 || len(record.CanaryRoutes) > 0)
}

func proposalApplyMessage(record *configProposalRecord) string {
	if record != nil && record.Status == "canary_active" {
		return "Proposal canary rollout started successfully"
	}
	return "Proposal applied successfully"
}

func (api *ManagementAPI) describeProposalCanaryPlan(record *configProposalRecord) (map[string]interface{}, error) {
	if record == nil || record.Config == nil {
		return nil, fmt.Errorf("proposal has no stored configuration")
	}
	if !hasProposalCanaryPlan(record) {
		return map[string]interface{}{
			"matched_services": nil,
			"matched_routes":   nil,
		}, nil
	}

	matchedServices := make([]string, 0)
	matchedRoutes := make([]string, 0)
	for _, svcCfg := range record.Config.Services {
		for _, svc := range svcCfg.Services {
			if serviceSelectedForCanary(svc, record.CanaryServices, record.CanaryRoutes) {
				matchedServices = appendUniqueString(matchedServices, strings.TrimSpace(svc.Name))
			}
			for _, route := range svc.Routes {
				if routeSelectedForCanary(svc, route, record.CanaryRoutes) {
					matchedRoutes = appendUniqueString(matchedRoutes, fmt.Sprintf("%s:%s", strings.TrimSpace(svc.Name), strings.TrimSpace(route.Path)))
				}
			}
		}
	}
	return map[string]interface{}{
		"matched_services": matchedServices,
		"matched_routes":   matchedRoutes,
	}, nil
}

func (api *ManagementAPI) buildCanaryApplyConfig(record *configProposalRecord) (*config.Config, map[string]interface{}, error) {
	if record == nil || record.Config == nil {
		return nil, nil, fmt.Errorf("proposal has no stored configuration")
	}
	if !strings.HasPrefix(record.Action, "services_") {
		return nil, nil, fmt.Errorf("canary apply is currently supported only for service proposals")
	}
	if len(record.CanaryHeaders) > 0 {
		return api.buildHeaderScopedCanaryApplyConfig(record)
	}
	if record.CanaryPercent > 0 {
		return api.buildPercentageScopedCanaryApplyConfig(record)
	}
	current := api.gateway.GetConfig()
	if current == nil {
		return nil, nil, fmt.Errorf("current gateway configuration is not available")
	}
	nextCfg, err := cloneConfig(current)
	if err != nil {
		return nil, nil, err
	}
	planServices := make([]string, 0)
	planRoutes := make([]string, 0)
	for _, selector := range record.CanaryServices {
		selector = strings.TrimSpace(selector)
		if selector != "" {
			planServices = append(planServices, selector)
		}
	}
	for _, selector := range record.CanaryRoutes {
		selector = strings.TrimSpace(selector)
		if selector != "" {
			planRoutes = append(planRoutes, selector)
		}
	}
	changedServices := make([]string, 0)
	changedRoutes := make([]map[string]interface{}, 0)

	for _, proposalSvc := range flattenServices(record.Config) {
		if !serviceSelectedForCanary(proposalSvc, planServices, planRoutes) {
			continue
		}
		changed, routes := applyCanaryServiceToConfig(nextCfg, proposalSvc, planServices, planRoutes)
		if changed {
			changedServices = append(changedServices, displayServiceName(proposalSvc))
		}
		changedRoutes = append(changedRoutes, routes...)
	}
	if len(changedServices) == 0 && len(changedRoutes) == 0 {
		return nil, nil, fmt.Errorf("canary plan did not match any services or routes in the proposal")
	}
	sort.Strings(changedServices)
	sortRouteSummaries(changedRoutes)
	summary := serviceChangeSummary(current, nextCfg)
	summary["canary"] = true
	summary["canary_services"] = planServices
	summary["canary_routes"] = planRoutes
	summary["canary_headers"] = record.CanaryHeaders
	summary["canary_changed_services"] = changedServices
	summary["canary_changed_routes"] = changedRoutes
	return nextCfg, summary, nil
}

func (api *ManagementAPI) buildHeaderScopedCanaryApplyConfig(record *configProposalRecord) (*config.Config, map[string]interface{}, error) {
	current := api.gateway.GetConfig()
	if current == nil {
		return nil, nil, fmt.Errorf("current gateway configuration is not available")
	}
	nextCfg, err := cloneConfig(current)
	if err != nil {
		return nil, nil, err
	}
	headerMatchers := parseCanaryHeaderMatchers(record.CanaryHeaders)
	if len(headerMatchers) == 0 {
		return nil, nil, fmt.Errorf("canary headers are required for header-scoped canary rollout")
	}

	planServices := normalizeQueryList(record.CanaryServices)
	planRoutes := normalizeQueryList(record.CanaryRoutes)
	changedServices := make([]string, 0)
	changedRoutes := make([]map[string]interface{}, 0)

	for _, proposalSvc := range flattenServices(record.Config) {
		if !serviceSelectedForCanary(proposalSvc, planServices, planRoutes) {
			continue
		}
		canarySvc, routes := buildHeaderScopedCanaryService(proposalSvc, planServices, planRoutes, headerMatchers)
		if len(canarySvc.Routes) == 0 {
			continue
		}
		replaceOrAppendService(nextCfg, canarySvc)
		changedServices = appendUniqueString(changedServices, displayServiceName(proposalSvc))
		changedRoutes = append(changedRoutes, routes...)
	}
	if len(changedServices) == 0 && len(changedRoutes) == 0 {
		return nil, nil, fmt.Errorf("canary plan did not match any services or routes in the proposal")
	}
	sort.Strings(changedServices)
	sortRouteSummaries(changedRoutes)
	summary := serviceChangeSummary(current, nextCfg)
	summary["canary"] = true
	summary["canary_strategy"] = "header_scoped"
	summary["canary_services"] = planServices
	summary["canary_routes"] = planRoutes
	summary["canary_headers"] = record.CanaryHeaders
	summary["canary_changed_services"] = changedServices
	summary["canary_changed_routes"] = changedRoutes
	return nextCfg, summary, nil
}

func (api *ManagementAPI) buildPercentageScopedCanaryApplyConfig(record *configProposalRecord) (*config.Config, map[string]interface{}, error) {
	current := api.gateway.GetConfig()
	if current == nil {
		return nil, nil, fmt.Errorf("current gateway configuration is not available")
	}
	nextCfg, err := cloneConfig(current)
	if err != nil {
		return nil, nil, err
	}
	planServices := normalizeQueryList(record.CanaryServices)
	planRoutes := normalizeQueryList(record.CanaryRoutes)
	changedServices := make([]string, 0)
	changedRoutes := make([]map[string]interface{}, 0)

	for _, proposalSvc := range flattenServices(record.Config) {
		if !serviceSelectedForCanary(proposalSvc, planServices, planRoutes) {
			continue
		}
		canarySvc, routes := buildPercentageScopedCanaryService(proposalSvc, planServices, planRoutes, record.CanaryPercent)
		if len(canarySvc.Routes) == 0 {
			continue
		}
		replaceOrAppendService(nextCfg, canarySvc)
		changedServices = appendUniqueString(changedServices, displayServiceName(proposalSvc))
		changedRoutes = append(changedRoutes, routes...)
	}
	if len(changedServices) == 0 && len(changedRoutes) == 0 {
		return nil, nil, fmt.Errorf("canary plan did not match any services or routes in the proposal")
	}
	sort.Strings(changedServices)
	sortRouteSummaries(changedRoutes)
	summary := serviceChangeSummary(current, nextCfg)
	summary["canary"] = true
	summary["canary_strategy"] = "percentage"
	summary["canary_services"] = planServices
	summary["canary_routes"] = planRoutes
	summary["canary_percent"] = record.CanaryPercent
	summary["canary_changed_services"] = changedServices
	summary["canary_changed_routes"] = changedRoutes
	return nextCfg, summary, nil
}

func applyCanaryServiceToConfig(cfg *config.Config, proposalSvc config.Service, canaryServices, canaryRoutes []string) (bool, []map[string]interface{}) {
	if cfg == nil {
		return false, nil
	}
	if len(cfg.Services) == 0 {
		cfg.Services = []config.ServiceConfig{{Version: 1}}
	}
	serviceIdx, existingSvc := findServiceForCanary(cfg, proposalSvc)
	targetSvc := existingSvc
	changedRoutes := make([]map[string]interface{}, 0)
	changed := false

	serviceOnly := serviceSelectedOnlyByName(proposalSvc, canaryServices, canaryRoutes)
	if serviceOnly {
		targetSvc = proposalSvc
		changed = true
		for _, route := range proposalSvc.Routes {
			changedRoutes = append(changedRoutes, routeSummary(proposalSvc, route))
		}
	} else {
		for _, proposalRoute := range proposalSvc.Routes {
			if !routeSelectedForCanary(proposalSvc, proposalRoute, canaryRoutes) {
				continue
			}
			targetSvc, changed = mergeCanaryRoute(targetSvc, proposalSvc, proposalRoute, changed)
			changedRoutes = append(changedRoutes, routeSummary(proposalSvc, proposalRoute))
		}
	}
	if !changed {
		return false, nil
	}
	if serviceIdx >= 0 {
		cfg.Services[0].Services[serviceIdx] = targetSvc
	} else {
		cfg.Services[0].Services = append(cfg.Services[0].Services, targetSvc)
	}
	return true, changedRoutes
}

func buildHeaderScopedCanaryService(proposalSvc config.Service, canaryServices, canaryRoutes []string, headerMatchers map[string]string) (config.Service, []map[string]interface{}) {
	canarySvc := proposalSvc
	canarySvc.Name = canaryServiceName(displayServiceName(proposalSvc))
	canarySvc.Routes = nil
	changedRoutes := make([]map[string]interface{}, 0)

	serviceOnly := serviceSelectedOnlyByName(proposalSvc, canaryServices, canaryRoutes)
	for _, proposalRoute := range proposalSvc.Routes {
		if !serviceOnly && !routeSelectedForCanary(proposalSvc, proposalRoute, canaryRoutes) {
			continue
		}
		clonedRoute := proposalRoute
		clonedRoute.MatchHeaders = cloneHeaderMap(headerMatchers)
		canarySvc.Routes = append(canarySvc.Routes, clonedRoute)
		changedRoutes = append(changedRoutes, routeSummary(proposalSvc, clonedRoute))
	}
	return canarySvc, changedRoutes
}

func buildPercentageScopedCanaryService(proposalSvc config.Service, canaryServices, canaryRoutes []string, percent int) (config.Service, []map[string]interface{}) {
	canarySvc := proposalSvc
	canarySvc.Name = canaryServiceName(displayServiceName(proposalSvc))
	canarySvc.Routes = nil
	changedRoutes := make([]map[string]interface{}, 0)

	serviceOnly := serviceSelectedOnlyByName(proposalSvc, canaryServices, canaryRoutes)
	for _, proposalRoute := range proposalSvc.Routes {
		if !serviceOnly && !routeSelectedForCanary(proposalSvc, proposalRoute, canaryRoutes) {
			continue
		}
		clonedRoute := proposalRoute
		clonedRoute.MatchPercent = percent
		canarySvc.Routes = append(canarySvc.Routes, clonedRoute)
		changedRoutes = append(changedRoutes, routeSummary(proposalSvc, clonedRoute))
	}
	return canarySvc, changedRoutes
}

func replaceOrAppendService(cfg *config.Config, svc config.Service) {
	if cfg == nil {
		return
	}
	if len(cfg.Services) == 0 {
		cfg.Services = []config.ServiceConfig{{Version: 1}}
	}
	for i := range cfg.Services {
		for j := range cfg.Services[i].Services {
			if strings.EqualFold(strings.TrimSpace(cfg.Services[i].Services[j].Name), strings.TrimSpace(svc.Name)) {
				cfg.Services[i].Services[j] = svc
				return
			}
		}
	}
	cfg.Services[0].Services = append(cfg.Services[0].Services, svc)
}

func canaryServiceName(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return "canary"
	}
	return name + "__canary"
}

func parseCanaryHeaderMatchers(values []string) map[string]string {
	out := make(map[string]string)
	for _, value := range values {
		parts := strings.SplitN(strings.TrimSpace(value), "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])
		if key == "" || val == "" {
			continue
		}
		out[key] = val
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func cloneHeaderMap(src map[string]string) map[string]string {
	if len(src) == 0 {
		return nil
	}
	dst := make(map[string]string, len(src))
	for key, value := range src {
		dst[key] = value
	}
	return dst
}

func findServiceForCanary(cfg *config.Config, proposalSvc config.Service) (int, config.Service) {
	for i, svc := range cfg.Services[0].Services {
		if serviceIdentity(svc) == serviceIdentity(proposalSvc) {
			return i, svc
		}
	}
	return -1, config.Service{
		Name:        proposalSvc.Name,
		Description: proposalSvc.Description,
		Host:        proposalSvc.Host,
		BasePath:    proposalSvc.BasePath,
		Tags:        append([]string(nil), proposalSvc.Tags...),
		Group:       proposalSvc.Group,
		Scopes:      append([]string(nil), proposalSvc.Scopes...),
	}
}

func serviceSelectedForCanary(svc config.Service, canaryServices, canaryRoutes []string) bool {
	return serviceSelectedOnlyByName(svc, canaryServices, canaryRoutes) || serviceHasSelectedCanaryRoute(svc, canaryRoutes)
}

func serviceSelectedOnlyByName(svc config.Service, canaryServices, canaryRoutes []string) bool {
	if len(canaryServices) == 0 {
		return false
	}
	if len(canaryRoutes) > 0 {
		return false
	}
	for _, selector := range canaryServices {
		if strings.EqualFold(strings.TrimSpace(selector), displayServiceName(svc)) {
			return true
		}
	}
	return false
}

func serviceHasSelectedCanaryRoute(svc config.Service, canaryRoutes []string) bool {
	for _, route := range svc.Routes {
		if routeSelectedForCanary(svc, route, canaryRoutes) {
			return true
		}
	}
	return false
}

func routeSelectedForCanary(svc config.Service, route config.RouterConfig, selectors []string) bool {
	if len(selectors) == 0 {
		return false
	}
	serviceName := displayServiceName(svc)
	effectivePath := svc.EffectiveRoutePath(route)
	for _, selector := range selectors {
		serviceSelector, pathSelector := parseCanaryRouteSelector(selector)
		if pathSelector == "" {
			continue
		}
		if serviceSelector != "" && !strings.EqualFold(serviceSelector, serviceName) {
			continue
		}
		if pathSelector == route.Path || pathSelector == effectivePath {
			return true
		}
	}
	return false
}

func parseCanaryRouteSelector(selector string) (string, string) {
	selector = strings.TrimSpace(selector)
	if selector == "" {
		return "", ""
	}
	if strings.HasPrefix(selector, "/") {
		return "", selector
	}
	if idx := strings.Index(selector, ":/"); idx > 0 {
		return strings.TrimSpace(selector[:idx]), strings.TrimSpace(selector[idx+1:])
	}
	return "", selector
}

func mergeCanaryRoute(targetSvc, proposalSvc config.Service, proposalRoute config.RouterConfig, alreadyChanged bool) (config.Service, bool) {
	targetSvc.Name = proposalSvc.Name
	targetSvc.Description = proposalSvc.Description
	targetSvc.Host = proposalSvc.Host
	targetSvc.BasePath = proposalSvc.BasePath
	targetSvc.Tags = append([]string(nil), proposalSvc.Tags...)
	targetSvc.Group = proposalSvc.Group
	targetSvc.Scopes = append([]string(nil), proposalSvc.Scopes...)
	if len(targetSvc.Routes) == 0 {
		targetSvc.Routes = []config.RouterConfig{}
	}
	routeID := stableRouteID(displayServiceName(proposalSvc), proposalSvc.EffectiveRoutePath(proposalRoute), proposalRoute.EffectiveMethods())
	for i, existing := range targetSvc.Routes {
		existingID := stableRouteID(displayServiceName(targetSvc), targetSvc.EffectiveRoutePath(existing), existing.EffectiveMethods())
		if existingID == routeID {
			targetSvc.Routes[i] = proposalRoute
			return targetSvc, true
		}
	}
	targetSvc.Routes = append(targetSvc.Routes, proposalRoute)
	return targetSvc, true || alreadyChanged
}

func flattenServices(cfg *config.Config) []config.Service {
	if cfg == nil {
		return nil
	}
	services := make([]config.Service, 0)
	for _, svcCfg := range cfg.Services {
		services = append(services, svcCfg.Services...)
	}
	return services
}

func serviceIdentity(svc config.Service) string {
	if strings.TrimSpace(svc.Name) != "" {
		return "name:" + strings.TrimSpace(svc.Name)
	}
	return "host:" + strings.TrimSpace(svc.Host)
}

func displayServiceName(svc config.Service) string {
	if strings.TrimSpace(svc.Name) != "" {
		return strings.TrimSpace(svc.Name)
	}
	return strings.TrimSpace(svc.Host)
}

func serviceMetaChanged(current, next config.Service) bool {
	return current.Name != next.Name ||
		current.Description != next.Description ||
		current.Host != next.Host ||
		current.BasePath != next.BasePath ||
		!reflect.DeepEqual(current.Tags, next.Tags) ||
		current.Group != next.Group ||
		!reflect.DeepEqual(current.Scopes, next.Scopes)
}

func routeSummaryIndex(svc config.Service) map[string]config.RouterConfig {
	index := make(map[string]config.RouterConfig, len(svc.Routes))
	for _, route := range svc.Routes {
		index[stableRouteID(displayServiceName(svc), svc.EffectiveRoutePath(route), route.EffectiveMethods())] = route
	}
	return index
}

func routeSummary(svc config.Service, route config.RouterConfig) map[string]interface{} {
	return map[string]interface{}{
		"service": svc.Name,
		"path":    svc.EffectiveRoutePath(route),
		"method":  route.Method,
		"methods": route.EffectiveMethods(),
	}
}

func routeConfigSummary(svc config.Service, route config.RouterConfig) map[string]interface{} {
	return map[string]interface{}{
		"service":       svc.Name,
		"path":          route.Path,
		"effectivePath": svc.EffectiveRoutePath(route),
		"methods":       route.EffectiveMethods(),
		"enabled":       route.IsEnabled(),
		"stripPath":     route.StripPath,
		"requireAuth":   route.RequireAuth,
		"requireJwt":    route.RequireJwt,
		"backend":       route.Backends,
	}
}

func sortRouteSummaries(items []map[string]interface{}) {
	sort.SliceStable(items, func(i, j int) bool {
		left := fmt.Sprintf("%v|%v|%v", items[i]["service"], items[i]["path"], items[i]["methods"])
		right := fmt.Sprintf("%v|%v|%v", items[j]["service"], items[j]["path"], items[j]["methods"])
		return left < right
	})
}

func routeChangeSummary(current *config.RouterConfig, next *config.RouterConfig, svc config.Service) map[string]interface{} {
	summary := routeConfigSummary(svc, *next)
	if current == nil {
		summary["action"] = "create"
		return summary
	}

	currentMap := make(map[string]interface{})
	nextMap := make(map[string]interface{})
	if data, err := json.Marshal(current); err == nil {
		_ = json.Unmarshal(data, &currentMap)
	}
	if data, err := json.Marshal(next); err == nil {
		_ = json.Unmarshal(data, &nextMap)
	}

	summary["action"] = "update"
	summary["changed_fields"] = collectChangedPaths("", currentMap, nextMap)
	return summary
}

func (api *ManagementAPI) routeRecords(cfg *config.Config) []routeRecord {
	if cfg == nil {
		return nil
	}
	records := make([]routeRecord, 0)
	for sci, svcCfg := range cfg.Services {
		for si, svc := range svcCfg.Services {
			for ri, route := range svc.Routes {
				records = append(records, routeRecord{
					ID:                 stableRouteID(svc.Name, svc.EffectiveRoutePath(route), route.EffectiveMethods()),
					ServiceConfigIndex: sci,
					ServiceIndex:       si,
					RouteIndex:         ri,
					Service:            svc,
					Route:              route,
					EffectivePath:      svc.EffectiveRoutePath(route),
				})
			}
		}
	}
	return records
}

func (api *ManagementAPI) routeInfoFromRecord(record routeRecord) RouteInfo {
	timeout := 0
	if record.Route.Timeout != nil {
		timeout = int(record.Route.Timeout.Seconds())
	}
	return RouteInfo{
		ID:          record.ID,
		Path:        record.EffectivePath,
		Destination: record.Service.Host,
		Methods:     record.Route.EffectiveMethods(),
		RequireAuth: record.Route.RequireAuth,
		Timeout:     timeout,
		StripPath:   record.Route.StripPath,
		Enabled:     record.Route.IsEnabled(),
		Stats: map[string]interface{}{
			"requests": len(api.logger.RecentLogs(500, "")),
			"errors":   len(api.logger.RecentLogs(500, "error")),
		},
	}
}

func stableRouteID(serviceName, effectivePath string, methods []string) string {
	normalizedMethods := make([]string, len(methods))
	copy(normalizedMethods, methods)
	for i := range normalizedMethods {
		normalizedMethods[i] = strings.ToUpper(normalizedMethods[i])
	}
	payload := strings.Join([]string{serviceName, effectivePath, strings.Join(normalizedMethods, ",")}, "|")
	sum := sha1.Sum([]byte(payload))
	return fmt.Sprintf("route-%x", sum[:6])
}

func (api *ManagementAPI) findRouteRecord(cfg *config.Config, id string) (routeRecord, error) {
	for _, record := range api.routeRecords(cfg) {
		if record.ID == id {
			return record, nil
		}
	}
	return routeRecord{}, fmt.Errorf("route not found")
}

func (api *ManagementAPI) findRouteByServicePathMethod(cfg *config.Config, serviceName, path string, methods []string) (routeRecord, error) {
	for _, record := range api.routeRecords(cfg) {
		if record.Service.Name == serviceName && record.Route.Path == path && sameMethods(record.Route.EffectiveMethods(), methods) {
			return record, nil
		}
	}
	return routeRecord{}, fmt.Errorf("route not found")
}

func sameMethods(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	seen := make(map[string]int, len(a))
	for _, m := range a {
		seen[strings.ToUpper(m)]++
	}
	for _, m := range b {
		key := strings.ToUpper(m)
		if seen[key] == 0 {
			return false
		}
		seen[key]--
	}
	return true
}

func findServiceByName(cfg *config.Config, name string) (*config.Service, error) {
	for sci := range cfg.Services {
		for si := range cfg.Services[sci].Services {
			if cfg.Services[sci].Services[si].Name == name {
				return &cfg.Services[sci].Services[si], nil
			}
		}
	}
	return nil, fmt.Errorf("service not found")
}

func mergeRouteUpdate(dst *config.RouterConfig, src config.RouterConfig) {
	if src.Path != "" {
		dst.Path = src.Path
	}
	if src.Method != "" {
		dst.Method = src.Method
	}
	if len(src.Methods) > 0 {
		dst.Methods = src.Methods
	}
	if src.Enabled != nil {
		dst.Enabled = src.Enabled
	}
	if src.RequireAuth {
		dst.RequireAuth = src.RequireAuth
	}
	if src.RequireJwt {
		dst.RequireJwt = src.RequireJwt
	}
	if src.StripPath {
		dst.StripPath = src.StripPath
	}
	if src.Name != "" {
		dst.Name = src.Name
	}
	if src.Description != "" {
		dst.Description = src.Description
	}
	if len(src.Backends) > 0 {
		dst.Backends = src.Backends
	}
	if len(src.Headers) > 0 {
		dst.Headers = src.Headers
	}
	if len(src.Scopes) > 0 {
		dst.Scopes = src.Scopes
	}
	if len(src.Roles) > 0 {
		dst.Roles = src.Roles
	}
	if src.AuthPlugin != "" {
		dst.AuthPlugin = src.AuthPlugin
	}
}

func applyRouteRawUpdate(dst *config.RouterConfig, raw map[string]interface{}) {
	if value, ok := raw["requireAuth"].(bool); ok {
		dst.RequireAuth = value
	}
	if value, ok := raw["requireJwt"].(bool); ok {
		dst.RequireJwt = value
	}
	if value, ok := raw["stripPath"].(bool); ok {
		dst.StripPath = value
	}
	if value, ok := raw["enabled"].(bool); ok {
		dst.Enabled = config.NewBool(value)
	}
}

func (api *ManagementAPI) setRouteEnabled(r *http.Request, id string, enabled bool) error {
	cfg := api.gateway.GetConfig()
	record, err := api.findRouteRecord(cfg, id)
	if err != nil {
		return err
	}
	simCfg, err := cloneConfig(cfg)
	if err != nil {
		return err
	}
	simCfg.Services[record.ServiceConfigIndex].Services[record.ServiceIndex].Routes[record.RouteIndex].Enabled = config.NewBool(enabled)
	label, note, changeRef := revisionMetadataFromRequest(r)
	return api.applyManagedConfigChange(simCfg, "route_set_enabled", label, note, changeRef, map[string]interface{}{
		"route_id": id,
		"enabled":  enabled,
	})
}

func (api *ManagementAPI) pluginEnabled(name string) bool {
	cfg := api.gateway.GetConfig()
	if cfg == nil {
		return false
	}
	pluginCfg, ok := cfg.GetPluginConfig(name)
	if !ok {
		return false
	}
	if enabled, ok := pluginCfg["enabled"].(bool); ok {
		return enabled
	}
	return true
}

func (api *ManagementAPI) setPluginEnabled(r *http.Request, name string, enabled bool) error {
	p, err := api.registry.Get(name)
	if err != nil {
		return fmt.Errorf("plugin not found")
	}
	cfg := api.gateway.GetConfig()
	if cfg == nil {
		return fmt.Errorf("configuration not available")
	}
	simCfg, err := cloneConfig(cfg)
	if err != nil {
		return err
	}
	pluginCfg, _ := simCfg.GetPluginConfig(name)
	if pluginCfg == nil {
		pluginCfg = map[string]interface{}{}
	}
	pluginCfg["enabled"] = enabled
	simCfg.SetPluginConfig(name, pluginCfg)
	if err := p.Initialize(pluginCfg); err != nil {
		return err
	}
	label, note, changeRef := revisionMetadataFromRequest(r)
	return api.applyManagedConfigChange(simCfg, "plugin_set_enabled", label, note, changeRef, map[string]interface{}{
		"plugin":  name,
		"enabled": enabled,
	})
}

func adminDataDir() string {
	return filepath.Join(".iket-admin")
}

func certificatesDir() string {
	return filepath.Join(adminDataDir(), "certificates")
}

func backupsDir() string {
	return filepath.Join(adminDataDir(), "backups")
}

func enrollmentTokensDir() string {
	return filepath.Join(adminDataDir(), "enrollment-tokens")
}

func revisionsDir() string {
	return filepath.Join(adminDataDir(), "revisions")
}

func proposalsDir() string {
	return filepath.Join(adminDataDir(), "proposals")
}

func notificationDeliveriesDir() string {
	return filepath.Join(adminDataDir(), "notification-deliveries")
}

type configRevisionRecord struct {
	ID        string                 `json:"id"`
	Action    string                 `json:"action"`
	Label     string                 `json:"label,omitempty"`
	Note      string                 `json:"note,omitempty"`
	ChangeRef string                 `json:"change_ref,omitempty"`
	CreatedAt time.Time              `json:"created_at"`
	Summary   map[string]interface{} `json:"summary,omitempty"`
	Config    *config.Config         `json:"config"`
}

type configProposalRecord struct {
	ID                       string                 `json:"id"`
	Action                   string                 `json:"action"`
	Status                   string                 `json:"status"`
	CreatedBy                string                 `json:"created_by,omitempty"`
	Environment              string                 `json:"environment,omitempty"`
	PromotedFrom             string                 `json:"promoted_from,omitempty"`
	ConfigHash               string                 `json:"config_hash,omitempty"`
	SourceConfigHash         string                 `json:"source_config_hash,omitempty"`
	CanaryServices           []string               `json:"canary_services,omitempty"`
	CanaryRoutes             []string               `json:"canary_routes,omitempty"`
	CanaryHeaders            []string               `json:"canary_headers,omitempty"`
	CanaryPercent            int                    `json:"canary_percent,omitempty"`
	CanarySteps              []int                  `json:"canary_steps,omitempty"`
	CanaryMinRequests        int                    `json:"canary_min_requests,omitempty"`
	CanaryMaxErrorRate       float64                `json:"canary_max_error_rate,omitempty"`
	CanaryMaxP95Latency      string                 `json:"canary_max_p95_latency,omitempty"`
	CanaryAutoReconcile      bool                   `json:"canary_auto_reconcile,omitempty"`
	CanaryAutoInterval       string                 `json:"canary_auto_interval,omitempty"`
	CanaryAutoReviewer       string                 `json:"canary_auto_reviewer,omitempty"`
	CanaryLastReconciled     time.Time              `json:"canary_last_reconciled,omitempty"`
	CanaryNextReconcile      time.Time              `json:"canary_next_reconcile,omitempty"`
	CanaryBaselineConfig     *config.Config         `json:"canary_baseline_config,omitempty"`
	ShadowVerificationPasses int                    `json:"shadow_verification_passes,omitempty"`
	ShadowLastVerifiedAt     time.Time              `json:"shadow_last_verified_at,omitempty"`
	ShadowLastHealthy        bool                   `json:"shadow_last_healthy,omitempty"`
	ShadowReady              bool                   `json:"shadow_ready,omitempty"`
	ShadowReadyAt            time.Time              `json:"shadow_ready_at,omitempty"`
	Label                    string                 `json:"label,omitempty"`
	Note                     string                 `json:"note,omitempty"`
	ChangeRef                string                 `json:"change_ref,omitempty"`
	Strategy                 string                 `json:"strategy,omitempty"`
	CreatedAt                time.Time              `json:"created_at"`
	NotBefore                time.Time              `json:"not_before,omitempty"`
	ReviewedAt               time.Time              `json:"reviewed_at,omitempty"`
	AppliedAt                time.Time              `json:"applied_at,omitempty"`
	ReviewedBy               string                 `json:"reviewed_by,omitempty"`
	ReviewNote               string                 `json:"review_note,omitempty"`
	Approvals                []proposalApproval     `json:"approvals,omitempty"`
	ExpiredAt                time.Time              `json:"expired_at,omitempty"`
	ExpirationReason         string                 `json:"expiration_reason,omitempty"`
	RequiredApprovals        int                    `json:"required_approvals,omitempty"`
	Summary                  map[string]interface{} `json:"summary,omitempty"`
	Config                   *config.Config         `json:"config"`
	RevisionID               string                 `json:"revision_id,omitempty"`
}

type proposalApproval struct {
	Reviewer   string    `json:"reviewer"`
	ReviewNote string    `json:"review_note,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
}

type canaryEvaluationThresholds struct {
	MinRequests   int     `json:"min_requests,omitempty"`
	MaxErrorRate  float64 `json:"max_error_rate,omitempty"`
	MaxP95Latency string  `json:"max_p95_latency,omitempty"`
}

type enrollmentTokenRecord struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	TokenHash string    `json:"token_hash"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	UsedAt    time.Time `json:"used_at,omitempty"`
	ServerURL string    `json:"server_url,omitempty"`
	EnrollURL string    `json:"enroll_url,omitempty"`
	ClientCN  string    `json:"client_cn,omitempty"`
}

func saveNotificationDeliveryRecord(record notificationDeliveryRecord) error {
	if strings.TrimSpace(record.ID) == "" {
		return fmt.Errorf("notification delivery id is required")
	}
	if err := os.MkdirAll(notificationDeliveriesDir(), 0755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(notificationDeliveriesDir(), record.ID+".json"), data, 0644)
}

func loadNotificationDeliveryRecord(id string) (*notificationDeliveryRecord, error) {
	data, err := os.ReadFile(filepath.Join(notificationDeliveriesDir(), id+".json"))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("notification delivery not found")
		}
		return nil, err
	}
	var record notificationDeliveryRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return nil, err
	}
	return &record, nil
}

func listNotificationDeliveryRecords() ([]map[string]interface{}, error) {
	if err := os.MkdirAll(notificationDeliveriesDir(), 0755); err != nil {
		return nil, err
	}
	files, err := os.ReadDir(notificationDeliveriesDir())
	if err != nil {
		return nil, err
	}
	records := make([]map[string]interface{}, 0, len(files))
	for _, file := range files {
		if file.IsDir() || filepath.Ext(file.Name()) != ".json" {
			continue
		}
		record, err := loadNotificationDeliveryRecord(strings.TrimSuffix(file.Name(), ".json"))
		if err != nil {
			continue
		}
		records = append(records, map[string]interface{}{
			"id":               record.ID,
			"event":            record.Event,
			"proposal_id":      record.ProposalID,
			"webhook_name":     record.WebhookName,
			"webhook_url":      record.WebhookURL,
			"webhook_format":   record.WebhookFormat,
			"occurred_at":      record.OccurredAt,
			"delivered_at":     record.DeliveredAt,
			"success":          record.Success,
			"attempts":         record.Attempts,
			"last_status_code": record.LastStatusCode,
			"last_error":       record.LastError,
			"replay_of":        record.ReplayOf,
		})
	}
	sort.SliceStable(records, func(i, j int) bool {
		return fmt.Sprint(records[i]["id"]) > fmt.Sprint(records[j]["id"])
	})
	return records, nil
}

func filterNotificationDeliveryRecords(records []map[string]interface{}, event, proposalID, webhook, success string) []map[string]interface{} {
	if strings.TrimSpace(event) == "" && strings.TrimSpace(proposalID) == "" && strings.TrimSpace(webhook) == "" && strings.TrimSpace(success) == "" {
		return records
	}
	wantEvent := strings.ToLower(strings.TrimSpace(event))
	wantProposalID := strings.TrimSpace(proposalID)
	wantWebhook := strings.ToLower(strings.TrimSpace(webhook))
	wantSuccess := strings.ToLower(strings.TrimSpace(success))
	filtered := make([]map[string]interface{}, 0, len(records))
	for _, record := range records {
		if wantEvent != "" && strings.ToLower(strings.TrimSpace(fmt.Sprint(record["event"]))) != wantEvent {
			continue
		}
		if wantProposalID != "" && strings.TrimSpace(fmt.Sprint(record["proposal_id"])) != wantProposalID {
			continue
		}
		if wantWebhook != "" {
			webhookName := strings.ToLower(strings.TrimSpace(fmt.Sprint(record["webhook_name"])))
			webhookURL := strings.ToLower(strings.TrimSpace(fmt.Sprint(record["webhook_url"])))
			if webhookName != wantWebhook && webhookURL != wantWebhook {
				continue
			}
		}
		if wantSuccess != "" {
			successValue := strings.ToLower(strings.TrimSpace(fmt.Sprint(record["success"])))
			if successValue != wantSuccess {
				continue
			}
		}
		filtered = append(filtered, record)
	}
	return filtered
}

func loadManagedCertificates() ([]map[string]interface{}, error) {
	if err := os.MkdirAll(certificatesDir(), 0755); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(certificatesDir())
	if err != nil {
		return nil, err
	}
	out := make([]map[string]interface{}, 0)
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(certificatesDir(), entry.Name()))
		if err != nil {
			continue
		}
		var meta map[string]interface{}
		if err := json.Unmarshal(data, &meta); err == nil {
			out = append(out, meta)
		}
	}
	return out, nil
}

func saveManagedCertificate(name, certType, certPEM, keyPEM string) (map[string]interface{}, error) {
	if name == "" || certPEM == "" {
		return nil, fmt.Errorf("name and cert_pem are required")
	}
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return nil, fmt.Errorf("invalid cert_pem")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("invalid certificate: %w", err)
	}
	if err := os.MkdirAll(certificatesDir(), 0755); err != nil {
		return nil, err
	}
	sum := sha1.Sum([]byte(name + cert.Subject.String() + time.Now().String()))
	id := fmt.Sprintf("%x", sum[:6])
	meta := map[string]interface{}{
		"id":          id,
		"name":        name,
		"type":        certType,
		"subject":     cert.Subject.String(),
		"issuer":      cert.Issuer.String(),
		"valid_from":  cert.NotBefore,
		"valid_until": cert.NotAfter,
		"status":      "valid",
		"cert_pem":    certPEM,
	}
	if keyPEM != "" {
		meta["key_pem"] = keyPEM
	}
	data, _ := json.MarshalIndent(meta, "", "  ")
	if err := os.WriteFile(filepath.Join(certificatesDir(), id+".json"), data, 0644); err != nil {
		return nil, err
	}
	return meta, nil
}

func deleteManagedCertificate(id string) error {
	path := filepath.Join(certificatesDir(), id+".json")
	if _, err := os.Stat(path); err != nil {
		return fmt.Errorf("certificate not found")
	}
	return os.Remove(path)
}

func saveEnrollmentTokenRecord(record enrollmentTokenRecord) error {
	if err := os.MkdirAll(enrollmentTokensDir(), 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(enrollmentTokensDir(), record.ID+".json"), data, 0600)
}

func loadEnrollmentTokenRecord(id string) (*enrollmentTokenRecord, error) {
	data, err := os.ReadFile(filepath.Join(enrollmentTokensDir(), id+".json"))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("enrollment token not found")
		}
		return nil, err
	}
	var record enrollmentTokenRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return nil, err
	}
	return &record, nil
}

func listEnrollmentTokenRecords() ([]enrollmentTokenRecord, error) {
	if err := os.MkdirAll(enrollmentTokensDir(), 0700); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(enrollmentTokensDir())
	if err != nil {
		return nil, err
	}
	out := make([]enrollmentTokenRecord, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(enrollmentTokensDir(), entry.Name()))
		if err != nil {
			continue
		}
		var record enrollmentTokenRecord
		if err := json.Unmarshal(data, &record); err == nil {
			out = append(out, record)
		}
	}
	return out, nil
}

func deleteEnrollmentTokenRecord(id string) error {
	path := filepath.Join(enrollmentTokensDir(), id+".json")
	if _, err := os.Stat(path); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("enrollment token not found")
		}
		return err
	}
	return os.Remove(path)
}

func isActiveEnrollmentToken(record enrollmentTokenRecord, now time.Time) bool {
	return record.UsedAt.IsZero() && now.Before(record.ExpiresAt)
}

func parseEnrollmentToken(token string) (string, string, error) {
	parts := strings.SplitN(strings.TrimSpace(token), ".", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", fmt.Errorf("invalid enrollment token")
	}
	return parts[0], parts[1], nil
}

func hashEnrollmentSecret(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

func randomHex(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

func loadEnrollmentCA(tlsCfg config.TLSConfig) (*rsa.PrivateKey, *x509.Certificate, []byte, error) {
	if tlsCfg.ClientCAFile == "" {
		return nil, nil, nil, fmt.Errorf("client CA is not configured")
	}
	caPEM, err := os.ReadFile(tlsCfg.ClientCAFile)
	if err != nil {
		return nil, nil, nil, err
	}
	caBlock, _ := pem.Decode(caPEM)
	if caBlock == nil {
		return nil, nil, nil, fmt.Errorf("invalid client CA certificate")
	}
	caCert, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		return nil, nil, nil, err
	}

	caKeyPath := filepath.Join(filepath.Dir(tlsCfg.ClientCAFile), "ca.key")
	caKeyPEM, err := os.ReadFile(caKeyPath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil, nil, fmt.Errorf("ca.key not found next to %s; enrollment requires a locally managed CA", tlsCfg.ClientCAFile)
		}
		return nil, nil, nil, err
	}
	keyBlock, _ := pem.Decode(caKeyPEM)
	if keyBlock == nil {
		return nil, nil, nil, fmt.Errorf("invalid ca private key")
	}
	caKey, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, nil, nil, err
	}
	return caKey, caCert, caPEM, nil
}

func signEnrollmentCSR(csrPEM []byte, commonName string, caKey *rsa.PrivateKey, caCert *x509.Certificate) ([]byte, *x509.Certificate, error) {
	block, _ := pem.Decode(csrPEM)
	if block == nil {
		return nil, nil, fmt.Errorf("invalid csr_pem")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, nil, err
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, nil, err
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{"Iket"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, csr.PublicKey, caKey)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}), cert, nil
}

func createConfigBackup(cfg *config.Config) (string, string, int64, error) {
	if err := os.MkdirAll(backupsDir(), 0755); err != nil {
		return "", "", 0, err
	}
	id := fmt.Sprintf("backup-%s", time.Now().Format("20060102-150405"))
	path := filepath.Join(backupsDir(), id+".json")
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return "", "", 0, err
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		return "", "", 0, err
	}
	return id, path, int64(len(data)), nil
}

func listConfigBackups() ([]map[string]interface{}, error) {
	if err := os.MkdirAll(backupsDir(), 0755); err != nil {
		return nil, err
	}
	files, err := os.ReadDir(backupsDir())
	if err != nil {
		return nil, err
	}
	backups := make([]map[string]interface{}, 0)
	for _, file := range files {
		if file.IsDir() || filepath.Ext(file.Name()) != ".json" {
			continue
		}
		info, err := file.Info()
		if err != nil {
			continue
		}
		backups = append(backups, map[string]interface{}{
			"id":         strings.TrimSuffix(file.Name(), ".json"),
			"filename":   file.Name(),
			"size_bytes": info.Size(),
			"created_at": info.ModTime(),
		})
	}
	return backups, nil
}

func restoreConfigBackup(gw *gateway.Gateway, id string) error {
	path := filepath.Join(backupsDir(), id+".json")
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("backup not found")
		}
		return err
	}
	var cfg config.Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return err
	}
	return gw.UpdateConfig(&cfg)
}

func saveConfigRevision(action, label, note, changeRef string, summary map[string]interface{}, cfg *config.Config) (string, error) {
	if cfg == nil {
		return "", fmt.Errorf("configuration not available")
	}
	if err := os.MkdirAll(revisionsDir(), 0755); err != nil {
		return "", err
	}
	id := fmt.Sprintf("rev-%s", time.Now().UTC().Format("20060102-150405.000000000"))
	cloned, err := cloneConfig(cfg)
	if err != nil {
		return "", err
	}
	record := configRevisionRecord{
		ID:        id,
		Action:    action,
		Label:     strings.TrimSpace(label),
		Note:      strings.TrimSpace(note),
		ChangeRef: strings.TrimSpace(changeRef),
		CreatedAt: time.Now().UTC(),
		Summary:   summary,
		Config:    cloned,
	}
	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(filepath.Join(revisionsDir(), id+".json"), data, 0644); err != nil {
		return "", err
	}
	return id, nil
}

func listConfigRevisions() ([]map[string]interface{}, error) {
	if err := os.MkdirAll(revisionsDir(), 0755); err != nil {
		return nil, err
	}
	files, err := os.ReadDir(revisionsDir())
	if err != nil {
		return nil, err
	}
	revisions := make([]map[string]interface{}, 0)
	for _, file := range files {
		if file.IsDir() || filepath.Ext(file.Name()) != ".json" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(revisionsDir(), file.Name()))
		if err != nil {
			continue
		}
		var record configRevisionRecord
		if err := json.Unmarshal(data, &record); err != nil {
			continue
		}
		serviceCount := 0
		routeCount := 0
		if record.Config != nil {
			for _, svcCfg := range record.Config.Services {
				serviceCount += len(svcCfg.Services)
				for _, svc := range svcCfg.Services {
					routeCount += len(svc.Routes)
				}
			}
		}
		revisions = append(revisions, map[string]interface{}{
			"id":            record.ID,
			"action":        record.Action,
			"label":         record.Label,
			"note":          record.Note,
			"change_ref":    record.ChangeRef,
			"created_at":    record.CreatedAt,
			"summary":       record.Summary,
			"service_count": serviceCount,
			"route_count":   routeCount,
		})
	}
	sort.SliceStable(revisions, func(i, j int) bool {
		return fmt.Sprint(revisions[i]["id"]) > fmt.Sprint(revisions[j]["id"])
	})
	return revisions, nil
}

func loadConfigRevision(id string) (*configRevisionRecord, error) {
	data, err := os.ReadFile(filepath.Join(revisionsDir(), id+".json"))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("revision not found")
		}
		return nil, err
	}
	var record configRevisionRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return nil, err
	}
	return &record, nil
}

func saveConfigProposal(action, strategy, proposer, environment, promotedFrom, sourceConfigHash string, canaryServices, canaryRoutes, canaryHeaders []string, canaryPercent int, canarySteps []int, canaryMinRequests int, canaryMaxErrorRate float64, canaryMaxP95Latency string, canaryAutoReconcile bool, canaryAutoInterval, canaryAutoReviewer, label, note, changeRef string, notBefore time.Time, requiredApprovals int, summary map[string]interface{}, cfg *config.Config) (string, error) {
	if cfg == nil {
		return "", fmt.Errorf("configuration not available")
	}
	if err := os.MkdirAll(proposalsDir(), 0755); err != nil {
		return "", err
	}
	id := fmt.Sprintf("prp-%s", time.Now().UTC().Format("20060102-150405.000000000"))
	cloned, err := cloneConfig(cfg)
	if err != nil {
		return "", err
	}
	configHash, err := configFingerprint(cloned)
	if err != nil {
		return "", err
	}
	record := &configProposalRecord{
		ID:                  id,
		Action:              action,
		Status:              "pending",
		CreatedBy:           strings.TrimSpace(proposer),
		Environment:         strings.TrimSpace(environment),
		PromotedFrom:        strings.TrimSpace(promotedFrom),
		ConfigHash:          configHash,
		SourceConfigHash:    strings.TrimSpace(sourceConfigHash),
		CanaryServices:      append([]string(nil), canaryServices...),
		CanaryRoutes:        append([]string(nil), canaryRoutes...),
		CanaryHeaders:       append([]string(nil), canaryHeaders...),
		CanaryPercent:       canaryPercent,
		CanarySteps:         append([]int(nil), canarySteps...),
		CanaryMinRequests:   canaryMinRequests,
		CanaryMaxErrorRate:  canaryMaxErrorRate,
		CanaryMaxP95Latency: strings.TrimSpace(canaryMaxP95Latency),
		CanaryAutoReconcile: canaryAutoReconcile,
		CanaryAutoInterval:  strings.TrimSpace(canaryAutoInterval),
		CanaryAutoReviewer:  strings.TrimSpace(canaryAutoReviewer),
		Label:               strings.TrimSpace(label),
		Note:                strings.TrimSpace(note),
		ChangeRef:           strings.TrimSpace(changeRef),
		Strategy:            strings.TrimSpace(strategy),
		CreatedAt:           time.Now().UTC(),
		NotBefore:           notBefore,
		RequiredApprovals:   requiredApprovals,
		Summary:             summary,
		Config:              cloned,
	}
	if err := saveConfigProposalRecord(record); err != nil {
		return "", err
	}
	return id, nil
}

func saveConfigProposalRecord(record *configProposalRecord) error {
	if record == nil {
		return fmt.Errorf("proposal not available")
	}
	if err := os.MkdirAll(proposalsDir(), 0755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(proposalsDir(), record.ID+".json"), data, 0644)
}

func listConfigProposals() ([]map[string]interface{}, error) {
	if err := os.MkdirAll(proposalsDir(), 0755); err != nil {
		return nil, err
	}
	files, err := os.ReadDir(proposalsDir())
	if err != nil {
		return nil, err
	}
	proposals := make([]map[string]interface{}, 0)
	for _, file := range files {
		if file.IsDir() || filepath.Ext(file.Name()) != ".json" {
			continue
		}
		record, err := loadConfigProposal(strings.TrimSuffix(file.Name(), ".json"))
		if err != nil {
			continue
		}
		serviceCount := 0
		routeCount := 0
		if record.Config != nil {
			for _, svcCfg := range record.Config.Services {
				serviceCount += len(svcCfg.Services)
				for _, svc := range svcCfg.Services {
					routeCount += len(svc.Routes)
				}
			}
		}
		proposals = append(proposals, map[string]interface{}{
			"id":                     record.ID,
			"action":                 record.Action,
			"status":                 record.Status,
			"created_by":             record.CreatedBy,
			"environment":            record.Environment,
			"promoted_from":          record.PromotedFrom,
			"canary_services":        record.CanaryServices,
			"canary_routes":          record.CanaryRoutes,
			"canary_headers":         record.CanaryHeaders,
			"canary_percent":         record.CanaryPercent,
			"canary_steps":           record.CanarySteps,
			"canary_min_requests":    record.CanaryMinRequests,
			"canary_max_error_rate":  record.CanaryMaxErrorRate,
			"canary_max_p95_latency": record.CanaryMaxP95Latency,
			"label":                  record.Label,
			"note":                   record.Note,
			"change_ref":             record.ChangeRef,
			"strategy":               record.Strategy,
			"created_at":             record.CreatedAt,
			"not_before":             record.NotBefore,
			"reviewed_at":            record.ReviewedAt,
			"applied_at":             record.AppliedAt,
			"reviewed_by":            record.ReviewedBy,
			"review_note":            record.ReviewNote,
			"expired_at":             record.ExpiredAt,
			"expiration_reason":      record.ExpirationReason,
			"summary":                record.Summary,
			"service_count":          serviceCount,
			"route_count":            routeCount,
			"revision_id":            record.RevisionID,
			"approval_count":         proposalApprovalCount(nil, record),
			"required_approvals":     requiredProposalApprovers(nil, record),
		})
	}
	sort.SliceStable(proposals, func(i, j int) bool {
		return fmt.Sprint(proposals[i]["id"]) > fmt.Sprint(proposals[j]["id"])
	})
	return proposals, nil
}

func loadConfigProposal(id string) (*configProposalRecord, error) {
	data, err := os.ReadFile(filepath.Join(proposalsDir(), id+".json"))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("proposal not found")
		}
		return nil, err
	}
	var record configProposalRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return nil, err
	}
	return &record, nil
}

func (api *ManagementAPI) resolveRevisionConfig(id string) (*config.Config, map[string]interface{}, error) {
	if strings.EqualFold(id, "current") {
		cfg, err := cloneConfig(api.gateway.GetConfig())
		if err != nil {
			return nil, nil, err
		}
		return cfg, map[string]interface{}{
			"source":     "current",
			"action":     "live_config",
			"label":      "",
			"note":       "",
			"change_ref": "",
			"created_at": time.Now().UTC(),
		}, nil
	}
	record, err := loadConfigRevision(id)
	if err != nil {
		return nil, nil, err
	}
	if record.Config == nil {
		return nil, nil, fmt.Errorf("revision has no stored configuration")
	}
	return record.Config, map[string]interface{}{
		"source":     "revision",
		"action":     record.Action,
		"label":      record.Label,
		"note":       record.Note,
		"change_ref": record.ChangeRef,
		"created_at": record.CreatedAt,
	}, nil
}

func proposalMetadataFromRequest(r *http.Request, record *configProposalRecord) (string, string, string) {
	label, note, changeRef := revisionMetadataFromRequest(r)
	if record == nil {
		return label, note, changeRef
	}
	return firstNonEmpty(label, record.Label), firstNonEmpty(note, record.Note), firstNonEmpty(changeRef, record.ChangeRef)
}

func proposalReviewMetadataFromRequest(r *http.Request, record *configProposalRecord) (string, string) {
	if r == nil {
		if record == nil {
			return "", ""
		}
		return strings.TrimSpace(record.ReviewedBy), strings.TrimSpace(record.ReviewNote)
	}
	reviewer := strings.TrimSpace(r.URL.Query().Get("reviewer"))
	reviewNote := strings.TrimSpace(r.URL.Query().Get("review_note"))
	if record == nil {
		return reviewer, reviewNote
	}
	return firstNonEmpty(reviewer, record.ReviewedBy), firstNonEmpty(reviewNote, record.ReviewNote)
}

func upsertProposalApproval(record *configProposalRecord, reviewer, reviewNote string) {
	if record == nil || strings.TrimSpace(reviewer) == "" {
		return
	}
	reviewer = strings.TrimSpace(reviewer)
	reviewNote = strings.TrimSpace(reviewNote)
	for i := range record.Approvals {
		if strings.EqualFold(strings.TrimSpace(record.Approvals[i].Reviewer), reviewer) {
			record.Approvals[i].Reviewer = reviewer
			record.Approvals[i].ReviewNote = reviewNote
			record.Approvals[i].CreatedAt = time.Now().UTC()
			return
		}
	}
	record.Approvals = append(record.Approvals, proposalApproval{
		Reviewer:   reviewer,
		ReviewNote: reviewNote,
		CreatedAt:  time.Now().UTC(),
	})
}

func proposalApprovalCount(cfg *config.Config, record *configProposalRecord) int {
	if record == nil {
		return 0
	}
	maxApprovalAge := proposalApprovalMaxAge(cfg)
	now := time.Now().UTC()
	seen := make(map[string]struct{})
	for _, approval := range record.Approvals {
		if maxApprovalAge > 0 && approval.CreatedAt.Add(maxApprovalAge).Before(now) {
			continue
		}
		reviewer := strings.ToLower(strings.TrimSpace(approval.Reviewer))
		if reviewer == "" {
			continue
		}
		seen[reviewer] = struct{}{}
	}
	return len(seen)
}

func requiredProposalApprovers(cfg *config.Config, record *configProposalRecord) int {
	if record == nil {
		return 1
	}
	if record.RequiredApprovals > 0 {
		return record.RequiredApprovals
	}
	if cfg == nil {
		return 1
	}
	policy := cfg.Security.MutationPolicy
	if !policy.Enabled || !isHighImpactMutationAction(record.Action) || policy.MinApproversForHighImpactProposals <= 0 {
		return 1
	}
	return policy.MinApproversForHighImpactProposals
}

func proposalStatusAfterApproval(cfg *config.Config, record *configProposalRecord) string {
	if proposalApprovalCount(cfg, record) >= requiredProposalApprovers(cfg, record) {
		return "approved"
	}
	return "pending"
}

func proposalProposerFromRequest(r *http.Request) string {
	if r == nil {
		return ""
	}
	return strings.TrimSpace(r.URL.Query().Get("proposer"))
}

func proposalEnvironmentFromRequest(r *http.Request) string {
	if r == nil {
		return ""
	}
	return strings.TrimSpace(r.URL.Query().Get("environment"))
}

func proposalCanaryServicesFromRequest(r *http.Request, record *configProposalRecord) []string {
	if r == nil {
		if record == nil {
			return nil
		}
		return append([]string(nil), record.CanaryServices...)
	}
	values := normalizeQueryList(r.URL.Query()["canary_service"])
	if len(values) > 0 {
		return values
	}
	if record == nil {
		return nil
	}
	return append([]string(nil), record.CanaryServices...)
}

func proposalCanaryRoutesFromRequest(r *http.Request, record *configProposalRecord) []string {
	if r == nil {
		if record == nil {
			return nil
		}
		return append([]string(nil), record.CanaryRoutes...)
	}
	values := normalizeQueryList(r.URL.Query()["canary_route"])
	if len(values) > 0 {
		return values
	}
	if record == nil {
		return nil
	}
	return append([]string(nil), record.CanaryRoutes...)
}

func proposalCanaryHeadersFromRequest(r *http.Request, record *configProposalRecord) []string {
	if r == nil {
		if record == nil {
			return nil
		}
		return append([]string(nil), record.CanaryHeaders...)
	}
	values := normalizeHeaderQueryList(r.URL.Query()["canary_header"])
	if len(values) > 0 {
		return values
	}
	if record == nil {
		return nil
	}
	return append([]string(nil), record.CanaryHeaders...)
}

func proposalCanaryPercentFromRequest(r *http.Request, record *configProposalRecord) (int, error) {
	if r == nil {
		if record == nil {
			return 0, nil
		}
		return record.CanaryPercent, nil
	}
	value := strings.TrimSpace(r.URL.Query().Get("canary_percent"))
	if value == "" {
		if record == nil {
			return 0, nil
		}
		return record.CanaryPercent, nil
	}
	percent, err := strconv.Atoi(value)
	if err != nil {
		return 0, fmt.Errorf("invalid canary_percent, expected integer between 1 and 99")
	}
	if percent < 1 || percent > 99 {
		return 0, fmt.Errorf("invalid canary_percent, expected integer between 1 and 99")
	}
	return percent, nil
}

func proposalCanaryStepsFromRequest(r *http.Request, record *configProposalRecord) ([]int, error) {
	if r == nil {
		if record == nil {
			return nil, nil
		}
		return append([]int(nil), record.CanarySteps...), nil
	}
	values := r.URL.Query()["canary_step"]
	if len(values) == 0 {
		if record == nil {
			return nil, nil
		}
		return append([]int(nil), record.CanarySteps...), nil
	}
	steps := make([]int, 0, len(values))
	seen := make(map[int]struct{})
	for _, raw := range values {
		for _, part := range strings.Split(raw, ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			step, err := strconv.Atoi(part)
			if err != nil || step < 1 || step > 100 {
				return nil, fmt.Errorf("invalid canary_step, expected integer between 1 and 100")
			}
			if _, ok := seen[step]; ok {
				continue
			}
			seen[step] = struct{}{}
			steps = append(steps, step)
		}
	}
	sort.Ints(steps)
	return steps, nil
}

func proposalCanaryMinRequestsFromRequest(r *http.Request, record *configProposalRecord) (int, error) {
	if r == nil {
		if record == nil {
			return 0, nil
		}
		return record.CanaryMinRequests, nil
	}
	value := strings.TrimSpace(r.URL.Query().Get("canary_min_requests"))
	if value == "" {
		if record == nil {
			return 0, nil
		}
		return record.CanaryMinRequests, nil
	}
	minRequests, err := strconv.Atoi(value)
	if err != nil || minRequests < 0 {
		return 0, fmt.Errorf("invalid canary_min_requests, expected non-negative integer")
	}
	return minRequests, nil
}

func proposalCanaryMaxErrorRateFromRequest(r *http.Request, record *configProposalRecord) (float64, error) {
	if r == nil {
		if record == nil {
			return 0, nil
		}
		return record.CanaryMaxErrorRate, nil
	}
	value := strings.TrimSpace(r.URL.Query().Get("canary_max_error_rate"))
	if value == "" {
		if record == nil {
			return 0, nil
		}
		return record.CanaryMaxErrorRate, nil
	}
	rate, err := strconv.ParseFloat(value, 64)
	if err != nil || rate < 0 || rate > 1 {
		return 0, fmt.Errorf("invalid canary_max_error_rate, expected number between 0 and 1")
	}
	return rate, nil
}

func proposalCanaryMaxP95LatencyFromRequest(r *http.Request, record *configProposalRecord) (string, error) {
	if r == nil {
		if record == nil {
			return "", nil
		}
		return strings.TrimSpace(record.CanaryMaxP95Latency), nil
	}
	value := strings.TrimSpace(r.URL.Query().Get("canary_max_p95_latency"))
	if value == "" {
		if record == nil {
			return "", nil
		}
		return strings.TrimSpace(record.CanaryMaxP95Latency), nil
	}
	if _, err := time.ParseDuration(value); err != nil {
		return "", fmt.Errorf("invalid canary_max_p95_latency, expected Go duration like 500ms or 2s")
	}
	return value, nil
}

func proposalCanaryAutoReconcileFromRequest(r *http.Request, record *configProposalRecord) (bool, error) {
	if r == nil {
		return record != nil && record.CanaryAutoReconcile, nil
	}
	value := strings.TrimSpace(r.URL.Query().Get("canary_auto"))
	if value == "" {
		if record == nil {
			return false, nil
		}
		return record.CanaryAutoReconcile, nil
	}
	enabled, err := strconv.ParseBool(value)
	if err != nil {
		return false, fmt.Errorf("invalid canary_auto, expected true or false")
	}
	return enabled, nil
}

func proposalCanaryAutoIntervalFromRequest(r *http.Request, record *configProposalRecord) (string, error) {
	if r == nil {
		if record == nil {
			return "", nil
		}
		return strings.TrimSpace(record.CanaryAutoInterval), nil
	}
	value := strings.TrimSpace(r.URL.Query().Get("canary_auto_interval"))
	if value == "" {
		if record == nil {
			return "", nil
		}
		return strings.TrimSpace(record.CanaryAutoInterval), nil
	}
	if _, err := time.ParseDuration(value); err != nil {
		return "", fmt.Errorf("invalid canary_auto_interval, expected Go duration like 30s or 5m")
	}
	return value, nil
}

func proposalCanaryAutoReviewerFromRequest(r *http.Request, record *configProposalRecord) string {
	if r == nil {
		if record == nil {
			return ""
		}
		return strings.TrimSpace(record.CanaryAutoReviewer)
	}
	value := strings.TrimSpace(r.URL.Query().Get("canary_auto_reviewer"))
	if value != "" {
		return value
	}
	if record == nil {
		return ""
	}
	return strings.TrimSpace(record.CanaryAutoReviewer)
}

func normalizeQueryList(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func normalizeHeaderQueryList(values []string) []string {
	normalized := normalizeQueryList(values)
	if len(normalized) == 0 {
		return nil
	}
	out := make([]string, 0, len(normalized))
	for _, value := range normalized {
		if strings.Contains(value, "=") {
			out = append(out, value)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func mergeNormalizedLists(base, extra []string) []string {
	return normalizeQueryList(append(append([]string(nil), base...), extra...))
}

func appendUniqueString(values []string, candidate string) []string {
	candidate = strings.TrimSpace(candidate)
	if candidate == "" {
		return values
	}
	for _, value := range values {
		if strings.EqualFold(strings.TrimSpace(value), candidate) {
			return values
		}
	}
	return append(values, candidate)
}

func proposalNotBeforeFromRequest(r *http.Request) (time.Time, error) {
	if r == nil {
		return time.Time{}, nil
	}
	value := strings.TrimSpace(r.URL.Query().Get("not_before"))
	if value == "" {
		return time.Time{}, nil
	}
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid not_before timestamp, expected RFC3339")
	}
	return parsed.UTC(), nil
}

func (api *ManagementAPI) enforceProposalSchedule(action string, notBefore time.Time) error {
	cfg := api.gateway.GetConfig()
	if cfg == nil {
		return nil
	}
	policy := cfg.Security.MutationPolicy
	if !policy.Enabled || !policy.RequireNotBeforeForHighImpactProposals || !isHighImpactMutationAction(action) {
		return nil
	}
	if notBefore.IsZero() {
		return fmt.Errorf("mutation policy requires not_before for high-impact proposals")
	}
	return nil
}

func proposalMaxAge(cfg *config.Config) time.Duration {
	if cfg == nil {
		return 0
	}
	value := strings.TrimSpace(cfg.Security.MutationPolicy.MaxProposalAge)
	if value == "" {
		return 0
	}
	duration, err := time.ParseDuration(value)
	if err != nil {
		return 0
	}
	return duration
}

func proposalApprovalMaxAge(cfg *config.Config) time.Duration {
	if cfg == nil {
		return 0
	}
	value := strings.TrimSpace(cfg.Security.MutationPolicy.MaxApprovalAge)
	if value == "" {
		return 0
	}
	duration, err := time.ParseDuration(value)
	if err != nil {
		return 0
	}
	return duration
}

func (api *ManagementAPI) enforceProposalFreshness(record *configProposalRecord, now time.Time) error {
	if record == nil {
		return nil
	}
	cfg := api.gateway.GetConfig()
	if cfg == nil {
		return nil
	}
	if err := api.enforceProposalExpiration(record, now); err != nil {
		return err
	}
	if maxApprovalAge := proposalApprovalMaxAge(cfg); maxApprovalAge > 0 {
		approvalCount := proposalApprovalCount(cfg, record)
		requiredApprovers := requiredProposalApprovers(cfg, record)
		if approvalCount < requiredApprovers {
			record.Status = "pending"
			if err := saveConfigProposalRecord(record); err != nil {
				api.logger.Warn("Proposal freshness recalculated but failed to persist pending state", logging.Error(err))
			}
			return fmt.Errorf("proposal requires %d fresh approval(s) before apply; current fresh approvals: %d", requiredApprovers, approvalCount)
		}
	}
	return nil
}

func (api *ManagementAPI) enforceProposalExpiration(record *configProposalRecord, now time.Time) error {
	if record == nil {
		return nil
	}
	cfg := api.gateway.GetConfig()
	if cfg == nil {
		return nil
	}
	if maxAge := proposalMaxAge(cfg); maxAge > 0 && record.CreatedAt.Add(maxAge).Before(now) {
		record.Status = "expired"
		record.ExpiredAt = now
		record.ExpirationReason = fmt.Sprintf("proposal exceeded max age of %s", maxAge)
		if err := saveConfigProposalRecord(record); err != nil {
			api.logger.Warn("Proposal expired but failed to persist expiration state", logging.Error(err))
		}
		return fmt.Errorf("proposal expired because it exceeded max age of %s", maxAge)
	}
	return nil
}

func (api *ManagementAPI) enforceProposalBlackoutWindow(action string, now time.Time) error {
	cfg := api.gateway.GetConfig()
	if cfg == nil {
		return nil
	}
	policy := cfg.Security.MutationPolicy
	if !policy.Enabled || len(policy.BlockedApplyWindows) == 0 {
		return nil
	}
	for _, window := range policy.BlockedApplyWindows {
		if !mutationWindowApplies(action, window.Scopes) {
			continue
		}
		active, err := isWithinBlockedApplyWindow(now, window)
		if err != nil {
			return fmt.Errorf("failed to evaluate blocked apply window %q: %w", strings.TrimSpace(window.Name), err)
		}
		if active {
			name := strings.TrimSpace(window.Name)
			if name == "" {
				name = fmt.Sprintf("%s-%s", strings.TrimSpace(window.Start), strings.TrimSpace(window.End))
			}
			return fmt.Errorf("proposal apply is blocked by blackout window %q", name)
		}
	}
	return nil
}

func (api *ManagementAPI) enforceProposalReviewer(record *configProposalRecord, reviewer string) error {
	if record == nil {
		return nil
	}
	cfg := api.gateway.GetConfig()
	if cfg == nil {
		return nil
	}
	policy := cfg.Security.MutationPolicy
	if !policy.Enabled || !policy.RequireDifferentReviewerForProposals {
		return nil
	}
	if strings.TrimSpace(record.CreatedBy) == "" || strings.TrimSpace(reviewer) == "" {
		return nil
	}
	if strings.EqualFold(strings.TrimSpace(record.CreatedBy), strings.TrimSpace(reviewer)) {
		return fmt.Errorf("proposal reviewer must be different from the proposer")
	}
	return nil
}

func isHighImpactMutationAction(action string) bool {
	highImpact := map[string]bool{
		"gateway_config_replace": true,
		"services_replace":       true,
		"service_delete":         true,
		"route_delete":           true,
		"route_set_enabled":      true,
		"plugin_set_enabled":     true,
		"client_remove":          true,
		"restore_revision":       true,
	}
	return highImpact[action]
}

func mutationActionScopes(action string) []string {
	scopes := make([]string, 0, 2)
	switch {
	case strings.HasPrefix(action, "gateway_config_"):
		scopes = append(scopes, "config")
	case strings.HasPrefix(action, "services_"), strings.HasPrefix(action, "service_"):
		scopes = append(scopes, "services")
	case strings.HasPrefix(action, "route_"):
		scopes = append(scopes, "routes")
	case strings.HasPrefix(action, "plugin_"):
		scopes = append(scopes, "plugins")
	case strings.HasPrefix(action, "client_"):
		scopes = append(scopes, "clients")
	case strings.HasPrefix(action, "restore_revision"):
		scopes = append(scopes, "revisions")
	}
	if isHighImpactMutationAction(action) {
		scopes = append(scopes, "high_impact")
	}
	if len(scopes) == 0 {
		return []string{"all"}
	}
	return scopes
}

func mutationPolicyApplies(action string, policy config.MutationPolicy) bool {
	if !policy.Enabled {
		return false
	}
	if len(policy.EnforcedScopes) == 0 {
		return true
	}
	actionScopes := mutationActionScopes(action)
	for _, configuredScope := range policy.EnforcedScopes {
		scope := strings.ToLower(strings.TrimSpace(configuredScope))
		if scope == "" || scope == "all" {
			return true
		}
		for _, actionScope := range actionScopes {
			if scope == actionScope {
				return true
			}
		}
	}
	return false
}

func mutationWindowApplies(action string, scopes []string) bool {
	if len(scopes) == 0 {
		return isHighImpactMutationAction(action)
	}
	return mutationPolicyApplies(action, config.MutationPolicy{
		Enabled:        true,
		EnforcedScopes: scopes,
	})
}

func isWithinBlockedApplyWindow(now time.Time, window config.MutationApplyWindow) (bool, error) {
	locationName := strings.TrimSpace(window.Timezone)
	if locationName == "" {
		locationName = "UTC"
	}
	loc, err := time.LoadLocation(locationName)
	if err != nil {
		return false, err
	}
	startMinutes, err := parseClockMinutes(window.Start)
	if err != nil {
		return false, err
	}
	endMinutes, err := parseClockMinutes(window.End)
	if err != nil {
		return false, err
	}
	localNow := now.In(loc)
	currentMinutes := localNow.Hour()*60 + localNow.Minute()
	allowedDays, err := parsePolicyWeekdays(window.Days)
	if err != nil {
		return false, err
	}
	if startMinutes < endMinutes {
		return weekdayAllowed(allowedDays, localNow.Weekday()) && currentMinutes >= startMinutes && currentMinutes < endMinutes, nil
	}
	if weekdayAllowed(allowedDays, localNow.Weekday()) && currentMinutes >= startMinutes {
		return true, nil
	}
	previousDay := localNow.Add(-24 * time.Hour).Weekday()
	return weekdayAllowed(allowedDays, previousDay) && currentMinutes < endMinutes, nil
}

func parseClockMinutes(value string) (int, error) {
	parsed, err := time.Parse("15:04", strings.TrimSpace(value))
	if err != nil {
		return 0, fmt.Errorf("invalid clock value %q", value)
	}
	return parsed.Hour()*60 + parsed.Minute(), nil
}

func parsePolicyWeekdays(days []string) (map[time.Weekday]struct{}, error) {
	if len(days) == 0 {
		return nil, nil
	}
	out := make(map[time.Weekday]struct{}, len(days))
	for _, day := range days {
		weekday, err := parsePolicyWeekday(day)
		if err != nil {
			return nil, err
		}
		out[weekday] = struct{}{}
	}
	return out, nil
}

func parsePolicyWeekday(value string) (time.Weekday, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "sun", "sunday":
		return time.Sunday, nil
	case "mon", "monday":
		return time.Monday, nil
	case "tue", "tues", "tuesday":
		return time.Tuesday, nil
	case "wed", "wednesday":
		return time.Wednesday, nil
	case "thu", "thur", "thurs", "thursday":
		return time.Thursday, nil
	case "fri", "friday":
		return time.Friday, nil
	case "sat", "saturday":
		return time.Saturday, nil
	default:
		return time.Sunday, fmt.Errorf("invalid weekday %q", value)
	}
}

func weekdayAllowed(days map[time.Weekday]struct{}, weekday time.Weekday) bool {
	if len(days) == 0 {
		return true
	}
	_, ok := days[weekday]
	return ok
}

func (api *ManagementAPI) enforceMutationPolicy(action, label, note, changeRef string) error {
	cfg := api.gateway.GetConfig()
	if cfg == nil {
		return nil
	}
	policy := cfg.Security.MutationPolicy
	if !mutationPolicyApplies(action, policy) {
		return nil
	}
	if policy.RequireLabel && strings.TrimSpace(label) == "" {
		return fmt.Errorf("mutation policy requires label for action %q", action)
	}
	if isHighImpactMutationAction(action) {
		if policy.RequireNoteForHighImpact && strings.TrimSpace(note) == "" {
			return fmt.Errorf("mutation policy requires note for high-impact action %q", action)
		}
		if policy.RequireChangeRefForHighImpact && strings.TrimSpace(changeRef) == "" {
			return fmt.Errorf("mutation policy requires change_ref for high-impact action %q", action)
		}
	}
	return nil
}

func (api *ManagementAPI) applyManagedConfigChange(cfg *config.Config, action, label, note, changeRef string, summary map[string]interface{}) error {
	if err := api.enforceMutationPolicy(action, label, note, changeRef); err != nil {
		return err
	}
	if err := api.gateway.UpdateConfig(cfg); err != nil {
		return err
	}
	revisionID, err := saveConfigRevision(action, label, note, changeRef, summary, cfg)
	if err != nil {
		api.logger.Warn("Configuration updated but failed to record revision",
			logging.String("action", action),
			logging.Error(err),
		)
		return nil
	}
	api.logger.Info("Configuration revision recorded",
		logging.String("action", action),
		logging.String("revision_id", revisionID),
	)
	return nil
}

func revisionMetadataFromRequest(r *http.Request) (string, string, string) {
	if r == nil {
		return "", "", ""
	}
	return strings.TrimSpace(r.URL.Query().Get("label")), strings.TrimSpace(r.URL.Query().Get("note")), strings.TrimSpace(r.URL.Query().Get("change_ref"))
}

func (api *ManagementAPI) writeError(w http.ResponseWriter, message string, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	errorResponse := ErrorResponse{
		Error: ErrorDetails{
			Code:    getErrorCode(statusCode),
			Message: message,
		},
	}

	json.NewEncoder(w).Encode(errorResponse)
}

func getErrorCode(statusCode int) string {
	switch statusCode {
	case http.StatusUnauthorized:
		return "AUTHENTICATION_REQUIRED"
	case http.StatusForbidden:
		return "PERMISSION_DENIED"
	case http.StatusBadRequest:
		return "VALIDATION_ERROR"
	case http.StatusNotFound:
		return "NOT_FOUND"
	case http.StatusConflict:
		return "CONFLICT"
	default:
		return "INTERNAL_ERROR"
	}
}

func sanitizedClientCommonName(name string) string {
	name = strings.TrimSpace(strings.ToLower(name))
	if name == "" {
		return "iket-cli"
	}
	var b strings.Builder
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '-' || r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		return "iket-cli"
	}
	return out
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func (api *ManagementAPI) getServices(w http.ResponseWriter, r *http.Request) {
	cfg := api.gateway.GetConfig()
	if cfg == nil {
		api.writeError(w, "Configuration not available", http.StatusInternalServerError)
		return
	}

	// Redact sensitive info if needed (e.g., backend URLs, secrets)
	services := make([]map[string]interface{}, 0)
	for _, svcConfig := range cfg.Services {
		for _, svc := range svcConfig.Services {
			serviceInfo := map[string]interface{}{
				"name":        svc.Name,
				"description": svc.Description,
				"host":        svc.Host,
				"base_path":   svc.BasePath,
				"tags":        svc.Tags,
				"group":       svc.Group,
				"scopes":      svc.Scopes,
				"routes":      make([]map[string]interface{}, 0),
			}
			for _, route := range svc.Routes {
				routeInfo := map[string]interface{}{
					"path":        route.Path,
					"method":      route.Method,
					"methods":     route.EffectiveMethods(),
					"name":        route.Name,
					"description": route.Description,
					"tags":        route.Tags,
					"group":       route.Group,
					"priority":    route.Priority,
					"enabled":     route.IsEnabled(),
					"requireAuth": route.RequireAuth,
					"requireJwt":  route.RequireJwt,
					"stripPath":   route.StripPath,
					"scopes":      route.Scopes,
					"roles":       route.Roles,
					"auth_plugin": route.AuthPlugin,
					"backend":     route.Backends,
					"rateLimit":   route.RateLimit,
					"headers":     route.Headers,
				}
				serviceInfo["routes"] = append(serviceInfo["routes"].([]map[string]interface{}), routeInfo)
			}
			services = append(services, serviceInfo)
		}
	}
	response := map[string]interface{}{
		"services": services,
	}
	api.writeJSON(w, response)
}

// POST /api/v1/services
func (api *ManagementAPI) createService(w http.ResponseWriter, r *http.Request) {
	strategy := r.URL.Query().Get("strategy")
	if strategy == "" {
		strategy = "merge"
	}
	dryRun := r.URL.Query().Get("dry_run") == "true"
	proposalOnly := r.URL.Query().Get("proposal") == "true"

	cfg := api.gateway.GetConfig()
	if cfg == nil {
		api.writeError(w, "Configuration not available", http.StatusInternalServerError)
		return
	}
	var req struct {
		Services []config.Service `json:"services"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.writeError(w, "Invalid service definition", http.StatusBadRequest)
		return
	}

	// Create a working copy for simulation
	simCfg := *cfg
	// Deep copy services slice to avoid mutating live state during merge simulation
	simServices := make([]config.ServiceConfig, len(cfg.Services))
	copy(simServices, cfg.Services)
	simCfg.Services = simServices

	if strategy == "replace" {
		simCfg.Services = []config.ServiceConfig{{
			Version:  1,
			Services: cloneServices(req.Services),
		}}
		summary := serviceChangeSummary(cfg, &simCfg)

		if dryRun {
			msg := fmt.Sprintf("[DRY RUN] %d service(s) would replace the remote services set", len(req.Services))
			api.writeJSON(w, map[string]interface{}{
				"success":        true,
				"dry_run":        true,
				"replaced":       true,
				"services_count": len(req.Services),
				"summary":        summary,
				"message":        msg,
			})
			return
		}

		label, note, changeRef := revisionMetadataFromRequest(r)
		if proposalOnly {
			notBefore, err := proposalNotBeforeFromRequest(r)
			if err != nil {
				api.writeError(w, err.Error(), http.StatusBadRequest)
				return
			}
			if err := api.enforceProposalSchedule("services_replace", notBefore); err != nil {
				api.writeError(w, err.Error(), http.StatusBadRequest)
				return
			}
			canaryPercent, err := proposalCanaryPercentFromRequest(r, nil)
			if err != nil {
				api.writeError(w, err.Error(), http.StatusBadRequest)
				return
			}
			canarySteps, err := proposalCanaryStepsFromRequest(r, nil)
			if err != nil {
				api.writeError(w, err.Error(), http.StatusBadRequest)
				return
			}
			canaryMinRequests, err := proposalCanaryMinRequestsFromRequest(r, nil)
			if err != nil {
				api.writeError(w, err.Error(), http.StatusBadRequest)
				return
			}
			canaryMaxErrorRate, err := proposalCanaryMaxErrorRateFromRequest(r, nil)
			if err != nil {
				api.writeError(w, err.Error(), http.StatusBadRequest)
				return
			}
			canaryMaxP95Latency, err := proposalCanaryMaxP95LatencyFromRequest(r, nil)
			if err != nil {
				api.writeError(w, err.Error(), http.StatusBadRequest)
				return
			}
			canaryAutoReconcile, err := proposalCanaryAutoReconcileFromRequest(r, nil)
			if err != nil {
				api.writeError(w, err.Error(), http.StatusBadRequest)
				return
			}
			canaryAutoInterval, err := proposalCanaryAutoIntervalFromRequest(r, nil)
			if err != nil {
				api.writeError(w, err.Error(), http.StatusBadRequest)
				return
			}
			canaryAutoReviewer := proposalCanaryAutoReviewerFromRequest(r, nil)
			proposalID, err := saveConfigProposal("services_replace", strategy, proposalProposerFromRequest(r), proposalEnvironmentFromRequest(r), "", "", proposalCanaryServicesFromRequest(r, nil), proposalCanaryRoutesFromRequest(r, nil), proposalCanaryHeadersFromRequest(r, nil), canaryPercent, canarySteps, canaryMinRequests, canaryMaxErrorRate, canaryMaxP95Latency, canaryAutoReconcile, canaryAutoInterval, canaryAutoReviewer, label, note, changeRef, notBefore, requiredProposalApprovers(api.gateway.GetConfig(), &configProposalRecord{Action: "services_replace"}), summary, &simCfg)
			if err != nil {
				api.writeError(w, fmt.Sprintf("Failed to create proposal: %v", err), http.StatusInternalServerError)
				return
			}
			api.writeJSON(w, map[string]interface{}{
				"success":                true,
				"proposal_id":            proposalID,
				"proposal_only":          true,
				"replaced":               true,
				"services_count":         len(req.Services),
				"environment":            proposalEnvironmentFromRequest(r),
				"not_before":             notBefore,
				"canary_services":        proposalCanaryServicesFromRequest(r, nil),
				"canary_routes":          proposalCanaryRoutesFromRequest(r, nil),
				"canary_headers":         proposalCanaryHeadersFromRequest(r, nil),
				"canary_percent":         canaryPercent,
				"canary_steps":           canarySteps,
				"canary_min_requests":    canaryMinRequests,
				"canary_max_error_rate":  canaryMaxErrorRate,
				"canary_max_p95_latency": canaryMaxP95Latency,
				"canary_auto":            canaryAutoReconcile,
				"canary_auto_interval":   canaryAutoInterval,
				"canary_auto_reviewer":   canaryAutoReviewer,
				"summary":                summary,
				"message":                fmt.Sprintf("%d service(s) proposed for replacement", len(req.Services)),
			})
			return
		}
		if err := api.applyManagedConfigChange(&simCfg, "services_replace", label, note, changeRef, summary); err != nil {
			api.writeError(w, fmt.Sprintf("Failed to replace services: %v", err), http.StatusInternalServerError)
			return
		}
		api.writeJSON(w, map[string]interface{}{
			"success":        true,
			"replaced":       true,
			"services_count": len(req.Services),
			"summary":        summary,
			"message":        fmt.Sprintf("%d service(s) replaced successfully", len(req.Services)),
		})
		return
	}

	if len(simCfg.Services) == 0 {
		simCfg.Services = []config.ServiceConfig{{Version: 1, Services: []config.Service{}}}
	}

	addedRoutes := []map[string]interface{}{}
	updatedRoutes := []map[string]interface{}{}
	addedServices := 0

	for _, newSvc := range req.Services {
		found := false
		for i, svc := range simCfg.Services[0].Services {
			if (newSvc.Name != "" && svc.Name == newSvc.Name) || (newSvc.Name == "" && svc.Host == newSvc.Host) {
				found = true
				for _, newRoute := range newSvc.Routes {
					routeFound := false
					for k, existRoute := range svc.Routes {
						if existRoute.Path == newRoute.Path && existRoute.Method == newRoute.Method {
							simCfg.Services[0].Services[i].Routes[k] = newRoute
							updatedRoutes = append(updatedRoutes, map[string]interface{}{"path": newRoute.Path, "method": newRoute.Method, "service": svc.Name})
							routeFound = true
							break
						}
					}
					if !routeFound {
						simCfg.Services[0].Services[i].Routes = append(simCfg.Services[0].Services[i].Routes, newRoute)
						addedRoutes = append(addedRoutes, map[string]interface{}{"path": newRoute.Path, "method": newRoute.Method, "service": svc.Name})
					}
				}
				if newSvc.Host != "" {
					simCfg.Services[0].Services[i].Host = newSvc.Host
				}
				break
			}
		}
		if !found {
			simCfg.Services[0].Services = append(simCfg.Services[0].Services, newSvc)
			addedServices++
			for _, newRoute := range newSvc.Routes {
				addedRoutes = append(addedRoutes, map[string]interface{}{"path": newRoute.Path, "method": newRoute.Method, "service": newSvc.Name})
			}
		}
	}

	summary := serviceChangeSummary(cfg, &simCfg)

	if dryRun {
		msg := fmt.Sprintf("[DRY RUN] %d service(s) would be added, %d route(s) would be added, %d route(s) would be updated", addedServices, len(addedRoutes), len(updatedRoutes))
		api.writeJSON(w, map[string]interface{}{
			"success":        true,
			"dry_run":        true,
			"added_services": addedServices,
			"added_routes":   addedRoutes,
			"updated_routes": updatedRoutes,
			"summary":        summary,
			"message":        msg,
		})
		return
	}

	label, note, changeRef := revisionMetadataFromRequest(r)
	if proposalOnly {
		notBefore, err := proposalNotBeforeFromRequest(r)
		if err != nil {
			api.writeError(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := api.enforceProposalSchedule("services_merge", notBefore); err != nil {
			api.writeError(w, err.Error(), http.StatusBadRequest)
			return
		}
		canaryPercent, err := proposalCanaryPercentFromRequest(r, nil)
		if err != nil {
			api.writeError(w, err.Error(), http.StatusBadRequest)
			return
		}
		canarySteps, err := proposalCanaryStepsFromRequest(r, nil)
		if err != nil {
			api.writeError(w, err.Error(), http.StatusBadRequest)
			return
		}
		canaryMinRequests, err := proposalCanaryMinRequestsFromRequest(r, nil)
		if err != nil {
			api.writeError(w, err.Error(), http.StatusBadRequest)
			return
		}
		canaryMaxErrorRate, err := proposalCanaryMaxErrorRateFromRequest(r, nil)
		if err != nil {
			api.writeError(w, err.Error(), http.StatusBadRequest)
			return
		}
		canaryMaxP95Latency, err := proposalCanaryMaxP95LatencyFromRequest(r, nil)
		if err != nil {
			api.writeError(w, err.Error(), http.StatusBadRequest)
			return
		}
		canaryAutoReconcile, err := proposalCanaryAutoReconcileFromRequest(r, nil)
		if err != nil {
			api.writeError(w, err.Error(), http.StatusBadRequest)
			return
		}
		canaryAutoInterval, err := proposalCanaryAutoIntervalFromRequest(r, nil)
		if err != nil {
			api.writeError(w, err.Error(), http.StatusBadRequest)
			return
		}
		canaryAutoReviewer := proposalCanaryAutoReviewerFromRequest(r, nil)
		proposalID, err := saveConfigProposal("services_merge", strategy, proposalProposerFromRequest(r), proposalEnvironmentFromRequest(r), "", "", proposalCanaryServicesFromRequest(r, nil), proposalCanaryRoutesFromRequest(r, nil), proposalCanaryHeadersFromRequest(r, nil), canaryPercent, canarySteps, canaryMinRequests, canaryMaxErrorRate, canaryMaxP95Latency, canaryAutoReconcile, canaryAutoInterval, canaryAutoReviewer, label, note, changeRef, notBefore, requiredProposalApprovers(api.gateway.GetConfig(), &configProposalRecord{Action: "services_merge"}), summary, &simCfg)
		if err != nil {
			api.writeError(w, fmt.Sprintf("Failed to create proposal: %v", err), http.StatusInternalServerError)
			return
		}
		api.writeJSON(w, map[string]interface{}{
			"success":                true,
			"proposal_id":            proposalID,
			"proposal_only":          true,
			"added_services":         addedServices,
			"added_routes":           addedRoutes,
			"updated_routes":         updatedRoutes,
			"environment":            proposalEnvironmentFromRequest(r),
			"not_before":             notBefore,
			"canary_services":        proposalCanaryServicesFromRequest(r, nil),
			"canary_routes":          proposalCanaryRoutesFromRequest(r, nil),
			"canary_headers":         proposalCanaryHeadersFromRequest(r, nil),
			"canary_percent":         canaryPercent,
			"canary_steps":           canarySteps,
			"canary_min_requests":    canaryMinRequests,
			"canary_max_error_rate":  canaryMaxErrorRate,
			"canary_max_p95_latency": canaryMaxP95Latency,
			"canary_auto":            canaryAutoReconcile,
			"canary_auto_interval":   canaryAutoInterval,
			"canary_auto_reviewer":   canaryAutoReviewer,
			"summary":                summary,
			"message":                "Service merge proposal created successfully",
		})
		return
	}
	if err := api.applyManagedConfigChange(&simCfg, "services_merge", label, note, changeRef, summary); err != nil {
		api.writeError(w, fmt.Sprintf("Failed to update services: %v", err), http.StatusInternalServerError)
		return
	}
	msg := fmt.Sprintf("%d service(s) added, %d route(s) added, %d route(s) updated", addedServices, len(addedRoutes), len(updatedRoutes))
	api.writeJSON(w, map[string]interface{}{
		"success":        true,
		"added_services": addedServices,
		"added_routes":   addedRoutes,
		"updated_routes": updatedRoutes,
		"summary":        summary,
		"message":        msg,
	})
}

// PUT /api/v1/services/{name}
func (api *ManagementAPI) updateService(w http.ResponseWriter, r *http.Request) {
	dryRun := r.URL.Query().Get("dry_run") == "true"
	cfg := api.gateway.GetConfig()
	if cfg == nil {
		api.writeError(w, "Configuration not available", http.StatusInternalServerError)
		return
	}
	name := mux.Vars(r)["name"]
	var update config.Service
	if err := json.NewDecoder(r.Body).Decode(&update); err != nil {
		api.writeError(w, "Invalid service definition", http.StatusBadRequest)
		return
	}

	// Create a working copy for simulation
	simCfg := *cfg
	// Deep copy services slice to avoid mutating live state
	simServices := make([]config.ServiceConfig, len(cfg.Services))
	for i := range cfg.Services {
		simServices[i] = cfg.Services[i]
		// Deep copy the services within each ServiceConfig
		simServices[i].Services = make([]config.Service, len(cfg.Services[i].Services))
		copy(simServices[i].Services, cfg.Services[i].Services)
	}
	simCfg.Services = simServices

	updated := false
	addedRoutes := []map[string]interface{}{}
	updatedRoutes := []map[string]interface{}{}
	for i, svcConfig := range simCfg.Services {
		for j, svc := range svcConfig.Services {
			if svc.Name == name {
				existingRoutes := svc.Routes
				for _, newRoute := range update.Routes {
					found := false
					for k, existRoute := range existingRoutes {
						if existRoute.Path == newRoute.Path && existRoute.Method == newRoute.Method {
							simCfg.Services[i].Services[j].Routes[k] = newRoute
							updatedRoutes = append(updatedRoutes, map[string]interface{}{"path": newRoute.Path, "method": newRoute.Method})
							found = true
							break
						}
					}
					if !found {
						simCfg.Services[i].Services[j].Routes = append(simCfg.Services[i].Services[j].Routes, newRoute)
						addedRoutes = append(addedRoutes, map[string]interface{}{"path": newRoute.Path, "method": newRoute.Method})
					}
				}
				// Optionally update other service fields
				simCfg.Services[i].Services[j].Description = update.Description
				simCfg.Services[i].Services[j].Host = update.Host
				simCfg.Services[i].Services[j].BasePath = update.BasePath
				simCfg.Services[i].Services[j].Tags = update.Tags
				simCfg.Services[i].Services[j].Group = update.Group
				updated = true
				break
			}
		}
	}
	if !updated {
		api.writeError(w, "Service not found", http.StatusNotFound)
		return
	}

	serviceSummary := serviceChangeSummary(cfg, &simCfg)
	if dryRun {
		msg := fmt.Sprintf("[DRY RUN] %d route(s) would be updated, %d would be added for service %q", len(updatedRoutes), len(addedRoutes), name)
		api.writeJSON(w, map[string]interface{}{
			"success":        true,
			"dry_run":        true,
			"updated_routes": updatedRoutes,
			"added_routes":   addedRoutes,
			"summary":        serviceSummary,
			"message":        msg,
		})
		return
	}

	label, note, changeRef := revisionMetadataFromRequest(r)
	if err := api.applyManagedConfigChange(&simCfg, "service_update", label, note, changeRef, serviceSummary); err != nil {
		api.writeError(w, fmt.Sprintf("Failed to update service: %v", err), http.StatusInternalServerError)
		return
	}
	msg := fmt.Sprintf("%d route(s) updated, %d added for service %q", len(updatedRoutes), len(addedRoutes), name)
	api.writeJSON(w, map[string]interface{}{
		"success":        true,
		"updated_routes": updatedRoutes,
		"added_routes":   addedRoutes,
		"summary":        serviceSummary,
		"message":        msg,
	})
}

// DELETE /api/v1/services/{name}
func (api *ManagementAPI) deleteService(w http.ResponseWriter, r *http.Request) {
	cfg := api.gateway.GetConfig()
	if cfg == nil {
		api.writeError(w, "Configuration not available", http.StatusInternalServerError)
		return
	}
	name := mux.Vars(r)["name"]
	deleted := false
	for i, svcConfig := range cfg.Services {
		for j, svc := range svcConfig.Services {
			if svc.Name == name {
				cfg.Services[i].Services = append(cfg.Services[i].Services[:j], cfg.Services[i].Services[j+1:]...)
				deleted = true
				break
			}
		}
	}
	if !deleted {
		api.writeError(w, "Service not found", http.StatusNotFound)
		return
	}
	deletedSummary := map[string]interface{}{
		"deleted_service": name,
	}
	label, note, changeRef := revisionMetadataFromRequest(r)
	if err := api.applyManagedConfigChange(cfg, "service_delete", label, note, changeRef, deletedSummary); err != nil {
		api.writeError(w, fmt.Sprintf("Failed to delete service: %v", err), http.StatusInternalServerError)
		return
	}
	api.writeJSON(w, APIResponse{Success: true, Message: "Service deleted successfully", Data: deletedSummary})
}

func cloneServices(in []config.Service) []config.Service {
	if len(in) == 0 {
		return nil
	}
	out := make([]config.Service, len(in))
	for i, svc := range in {
		out[i] = svc
		if len(svc.Routes) > 0 {
			out[i].Routes = make([]config.RouterConfig, len(svc.Routes))
			copy(out[i].Routes, svc.Routes)
		}
		if len(svc.Tags) > 0 {
			out[i].Tags = append([]string(nil), svc.Tags...)
		}
		if len(svc.Scopes) > 0 {
			out[i].Scopes = append([]string(nil), svc.Scopes...)
		}
	}
	return out
}

func (api *ManagementAPI) listClients(w http.ResponseWriter, r *http.Request) {
	p, err := api.registry.Get("apikey")
	if err != nil {
		api.writeJSON(w, map[string]interface{}{"clients": []interface{}{}})
		return
	}

	// Use reflection to call ListClients if it exists
	val := reflect.ValueOf(p)
	method := val.MethodByName("ListClients")
	if !method.IsValid() {
		api.writeError(w, "Plugin does not support client listing", http.StatusNotImplemented)
		return
	}

	results := method.Call(nil)
	api.writeJSON(w, map[string]interface{}{"clients": results[0].Interface()})
}

func (api *ManagementAPI) addClient(w http.ResponseWriter, r *http.Request) {
	var client struct {
		ID     string   `json:"id"`
		Name   string   `json:"name"`
		Key    string   `json:"key"`
		Group  string   `json:"group"`
		Scopes []string `json:"scopes"`
		Tags   []string `json:"tags"`
	}

	if err := json.NewDecoder(r.Body).Decode(&client); err != nil {
		api.writeError(w, "Invalid client data", http.StatusBadRequest)
		return
	}

	p, err := api.registry.Get("apikey")
	if err != nil {
		api.writeError(w, "API Key plugin not found or not enabled", http.StatusNotFound)
		return
	}

	// Actually, easier if we just update config and re-initialize plugin
	cfg := api.gateway.GetConfig()
	pluginCfg, ok := cfg.GetPluginConfig("apikey")
	if !ok {
		pluginCfg = make(map[string]interface{})
	}

	clients, _ := pluginCfg["clients"].([]interface{})
	// Check if key already exists
	for _, c := range clients {
		if m, ok := c.(map[string]interface{}); ok {
			if m["key"] == client.Key {
				api.writeError(w, "Client with this key already exists", http.StatusConflict)
				return
			}
		}
	}

	clients = append(clients, map[string]interface{}{
		"id":     client.ID,
		"name":   client.Name,
		"key":    client.Key,
		"group":  client.Group,
		"scopes": client.Scopes,
		"tags":   client.Tags,
	})
	pluginCfg["clients"] = clients
	cfg.SetPluginConfig("apikey", pluginCfg)

	clientAddSummary := map[string]interface{}{
		"client_id": client.ID,
		"group":     client.Group,
	}
	label, note, changeRef := revisionMetadataFromRequest(r)
	if err := api.applyManagedConfigChange(cfg, "client_add", label, note, changeRef, clientAddSummary); err != nil {
		api.writeError(w, "Failed to save configuration", http.StatusInternalServerError)
		return
	}

	// Re-initialize plugin
	if err := p.Initialize(pluginCfg); err != nil {
		api.writeError(w, "Failed to re-initialize plugin", http.StatusInternalServerError)
		return
	}

	api.writeJSON(w, APIResponse{Success: true, Message: "Client added successfully"})
}

func (api *ManagementAPI) removeClient(w http.ResponseWriter, r *http.Request) {
	key := mux.Vars(r)["key"]

	p, err := api.registry.Get("apikey")
	if err != nil {
		api.writeError(w, "API Key plugin not found", http.StatusNotFound)
		return
	}

	cfg := api.gateway.GetConfig()
	pluginCfg, ok := cfg.GetPluginConfig("apikey")
	if !ok {
		api.writeError(w, "Plugin configuration not found", http.StatusNotFound)
		return
	}

	clients, ok := pluginCfg["clients"].([]interface{})
	if !ok {
		api.writeError(w, "No clients configured", http.StatusNotFound)
		return
	}

	newClients := []interface{}{}
	found := false
	for _, c := range clients {
		if m, ok := c.(map[string]interface{}); ok {
			if m["key"] == key {
				found = true
				continue
			}
		}
		newClients = append(newClients, c)
	}

	if !found {
		api.writeError(w, "Client not found", http.StatusNotFound)
		return
	}

	pluginCfg["clients"] = newClients
	cfg.SetPluginConfig("apikey", pluginCfg)

	clientRemoveSummary := map[string]interface{}{
		"client_key": key,
	}
	label, note, changeRef := revisionMetadataFromRequest(r)
	if err := api.applyManagedConfigChange(cfg, "client_remove", label, note, changeRef, clientRemoveSummary); err != nil {
		api.writeError(w, "Failed to save configuration", http.StatusInternalServerError)
		return
	}

	// Re-initialize plugin
	if err := p.Initialize(pluginCfg); err != nil {
		api.writeError(w, "Failed to re-initialize plugin", http.StatusInternalServerError)
		return
	}

	api.writeJSON(w, APIResponse{Success: true, Message: "Client removed successfully"})
}
