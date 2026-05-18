package api

import (
	"encoding/json"
	"errors"
	"fmt"
	coreerrors "github.com/bhangun/iket/pkg/core/errors"
	"github.com/gorilla/mux"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

func (api *ManagementAPI) listNotificationDeliveries(w http.ResponseWriter, r *http.Request) {
	records, err := listNotificationDeliveryRecords()
	if err != nil {
		api.writeManagedError(w, managedConfigError("Failed to list notification deliveries", err), http.StatusInternalServerError)
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
		api.writeManagedError(w, err, http.StatusNotFound)
		return
	}
	api.writeJSON(w, record)
}

func (api *ManagementAPI) replayNotificationDelivery(w http.ResponseWriter, r *http.Request) {
	record, err := loadNotificationDeliveryRecord(mux.Vars(r)["id"])
	if err != nil {
		api.writeManagedError(w, err, http.StatusNotFound)
		return
	}
	replayed, replayErr := api.postNotificationWebhook(record.Webhook, record.Payload, record.ID)
	if replayErr != nil {
		api.writeManagedError(w, managedError(coreerrors.CodeUpstreamError, "Failed to replay notification delivery", replayErr), http.StatusBadGateway)
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
		api.writeManagedError(w, managedConfigError("Failed to list notification deliveries", err), http.StatusInternalServerError)
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
			api.writeManagedError(w, managedValidationError("limit must be zero or greater", parseErr), http.StatusBadRequest)
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
			return nil, coreerrors.New(coreerrors.CodeNotificationDeliveryNotFound, "Notification delivery not found")
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
