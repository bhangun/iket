package api

import (
	"fmt"
	"strings"
	"time"

	"github.com/bhangun/iket/pkg/logging"
)

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
