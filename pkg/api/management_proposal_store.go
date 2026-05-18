package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/bhangun/iket/pkg/config"
	coreerrors "github.com/bhangun/iket/pkg/core/errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

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

func saveConfigProposal(action, strategy, proposer, environment, promotedFrom, sourceConfigHash string, canaryServices, canaryRoutes, canaryHeaders []string, canaryPercent int, canarySteps []int, canaryMinRequests int, canaryMaxErrorRate float64, canaryMaxP95Latency string, canaryAutoReconcile bool, canaryAutoInterval, canaryAutoReviewer, label, note, changeRef string, notBefore time.Time, requiredApprovals int, summary map[string]interface{}, cfg *config.Config) (string, error) {
	if cfg == nil {
		return "", coreerrors.New(coreerrors.CodeConfigNotAvailable, "Configuration not available")
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
			return nil, coreerrors.New(coreerrors.CodeProposalNotFound, "Proposal not found")
		}
		return nil, err
	}
	var record configProposalRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return nil, err
	}
	return &record, nil
}
