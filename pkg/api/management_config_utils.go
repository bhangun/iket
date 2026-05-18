package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"github.com/bhangun/iket/pkg/config"
	"strings"
)

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
