package api

import (
	"github.com/bhangun/iket/pkg/config"
	"strings"
	"time"
)

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
