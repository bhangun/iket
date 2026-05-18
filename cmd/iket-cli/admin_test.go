package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestBuildProposalQueueDigest(t *testing.T) {
	queueResp := []byte(`{
	  "queue": [
	    {
	      "id": "prp-ready",
	      "environment": "prod",
	      "next_action": "apply",
	      "urgency": "overdue",
	      "sla_breached": true,
	      "sla_age_seconds": 7200,
	      "sla_threshold_seconds": 3600,
	      "ready_for_apply": true,
	      "priority_score": 55,
	      "priority_reason": "ready_to_apply",
	      "ready_age_seconds": 7200,
	      "blocker_count": 0,
	      "blockers": []
	    },
	    {
	      "id": "prp-blocked",
	      "environment": "prod",
	      "next_action": "needs_approval",
	      "ready_for_apply": false,
	      "priority_score": 91,
	      "priority_reason": "approval_blocked",
	      "ready_age_seconds": 0,
	      "blocker_count": 2,
	      "blockers": ["requires 2 approval(s); current fresh approvals: 0"]
	    }
	  ],
	  "summary": {
	    "total": 2,
	    "ready_count": 1,
	    "blocked_count": 1,
	    "sla_breach_count": 1,
	    "sla_breaches_by_environment": {"prod": 1},
	    "oldest_sla_breach": {"proposal_id": "prp-ready", "age_seconds": 7200}
	  }
	}`)

	blockedResp := []byte(`{
	  "blocked_proposal_count": 1,
	  "blockers": [
	    {
	      "reason": "requires 2 approval(s); current fresh approvals: 0",
	      "count": 1,
	      "proposal_ids": ["prp-blocked"]
	    }
	  ]
	}`)

	out, err := buildProposalQueueDigest(queueResp, blockedResp)
	if err != nil {
		t.Fatalf("expected digest build to succeed, got %v", err)
	}

	var payload struct {
		BlockedProposalCount int `json:"blocked_proposal_count"`
		TopReady             []struct {
			ProposalID string `json:"proposal_id"`
		} `json:"top_ready"`
		TopBlocked []struct {
			ProposalID     string `json:"proposal_id"`
			PrimaryBlocker string `json:"primary_blocker"`
		} `json:"top_blocked"`
		AttentionRequired struct {
			SLABreachCount int `json:"sla_breach_count"`
			TopSLABreaches []struct {
				ProposalID string `json:"proposal_id"`
			} `json:"top_sla_breaches"`
			SLABreachesByEnvironment map[string]int `json:"sla_breaches_by_environment"`
		} `json:"attention_required"`
		TopBlockers []struct {
			Reason string `json:"reason"`
		} `json:"top_blockers"`
	}
	if err := json.Unmarshal(out, &payload); err != nil {
		t.Fatalf("failed to decode digest: %v", err)
	}
	if payload.BlockedProposalCount != 1 {
		t.Fatalf("expected blocked proposal count 1, got %d", payload.BlockedProposalCount)
	}
	if len(payload.TopReady) != 1 || payload.TopReady[0].ProposalID != "prp-ready" {
		t.Fatalf("unexpected top ready payload: %+v", payload.TopReady)
	}
	if len(payload.TopBlocked) != 1 || payload.TopBlocked[0].ProposalID != "prp-blocked" {
		t.Fatalf("unexpected top blocked payload: %+v", payload.TopBlocked)
	}
	if payload.AttentionRequired.SLABreachCount != 1 || len(payload.AttentionRequired.TopSLABreaches) != 1 || payload.AttentionRequired.TopSLABreaches[0].ProposalID != "prp-ready" {
		t.Fatalf("unexpected attention-required payload: %+v", payload.AttentionRequired)
	}
	if payload.AttentionRequired.SLABreachesByEnvironment["prod"] != 1 {
		t.Fatalf("expected prod SLA breach count in digest attention section, got %+v", payload.AttentionRequired.SLABreachesByEnvironment)
	}
	if payload.TopBlocked[0].PrimaryBlocker == "" {
		t.Fatalf("expected primary blocker in blocked digest")
	}
	if len(payload.TopBlockers) != 1 || payload.TopBlockers[0].Reason == "" {
		t.Fatalf("unexpected top blockers payload: %+v", payload.TopBlockers)
	}
}

func TestBuildProposalBatchBlockedView(t *testing.T) {
	queueResp := []byte(`{
	  "queue": [
	    {
	      "id": "prp-ready",
	      "action": "merge",
	      "status": "approved",
	      "environment": "prod",
	      "next_action": "apply",
	      "ready_for_apply": true,
	      "blocker_count": 0,
	      "blockers": []
	    },
	    {
	      "id": "prp-blocked-1",
	      "action": "replace",
	      "status": "pending",
	      "environment": "prod",
	      "next_action": "needs_approval",
	      "ready_for_apply": false,
	      "blocker_count": 1,
	      "blockers": ["requires approval"]
	    },
	    {
	      "id": "prp-blocked-2",
	      "action": "replace",
	      "status": "pending",
	      "environment": "prod",
	      "next_action": "needs_approval",
	      "ready_for_apply": false,
	      "blocker_count": 2,
	      "blockers": ["requires approval", "outside window"]
	    }
	  ],
	  "summary": {
	    "filters": {
	      "environment": "prod",
	      "status": "pending",
	      "next_action": "needs_approval"
	    }
	  }
	}`)

	out, err := buildProposalBatchBlockedView(queueResp)
	if err != nil {
		t.Fatalf("expected blocked batch view build to succeed, got %v", err)
	}

	var payload struct {
		BlockedProposalCount int            `json:"blocked_proposal_count"`
		BlockedProposalIDs   []string       `json:"blocked_proposal_ids"`
		ByNextAction         map[string]int `json:"by_next_action"`
		ByAction             map[string]int `json:"by_action"`
		Blockers             []struct {
			Reason string `json:"reason"`
			Count  int    `json:"count"`
		} `json:"blockers"`
	}
	if err := json.Unmarshal(out, &payload); err != nil {
		t.Fatalf("failed to decode blocked batch view: %v", err)
	}
	if payload.BlockedProposalCount != 2 || len(payload.BlockedProposalIDs) != 2 {
		t.Fatalf("unexpected blocked proposal summary: %+v", payload)
	}
	if payload.ByNextAction["needs_approval"] != 2 {
		t.Fatalf("unexpected next-action grouping: %+v", payload.ByNextAction)
	}
	if payload.ByAction["replace"] != 2 {
		t.Fatalf("unexpected action grouping: %+v", payload.ByAction)
	}
	if len(payload.Blockers) != 2 || payload.Blockers[0].Reason != "requires approval" || payload.Blockers[0].Count != 2 {
		t.Fatalf("unexpected blocker aggregation: %+v", payload.Blockers)
	}
}

func TestBuildProposalBatchExplainView(t *testing.T) {
	queueResp := []byte(`{
	  "queue": [
	    {
	      "id": "prp-blocked-1",
	      "action": "replace",
	      "status": "pending",
	      "environment": "prod",
	      "next_action": "needs_approval",
	      "ready_for_apply": false,
	      "blocker_count": 1,
	      "blockers": ["requires approval"]
	    },
	    {
	      "id": "prp-blocked-2",
	      "action": "replace",
	      "status": "pending",
	      "environment": "prod",
	      "next_action": "needs_approval",
	      "ready_for_apply": false,
	      "blocker_count": 2,
	      "blockers": ["requires approval", "outside window"]
	    }
	  ],
	  "summary": {
	    "filters": {
	      "environment": "prod",
	      "status": "pending",
	      "next_action": "needs_approval"
	    }
	  }
	}`)

	out, err := buildProposalBatchExplainView(queueResp)
	if err != nil {
		t.Fatalf("expected batch explain view build to succeed, got %v", err)
	}

	var payload struct {
		AffectedCount        int            `json:"affected_count"`
		AffectedProposalIDs  []string       `json:"affected_proposal_ids"`
		PrimaryBlocker       string         `json:"primary_blocker"`
		NextAction           string         `json:"next_action"`
		ByNextAction         map[string]int `json:"by_next_action"`
		ByBlocker            map[string]int `json:"by_blocker"`
		SuggestedAction      string         `json:"suggested_action"`
		SuggestedCommand     string         `json:"suggested_command"`
		SuggestedSteps       []string       `json:"suggested_steps"`
		SuggestedStepObjects []struct {
			Kind        string `json:"kind"`
			Status      string `json:"status"`
			StepIndex   string `json:"step_index"`
			Command     string `json:"command"`
			Description string `json:"description"`
			Reason      string `json:"reason"`
		} `json:"suggested_step_objects"`
		SuggestedPlan struct {
			PlanID           string `json:"plan_id"`
			GeneratedAt      string `json:"generated_at"`
			Summary          string `json:"summary"`
			Status           string `json:"status"`
			NextAction       string `json:"next_action"`
			PrimaryBlocker   string `json:"primary_blocker"`
			CurrentStepIndex int    `json:"current_step_index"`
			CurrentStep      struct {
				Kind      string `json:"kind"`
				Status    string `json:"status"`
				StepIndex string `json:"step_index"`
			} `json:"current_step"`
			ExecutionHints struct {
				ReadyToExecute    bool   `json:"ready_to_execute"`
				RequiresReviewer  bool   `json:"requires_reviewer"`
				ExecutionMode     string `json:"execution_mode"`
				RecommendedAction string `json:"recommended_action"`
				NextCommand       string `json:"next_command"`
				DryRunCommand     string `json:"dry_run_command"`
				ExecuteCommand    string `json:"execute_command"`
			} `json:"execution_hints"`
			StepCount int `json:"step_count"`
			Steps     []struct {
				Kind      string `json:"kind"`
				Status    string `json:"status"`
				StepIndex string `json:"step_index"`
			} `json:"steps"`
		} `json:"suggested_plan"`
		Explanation string `json:"explanation"`
	}
	if err := json.Unmarshal(out, &payload); err != nil {
		t.Fatalf("failed to decode batch explain view: %v", err)
	}
	if payload.AffectedCount != 2 || len(payload.AffectedProposalIDs) != 2 {
		t.Fatalf("unexpected affected proposal summary: %+v", payload)
	}
	if payload.NextAction != "needs_approval" || payload.PrimaryBlocker != "requires approval" {
		t.Fatalf("unexpected dominant blocker summary: %+v", payload)
	}
	if payload.ByNextAction["needs_approval"] != 2 || payload.ByBlocker["requires approval"] != 2 {
		t.Fatalf("unexpected explanation grouping: %+v", payload)
	}
	if !strings.Contains(payload.Explanation, "blocked on approval") {
		t.Fatalf("expected remediation-oriented explanation, got %q", payload.Explanation)
	}
	if payload.SuggestedAction != "approve_batch" {
		t.Fatalf("expected approve_batch suggestion, got %q", payload.SuggestedAction)
	}
	if !strings.Contains(payload.SuggestedCommand, "iket proposal batch act --action approve") || !strings.Contains(payload.SuggestedCommand, "--env prod") || !strings.Contains(payload.SuggestedCommand, "--next-action needs_approval") {
		t.Fatalf("unexpected suggested command: %q", payload.SuggestedCommand)
	}
	if len(payload.SuggestedSteps) < 3 {
		t.Fatalf("expected multi-step remediation plan, got %+v", payload.SuggestedSteps)
	}
	if !strings.Contains(payload.SuggestedSteps[1], "batch act --action approve --dry-run") {
		t.Fatalf("expected preview step in remediation plan, got %+v", payload.SuggestedSteps)
	}
	if len(payload.SuggestedStepObjects) < 3 {
		t.Fatalf("expected structured remediation plan, got %+v", payload.SuggestedStepObjects)
	}
	if payload.SuggestedStepObjects[0].Status != "current" || payload.SuggestedStepObjects[0].StepIndex != "0" {
		t.Fatalf("expected first step to be current with index 0, got %+v", payload.SuggestedStepObjects[0])
	}
	if payload.SuggestedStepObjects[1].Kind != "preview" || payload.SuggestedStepObjects[1].Status != "pending" || payload.SuggestedStepObjects[1].StepIndex != "1" || !strings.Contains(payload.SuggestedStepObjects[1].Command, "batch act --action approve --dry-run") || payload.SuggestedStepObjects[1].Reason == "" {
		t.Fatalf("unexpected structured remediation preview step: %+v", payload.SuggestedStepObjects[1])
	}
	if payload.SuggestedPlan.PlanID == "" || payload.SuggestedPlan.GeneratedAt == "" || payload.SuggestedPlan.Status != "pending" || payload.SuggestedPlan.NextAction != "needs_approval" || payload.SuggestedPlan.PrimaryBlocker != "requires approval" {
		t.Fatalf("unexpected suggested plan envelope: %+v", payload.SuggestedPlan)
	}
	if payload.SuggestedPlan.StepCount != len(payload.SuggestedStepObjects) || len(payload.SuggestedPlan.Steps) != len(payload.SuggestedStepObjects) {
		t.Fatalf("expected suggested plan step counts to match structured step objects: plan=%+v steps=%+v", payload.SuggestedPlan, payload.SuggestedStepObjects)
	}
	if payload.SuggestedPlan.CurrentStepIndex != 0 || payload.SuggestedPlan.CurrentStep.Kind != "inspect" || payload.SuggestedPlan.CurrentStep.Status != "current" || payload.SuggestedPlan.CurrentStep.StepIndex != "0" {
		t.Fatalf("unexpected current step metadata: %+v", payload.SuggestedPlan.CurrentStep)
	}
	if !payload.SuggestedPlan.ExecutionHints.ReadyToExecute || !payload.SuggestedPlan.ExecutionHints.RequiresReviewer || payload.SuggestedPlan.ExecutionHints.ExecutionMode != "mutation" || payload.SuggestedPlan.ExecutionHints.RecommendedAction != "approve" {
		t.Fatalf("unexpected execution hints: %+v", payload.SuggestedPlan.ExecutionHints)
	}
	if !strings.Contains(payload.SuggestedPlan.ExecutionHints.NextCommand, "batch act --action approve") || !strings.Contains(payload.SuggestedPlan.ExecutionHints.DryRunCommand, "batch act --action approve --dry-run") || !strings.Contains(payload.SuggestedPlan.ExecutionHints.ExecuteCommand, "batch act --action approve") {
		t.Fatalf("unexpected execution hint commands: %+v", payload.SuggestedPlan.ExecutionHints)
	}
	if payload.SuggestedPlan.Steps[0].Status != "current" || payload.SuggestedPlan.Steps[0].StepIndex != "0" {
		t.Fatalf("expected first plan step to be current with index 0, got %+v", payload.SuggestedPlan.Steps[0])
	}
}

func TestBuildProposalBatchMutationPath(t *testing.T) {
	path, err := buildProposalBatchMutationPath(true, "apply", "platform-admin", "batch", "prod", "approved", "apply", "aging", 3)
	if err != nil {
		t.Fatalf("expected apply batch path to succeed, got %v", err)
	}
	expectedParts := []string{
		"/api/v1/proposals/queue/apply-ready",
		"dry_run=true",
		"reviewer=platform-admin",
		"review_note=batch",
		"environment=prod",
		"status=approved",
		"next_action=apply",
		"urgency=aging",
		"limit=3",
	}
	for _, part := range expectedParts {
		if !strings.Contains(path, part) {
			t.Fatalf("expected path %q to contain %q", path, part)
		}
	}

	if _, err := buildProposalBatchMutationPath(false, "ship", "", "", "", "", "", "", 0); err == nil {
		t.Fatalf("expected invalid batch action to fail")
	}
}

func TestBuildProposalQueuePath(t *testing.T) {
	path, err := buildProposalQueuePath("prod", "approved", "apply", "overdue", true, false, 2)
	if err != nil {
		t.Fatalf("expected queue path to succeed, got %v", err)
	}
	expectedParts := []string{
		"/api/v1/proposals/queue",
		"environment=prod",
		"status=approved",
		"next_action=apply",
		"urgency=overdue",
		"ready=true",
		"limit=2",
	}
	for _, part := range expectedParts {
		if !strings.Contains(path, part) {
			t.Fatalf("expected path %q to contain %q", path, part)
		}
	}
	if _, err := buildProposalQueuePath("", "", "", "", true, true, 0); err == nil {
		t.Fatalf("expected mutually exclusive ready filters to fail")
	}
}

func TestLoadProposalBatchViewRejectsInvalidView(t *testing.T) {
	if _, _, err := loadProposalBatchView("report", "", "", "", "", false, false, 0); err == nil {
		t.Fatalf("expected invalid batch view to fail")
	}
}

func TestValidateProposalBatchActOptions(t *testing.T) {
	action, view, err := validateProposalBatchActOptions("export", "", "/tmp/out.json")
	if err != nil {
		t.Fatalf("expected export batch act options to succeed, got %v", err)
	}
	if action != "export" || view != "queue" {
		t.Fatalf("unexpected normalized export act options: action=%q view=%q", action, view)
	}

	if _, _, err := validateProposalBatchActOptions("export", "digest", ""); err == nil {
		t.Fatalf("expected export without output to fail")
	}
	if _, _, err := validateProposalBatchActOptions("preview", "", ""); err == nil {
		t.Fatalf("expected unsupported preview act action to fail")
	}
}

func TestProposalBatchSelectorFlags(t *testing.T) {
	flags := proposalBatchSelectorFlags(map[string]interface{}{
		"environment": "prod",
		"status":      "approved",
		"next_action": "apply",
		"ready":       true,
	})
	for _, part := range []string{"--env prod", "--status approved", "--next-action apply", "--ready-only"} {
		if !strings.Contains(flags, part) {
			t.Fatalf("expected selector flags %q to contain %q", flags, part)
		}
	}
}

func TestBuildProposalBatchSuggestedStepsForSchedule(t *testing.T) {
	steps := buildProposalBatchSuggestedSteps("needs_schedule", map[string]interface{}{
		"environment": "prod",
		"status":      "pending",
		"next_action": "needs_schedule",
	})
	if len(steps) < 3 {
		t.Fatalf("expected schedule remediation plan, got %+v", steps)
	}
	if !strings.Contains(steps[0], "batch blocked") || !strings.Contains(steps[2], "batch explain") {
		t.Fatalf("unexpected schedule remediation steps: %+v", steps)
	}
}

func TestBuildProposalBatchSuggestedStepObjectsForVerification(t *testing.T) {
	steps := buildProposalBatchSuggestedStepObjects("needs_verification", map[string]interface{}{
		"environment": "prod",
		"status":      "approved",
		"next_action": "needs_verification",
	})
	if len(steps) < 3 {
		t.Fatalf("expected verification remediation step objects, got %+v", steps)
	}
	if steps[0]["status"] != "current" || steps[0]["step_index"] != "0" {
		t.Fatalf("expected first verification step to be current, got %+v", steps[0])
	}
	if steps[1]["kind"] != "verify" || steps[1]["reason"] == "" || steps[1]["status"] != "pending" || steps[1]["step_index"] != "1" {
		t.Fatalf("unexpected verification remediation step object: %+v", steps[1])
	}
	if !strings.Contains(steps[2]["command"], "iket proposal batch explain") {
		t.Fatalf("unexpected verification follow-up command: %+v", steps[2])
	}
}

func TestBuildProposalBatchExecutionHintsForSchedule(t *testing.T) {
	hints := buildProposalBatchExecutionHints("needs_schedule", map[string]interface{}{
		"environment": "prod",
		"status":      "pending",
		"next_action": "needs_schedule",
	}, "iket proposal batch blocked --env prod --status pending --next-action needs_schedule")
	if ready, _ := hints["ready_to_execute"].(bool); ready {
		t.Fatalf("expected schedule hints to not be ready to execute: %+v", hints)
	}
	if mode, _ := hints["execution_mode"].(string); mode != "inspection" {
		t.Fatalf("expected schedule hints to be inspection mode: %+v", hints)
	}
	if next, _ := hints["next_command"].(string); !strings.Contains(next, "iket proposal batch blocked") {
		t.Fatalf("unexpected schedule hint next command: %+v", hints)
	}
}
