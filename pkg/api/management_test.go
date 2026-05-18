package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/bhangun/iket/pkg/config"
	gatewaypkg "github.com/bhangun/iket/pkg/core/gateway"
	"github.com/bhangun/iket/pkg/logging"
	"github.com/gorilla/mux"
)

func newNotificationTestServer(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	var server *httptest.Server
	defer func() {
		if r := recover(); r != nil {
			t.Skipf("skipping webhook notification test in this environment: %v", r)
		}
	}()
	server = httptest.NewServer(handler)
	return server
}

func mustTestGateway(t *testing.T, cfg *config.Config) *gatewaypkg.Gateway {
	t.Helper()
	gw, err := gatewaypkg.NewGateway(gatewaypkg.Dependencies{Config: cfg, Logger: logging.NewLogger(false)}, "test")
	if err != nil {
		t.Fatalf("failed to create test gateway: %v", err)
	}
	return gw
}

func TestConfigChangeSummaryReportsChangedFields(t *testing.T) {
	current := &config.Config{
		Server:  config.ServerConfig{Port: 8080},
		Storage: config.StorageConfig{Mode: "postgres"},
	}
	next := &config.Config{
		Server:  config.ServerConfig{Port: 9090},
		Storage: config.StorageConfig{Mode: "postgres"},
	}

	summary := configChangeSummary(current, next)
	changedCount, ok := summary["changed_count"].(int)
	if !ok {
		t.Fatalf("expected changed_count to be an int, got %T", summary["changed_count"])
	}
	if changedCount == 0 {
		t.Fatalf("expected at least one changed field")
	}

	fields, ok := summary["changed_fields"].([]string)
	if !ok {
		t.Fatalf("expected changed_fields to be []string, got %T", summary["changed_fields"])
	}
	found := false
	for _, field := range fields {
		if field == "server.port" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected changed_fields to include server.port, got %v", fields)
	}
}

func TestServiceChangeSummaryReportsAddedRemovedAndUpdated(t *testing.T) {
	current := &config.Config{
		Services: []config.ServiceConfig{{
			Version: 1,
			Services: []config.Service{
				{
					Name:     "identity",
					Host:     "http://identity:8080",
					BasePath: "/v1",
					Routes: []config.RouterConfig{
						{Path: "/auth/{rest:.*}", Methods: []string{"GET"}},
						{Path: "/auth/{rest:.*}", Methods: []string{"POST"}},
					},
				},
			},
		}},
	}
	next := &config.Config{
		Services: []config.ServiceConfig{{
			Version: 1,
			Services: []config.Service{
				{
					Name:     "identity",
					Host:     "http://identity-v2:8080",
					BasePath: "/v1",
					Routes: []config.RouterConfig{
						{Path: "/auth/{rest:.*}", Methods: []string{"GET"}},
						{Path: "/profile", Methods: []string{"GET"}},
					},
				},
				{
					Name: "billing",
					Host: "http://billing:8080",
					Routes: []config.RouterConfig{
						{Path: "/invoices", Methods: []string{"GET"}},
					},
				},
			},
		}},
	}

	summary := serviceChangeSummary(current, next)

	addedServices, ok := summary["added_services"].([]string)
	if !ok {
		t.Fatalf("expected added_services to be []string, got %T", summary["added_services"])
	}
	if len(addedServices) != 1 || addedServices[0] != "billing" {
		t.Fatalf("unexpected added services: %v", addedServices)
	}

	updatedServices, ok := summary["updated_services"].([]string)
	if !ok {
		t.Fatalf("expected updated_services to be []string, got %T", summary["updated_services"])
	}
	if len(updatedServices) != 1 || updatedServices[0] != "identity" {
		t.Fatalf("unexpected updated services: %v", updatedServices)
	}

	removedRoutes, ok := summary["removed_routes"].([]map[string]interface{})
	if !ok {
		t.Fatalf("expected removed_routes to be []map[string]interface{}, got %T", summary["removed_routes"])
	}
	if len(removedRoutes) != 1 {
		t.Fatalf("expected one removed route, got %v", removedRoutes)
	}

	addedRoutes, ok := summary["added_routes"].([]map[string]interface{})
	if !ok {
		t.Fatalf("expected added_routes to be []map[string]interface{}, got %T", summary["added_routes"])
	}
	if len(addedRoutes) != 2 {
		t.Fatalf("expected two added routes, got %v", addedRoutes)
	}
}

func TestRouteChangeSummaryReportsUpdateFields(t *testing.T) {
	service := config.Service{Name: "identity", BasePath: "/v1"}
	current := &config.RouterConfig{
		Path:      "/auth/{rest:.*}",
		Methods:   []string{"GET"},
		StripPath: true,
	}
	next := &config.RouterConfig{
		Path:        "/auth/{rest:.*}",
		Methods:     []string{"GET", "POST"},
		StripPath:   false,
		RequireAuth: true,
	}

	summary := routeChangeSummary(current, next, service)
	if summary["action"] != "update" {
		t.Fatalf("expected update action, got %v", summary["action"])
	}
	changedFields, ok := summary["changed_fields"].([]string)
	if !ok {
		t.Fatalf("expected changed_fields to be []string, got %T", summary["changed_fields"])
	}
	if len(changedFields) == 0 {
		t.Fatalf("expected changed fields for route update")
	}
}

func TestConfigChangeSummaryReportsSectionNamesInConfigStyle(t *testing.T) {
	current := &config.Config{
		Server: config.ServerConfig{Port: 8080},
	}
	next := &config.Config{
		Server:  config.ServerConfig{Port: 8080},
		Storage: config.StorageConfig{Mode: "postgres"},
	}

	summary := configChangeSummary(current, next)
	sections, ok := summary["changed_sections"].([]string)
	if !ok {
		t.Fatalf("expected changed_sections to be []string, got %T", summary["changed_sections"])
	}
	found := false
	for _, section := range sections {
		if section == "storage" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected changed_sections to include storage, got %v", sections)
	}
}

func TestMutationActionScopesIncludeDomainAndHighImpact(t *testing.T) {
	scopes := mutationActionScopes("services_replace")
	if len(scopes) != 2 || scopes[0] != "services" || scopes[1] != "high_impact" {
		t.Fatalf("unexpected scopes for services_replace: %v", scopes)
	}
}

func TestMutationPolicyAppliesToConfiguredScope(t *testing.T) {
	policy := config.MutationPolicy{
		Enabled:        true,
		EnforcedScopes: []string{"services"},
	}
	if !mutationPolicyApplies("service_update", policy) {
		t.Fatalf("expected policy to apply to services scope")
	}
	if mutationPolicyApplies("route_update", policy) {
		t.Fatalf("did not expect services-only policy to apply to route_update")
	}
}

func TestMutationPolicyCanTargetOnlyHighImpactActions(t *testing.T) {
	policy := config.MutationPolicy{
		Enabled:        true,
		EnforcedScopes: []string{"high_impact"},
	}
	if !mutationPolicyApplies("service_delete", policy) {
		t.Fatalf("expected high_impact policy to apply to service_delete")
	}
	if mutationPolicyApplies("service_update", policy) {
		t.Fatalf("did not expect high_impact policy to apply to service_update")
	}
}

func TestProposalReviewMetadataFromRequestUsesRequestValues(t *testing.T) {
	req := httptest.NewRequest("POST", "/api/v1/proposals/prp-1/apply", nil)
	q := url.Values{}
	q.Set("reviewer", "ops-lead")
	q.Set("review_note", "Approved after staging verification")
	req.URL.RawQuery = q.Encode()

	reviewer, note := proposalReviewMetadataFromRequest(req, nil)
	if reviewer != "ops-lead" || note != "Approved after staging verification" {
		t.Fatalf("unexpected review metadata: reviewer=%q note=%q", reviewer, note)
	}
}

func TestProposalReviewMetadataFromRequestFallsBackToStoredRecord(t *testing.T) {
	record := &configProposalRecord{
		ReviewedBy: "platform-admin",
		ReviewNote: "Previously reviewed",
	}

	reviewer, note := proposalReviewMetadataFromRequest(nil, record)
	if reviewer != "platform-admin" || note != "Previously reviewed" {
		t.Fatalf("unexpected fallback review metadata: reviewer=%q note=%q", reviewer, note)
	}
}

func TestProposalProposerFromRequest(t *testing.T) {
	req := httptest.NewRequest("POST", "/api/v1/services?proposal=true", nil)
	q := url.Values{}
	q.Set("proposer", "deploy-bot")
	req.URL.RawQuery = q.Encode()

	if proposer := proposalProposerFromRequest(req); proposer != "deploy-bot" {
		t.Fatalf("unexpected proposer: %q", proposer)
	}
}

func TestProposalEnvironmentFromRequest(t *testing.T) {
	req := httptest.NewRequest("POST", "/api/v1/services?proposal=true", nil)
	q := url.Values{}
	q.Set("environment", "prod")
	req.URL.RawQuery = q.Encode()

	if environment := proposalEnvironmentFromRequest(req); environment != "prod" {
		t.Fatalf("unexpected environment: %q", environment)
	}
}

func TestEnforceProposalReviewerRejectsSelfApprovalWhenPolicyEnabled(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Security: config.SecurityConfig{
			MutationPolicy: config.MutationPolicy{
				Enabled:                              true,
				RequireDifferentReviewerForProposals: true,
			},
		},
	}
	gw, err := gatewaypkg.NewGateway(gatewaypkg.Dependencies{Config: cfg, Logger: logging.NewLogger(false)}, "test")
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}
	api := &ManagementAPI{gateway: gw}

	err = api.enforceProposalReviewer(&configProposalRecord{CreatedBy: "ops-lead"}, "ops-lead")
	if err == nil {
		t.Fatalf("expected self-approval to be rejected")
	}
}

func TestEnforceProposalReviewerAllowsDifferentReviewer(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Security: config.SecurityConfig{
			MutationPolicy: config.MutationPolicy{
				Enabled:                              true,
				RequireDifferentReviewerForProposals: true,
			},
		},
	}
	gw, err := gatewaypkg.NewGateway(gatewaypkg.Dependencies{Config: cfg, Logger: logging.NewLogger(false)}, "test")
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}
	api := &ManagementAPI{gateway: gw}

	if err := api.enforceProposalReviewer(&configProposalRecord{CreatedBy: "deploy-bot"}, "ops-lead"); err != nil {
		t.Fatalf("expected different reviewer to be allowed, got %v", err)
	}
}

func TestProposalApprovalCountCountsDistinctReviewers(t *testing.T) {
	record := &configProposalRecord{
		Approvals: []proposalApproval{
			{Reviewer: "ops-lead"},
			{Reviewer: "OPS-LEAD"},
			{Reviewer: "platform-admin"},
		},
	}
	if got := proposalApprovalCount(nil, record); got != 2 {
		t.Fatalf("expected 2 distinct approvals, got %d", got)
	}
}

func TestRequiredProposalApproversUsesPolicyForHighImpact(t *testing.T) {
	cfg := &config.Config{
		Security: config.SecurityConfig{
			MutationPolicy: config.MutationPolicy{
				Enabled:                            true,
				MinApproversForHighImpactProposals: 2,
			},
		},
	}
	record := &configProposalRecord{Action: "services_replace"}
	if got := requiredProposalApprovers(cfg, record); got != 2 {
		t.Fatalf("expected required approvers to be 2, got %d", got)
	}
}

func TestProposalStatusAfterApprovalBecomesApprovedWhenThresholdMet(t *testing.T) {
	cfg := &config.Config{
		Security: config.SecurityConfig{
			MutationPolicy: config.MutationPolicy{
				Enabled:                            true,
				MinApproversForHighImpactProposals: 2,
			},
		},
	}
	record := &configProposalRecord{
		Action: "services_replace",
		Approvals: []proposalApproval{
			{Reviewer: "ops-lead"},
			{Reviewer: "platform-admin"},
		},
	}
	if status := proposalStatusAfterApproval(cfg, record); status != "approved" {
		t.Fatalf("expected approved status, got %q", status)
	}
}

func TestProposalNotBeforeFromRequestParsesRFC3339(t *testing.T) {
	req := httptest.NewRequest("POST", "/api/v1/services?proposal=true", nil)
	q := url.Values{}
	q.Set("not_before", "2026-05-18T10:00:00Z")
	req.URL.RawQuery = q.Encode()

	got, err := proposalNotBeforeFromRequest(req)
	if err != nil {
		t.Fatalf("expected valid not_before, got %v", err)
	}
	if got.Format(time.RFC3339) != "2026-05-18T10:00:00Z" {
		t.Fatalf("unexpected parsed not_before: %s", got.Format(time.RFC3339))
	}
}

func TestEnforceProposalScheduleRequiresNotBeforeForHighImpactWhenEnabled(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Security: config.SecurityConfig{
			MutationPolicy: config.MutationPolicy{
				Enabled:                                true,
				RequireNotBeforeForHighImpactProposals: true,
			},
		},
	}
	gw, err := gatewaypkg.NewGateway(gatewaypkg.Dependencies{Config: cfg, Logger: logging.NewLogger(false)}, "test")
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}
	api := &ManagementAPI{gateway: gw}

	err = api.enforceProposalSchedule("services_replace", time.Time{})
	if err == nil {
		t.Fatalf("expected missing not_before to be rejected")
	}
}

func TestMutationWindowAppliesDefaultsToHighImpact(t *testing.T) {
	if !mutationWindowApplies("services_replace", nil) {
		t.Fatalf("expected empty blackout scopes to apply to high-impact action")
	}
	if mutationWindowApplies("service_update", nil) {
		t.Fatalf("did not expect empty blackout scopes to apply to non-high-impact action")
	}
}

func TestIsWithinBlockedApplyWindowMatchesSameDayWindow(t *testing.T) {
	now := time.Date(2026, time.May, 18, 2, 30, 0, 0, time.UTC)
	active, err := isWithinBlockedApplyWindow(now, config.MutationApplyWindow{
		Name:     "maintenance-freeze",
		Days:     []string{"mon"},
		Start:    "02:00",
		End:      "04:00",
		Timezone: "UTC",
	})
	if err != nil {
		t.Fatalf("expected blackout window evaluation to succeed, got %v", err)
	}
	if !active {
		t.Fatalf("expected blackout window to be active")
	}
}

func TestIsWithinBlockedApplyWindowMatchesOvernightWindow(t *testing.T) {
	now := time.Date(2026, time.May, 19, 1, 30, 0, 0, time.UTC)
	active, err := isWithinBlockedApplyWindow(now, config.MutationApplyWindow{
		Name:     "overnight-freeze",
		Days:     []string{"mon"},
		Start:    "22:00",
		End:      "03:00",
		Timezone: "UTC",
	})
	if err != nil {
		t.Fatalf("expected overnight blackout window evaluation to succeed, got %v", err)
	}
	if !active {
		t.Fatalf("expected overnight blackout window to remain active after midnight")
	}
}

func TestEnforceProposalBlackoutWindowRejectsBlockedApply(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Security: config.SecurityConfig{
			MutationPolicy: config.MutationPolicy{
				Enabled: true,
				BlockedApplyWindows: []config.MutationApplyWindow{
					{
						Name:     "freeze",
						Days:     []string{"mon"},
						Start:    "00:00",
						End:      "23:59",
						Timezone: "UTC",
					},
				},
			},
		},
	}
	gw, err := gatewaypkg.NewGateway(gatewaypkg.Dependencies{Config: cfg, Logger: logging.NewLogger(false)}, "test")
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}
	api := NewManagementAPI(gw, logging.NewLogger(false), nil)

	err = api.enforceProposalBlackoutWindow("services_replace", time.Date(2026, time.May, 18, 12, 0, 0, 0, time.UTC))
	if err == nil {
		t.Fatalf("expected blackout window to block apply")
	}
}

func TestProposalApprovalCountRespectsApprovalFreshness(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Security: config.SecurityConfig{
			MutationPolicy: config.MutationPolicy{
				Enabled:        true,
				MaxApprovalAge: "1h",
			},
		},
	}
	record := &configProposalRecord{
		Approvals: []proposalApproval{
			{Reviewer: "ops-a", CreatedAt: time.Now().UTC().Add(-30 * time.Minute)},
			{Reviewer: "ops-b", CreatedAt: time.Now().UTC().Add(-2 * time.Hour)},
		},
	}

	if got := proposalApprovalCount(cfg, record); got != 1 {
		t.Fatalf("expected only one fresh approval, got %d", got)
	}
}

func TestEnforceProposalExpirationMarksProposalExpired(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Security: config.SecurityConfig{
			MutationPolicy: config.MutationPolicy{
				Enabled:        true,
				MaxProposalAge: "1h",
			},
		},
	}
	gw, err := gatewaypkg.NewGateway(gatewaypkg.Dependencies{Config: cfg, Logger: logging.NewLogger(false)}, "test")
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}
	api := NewManagementAPI(gw, logging.NewLogger(false), nil)
	record := &configProposalRecord{
		ID:        "prp-expired",
		Action:    "services_replace",
		Status:    "approved",
		CreatedAt: time.Now().UTC().Add(-2 * time.Hour),
		Config:    &config.Config{Server: config.ServerConfig{Port: 8080}},
	}

	err = api.enforceProposalExpiration(record, time.Now().UTC())
	if err == nil {
		t.Fatalf("expected proposal expiration to be enforced")
	}
	if record.Status != "expired" {
		t.Fatalf("expected proposal status to become expired, got %q", record.Status)
	}
}

func TestPromoteProposalClonesEnvironmentAndLineage(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get working directory: %v", err)
	}
	tempDir := t.TempDir()
	if err := os.Chdir(tempDir); err != nil {
		t.Fatalf("failed to chdir temp dir: %v", err)
	}
	defer func() {
		_ = os.Chdir(wd)
	}()

	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Security: config.SecurityConfig{
			MutationPolicy: config.MutationPolicy{Enabled: true},
		},
	}
	gw, err := gatewaypkg.NewGateway(gatewaypkg.Dependencies{Config: cfg, Logger: logging.NewLogger(false)}, "test")
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}
	api := NewManagementAPI(gw, logging.NewLogger(false), nil)

	originalID, err := saveConfigProposal(
		"services_replace",
		"replace",
		"deploy-bot",
		"staging",
		"",
		"",
		nil,
		nil,
		nil,
		0,
		nil,
		0,
		0,
		"",
		false,
		"",
		"",
		"tenant-cutover",
		"Promote after staging signoff",
		"CHG-1001",
		time.Time{},
		2,
		map[string]interface{}{"action": "replace"},
		cfg,
	)
	if err != nil {
		t.Fatalf("failed to save original proposal: %v", err)
	}

	req := httptest.NewRequest("POST", "/api/v1/proposals/"+originalID+"/promote", nil)
	q := url.Values{}
	q.Set("environment", "prod")
	q.Set("proposer", "platform-admin")
	q.Set("not_before", "2026-05-18T02:00:00Z")
	req.URL.RawQuery = q.Encode()
	req = mux.SetURLVars(req, map[string]string{"id": originalID})
	w := httptest.NewRecorder()

	api.promoteProposal(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	proposals, err := listConfigProposals()
	if err != nil {
		t.Fatalf("failed to list proposals: %v", err)
	}
	if len(proposals) < 2 {
		t.Fatalf("expected promoted proposal to be created, got %d proposals", len(proposals))
	}

	newest, err := loadConfigProposal(proposals[0]["id"].(string))
	if err != nil {
		t.Fatalf("failed to load promoted proposal: %v", err)
	}
	if newest.PromotedFrom != originalID {
		t.Fatalf("expected promoted_from %q, got %q", originalID, newest.PromotedFrom)
	}
	if newest.Environment != "prod" {
		t.Fatalf("expected environment prod, got %q", newest.Environment)
	}
	if newest.CreatedBy != "platform-admin" {
		t.Fatalf("expected proposer platform-admin, got %q", newest.CreatedBy)
	}
	if len(newest.Approvals) != 0 {
		t.Fatalf("expected promoted proposal to reset approvals, got %d", len(newest.Approvals))
	}
}

func TestBuildProposalVerificationMatchesPromotedSource(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get working directory: %v", err)
	}
	tempDir := t.TempDir()
	if err := os.Chdir(tempDir); err != nil {
		t.Fatalf("failed to chdir temp dir: %v", err)
	}
	defer func() {
		_ = os.Chdir(wd)
	}()

	cfg := &config.Config{Server: config.ServerConfig{Port: 8080}}
	gw, err := gatewaypkg.NewGateway(gatewaypkg.Dependencies{Config: cfg, Logger: logging.NewLogger(false)}, "test")
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}
	api := NewManagementAPI(gw, logging.NewLogger(false), nil)

	sourceID, err := saveConfigProposal("services_replace", "replace", "deploy-bot", "staging", "", "", nil, nil, nil, 0, nil, 0, 0, "", false, "", "", "rollout", "stage approved", "CHG-1", time.Time{}, 1, map[string]interface{}{"action": "replace"}, cfg)
	if err != nil {
		t.Fatalf("failed to save source proposal: %v", err)
	}
	sourceRecord, err := loadConfigProposal(sourceID)
	if err != nil {
		t.Fatalf("failed to load source proposal: %v", err)
	}
	promotedID, err := saveConfigProposal("services_replace", "replace", "platform-admin", "prod", sourceID, sourceRecord.ConfigHash, nil, nil, nil, 0, nil, 0, 0, "", false, "", "", "rollout", "prod scheduled", "CHG-1", time.Time{}, 1, map[string]interface{}{"action": "replace"}, cfg)
	if err != nil {
		t.Fatalf("failed to save promoted proposal: %v", err)
	}
	record, err := loadConfigProposal(promotedID)
	if err != nil {
		t.Fatalf("failed to load promoted proposal: %v", err)
	}

	result, err := api.buildProposalVerification(record)
	if err != nil {
		t.Fatalf("expected proposal verification to succeed, got %v", err)
	}
	if integrityOK, _ := result["integrity_ok"].(bool); !integrityOK {
		t.Fatalf("expected integrity check to pass, got %v", result["integrity_ok"])
	}
	if matchesSource, _ := result["matches_source"].(bool); !matchesSource {
		t.Fatalf("expected promoted proposal to match source, got %v", result["matches_source"])
	}
}

func TestEnforceProposalVerificationRejectsDriftedPromotedProposal(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get working directory: %v", err)
	}
	tempDir := t.TempDir()
	if err := os.Chdir(tempDir); err != nil {
		t.Fatalf("failed to chdir temp dir: %v", err)
	}
	defer func() {
		_ = os.Chdir(wd)
	}()

	baseCfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Security: config.SecurityConfig{
			MutationPolicy: config.MutationPolicy{
				Enabled: true,
				RequireVerificationForPromotedHighImpactProposals: true,
			},
		},
	}
	gw, err := gatewaypkg.NewGateway(gatewaypkg.Dependencies{Config: baseCfg, Logger: logging.NewLogger(false)}, "test")
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}
	api := NewManagementAPI(gw, logging.NewLogger(false), nil)

	sourceID, err := saveConfigProposal("services_replace", "replace", "deploy-bot", "staging", "", "", nil, nil, nil, 0, nil, 0, 0, "", false, "", "", "rollout", "stage approved", "CHG-1", time.Time{}, 1, map[string]interface{}{"action": "replace"}, baseCfg)
	if err != nil {
		t.Fatalf("failed to save source proposal: %v", err)
	}
	sourceRecord, err := loadConfigProposal(sourceID)
	if err != nil {
		t.Fatalf("failed to load source proposal: %v", err)
	}

	driftedCfg, err := cloneConfig(baseCfg)
	if err != nil {
		t.Fatalf("failed to clone config: %v", err)
	}
	driftedCfg.Server.Port = 9090
	promotedID, err := saveConfigProposal("services_replace", "replace", "platform-admin", "prod", sourceID, sourceRecord.ConfigHash, nil, nil, nil, 0, nil, 0, 0, "", false, "", "", "rollout", "prod scheduled", "CHG-1", time.Time{}, 1, map[string]interface{}{"action": "replace"}, driftedCfg)
	if err != nil {
		t.Fatalf("failed to save promoted proposal: %v", err)
	}
	record, err := loadConfigProposal(promotedID)
	if err != nil {
		t.Fatalf("failed to load promoted proposal: %v", err)
	}

	err = api.enforceProposalVerification(record)
	if err == nil {
		t.Fatalf("expected drifted promoted proposal to be rejected")
	}
}

func TestEnforceProposalVerificationRejectsUnhealthyShadowEvaluation(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get working directory: %v", err)
	}
	tempDir := t.TempDir()
	if err := os.Chdir(tempDir); err != nil {
		t.Fatalf("failed to chdir temp dir: %v", err)
	}
	defer func() {
		_ = os.Chdir(wd)
	}()

	baseCfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Security: config.SecurityConfig{
			MutationPolicy: config.MutationPolicy{
				Enabled: true,
				RequireVerificationForPromotedHighImpactProposals:     true,
				RequireShadowEvaluationForPromotedHighImpactProposals: true,
			},
		},
		Services: []config.ServiceConfig{{
			Version: 1,
			Services: []config.Service{{
				Name: "identity",
				Host: "http://identity:8080",
				Routes: []config.RouterConfig{{
					Path:                  "/auth/{rest:.*}",
					Methods:               []string{"GET"},
					ShadowTrafficPercent:  10,
					ShadowMinRequests:     1,
					ShadowMaxLatencyDelta: "10ms",
					Backends: []config.Backend{{
						URLPattern: "/api/{rest:.*}",
					}},
				}},
			}},
		}},
	}
	gw, err := gatewaypkg.NewGateway(gatewaypkg.Dependencies{Config: baseCfg, Logger: logging.NewLogger(false)}, "test")
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}
	api := NewManagementAPI(gw, logging.NewLogger(false), nil)

	route := baseCfg.GetAllRoutesFromServices(logging.NewLogger(false))[0]
	backend := route.Backends[0]
	destination := strings.TrimSpace(route.ServiceHost)
	gw.RecordBackendSuccessForTest(route, backend, destination, http.StatusOK, 100*time.Millisecond, time.Now().UTC())
	gw.RecordShadowResultForTest(route, backend, destination, http.StatusOK, 140*time.Millisecond, nil)

	sourceID, err := saveConfigProposal("services_replace", "replace", "deploy-bot", "staging", "", "", nil, nil, nil, 0, nil, 0, 0, "", false, "", "", "rollout", "stage approved", "CHG-1", time.Time{}, 1, map[string]interface{}{"action": "replace"}, baseCfg)
	if err != nil {
		t.Fatalf("failed to save source proposal: %v", err)
	}
	sourceRecord, err := loadConfigProposal(sourceID)
	if err != nil {
		t.Fatalf("failed to load source proposal: %v", err)
	}
	promotedID, err := saveConfigProposal("services_replace", "replace", "platform-admin", "prod", sourceID, sourceRecord.ConfigHash, nil, nil, nil, 0, nil, 0, 0, "", false, "", "", "rollout", "prod scheduled", "CHG-1", time.Time{}, 1, map[string]interface{}{"action": "replace"}, baseCfg)
	if err != nil {
		t.Fatalf("failed to save promoted proposal: %v", err)
	}
	record, err := loadConfigProposal(promotedID)
	if err != nil {
		t.Fatalf("failed to load promoted proposal: %v", err)
	}

	err = api.enforceProposalVerification(record)
	if err == nil || !strings.Contains(err.Error(), "shadow evaluation") {
		t.Fatalf("expected unhealthy shadow evaluation to be rejected, got %v", err)
	}
}

func TestPromotedProposalRequiresHealthyShadowVerificationStreak(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get working directory: %v", err)
	}
	tempDir := t.TempDir()
	if err := os.Chdir(tempDir); err != nil {
		t.Fatalf("failed to chdir temp dir: %v", err)
	}
	defer func() {
		_ = os.Chdir(wd)
	}()

	baseCfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Security: config.SecurityConfig{
			MutationPolicy: config.MutationPolicy{
				Enabled: true,
				RequireVerificationForPromotedHighImpactProposals:           true,
				RequireShadowEvaluationForPromotedHighImpactProposals:       true,
				MinShadowHealthyVerificationsForPromotedHighImpactProposals: 2,
			},
		},
		Services: []config.ServiceConfig{{
			Version: 1,
			Services: []config.Service{{
				Name: "identity",
				Host: "http://identity:8080",
				Routes: []config.RouterConfig{{
					Path:                  "/auth/{rest:.*}",
					Methods:               []string{"GET"},
					ShadowTrafficPercent:  10,
					ShadowMinRequests:     1,
					ShadowMaxLatencyDelta: "50ms",
					Backends: []config.Backend{{
						URLPattern: "/api/{rest:.*}",
					}},
				}},
			}},
		}},
	}
	gw, err := gatewaypkg.NewGateway(gatewaypkg.Dependencies{Config: baseCfg, Logger: logging.NewLogger(false)}, "test")
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}
	api := NewManagementAPI(gw, logging.NewLogger(false), nil)

	route := baseCfg.GetAllRoutesFromServices(logging.NewLogger(false))[0]
	backend := route.Backends[0]
	destination := strings.TrimSpace(route.ServiceHost)
	gw.RecordBackendSuccessForTest(route, backend, destination, http.StatusOK, 100*time.Millisecond, time.Now().UTC())
	gw.RecordShadowResultForTest(route, backend, destination, http.StatusOK, 120*time.Millisecond, nil)

	sourceID, err := saveConfigProposal("services_replace", "replace", "deploy-bot", "staging", "", "", nil, nil, nil, 0, nil, 0, 0, "", false, "", "", "rollout", "stage approved", "CHG-2", time.Time{}, 1, map[string]interface{}{"action": "replace"}, baseCfg)
	if err != nil {
		t.Fatalf("failed to save source proposal: %v", err)
	}
	sourceRecord, err := loadConfigProposal(sourceID)
	if err != nil {
		t.Fatalf("failed to load source proposal: %v", err)
	}
	promotedID, err := saveConfigProposal("services_replace", "replace", "platform-admin", "prod", sourceID, sourceRecord.ConfigHash, nil, nil, nil, 0, nil, 0, 0, "", false, "", "", "rollout", "prod scheduled", "CHG-2", time.Time{}, 1, map[string]interface{}{"action": "replace"}, baseCfg)
	if err != nil {
		t.Fatalf("failed to save promoted proposal: %v", err)
	}
	record, err := loadConfigProposal(promotedID)
	if err != nil {
		t.Fatalf("failed to load promoted proposal: %v", err)
	}

	if err := api.enforceProposalVerification(record); err == nil || !strings.Contains(err.Error(), "current streak: 1") {
		t.Fatalf("expected first healthy shadow verification to be insufficient, got %v", err)
	}

	record, err = loadConfigProposal(promotedID)
	if err != nil {
		t.Fatalf("failed to reload proposal after first verification: %v", err)
	}
	if record.ShadowVerificationPasses != 1 {
		t.Fatalf("expected first healthy shadow verification streak to be 1, got %d", record.ShadowVerificationPasses)
	}

	if err := api.enforceProposalVerification(record); err != nil {
		t.Fatalf("expected verification to pass after second consecutive healthy check, got %v", err)
	}

	record, err = loadConfigProposal(promotedID)
	if err != nil {
		t.Fatalf("failed to reload proposal after second verification: %v", err)
	}
	if record.ShadowVerificationPasses != 2 {
		t.Fatalf("expected second healthy shadow verification streak to be 2, got %d", record.ShadowVerificationPasses)
	}
	if !record.ShadowReady || record.ShadowReadyAt.IsZero() {
		t.Fatalf("expected proposal to become shadow-ready after required streak, got ready=%v at=%v", record.ShadowReady, record.ShadowReadyAt)
	}
}

func TestBuildCanaryApplyConfigLimitsChangesToSelectedService(t *testing.T) {
	current := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Services: []config.ServiceConfig{{
			Version: 1,
			Services: []config.Service{
				{
					Name: "identity",
					Host: "http://identity-v1:8080",
					Routes: []config.RouterConfig{
						{Path: "/auth", Method: "GET", Backends: []config.Backend{{URLPattern: "/auth"}}},
					},
				},
				{
					Name: "billing",
					Host: "http://billing-v1:8080",
					Routes: []config.RouterConfig{
						{Path: "/invoices", Method: "GET", Backends: []config.Backend{{URLPattern: "/invoices"}}},
					},
				},
			},
		}},
	}
	proposalCfg, err := cloneConfig(current)
	if err != nil {
		t.Fatalf("failed to clone current config: %v", err)
	}
	proposalCfg.Services[0].Services[0].Host = "http://identity-v2:8080"
	proposalCfg.Services[0].Services[1].Host = "http://billing-v2:8080"

	gw, err := gatewaypkg.NewGateway(gatewaypkg.Dependencies{Config: current, Logger: logging.NewLogger(false)}, "test")
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}
	api := NewManagementAPI(gw, logging.NewLogger(false), nil)
	record := &configProposalRecord{
		Action:         "services_replace",
		Config:         proposalCfg,
		CanaryServices: []string{"identity"},
	}

	nextCfg, summary, err := api.buildCanaryApplyConfig(record)
	if err != nil {
		t.Fatalf("expected canary config build to succeed, got %v", err)
	}
	services := flattenServices(nextCfg)
	if services[0].Host != "http://identity-v2:8080" {
		t.Fatalf("expected identity service to use canary host, got %q", services[0].Host)
	}
	if services[1].Host != "http://billing-v1:8080" {
		t.Fatalf("expected billing service to stay unchanged, got %q", services[1].Host)
	}
	if canary, _ := summary["canary"].(bool); !canary {
		t.Fatalf("expected summary to mark canary apply")
	}
}

func TestBuildCanaryApplyConfigCreatesHeaderScopedCanaryService(t *testing.T) {
	current := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Services: []config.ServiceConfig{{
			Version: 1,
			Services: []config.Service{
				{
					Name: "identity",
					Host: "http://identity-v1:8080",
					Routes: []config.RouterConfig{
						{Path: "/auth", Method: "GET", Backends: []config.Backend{{URLPattern: "/auth"}}},
					},
				},
			},
		}},
	}
	proposalCfg, err := cloneConfig(current)
	if err != nil {
		t.Fatalf("failed to clone current config: %v", err)
	}
	proposalCfg.Services[0].Services[0].Host = "http://identity-v2:8080"

	gw, err := gatewaypkg.NewGateway(gatewaypkg.Dependencies{Config: current, Logger: logging.NewLogger(false)}, "test")
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}
	api := NewManagementAPI(gw, logging.NewLogger(false), nil)
	record := &configProposalRecord{
		Action:         "services_replace",
		Config:         proposalCfg,
		CanaryServices: []string{"identity"},
		CanaryHeaders:  []string{"X-Iket-Canary=identity-v2"},
	}

	nextCfg, summary, err := api.buildCanaryApplyConfig(record)
	if err != nil {
		t.Fatalf("expected header-scoped canary config build to succeed, got %v", err)
	}
	services := flattenServices(nextCfg)
	if len(services) != 2 {
		t.Fatalf("expected stable and canary services, got %d", len(services))
	}
	if services[0].Host != "http://identity-v1:8080" {
		t.Fatalf("expected stable service to remain unchanged, got %q", services[0].Host)
	}
	if services[1].Name != "identity__canary" {
		t.Fatalf("expected canary service name identity__canary, got %q", services[1].Name)
	}
	if services[1].Host != "http://identity-v2:8080" {
		t.Fatalf("expected canary service to use proposed host, got %q", services[1].Host)
	}
	if services[1].Routes[0].MatchHeaders["X-Iket-Canary"] != "identity-v2" {
		t.Fatalf("expected canary route to carry header matcher, got %v", services[1].Routes[0].MatchHeaders)
	}
	if strategy, _ := summary["canary_strategy"].(string); strategy != "header_scoped" {
		t.Fatalf("expected header_scoped canary strategy, got %q", strategy)
	}
}

func TestBuildCanaryApplyConfigCreatesPercentageScopedCanaryService(t *testing.T) {
	current := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Services: []config.ServiceConfig{{
			Version: 1,
			Services: []config.Service{
				{
					Name: "identity",
					Host: "http://identity-v1:8080",
					Routes: []config.RouterConfig{
						{Path: "/auth", Method: "GET", Backends: []config.Backend{{URLPattern: "/auth"}}},
					},
				},
			},
		}},
	}
	proposalCfg, err := cloneConfig(current)
	if err != nil {
		t.Fatalf("failed to clone current config: %v", err)
	}
	proposalCfg.Services[0].Services[0].Host = "http://identity-v2:8080"

	gw, err := gatewaypkg.NewGateway(gatewaypkg.Dependencies{Config: current, Logger: logging.NewLogger(false)}, "test")
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}
	api := NewManagementAPI(gw, logging.NewLogger(false), nil)
	record := &configProposalRecord{
		Action:         "services_replace",
		Config:         proposalCfg,
		CanaryServices: []string{"identity"},
		CanaryPercent:  25,
	}

	nextCfg, summary, err := api.buildCanaryApplyConfig(record)
	if err != nil {
		t.Fatalf("expected percentage canary config build to succeed, got %v", err)
	}
	services := flattenServices(nextCfg)
	if len(services) != 2 {
		t.Fatalf("expected stable and canary services, got %d", len(services))
	}
	if services[1].Routes[0].MatchPercent != 25 {
		t.Fatalf("expected canary route to carry 25 percent match, got %d", services[1].Routes[0].MatchPercent)
	}
	if strategy, _ := summary["canary_strategy"].(string); strategy != "percentage" {
		t.Fatalf("expected percentage canary strategy, got %q", strategy)
	}
}

func TestApplyProposalWithCanaryTransitionsToCanaryActive(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get working directory: %v", err)
	}
	tempDir := t.TempDir()
	if err := os.Chdir(tempDir); err != nil {
		t.Fatalf("failed to chdir temp dir: %v", err)
	}
	defer func() {
		_ = os.Chdir(wd)
	}()

	current := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Services: []config.ServiceConfig{{
			Version: 1,
			Services: []config.Service{
				{
					Name: "identity",
					Host: "http://identity-v1:8080",
					Routes: []config.RouterConfig{
						{Path: "/auth", Method: "GET", Backends: []config.Backend{{URLPattern: "/auth"}}},
					},
				},
				{
					Name: "billing",
					Host: "http://billing-v1:8080",
					Routes: []config.RouterConfig{
						{Path: "/invoices", Method: "GET", Backends: []config.Backend{{URLPattern: "/invoices"}}},
					},
				},
			},
		}},
	}
	proposalCfg, err := cloneConfig(current)
	if err != nil {
		t.Fatalf("failed to clone config: %v", err)
	}
	proposalCfg.Services[0].Services[0].Host = "http://identity-v2:8080"
	proposalCfg.Services[0].Services[1].Host = "http://billing-v2:8080"

	gw, err := gatewaypkg.NewGateway(gatewaypkg.Dependencies{Config: current, Logger: logging.NewLogger(false)}, "test")
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}
	api := NewManagementAPI(gw, logging.NewLogger(false), nil)

	proposalID, err := saveConfigProposal("services_replace", "replace", "deploy-bot", "staging", "", "", []string{"identity"}, nil, nil, 0, nil, 0, 0, "", false, "", "", "rollout", "canary start", "CHG-2", time.Time{}, 1, map[string]interface{}{"action": "replace"}, proposalCfg)
	if err != nil {
		t.Fatalf("failed to save proposal: %v", err)
	}

	req := httptest.NewRequest("POST", "/api/v1/proposals/"+proposalID+"/apply?reviewer=ops-lead", nil)
	req = mux.SetURLVars(req, map[string]string{"id": proposalID})
	w := httptest.NewRecorder()

	api.applyProposal(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	record, err := loadConfigProposal(proposalID)
	if err != nil {
		t.Fatalf("failed to load proposal: %v", err)
	}
	if record.Status != "canary_active" {
		t.Fatalf("expected proposal status canary_active, got %q", record.Status)
	}

	services := flattenServices(gw.GetConfig())
	if services[0].Host != "http://identity-v2:8080" {
		t.Fatalf("expected identity to be updated during canary apply, got %q", services[0].Host)
	}
	if services[1].Host != "http://billing-v1:8080" {
		t.Fatalf("expected billing to remain unchanged during canary apply, got %q", services[1].Host)
	}
}

func TestCompleteProposalCanaryAppliesFullProposal(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get working directory: %v", err)
	}
	tempDir := t.TempDir()
	if err := os.Chdir(tempDir); err != nil {
		t.Fatalf("failed to chdir temp dir: %v", err)
	}
	defer func() {
		_ = os.Chdir(wd)
	}()

	current := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Services: []config.ServiceConfig{{
			Version: 1,
			Services: []config.Service{
				{
					Name: "identity",
					Host: "http://identity-v2:8080",
					Routes: []config.RouterConfig{
						{Path: "/auth", Method: "GET", Backends: []config.Backend{{URLPattern: "/auth"}}},
					},
				},
				{
					Name: "billing",
					Host: "http://billing-v1:8080",
					Routes: []config.RouterConfig{
						{Path: "/invoices", Method: "GET", Backends: []config.Backend{{URLPattern: "/invoices"}}},
					},
				},
			},
		}},
	}
	proposalCfg, err := cloneConfig(current)
	if err != nil {
		t.Fatalf("failed to clone config: %v", err)
	}
	proposalCfg.Services[0].Services[1].Host = "http://billing-v2:8080"

	gw, err := gatewaypkg.NewGateway(gatewaypkg.Dependencies{Config: current, Logger: logging.NewLogger(false)}, "test")
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}
	api := NewManagementAPI(gw, logging.NewLogger(false), nil)

	proposalID, err := saveConfigProposal("services_replace", "replace", "deploy-bot", "staging", "", "", []string{"identity"}, nil, nil, 0, nil, 0, 0, "", false, "", "", "rollout", "canary finish", "CHG-3", time.Time{}, 1, map[string]interface{}{"action": "replace"}, proposalCfg)
	if err != nil {
		t.Fatalf("failed to save proposal: %v", err)
	}
	proposalRecord, err := loadConfigProposal(proposalID)
	if err != nil {
		t.Fatalf("failed to load proposal: %v", err)
	}
	proposalRecord.Status = "canary_active"
	if err := saveConfigProposalRecord(proposalRecord); err != nil {
		t.Fatalf("failed to persist canary-active status: %v", err)
	}

	req := httptest.NewRequest("POST", "/api/v1/proposals/"+proposalID+"/canary/complete?reviewer=ops-lead", nil)
	req = mux.SetURLVars(req, map[string]string{"id": proposalID})
	w := httptest.NewRecorder()

	api.completeProposalCanary(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	proposalRecord, err = loadConfigProposal(proposalID)
	if err != nil {
		t.Fatalf("failed to reload proposal: %v", err)
	}
	if proposalRecord.Status != "applied" {
		t.Fatalf("expected proposal status applied, got %q", proposalRecord.Status)
	}

	services := flattenServices(gw.GetConfig())
	if services[1].Host != "http://billing-v2:8080" {
		t.Fatalf("expected billing to be updated on canary completion, got %q", services[1].Host)
	}
}

func TestEvaluateProposalCanaryAndBlockCompletionWhenThresholdsFail(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get working directory: %v", err)
	}
	tempDir := t.TempDir()
	if err := os.Chdir(tempDir); err != nil {
		t.Fatalf("failed to chdir temp dir: %v", err)
	}
	defer func() {
		_ = os.Chdir(wd)
	}()

	current := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Services: []config.ServiceConfig{{
			Version: 1,
			Services: []config.Service{
				{
					Name: "identity",
					Host: "http://identity-v1:8080",
					Routes: []config.RouterConfig{
						{Path: "/auth", Method: "GET", Backends: []config.Backend{{URLPattern: "/auth"}}},
					},
				},
			},
		}},
	}
	proposalCfg, err := cloneConfig(current)
	if err != nil {
		t.Fatalf("failed to clone config: %v", err)
	}
	proposalCfg.Services[0].Services[0].Host = "http://identity-v2:8080"

	logger := logging.NewLogger(false)
	gw, err := gatewaypkg.NewGateway(gatewaypkg.Dependencies{Config: current, Logger: logger}, "test")
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}
	api := NewManagementAPI(gw, logger, nil)

	proposalID, err := saveConfigProposal("services_replace", "replace", "deploy-bot", "staging", "", "", []string{"identity"}, nil, nil, 10, nil, 1, 0.10, "500ms", false, "", "", "rollout", "guarded canary", "CHG-4", time.Time{}, 1, map[string]interface{}{"action": "replace"}, proposalCfg)
	if err != nil {
		t.Fatalf("failed to save proposal: %v", err)
	}

	applyReq := httptest.NewRequest("POST", "/api/v1/proposals/"+proposalID+"/apply?reviewer=ops-lead", nil)
	applyReq = mux.SetURLVars(applyReq, map[string]string{"id": proposalID})
	applyResp := httptest.NewRecorder()
	api.applyProposal(applyResp, applyReq)
	if applyResp.Code != http.StatusOK {
		t.Fatalf("expected 200 from initial guarded canary apply, got %d: %s", applyResp.Code, applyResp.Body.String())
	}

	logger.Info("HTTP request",
		logging.String("service_name", "identity__canary"),
		logging.String("route_name", "/auth"),
		logging.Int("status_code", 500),
		logging.Duration("duration", 800*time.Millisecond),
	)

	evalReq := httptest.NewRequest("GET", "/api/v1/proposals/"+proposalID+"/canary/evaluate", nil)
	evalReq = mux.SetURLVars(evalReq, map[string]string{"id": proposalID})
	evalResp := httptest.NewRecorder()
	api.evaluateProposalCanary(evalResp, evalReq)
	if evalResp.Code != http.StatusOK {
		t.Fatalf("expected 200 from canary evaluation, got %d: %s", evalResp.Code, evalResp.Body.String())
	}
	if !strings.Contains(evalResp.Body.String(), `"healthy":false`) {
		t.Fatalf("expected unhealthy canary evaluation, got %s", evalResp.Body.String())
	}

	completeReq := httptest.NewRequest("POST", "/api/v1/proposals/"+proposalID+"/canary/complete?reviewer=ops-lead", nil)
	completeReq = mux.SetURLVars(completeReq, map[string]string{"id": proposalID})
	completeResp := httptest.NewRecorder()
	api.completeProposalCanary(completeResp, completeReq)
	if completeResp.Code != http.StatusOK {
		t.Fatalf("expected 200 with rollback payload when guarded canary fails thresholds, got %d: %s", completeResp.Code, completeResp.Body.String())
	}
	record, err := loadConfigProposal(proposalID)
	if err != nil {
		t.Fatalf("failed to reload proposal after rollback: %v", err)
	}
	if record.Status != "canary_aborted" {
		t.Fatalf("expected proposal status canary_aborted after rollback, got %q", record.Status)
	}
	services := flattenServices(gw.GetConfig())
	if services[0].Host != "http://identity-v1:8080" {
		t.Fatalf("expected rollback to restore identity-v1, got %q", services[0].Host)
	}
}

func TestAdvanceProposalCanaryMovesToNextStep(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get working directory: %v", err)
	}
	tempDir := t.TempDir()
	if err := os.Chdir(tempDir); err != nil {
		t.Fatalf("failed to chdir temp dir: %v", err)
	}
	defer func() {
		_ = os.Chdir(wd)
	}()

	current := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Services: []config.ServiceConfig{{
			Version: 1,
			Services: []config.Service{
				{
					Name: "identity",
					Host: "http://identity-v1:8080",
					Routes: []config.RouterConfig{
						{Path: "/auth", Method: "GET", Backends: []config.Backend{{URLPattern: "/auth"}}},
					},
				},
			},
		}},
	}
	proposalCfg, err := cloneConfig(current)
	if err != nil {
		t.Fatalf("failed to clone config: %v", err)
	}
	proposalCfg.Services[0].Services[0].Host = "http://identity-v2:8080"

	logger := logging.NewLogger(false)
	gw, err := gatewaypkg.NewGateway(gatewaypkg.Dependencies{Config: current, Logger: logger}, "test")
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}
	api := NewManagementAPI(gw, logger, nil)

	proposalID, err := saveConfigProposal("services_replace", "replace", "deploy-bot", "staging", "", "", []string{"identity"}, nil, nil, 10, []int{10, 25, 100}, 0, 0, "", false, "", "", "rollout", "step canary", "CHG-5", time.Time{}, 1, map[string]interface{}{"action": "replace"}, proposalCfg)
	if err != nil {
		t.Fatalf("failed to save proposal: %v", err)
	}

	applyReq := httptest.NewRequest("POST", "/api/v1/proposals/"+proposalID+"/apply?reviewer=ops-lead", nil)
	applyReq = mux.SetURLVars(applyReq, map[string]string{"id": proposalID})
	applyResp := httptest.NewRecorder()
	api.applyProposal(applyResp, applyReq)
	if applyResp.Code != http.StatusOK {
		t.Fatalf("expected 200 from initial canary apply, got %d: %s", applyResp.Code, applyResp.Body.String())
	}

	advanceReq := httptest.NewRequest("POST", "/api/v1/proposals/"+proposalID+"/canary/advance?reviewer=ops-lead", nil)
	advanceReq = mux.SetURLVars(advanceReq, map[string]string{"id": proposalID})
	advanceResp := httptest.NewRecorder()
	api.advanceProposalCanary(advanceResp, advanceReq)
	if advanceResp.Code != http.StatusOK {
		t.Fatalf("expected 200 from canary advance, got %d: %s", advanceResp.Code, advanceResp.Body.String())
	}

	record, err := loadConfigProposal(proposalID)
	if err != nil {
		t.Fatalf("failed to reload proposal: %v", err)
	}
	if record.CanaryPercent != 25 {
		t.Fatalf("expected canary percent 25 after advance, got %d", record.CanaryPercent)
	}

	services := flattenServices(gw.GetConfig())
	found := false
	for _, svc := range services {
		if svc.Name != "identity__canary" {
			continue
		}
		found = true
		if len(svc.Routes) == 0 || svc.Routes[0].MatchPercent != 25 {
			t.Fatalf("expected canary route matchPercent 25, got %+v", svc.Routes)
		}
	}
	if !found {
		t.Fatalf("expected identity__canary service to exist after advance")
	}
}

func TestReconcileProposalCanaryAdvancesHealthyStep(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get working directory: %v", err)
	}
	tempDir := t.TempDir()
	if err := os.Chdir(tempDir); err != nil {
		t.Fatalf("failed to chdir temp dir: %v", err)
	}
	defer func() {
		_ = os.Chdir(wd)
	}()

	current := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Services: []config.ServiceConfig{{
			Version: 1,
			Services: []config.Service{
				{
					Name: "identity",
					Host: "http://identity-v1:8080",
					Routes: []config.RouterConfig{
						{Path: "/auth", Method: "GET", Backends: []config.Backend{{URLPattern: "/auth"}}},
					},
				},
			},
		}},
	}
	proposalCfg, err := cloneConfig(current)
	if err != nil {
		t.Fatalf("failed to clone config: %v", err)
	}
	proposalCfg.Services[0].Services[0].Host = "http://identity-v2:8080"

	logger := logging.NewLogger(false)
	gw, err := gatewaypkg.NewGateway(gatewaypkg.Dependencies{Config: current, Logger: logger}, "test")
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}
	api := NewManagementAPI(gw, logger, nil)

	proposalID, err := saveConfigProposal("services_replace", "replace", "deploy-bot", "staging", "", "", []string{"identity"}, nil, nil, 10, []int{10, 25, 100}, 0, 0, "", false, "", "", "rollout", "step canary", "CHG-6", time.Time{}, 1, map[string]interface{}{"action": "replace"}, proposalCfg)
	if err != nil {
		t.Fatalf("failed to save proposal: %v", err)
	}

	applyReq := httptest.NewRequest("POST", "/api/v1/proposals/"+proposalID+"/apply?reviewer=ops-lead", nil)
	applyReq = mux.SetURLVars(applyReq, map[string]string{"id": proposalID})
	applyResp := httptest.NewRecorder()
	api.applyProposal(applyResp, applyReq)
	if applyResp.Code != http.StatusOK {
		t.Fatalf("expected 200 from initial canary apply, got %d: %s", applyResp.Code, applyResp.Body.String())
	}

	reconcileReq := httptest.NewRequest("POST", "/api/v1/proposals/"+proposalID+"/canary/reconcile?reviewer=ops-lead", nil)
	reconcileReq = mux.SetURLVars(reconcileReq, map[string]string{"id": proposalID})
	reconcileResp := httptest.NewRecorder()
	api.reconcileProposalCanary(reconcileResp, reconcileReq)
	if reconcileResp.Code != http.StatusOK {
		t.Fatalf("expected 200 from canary reconcile, got %d: %s", reconcileResp.Code, reconcileResp.Body.String())
	}
	if !strings.Contains(reconcileResp.Body.String(), `"action_taken":"advance"`) {
		t.Fatalf("expected reconcile to advance canary, got %s", reconcileResp.Body.String())
	}

	record, err := loadConfigProposal(proposalID)
	if err != nil {
		t.Fatalf("failed to reload proposal: %v", err)
	}
	if record.CanaryPercent != 25 {
		t.Fatalf("expected canary percent 25 after reconcile, got %d", record.CanaryPercent)
	}
}

func TestReconcileProposalCanaryRollsBackUnhealthyCanary(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get working directory: %v", err)
	}
	tempDir := t.TempDir()
	if err := os.Chdir(tempDir); err != nil {
		t.Fatalf("failed to chdir temp dir: %v", err)
	}
	defer func() {
		_ = os.Chdir(wd)
	}()

	current := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Services: []config.ServiceConfig{{
			Version: 1,
			Services: []config.Service{
				{
					Name: "identity",
					Host: "http://identity-v1:8080",
					Routes: []config.RouterConfig{
						{Path: "/auth", Method: "GET", Backends: []config.Backend{{URLPattern: "/auth"}}},
					},
				},
			},
		}},
	}
	proposalCfg, err := cloneConfig(current)
	if err != nil {
		t.Fatalf("failed to clone config: %v", err)
	}
	proposalCfg.Services[0].Services[0].Host = "http://identity-v2:8080"

	logger := logging.NewLogger(false)
	gw, err := gatewaypkg.NewGateway(gatewaypkg.Dependencies{Config: current, Logger: logger}, "test")
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}
	api := NewManagementAPI(gw, logger, nil)

	proposalID, err := saveConfigProposal("services_replace", "replace", "deploy-bot", "staging", "", "", []string{"identity"}, nil, nil, 10, []int{10, 25, 100}, 1, 0.10, "500ms", false, "", "", "rollout", "guarded canary", "CHG-7", time.Time{}, 1, map[string]interface{}{"action": "replace"}, proposalCfg)
	if err != nil {
		t.Fatalf("failed to save proposal: %v", err)
	}

	applyReq := httptest.NewRequest("POST", "/api/v1/proposals/"+proposalID+"/apply?reviewer=ops-lead", nil)
	applyReq = mux.SetURLVars(applyReq, map[string]string{"id": proposalID})
	applyResp := httptest.NewRecorder()
	api.applyProposal(applyResp, applyReq)
	if applyResp.Code != http.StatusOK {
		t.Fatalf("expected 200 from initial canary apply, got %d: %s", applyResp.Code, applyResp.Body.String())
	}

	logger.Info("HTTP request",
		logging.String("service_name", "identity__canary"),
		logging.String("route_name", "/auth"),
		logging.Int("status_code", 500),
		logging.Duration("duration", 800*time.Millisecond),
	)

	reconcileReq := httptest.NewRequest("POST", "/api/v1/proposals/"+proposalID+"/canary/reconcile?reviewer=ops-lead", nil)
	reconcileReq = mux.SetURLVars(reconcileReq, map[string]string{"id": proposalID})
	reconcileResp := httptest.NewRecorder()
	api.reconcileProposalCanary(reconcileResp, reconcileReq)
	if reconcileResp.Code != http.StatusOK {
		t.Fatalf("expected 200 from canary reconcile rollback, got %d: %s", reconcileResp.Code, reconcileResp.Body.String())
	}
	if !strings.Contains(reconcileResp.Body.String(), `"action_taken":"rollback"`) {
		t.Fatalf("expected reconcile to roll back canary, got %s", reconcileResp.Body.String())
	}

	record, err := loadConfigProposal(proposalID)
	if err != nil {
		t.Fatalf("failed to reload proposal after rollback: %v", err)
	}
	if record.Status != "canary_aborted" {
		t.Fatalf("expected proposal status canary_aborted after reconcile rollback, got %q", record.Status)
	}
	services := flattenServices(gw.GetConfig())
	if services[0].Host != "http://identity-v1:8080" {
		t.Fatalf("expected rollback to restore identity-v1, got %q", services[0].Host)
	}
}

func TestAutoReconcileCanaryAdvancesWhenDue(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get working directory: %v", err)
	}
	tempDir := t.TempDir()
	if err := os.Chdir(tempDir); err != nil {
		t.Fatalf("failed to chdir temp dir: %v", err)
	}
	defer func() {
		_ = os.Chdir(wd)
	}()

	current := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Services: []config.ServiceConfig{{
			Version: 1,
			Services: []config.Service{
				{
					Name: "identity",
					Host: "http://identity-v1:8080",
					Routes: []config.RouterConfig{
						{Path: "/auth", Method: "GET", Backends: []config.Backend{{URLPattern: "/auth"}}},
					},
				},
			},
		}},
	}
	proposalCfg, err := cloneConfig(current)
	if err != nil {
		t.Fatalf("failed to clone config: %v", err)
	}
	proposalCfg.Services[0].Services[0].Host = "http://identity-v2:8080"

	logger := logging.NewLogger(false)
	gw, err := gatewaypkg.NewGateway(gatewaypkg.Dependencies{Config: current, Logger: logger}, "test")
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}
	api := NewManagementAPI(gw, logger, nil)

	proposalID, err := saveConfigProposal("services_replace", "replace", "deploy-bot", "staging", "", "", []string{"identity"}, nil, nil, 10, []int{10, 25, 100}, 0, 0, "", true, "1s", "ops-bot", "rollout", "auto step canary", "CHG-8", time.Time{}, 1, map[string]interface{}{"action": "replace"}, proposalCfg)
	if err != nil {
		t.Fatalf("failed to save proposal: %v", err)
	}

	applyReq := httptest.NewRequest("POST", "/api/v1/proposals/"+proposalID+"/apply?reviewer=ops-lead", nil)
	applyReq = mux.SetURLVars(applyReq, map[string]string{"id": proposalID})
	applyResp := httptest.NewRecorder()
	api.applyProposal(applyResp, applyReq)
	if applyResp.Code != http.StatusOK {
		t.Fatalf("expected 200 from initial canary apply, got %d: %s", applyResp.Code, applyResp.Body.String())
	}

	record, err := loadConfigProposal(proposalID)
	if err != nil {
		t.Fatalf("failed to reload proposal: %v", err)
	}
	if record.CanaryNextReconcile.IsZero() {
		t.Fatalf("expected active auto canary to schedule next reconcile")
	}

	api.reconcileAutoCanaries(record.CanaryNextReconcile.Add(10 * time.Millisecond))

	record, err = loadConfigProposal(proposalID)
	if err != nil {
		t.Fatalf("failed to reload proposal after auto reconcile: %v", err)
	}
	if record.CanaryPercent != 25 {
		t.Fatalf("expected canary percent 25 after automatic reconcile, got %d", record.CanaryPercent)
	}
	if record.ReviewedBy != "ops-bot" {
		t.Fatalf("expected automatic reconcile reviewer ops-bot, got %q", record.ReviewedBy)
	}
}

func TestApproveProposalEmitsNotificationWebhook(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get working directory: %v", err)
	}
	tempDir := t.TempDir()
	if err := os.Chdir(tempDir); err != nil {
		t.Fatalf("failed to chdir temp dir: %v", err)
	}
	defer func() {
		_ = os.Chdir(wd)
	}()

	eventCh := make(chan map[string]interface{}, 1)
	headerCh := make(chan http.Header, 1)
	bodyCh := make(chan []byte, 1)
	server := newNotificationTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		rawBody, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("failed to read webhook body: %v", err)
		}
		var payload map[string]interface{}
		if err := json.Unmarshal(rawBody, &payload); err != nil {
			t.Fatalf("failed to decode webhook payload: %v", err)
		}
		headerCh <- r.Header.Clone()
		bodyCh <- rawBody
		eventCh <- payload
		w.WriteHeader(http.StatusNoContent)
	})
	defer server.Close()

	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Security: config.SecurityConfig{
			NotificationWebhooks: []config.NotificationWebhook{
				{
					URL:             server.URL,
					Events:          []string{"proposal.approved"},
					Timeout:         "2s",
					SigningSecret:   "super-secret",
					SignatureHeader: "X-Test-Signature",
					TimestampHeader: "X-Test-Timestamp",
				},
			},
		},
	}
	gw, err := gatewaypkg.NewGateway(gatewaypkg.Dependencies{Config: cfg, Logger: logging.NewLogger(false)}, "test")
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}
	api := NewManagementAPI(gw, logging.NewLogger(false), nil)

	proposalID, err := saveConfigProposal("services_replace", "replace", "deploy-bot", "staging", "", "", nil, nil, nil, 0, nil, 0, 0, "", false, "", "", "rollout", "notify approval", "CHG-N1", time.Time{}, 1, map[string]interface{}{"action": "replace"}, cfg)
	if err != nil {
		t.Fatalf("failed to save proposal: %v", err)
	}

	req := httptest.NewRequest("POST", "/api/v1/proposals/"+proposalID+"/approve?reviewer=ops-lead&review_note=Approved", nil)
	req = mux.SetURLVars(req, map[string]string{"id": proposalID})
	w := httptest.NewRecorder()
	api.approveProposal(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	select {
	case payload := <-eventCh:
		headers := <-headerCh
		rawBody := <-bodyCh
		if payload["event"] != "proposal.approved" {
			t.Fatalf("expected proposal.approved event, got %v", payload["event"])
		}
		if payload["proposal_id"] != proposalID {
			t.Fatalf("expected proposal id %s, got %v", proposalID, payload["proposal_id"])
		}
		if payload["reviewer"] != "ops-lead" {
			t.Fatalf("expected reviewer ops-lead, got %v", payload["reviewer"])
		}
		timestamp := headers.Get("X-Test-Timestamp")
		if timestamp == "" {
			t.Fatalf("expected X-Test-Timestamp header to be set")
		}
		expectedSignature := signNotificationWebhook("super-secret", timestamp, rawBody)
		if headers.Get("X-Test-Signature") != expectedSignature {
			t.Fatalf("expected signed webhook header %q, got %q", expectedSignature, headers.Get("X-Test-Signature"))
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for webhook event")
	}
}

func TestApproveProposalEmitsSlackFormattedNotification(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get working directory: %v", err)
	}
	tempDir := t.TempDir()
	if err := os.Chdir(tempDir); err != nil {
		t.Fatalf("failed to chdir temp dir: %v", err)
	}
	defer func() {
		_ = os.Chdir(wd)
	}()

	bodyCh := make(chan map[string]interface{}, 1)
	server := newNotificationTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		var payload map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatalf("failed to decode slack webhook payload: %v", err)
		}
		bodyCh <- payload
		w.WriteHeader(http.StatusNoContent)
	})
	defer server.Close()

	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Security: config.SecurityConfig{
			NotificationWebhooks: []config.NotificationWebhook{
				{
					URL:    server.URL,
					Format: "slack",
					Events: []string{"proposal.approved"},
				},
			},
		},
	}
	gw, err := gatewaypkg.NewGateway(gatewaypkg.Dependencies{Config: cfg, Logger: logging.NewLogger(false)}, "test")
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}
	api := NewManagementAPI(gw, logging.NewLogger(false), nil)

	proposalID, err := saveConfigProposal("services_replace", "replace", "deploy-bot", "prod", "", "", nil, nil, nil, 0, nil, 0, 0, "", false, "", "", "rollout", "notify slack", "CHG-N2", time.Time{}, 1, map[string]interface{}{"action": "replace"}, cfg)
	if err != nil {
		t.Fatalf("failed to save proposal: %v", err)
	}

	req := httptest.NewRequest("POST", "/api/v1/proposals/"+proposalID+"/approve?reviewer=ops-lead", nil)
	req = mux.SetURLVars(req, map[string]string{"id": proposalID})
	w := httptest.NewRecorder()
	api.approveProposal(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	select {
	case payload := <-bodyCh:
		text, _ := payload["text"].(string)
		if !strings.Contains(text, "proposal.approved") {
			t.Fatalf("expected slack text to contain event, got %q", text)
		}
		if !strings.Contains(text, proposalID) {
			t.Fatalf("expected slack text to contain proposal id, got %q", text)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for slack webhook event")
	}
}

func TestApproveProposalRetriesWebhookAndPersistsDeliveryHistory(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get working directory: %v", err)
	}
	tempDir := t.TempDir()
	if err := os.Chdir(tempDir); err != nil {
		t.Fatalf("failed to chdir temp dir: %v", err)
	}
	defer func() {
		_ = os.Chdir(wd)
	}()

	requests := 0
	server := newNotificationTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		requests++
		if requests == 1 {
			http.Error(w, "try again", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	defer server.Close()

	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Security: config.SecurityConfig{
			NotificationWebhooks: []config.NotificationWebhook{
				{
					Name:         "ops-events",
					URL:          server.URL,
					Events:       []string{"proposal.approved"},
					RetryCount:   1,
					RetryBackoff: "1ms",
				},
			},
		},
	}
	gw, err := gatewaypkg.NewGateway(gatewaypkg.Dependencies{Config: cfg, Logger: logging.NewLogger(false)}, "test")
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}
	api := NewManagementAPI(gw, logging.NewLogger(false), nil)

	proposalID, err := saveConfigProposal("services_replace", "replace", "deploy-bot", "staging", "", "", nil, nil, nil, 0, nil, 0, 0, "", false, "", "", "rollout", "retry delivery", "CHG-N3", time.Time{}, 1, map[string]interface{}{"action": "replace"}, cfg)
	if err != nil {
		t.Fatalf("failed to save proposal: %v", err)
	}

	req := httptest.NewRequest("POST", "/api/v1/proposals/"+proposalID+"/approve?reviewer=ops-lead", nil)
	req = mux.SetURLVars(req, map[string]string{"id": proposalID})
	w := httptest.NewRecorder()
	api.approveProposal(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	if requests != 2 {
		t.Fatalf("expected webhook retry to send 2 requests, got %d", requests)
	}

	deliveries, err := listNotificationDeliveryRecords()
	if err != nil {
		t.Fatalf("failed to list notification deliveries: %v", err)
	}
	if len(deliveries) != 1 {
		t.Fatalf("expected 1 persisted delivery record, got %d", len(deliveries))
	}
	if deliveries[0]["success"] != true {
		t.Fatalf("expected persisted delivery to be successful, got %v", deliveries[0]["success"])
	}
	if deliveries[0]["attempts"] != float64(2) && deliveries[0]["attempts"] != 2 {
		t.Fatalf("expected persisted delivery attempts to be 2, got %v", deliveries[0]["attempts"])
	}
}

func TestReplayNotificationDeliveryCreatesNewDeliveryRecord(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get working directory: %v", err)
	}
	tempDir := t.TempDir()
	if err := os.Chdir(tempDir); err != nil {
		t.Fatalf("failed to chdir temp dir: %v", err)
	}
	defer func() {
		_ = os.Chdir(wd)
	}()

	requests := 0
	server := newNotificationTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.WriteHeader(http.StatusNoContent)
	})
	defer server.Close()

	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Security: config.SecurityConfig{
			NotificationWebhooks: []config.NotificationWebhook{
				{
					Name:   "ops-events",
					URL:    server.URL,
					Events: []string{"proposal.approved"},
				},
			},
		},
	}
	gw, err := gatewaypkg.NewGateway(gatewaypkg.Dependencies{Config: cfg, Logger: logging.NewLogger(false)}, "test")
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}
	api := NewManagementAPI(gw, logging.NewLogger(false), nil)

	proposalID, err := saveConfigProposal("services_replace", "replace", "deploy-bot", "staging", "", "", nil, nil, nil, 0, nil, 0, 0, "", false, "", "", "rollout", "replay delivery", "CHG-N4", time.Time{}, 1, map[string]interface{}{"action": "replace"}, cfg)
	if err != nil {
		t.Fatalf("failed to save proposal: %v", err)
	}

	approveReq := httptest.NewRequest("POST", "/api/v1/proposals/"+proposalID+"/approve?reviewer=ops-lead", nil)
	approveReq = mux.SetURLVars(approveReq, map[string]string{"id": proposalID})
	approveResp := httptest.NewRecorder()
	api.approveProposal(approveResp, approveReq)
	if approveResp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", approveResp.Code, approveResp.Body.String())
	}

	deliveries, err := listNotificationDeliveryRecords()
	if err != nil {
		t.Fatalf("failed to list notification deliveries: %v", err)
	}
	if len(deliveries) != 1 {
		t.Fatalf("expected 1 delivery before replay, got %d", len(deliveries))
	}
	sourceID, _ := deliveries[0]["id"].(string)
	if sourceID == "" {
		t.Fatalf("expected delivery id in persisted record")
	}

	replayReq := httptest.NewRequest("POST", "/api/v1/notifications/deliveries/"+sourceID+"/replay", nil)
	replayReq = mux.SetURLVars(replayReq, map[string]string{"id": sourceID})
	replayResp := httptest.NewRecorder()
	api.replayNotificationDelivery(replayResp, replayReq)
	if replayResp.Code != http.StatusOK {
		t.Fatalf("expected 200 from replay, got %d: %s", replayResp.Code, replayResp.Body.String())
	}

	if requests != 2 {
		t.Fatalf("expected webhook server to receive 2 requests after replay, got %d", requests)
	}

	deliveries, err = listNotificationDeliveryRecords()
	if err != nil {
		t.Fatalf("failed to list notification deliveries after replay: %v", err)
	}
	if len(deliveries) != 2 {
		t.Fatalf("expected 2 deliveries after replay, got %d", len(deliveries))
	}
	foundReplay := false
	for _, delivery := range deliveries {
		if delivery["replay_of"] == sourceID {
			foundReplay = true
			break
		}
	}
	if !foundReplay {
		t.Fatalf("expected replay delivery linked back to source %s", sourceID)
	}
}

func TestListNotificationDeliveriesAppliesFilters(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get working directory: %v", err)
	}
	tempDir := t.TempDir()
	if err := os.Chdir(tempDir); err != nil {
		t.Fatalf("failed to chdir temp dir: %v", err)
	}
	defer func() {
		_ = os.Chdir(wd)
	}()

	err = saveNotificationDeliveryRecord(notificationDeliveryRecord{
		ID:            "ntf-a",
		Event:         "proposal.approved",
		ProposalID:    "prp-1",
		WebhookName:   "ops-events",
		WebhookURL:    "https://ops.example.com/a",
		WebhookFormat: "slack",
		OccurredAt:    time.Now().UTC(),
		DeliveredAt:   time.Now().UTC(),
		Success:       true,
		Attempts:      1,
	})
	if err != nil {
		t.Fatalf("failed to save first delivery record: %v", err)
	}
	err = saveNotificationDeliveryRecord(notificationDeliveryRecord{
		ID:            "ntf-b",
		Event:         "proposal.canary_aborted",
		ProposalID:    "prp-2",
		WebhookName:   "pager",
		WebhookURL:    "https://ops.example.com/b",
		WebhookFormat: "generic",
		OccurredAt:    time.Now().UTC(),
		DeliveredAt:   time.Now().UTC(),
		Success:       false,
		Attempts:      2,
		LastError:     "webhook responded with status 500",
	})
	if err != nil {
		t.Fatalf("failed to save second delivery record: %v", err)
	}

	api := NewManagementAPI(mustTestGateway(t, &config.Config{Server: config.ServerConfig{Port: 8080}}), logging.NewLogger(false), nil)
	req := httptest.NewRequest("GET", "/api/v1/notifications/deliveries?event=proposal.canary_aborted&success=false&webhook=pager", nil)
	resp := httptest.NewRecorder()
	api.listNotificationDeliveries(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.Code, resp.Body.String())
	}

	var payload map[string]interface{}
	if err := json.Unmarshal(resp.Body.Bytes(), &payload); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	deliveries, ok := payload["deliveries"].([]interface{})
	if !ok {
		t.Fatalf("expected deliveries array, got %T", payload["deliveries"])
	}
	if len(deliveries) != 1 {
		t.Fatalf("expected 1 filtered delivery, got %d", len(deliveries))
	}
	item := deliveries[0].(map[string]interface{})
	if item["id"] != "ntf-b" {
		t.Fatalf("expected filtered delivery ntf-b, got %v", item["id"])
	}
}

func TestReplayFailedNotificationDeliveriesReplaysMatchingFailures(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get working directory: %v", err)
	}
	tempDir := t.TempDir()
	if err := os.Chdir(tempDir); err != nil {
		t.Fatalf("failed to chdir temp dir: %v", err)
	}
	defer func() {
		_ = os.Chdir(wd)
	}()

	requests := 0
	server := newNotificationTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.WriteHeader(http.StatusNoContent)
	})
	defer server.Close()

	payload := managementWebhookEvent{
		Event:      "proposal.canary_aborted",
		OccurredAt: time.Now().UTC(),
		ProposalID: "prp-2",
	}
	webhook := config.NotificationWebhook{
		Name:   "pager",
		URL:    server.URL,
		Events: []string{"proposal.canary_aborted"},
	}
	err = saveNotificationDeliveryRecord(notificationDeliveryRecord{
		ID:            "ntf-failed",
		Event:         payload.Event,
		ProposalID:    payload.ProposalID,
		WebhookName:   webhook.Name,
		WebhookURL:    webhook.URL,
		WebhookFormat: webhook.Format,
		OccurredAt:    payload.OccurredAt,
		DeliveredAt:   time.Now().UTC(),
		Success:       false,
		Attempts:      1,
		LastError:     "webhook responded with status 500",
		Webhook:       webhook,
		Payload:       payload,
	})
	if err != nil {
		t.Fatalf("failed to save failed delivery record: %v", err)
	}
	err = saveNotificationDeliveryRecord(notificationDeliveryRecord{
		ID:            "ntf-success",
		Event:         "proposal.approved",
		ProposalID:    "prp-1",
		WebhookName:   "ops-events",
		WebhookURL:    "https://ops.example.com/a",
		WebhookFormat: "slack",
		OccurredAt:    time.Now().UTC(),
		DeliveredAt:   time.Now().UTC(),
		Success:       true,
		Attempts:      1,
	})
	if err != nil {
		t.Fatalf("failed to save success delivery record: %v", err)
	}

	api := NewManagementAPI(mustTestGateway(t, &config.Config{Server: config.ServerConfig{Port: 8080}}), logging.NewLogger(false), nil)
	req := httptest.NewRequest("POST", "/api/v1/notifications/deliveries/replay-failed?event=proposal.canary_aborted&webhook=pager", nil)
	resp := httptest.NewRecorder()
	api.replayFailedNotificationDeliveries(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.Code, resp.Body.String())
	}
	if requests != 1 {
		t.Fatalf("expected 1 replayed webhook request, got %d", requests)
	}

	deliveries, err := listNotificationDeliveryRecords()
	if err != nil {
		t.Fatalf("failed to list deliveries after bulk replay: %v", err)
	}
	if len(deliveries) != 3 {
		t.Fatalf("expected 3 delivery records after replay, got %d", len(deliveries))
	}
}

func TestNotifyProposalQueueDigestEmitsDigestAndSLABreachEvents(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get working directory: %v", err)
	}
	tempDir := t.TempDir()
	if err := os.Chdir(tempDir); err != nil {
		t.Fatalf("failed to chdir temp dir: %v", err)
	}
	defer func() {
		_ = os.Chdir(wd)
	}()

	receivedEvents := make([]string, 0, 2)
	server := newNotificationTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		var payload map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatalf("failed to decode webhook payload: %v", err)
		}
		receivedEvents = append(receivedEvents, strings.TrimSpace(fmt.Sprint(payload["event"])))
		w.WriteHeader(http.StatusOK)
	})
	defer server.Close()

	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Security: config.SecurityConfig{
			MutationPolicy: config.MutationPolicy{
				Enabled: true,
				ProposalQueue: config.ProposalQueuePolicy{
					EnvironmentUrgency: map[string]config.ProposalQueueUrgencyThresholds{
						"prod": {
							BlockedAgingAfter:   "30m",
							BlockedOverdueAfter: "1h",
						},
					},
				},
			},
			NotificationWebhooks: []config.NotificationWebhook{
				{
					URL:    server.URL,
					Events: []string{"proposal.digest", "proposal.sla_breach"},
				},
			},
		},
	}
	gw, err := gatewaypkg.NewGateway(gatewaypkg.Dependencies{Config: cfg, Logger: logging.NewLogger(false)}, "test")
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}
	api := NewManagementAPI(gw, logging.NewLogger(false), nil)

	proposalID, err := saveConfigProposal("services_replace", "replace", "deploy-bot", "prod", "", "", nil, nil, nil, 0, nil, 0, 0, "", false, "", "", "blocked", "queue blocked", "CHG-N1", time.Now().UTC().Add(time.Hour), 2, map[string]interface{}{"action": "replace"}, cfg)
	if err != nil {
		t.Fatalf("failed to save blocked proposal: %v", err)
	}
	record, err := loadConfigProposal(proposalID)
	if err != nil {
		t.Fatalf("failed to load blocked proposal: %v", err)
	}
	record.CreatedAt = time.Now().UTC().Add(-2 * time.Hour)
	if err := saveConfigProposalRecord(record); err != nil {
		t.Fatalf("failed to persist blocked proposal: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/proposals/queue/notify-digest?status=pending&urgency=overdue", nil)
	resp := httptest.NewRecorder()
	api.notifyProposalQueueDigest(resp, req)

	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.Code, resp.Body.String())
	}
	if len(receivedEvents) != 2 {
		t.Fatalf("expected 2 notification events, got %d (%v)", len(receivedEvents), receivedEvents)
	}
	if !strings.Contains(strings.Join(receivedEvents, ","), "proposal.digest") || !strings.Contains(strings.Join(receivedEvents, ","), "proposal.sla_breach") {
		t.Fatalf("expected proposal.digest and proposal.sla_breach events, got %v", receivedEvents)
	}

	deliveries, err := listNotificationDeliveryRecords()
	if err != nil {
		t.Fatalf("failed to list notification deliveries: %v", err)
	}
	if len(deliveries) != 2 {
		t.Fatalf("expected 2 persisted delivery records, got %d", len(deliveries))
	}
}

func TestReconcileProposalQueueDigestNotificationsDebouncesUnchangedDigests(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get working directory: %v", err)
	}
	tempDir := t.TempDir()
	if err := os.Chdir(tempDir); err != nil {
		t.Fatalf("failed to chdir temp dir: %v", err)
	}
	defer func() {
		_ = os.Chdir(wd)
	}()

	receivedEvents := make([]string, 0, 4)
	server := newNotificationTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		var payload map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatalf("failed to decode webhook payload: %v", err)
		}
		receivedEvents = append(receivedEvents, strings.TrimSpace(fmt.Sprint(payload["event"])))
		w.WriteHeader(http.StatusOK)
	})
	defer server.Close()

	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Security: config.SecurityConfig{
			MutationPolicy: config.MutationPolicy{
				Enabled: true,
				ProposalQueue: config.ProposalQueuePolicy{
					Notifications: config.ProposalQueueNotificationPolicy{
						Enabled:                 true,
						Interval:                "1m",
						MinNotificationInterval: "30s",
						OnlyOnChange:            true,
						Environments:            []string{"prod"},
					},
					EnvironmentUrgency: map[string]config.ProposalQueueUrgencyThresholds{
						"prod": {
							BlockedAgingAfter:   "30m",
							BlockedOverdueAfter: "1h",
						},
					},
				},
			},
			NotificationWebhooks: []config.NotificationWebhook{
				{
					URL:    server.URL,
					Events: []string{"proposal.digest", "proposal.sla_breach"},
				},
			},
		},
	}
	gw, err := gatewaypkg.NewGateway(gatewaypkg.Dependencies{Config: cfg, Logger: logging.NewLogger(false)}, "test")
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}
	api := NewManagementAPI(gw, logging.NewLogger(false), nil)

	proposalID, err := saveConfigProposal("services_replace", "replace", "deploy-bot", "prod", "", "", nil, nil, nil, 0, nil, 0, 0, "", false, "", "", "blocked", "queue blocked", "CHG-N2", time.Now().UTC().Add(time.Hour), 2, map[string]interface{}{"action": "replace"}, cfg)
	if err != nil {
		t.Fatalf("failed to save blocked proposal: %v", err)
	}
	record, err := loadConfigProposal(proposalID)
	if err != nil {
		t.Fatalf("failed to load blocked proposal: %v", err)
	}
	record.CreatedAt = time.Now().UTC().Add(-2 * time.Hour)
	if err := saveConfigProposalRecord(record); err != nil {
		t.Fatalf("failed to persist blocked proposal: %v", err)
	}

	now := time.Now().UTC()
	api.reconcileProposalQueueDigestNotifications(now)
	if len(receivedEvents) != 2 {
		t.Fatalf("expected first reconcile to emit 2 events, got %d (%v)", len(receivedEvents), receivedEvents)
	}

	api.reconcileProposalQueueDigestNotifications(now.Add(2 * time.Minute))
	if len(receivedEvents) != 2 {
		t.Fatalf("expected unchanged digest to be suppressed, got %d events (%v)", len(receivedEvents), receivedEvents)
	}

	secondID, err := saveConfigProposal("config_merge", "merge", "deploy-bot", "prod", "", "", nil, nil, nil, 0, nil, 0, 0, "", false, "", "", "blocked", "queue blocked second", "CHG-N3", time.Now().UTC().Add(time.Hour), 1, map[string]interface{}{"action": "merge"}, cfg)
	if err != nil {
		t.Fatalf("failed to save second blocked proposal: %v", err)
	}
	secondRecord, err := loadConfigProposal(secondID)
	if err != nil {
		t.Fatalf("failed to load second blocked proposal: %v", err)
	}
	secondRecord.CreatedAt = time.Now().UTC().Add(-3 * time.Hour)
	if err := saveConfigProposalRecord(secondRecord); err != nil {
		t.Fatalf("failed to persist second blocked proposal: %v", err)
	}

	api.reconcileProposalQueueDigestNotifications(now.Add(4 * time.Minute))
	if len(receivedEvents) != 4 {
		t.Fatalf("expected changed digest to emit another 2 events, got %d (%v)", len(receivedEvents), receivedEvents)
	}
}

func TestNotifyProposalQueueDigestHonorsWebhookSLABreachThresholds(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get working directory: %v", err)
	}
	tempDir := t.TempDir()
	if err := os.Chdir(tempDir); err != nil {
		t.Fatalf("failed to chdir temp dir: %v", err)
	}
	defer func() {
		_ = os.Chdir(wd)
	}()

	received := make([]string, 0, 3)
	server := newNotificationTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		var payload map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatalf("failed to decode webhook payload: %v", err)
		}
		received = append(received, strings.TrimSpace(fmt.Sprint(payload["event"]))+":"+strings.TrimSpace(r.Header.Get("X-Iket-Event")))
		w.WriteHeader(http.StatusOK)
	})
	defer server.Close()

	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Security: config.SecurityConfig{
			MutationPolicy: config.MutationPolicy{
				Enabled: true,
				ProposalQueue: config.ProposalQueuePolicy{
					EnvironmentUrgency: map[string]config.ProposalQueueUrgencyThresholds{
						"prod": {
							BlockedAgingAfter:   "30m",
							BlockedOverdueAfter: "1h",
						},
					},
				},
			},
			NotificationWebhooks: []config.NotificationWebhook{
				{
					Name:   "digest-all",
					URL:    server.URL,
					Events: []string{"proposal.digest", "proposal.sla_breach"},
				},
				{
					Name:              "sla-high-threshold",
					URL:               server.URL,
					Events:            []string{"proposal.sla_breach"},
					MinSLABreachCount: 2,
					Environments:      []string{"prod"},
				},
			},
		},
	}
	gw, err := gatewaypkg.NewGateway(gatewaypkg.Dependencies{Config: cfg, Logger: logging.NewLogger(false)}, "test")
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}
	api := NewManagementAPI(gw, logging.NewLogger(false), nil)

	proposalID, err := saveConfigProposal("services_replace", "replace", "deploy-bot", "prod", "", "", nil, nil, nil, 0, nil, 0, 0, "", false, "", "", "blocked", "queue blocked", "CHG-N4", time.Now().UTC().Add(time.Hour), 2, map[string]interface{}{"action": "replace"}, cfg)
	if err != nil {
		t.Fatalf("failed to save blocked proposal: %v", err)
	}
	record, err := loadConfigProposal(proposalID)
	if err != nil {
		t.Fatalf("failed to load blocked proposal: %v", err)
	}
	record.CreatedAt = time.Now().UTC().Add(-2 * time.Hour)
	if err := saveConfigProposalRecord(record); err != nil {
		t.Fatalf("failed to persist blocked proposal: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/proposals/queue/notify-digest?environment=prod", nil)
	resp := httptest.NewRecorder()
	api.notifyProposalQueueDigest(resp, req)

	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.Code, resp.Body.String())
	}
	digestCount := 0
	slaCount := 0
	for _, event := range received {
		if strings.Contains(event, "proposal.digest") {
			digestCount++
		}
		if strings.Contains(event, "proposal.sla_breach") {
			slaCount++
		}
	}
	if digestCount != 1 {
		t.Fatalf("expected exactly one digest delivery, got %d (%v)", digestCount, received)
	}
	if slaCount != 1 {
		t.Fatalf("expected only the low-threshold webhook to receive proposal.sla_breach, got %d (%v)", slaCount, received)
	}
}

func TestNotifyProposalQueueDigestHonorsWebhookSustainedSLABreachThresholds(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get working directory: %v", err)
	}
	tempDir := t.TempDir()
	if err := os.Chdir(tempDir); err != nil {
		t.Fatalf("failed to chdir temp dir: %v", err)
	}
	defer func() {
		_ = os.Chdir(wd)
	}()

	generalReceived := make([]string, 0, 4)
	escalationReceived := make([]string, 0, 2)
	generalServer := newNotificationTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		var payload map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatalf("failed to decode general webhook payload: %v", err)
		}
		generalReceived = append(generalReceived, strings.TrimSpace(fmt.Sprint(payload["event"])))
		w.WriteHeader(http.StatusOK)
	})
	defer generalServer.Close()
	escalationServer := newNotificationTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		var payload map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatalf("failed to decode escalation webhook payload: %v", err)
		}
		escalationReceived = append(escalationReceived, strings.TrimSpace(fmt.Sprint(payload["event"])))
		w.WriteHeader(http.StatusOK)
	})
	defer escalationServer.Close()

	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Security: config.SecurityConfig{
			MutationPolicy: config.MutationPolicy{
				Enabled: true,
				ProposalQueue: config.ProposalQueuePolicy{
					EnvironmentUrgency: map[string]config.ProposalQueueUrgencyThresholds{
						"prod": {
							BlockedAgingAfter:   "30m",
							BlockedOverdueAfter: "1h",
						},
					},
				},
			},
			NotificationWebhooks: []config.NotificationWebhook{
				{
					Name:   "digest-all",
					URL:    generalServer.URL,
					Events: []string{"proposal.digest", "proposal.sla_breach"},
				},
				{
					Name:                      "sla-sustained",
					URL:                       escalationServer.URL,
					Events:                    []string{"proposal.sla_breach"},
					Environments:              []string{"prod"},
					MinConsecutiveSLABreaches: 2,
				},
			},
		},
	}
	gw, err := gatewaypkg.NewGateway(gatewaypkg.Dependencies{Config: cfg, Logger: logging.NewLogger(false)}, "test")
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}
	api := NewManagementAPI(gw, logging.NewLogger(false), nil)

	proposalID, err := saveConfigProposal("services_replace", "replace", "deploy-bot", "prod", "", "", nil, nil, nil, 0, nil, 0, 0, "", false, "", "", "blocked", "queue blocked", "CHG-N5", time.Now().UTC().Add(time.Hour), 2, map[string]interface{}{"action": "replace"}, cfg)
	if err != nil {
		t.Fatalf("failed to save blocked proposal: %v", err)
	}
	record, err := loadConfigProposal(proposalID)
	if err != nil {
		t.Fatalf("failed to load blocked proposal: %v", err)
	}
	record.CreatedAt = time.Now().UTC().Add(-2 * time.Hour)
	if err := saveConfigProposalRecord(record); err != nil {
		t.Fatalf("failed to persist blocked proposal: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/proposals/queue/notify-digest?environment=prod", nil)
	resp := httptest.NewRecorder()
	api.notifyProposalQueueDigest(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected first notify to return 200, got %d: %s", resp.Code, resp.Body.String())
	}
	if len(escalationReceived) != 0 {
		t.Fatalf("expected sustained escalation webhook to stay quiet on first breach, got %v", escalationReceived)
	}

	resp = httptest.NewRecorder()
	api.notifyProposalQueueDigest(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected second notify to return 200, got %d: %s", resp.Code, resp.Body.String())
	}

	generalSLACount := 0
	for _, event := range generalReceived {
		if event == "proposal.sla_breach" {
			generalSLACount++
		}
	}
	if generalSLACount != 2 {
		t.Fatalf("expected general webhook to receive two proposal.sla_breach events, got %d (%v)", generalSLACount, generalReceived)
	}
	if len(escalationReceived) != 1 || escalationReceived[0] != "proposal.sla_breach" {
		t.Fatalf("expected sustained escalation webhook to receive exactly one proposal.sla_breach after the second breach, got %v", escalationReceived)
	}
}

func TestNotifyProposalQueueDigestHonorsWebhookSLABreachTierThresholds(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get working directory: %v", err)
	}
	tempDir := t.TempDir()
	if err := os.Chdir(tempDir); err != nil {
		t.Fatalf("failed to chdir temp dir: %v", err)
	}
	defer func() {
		_ = os.Chdir(wd)
	}()

	elevatedReceived := make([]string, 0, 2)
	criticalReceived := make([]string, 0, 2)
	elevatedServer := newNotificationTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		var payload map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatalf("failed to decode elevated webhook payload: %v", err)
		}
		elevatedReceived = append(elevatedReceived, strings.TrimSpace(fmt.Sprint(payload["event"]))+":"+strings.TrimSpace(fmt.Sprint(payload["data"].(map[string]interface{})["sla_breach_tier"])))
		w.WriteHeader(http.StatusOK)
	})
	defer elevatedServer.Close()
	criticalServer := newNotificationTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		var payload map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatalf("failed to decode critical webhook payload: %v", err)
		}
		criticalReceived = append(criticalReceived, strings.TrimSpace(fmt.Sprint(payload["event"]))+":"+strings.TrimSpace(fmt.Sprint(payload["data"].(map[string]interface{})["sla_breach_tier"])))
		w.WriteHeader(http.StatusOK)
	})
	defer criticalServer.Close()

	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Security: config.SecurityConfig{
			MutationPolicy: config.MutationPolicy{
				Enabled: true,
				ProposalQueue: config.ProposalQueuePolicy{
					EnvironmentUrgency: map[string]config.ProposalQueueUrgencyThresholds{
						"prod": {
							BlockedAgingAfter:   "30m",
							BlockedOverdueAfter: "1h",
						},
					},
				},
			},
			NotificationWebhooks: []config.NotificationWebhook{
				{
					Name:             "sla-elevated",
					URL:              elevatedServer.URL,
					Events:           []string{"proposal.sla_breach"},
					Environments:     []string{"prod"},
					MinSLABreachTier: "elevated",
				},
				{
					Name:             "sla-critical",
					URL:              criticalServer.URL,
					Events:           []string{"proposal.sla_breach"},
					Environments:     []string{"prod"},
					MinSLABreachTier: "critical",
				},
			},
		},
	}
	gw, err := gatewaypkg.NewGateway(gatewaypkg.Dependencies{Config: cfg, Logger: logging.NewLogger(false)}, "test")
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}
	api := NewManagementAPI(gw, logging.NewLogger(false), nil)

	proposalID, err := saveConfigProposal("services_replace", "replace", "deploy-bot", "prod", "", "", nil, nil, nil, 0, nil, 0, 0, "", false, "", "", "blocked", "queue blocked", "CHG-N6", time.Now().UTC().Add(time.Hour), 2, map[string]interface{}{"action": "replace"}, cfg)
	if err != nil {
		t.Fatalf("failed to save blocked proposal: %v", err)
	}
	record, err := loadConfigProposal(proposalID)
	if err != nil {
		t.Fatalf("failed to load blocked proposal: %v", err)
	}
	record.CreatedAt = time.Now().UTC().Add(-2 * time.Hour)
	if err := saveConfigProposalRecord(record); err != nil {
		t.Fatalf("failed to persist blocked proposal: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/proposals/queue/notify-digest?environment=prod", nil)
	resp := httptest.NewRecorder()
	api.notifyProposalQueueDigest(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected first notify to return 200, got %d: %s", resp.Code, resp.Body.String())
	}
	if len(elevatedReceived) != 0 || len(criticalReceived) != 0 {
		t.Fatalf("expected no tiered escalation on first warning breach, got elevated=%v critical=%v", elevatedReceived, criticalReceived)
	}

	resp = httptest.NewRecorder()
	api.notifyProposalQueueDigest(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected second notify to return 200, got %d: %s", resp.Code, resp.Body.String())
	}
	if len(elevatedReceived) != 1 || elevatedReceived[0] != "proposal.sla_breach:elevated" {
		t.Fatalf("expected elevated webhook to receive one elevated event after second breach, got %v", elevatedReceived)
	}
	if len(criticalReceived) != 0 {
		t.Fatalf("expected critical webhook to stay quiet after elevated-only breach, got %v", criticalReceived)
	}

	resp = httptest.NewRecorder()
	api.notifyProposalQueueDigest(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected third notify to return 200, got %d: %s", resp.Code, resp.Body.String())
	}
	if len(criticalReceived) != 1 || criticalReceived[0] != "proposal.sla_breach:critical" {
		t.Fatalf("expected critical webhook to receive one critical event after third breach, got %v", criticalReceived)
	}
}

func TestNotifyProposalQueueDigestHonorsWebhookSLABreachCooldownWithTierBypass(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get working directory: %v", err)
	}
	tempDir := t.TempDir()
	if err := os.Chdir(tempDir); err != nil {
		t.Fatalf("failed to chdir temp dir: %v", err)
	}
	defer func() {
		_ = os.Chdir(wd)
	}()

	received := make([]string, 0, 4)
	server := newNotificationTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		var payload map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatalf("failed to decode cooldown webhook payload: %v", err)
		}
		data, _ := payload["data"].(map[string]interface{})
		received = append(received, strings.TrimSpace(fmt.Sprint(payload["event"]))+":"+strings.TrimSpace(fmt.Sprint(data["sla_breach_tier"])))
		w.WriteHeader(http.StatusOK)
	})
	defer server.Close()

	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Security: config.SecurityConfig{
			MutationPolicy: config.MutationPolicy{
				Enabled: true,
				ProposalQueue: config.ProposalQueuePolicy{
					EnvironmentUrgency: map[string]config.ProposalQueueUrgencyThresholds{
						"prod": {
							BlockedAgingAfter:   "30m",
							BlockedOverdueAfter: "1h",
						},
					},
				},
			},
			NotificationWebhooks: []config.NotificationWebhook{
				{
					Name:              "sla-cooldown",
					URL:               server.URL,
					Events:            []string{"proposal.sla_breach"},
					Environments:      []string{"prod"},
					MinSLABreachTier:  "warning",
					SLABreachCooldown: "1h",
				},
			},
		},
	}
	gw, err := gatewaypkg.NewGateway(gatewaypkg.Dependencies{Config: cfg, Logger: logging.NewLogger(false)}, "test")
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}
	api := NewManagementAPI(gw, logging.NewLogger(false), nil)

	proposalID, err := saveConfigProposal("services_replace", "replace", "deploy-bot", "prod", "", "", nil, nil, nil, 0, nil, 0, 0, "", false, "", "", "blocked", "queue blocked", "CHG-N7", time.Now().UTC().Add(time.Hour), 2, map[string]interface{}{"action": "replace"}, cfg)
	if err != nil {
		t.Fatalf("failed to save blocked proposal: %v", err)
	}
	record, err := loadConfigProposal(proposalID)
	if err != nil {
		t.Fatalf("failed to load blocked proposal: %v", err)
	}
	record.CreatedAt = time.Now().UTC().Add(-2 * time.Hour)
	if err := saveConfigProposalRecord(record); err != nil {
		t.Fatalf("failed to persist blocked proposal: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/proposals/queue/notify-digest?environment=prod", nil)
	for i := 0; i < 4; i++ {
		resp := httptest.NewRecorder()
		api.notifyProposalQueueDigest(resp, req)
		if resp.Code != http.StatusOK {
			t.Fatalf("expected notify %d to return 200, got %d: %s", i+1, resp.Code, resp.Body.String())
		}
	}

	expected := []string{
		"proposal.sla_breach:warning",
		"proposal.sla_breach:elevated",
		"proposal.sla_breach:critical",
	}
	if !reflect.DeepEqual(received, expected) {
		t.Fatalf("expected cooldown webhook to suppress repeated same-tier critical alert while allowing tier rises, got %v want %v", received, expected)
	}
}

func TestNotifyProposalQueueDigestEmitsSLAResolvedForSameIncident(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get working directory: %v", err)
	}
	tempDir := t.TempDir()
	if err := os.Chdir(tempDir); err != nil {
		t.Fatalf("failed to chdir temp dir: %v", err)
	}
	defer func() {
		_ = os.Chdir(wd)
	}()

	type webhookRecord struct {
		Event      string
		IncidentID string
	}
	received := make([]webhookRecord, 0, 4)
	server := newNotificationTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		var payload map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatalf("failed to decode lifecycle webhook payload: %v", err)
		}
		event := strings.TrimSpace(fmt.Sprint(payload["event"]))
		data, _ := payload["data"].(map[string]interface{})
		incidentID := ""
		if event == "proposal.sla_breach" {
			if state, ok := data["sla_breach_state"].(map[string]interface{}); ok {
				incidentID = strings.TrimSpace(fmt.Sprint(state["incident_id"]))
			}
		}
		if event == "proposal.sla_resolved" {
			incidentID = strings.TrimSpace(fmt.Sprint(data["incident_id"]))
		}
		received = append(received, webhookRecord{Event: event, IncidentID: incidentID})
		w.WriteHeader(http.StatusOK)
	})
	defer server.Close()

	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Security: config.SecurityConfig{
			MutationPolicy: config.MutationPolicy{
				Enabled: true,
				ProposalQueue: config.ProposalQueuePolicy{
					EnvironmentUrgency: map[string]config.ProposalQueueUrgencyThresholds{
						"prod": {
							BlockedAgingAfter:   "30m",
							BlockedOverdueAfter: "1h",
						},
					},
				},
			},
			NotificationWebhooks: []config.NotificationWebhook{
				{
					Name:         "lifecycle",
					URL:          server.URL,
					Events:       []string{"proposal.sla_breach", "proposal.sla_resolved"},
					Environments: []string{"prod"},
				},
			},
		},
	}
	gw, err := gatewaypkg.NewGateway(gatewaypkg.Dependencies{Config: cfg, Logger: logging.NewLogger(false)}, "test")
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}
	api := NewManagementAPI(gw, logging.NewLogger(false), nil)

	proposalID, err := saveConfigProposal("services_replace", "replace", "deploy-bot", "prod", "", "", nil, nil, nil, 0, nil, 0, 0, "", false, "", "", "blocked", "queue blocked", "CHG-N8", time.Now().UTC().Add(time.Hour), 2, map[string]interface{}{"action": "replace"}, cfg)
	if err != nil {
		t.Fatalf("failed to save blocked proposal: %v", err)
	}
	record, err := loadConfigProposal(proposalID)
	if err != nil {
		t.Fatalf("failed to load blocked proposal: %v", err)
	}
	record.CreatedAt = time.Now().UTC().Add(-2 * time.Hour)
	if err := saveConfigProposalRecord(record); err != nil {
		t.Fatalf("failed to persist blocked proposal: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/proposals/queue/notify-digest?environment=prod", nil)
	resp := httptest.NewRecorder()
	api.notifyProposalQueueDigest(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected breach notify to return 200, got %d: %s", resp.Code, resp.Body.String())
	}

	record, err = loadConfigProposal(proposalID)
	if err != nil {
		t.Fatalf("failed to reload proposal: %v", err)
	}
	record.CreatedAt = time.Now().UTC()
	if err := saveConfigProposalRecord(record); err != nil {
		t.Fatalf("failed to persist resolved proposal: %v", err)
	}

	resp = httptest.NewRecorder()
	api.notifyProposalQueueDigest(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected resolved notify to return 200, got %d: %s", resp.Code, resp.Body.String())
	}

	breachIncident := ""
	resolvedIncident := ""
	for _, item := range received {
		if item.Event == "proposal.sla_breach" && breachIncident == "" {
			breachIncident = item.IncidentID
		}
		if item.Event == "proposal.sla_resolved" && resolvedIncident == "" {
			resolvedIncident = item.IncidentID
		}
	}
	if strings.TrimSpace(breachIncident) == "" {
		t.Fatalf("expected proposal.sla_breach with incident id, got %v", received)
	}
	if strings.TrimSpace(resolvedIncident) == "" {
		t.Fatalf("expected proposal.sla_resolved with incident id, got %v", received)
	}
	if breachIncident != resolvedIncident {
		t.Fatalf("expected resolved incident id to match breach incident id, got breach=%q resolved=%q", breachIncident, resolvedIncident)
	}
}

func TestNotifyProposalQueueDigestEmitsSLAStageChangedProgression(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get working directory: %v", err)
	}
	tempDir := t.TempDir()
	if err := os.Chdir(tempDir); err != nil {
		t.Fatalf("failed to chdir temp dir: %v", err)
	}
	defer func() {
		_ = os.Chdir(wd)
	}()

	type stageRecord struct {
		Previous   string
		Current    string
		IncidentID string
	}
	stages := make([]stageRecord, 0, 4)
	server := newNotificationTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		var payload map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatalf("failed to decode stage webhook payload: %v", err)
		}
		if strings.TrimSpace(fmt.Sprint(payload["event"])) != "proposal.sla_stage_changed" {
			w.WriteHeader(http.StatusOK)
			return
		}
		data, _ := payload["data"].(map[string]interface{})
		stages = append(stages, stageRecord{
			Previous:   strings.TrimSpace(fmt.Sprint(data["previous_stage"])),
			Current:    strings.TrimSpace(fmt.Sprint(data["current_stage"])),
			IncidentID: strings.TrimSpace(fmt.Sprint(data["incident_id"])),
		})
		w.WriteHeader(http.StatusOK)
	})
	defer server.Close()

	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Security: config.SecurityConfig{
			MutationPolicy: config.MutationPolicy{
				Enabled: true,
				ProposalQueue: config.ProposalQueuePolicy{
					EnvironmentUrgency: map[string]config.ProposalQueueUrgencyThresholds{
						"prod": {
							BlockedAgingAfter:   "30m",
							BlockedOverdueAfter: "1h",
						},
					},
				},
			},
			NotificationWebhooks: []config.NotificationWebhook{
				{
					Name:         "stage-events",
					URL:          server.URL,
					Events:       []string{"proposal.sla_stage_changed"},
					Environments: []string{"prod"},
				},
			},
		},
	}
	gw, err := gatewaypkg.NewGateway(gatewaypkg.Dependencies{Config: cfg, Logger: logging.NewLogger(false)}, "test")
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}
	api := NewManagementAPI(gw, logging.NewLogger(false), nil)

	proposalID, err := saveConfigProposal("services_replace", "replace", "deploy-bot", "prod", "", "", nil, nil, nil, 0, nil, 0, 0, "", false, "", "", "blocked", "queue blocked", "CHG-N9", time.Now().UTC().Add(time.Hour), 2, map[string]interface{}{"action": "replace"}, cfg)
	if err != nil {
		t.Fatalf("failed to save blocked proposal: %v", err)
	}
	record, err := loadConfigProposal(proposalID)
	if err != nil {
		t.Fatalf("failed to load blocked proposal: %v", err)
	}
	record.CreatedAt = time.Now().UTC().Add(-2 * time.Hour)
	if err := saveConfigProposalRecord(record); err != nil {
		t.Fatalf("failed to persist blocked proposal: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/proposals/queue/notify-digest?environment=prod", nil)
	resp := httptest.NewRecorder()
	api.notifyProposalQueueDigest(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected first stage notify to return 200, got %d: %s", resp.Code, resp.Body.String())
	}

	resp = httptest.NewRecorder()
	api.notifyProposalQueueDigest(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected second stage notify to return 200, got %d: %s", resp.Code, resp.Body.String())
	}

	if len(stages) != 2 {
		t.Fatalf("expected two stage change events, got %d (%v)", len(stages), stages)
	}
	if stages[0].Previous != "" || stages[0].Current != "warning" {
		t.Fatalf("expected first stage change to open warning incident, got %+v", stages[0])
	}
	if stages[1].Previous != "warning" || stages[1].Current != "elevated" {
		t.Fatalf("expected second stage change to elevate warning -> elevated, got %+v", stages[1])
	}
	if strings.TrimSpace(stages[0].IncidentID) == "" || stages[0].IncidentID != stages[1].IncidentID {
		t.Fatalf("expected both stage changes to share one incident id, got %+v", stages)
	}
}

func TestGetGatewayBackendsReturnsBackendStatuses(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Services: []config.ServiceConfig{{
			Version: 1,
			Services: []config.Service{{
				Name: "identity",
				Host: "http://identity-default:8080",
				Routes: []config.RouterConfig{{
					Path:    "/auth/{rest:.*}",
					Methods: []string{"GET"},
					Backends: []config.Backend{
						{
							URLPattern:      "/v1/{rest:.*}",
							Host:            "http://identity-v1:8080",
							Weight:          2,
							HealthCheckPath: "/health",
						},
					},
				}},
			}},
		}},
	}
	gw, err := gatewaypkg.NewGateway(gatewaypkg.Dependencies{Config: cfg, Logger: logging.NewLogger(false)}, "test")
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}
	api := NewManagementAPI(gw, logging.NewLogger(false), nil)

	req := httptest.NewRequest("GET", "/api/v1/gateway/backends", nil)
	resp := httptest.NewRecorder()
	api.getGatewayBackends(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.Code, resp.Body.String())
	}

	var payload map[string]interface{}
	if err := json.Unmarshal(resp.Body.Bytes(), &payload); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	backends, ok := payload["backends"].([]interface{})
	if !ok || len(backends) != 1 {
		t.Fatalf("expected one backend status entry, got %T len=%d", payload["backends"], len(backends))
	}
	entry := backends[0].(map[string]interface{})
	if entry["service_name"] != "identity" {
		t.Fatalf("expected service_name identity, got %v", entry["service_name"])
	}
	if entry["health_check_path"] != "/health" {
		t.Fatalf("expected health_check_path /health, got %v", entry["health_check_path"])
	}
}

func TestGetGatewayPolicyHitsReturnsAggregatedCounters(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Services: []config.ServiceConfig{{
			Version: 1,
			Services: []config.Service{{
				Name: "agent",
				Host: "http://agent-default:8080",
				Routes: []config.RouterConfig{
					{
						Path:    "/ai/chat",
						Methods: []string{"POST"},
						Backends: []config.Backend{
							{URLPattern: "/"},
						},
					},
					{
						Path:    "/ai/tools",
						Methods: []string{"POST"},
						Backends: []config.Backend{
							{URLPattern: "/"},
						},
					},
				},
			}},
		}},
	}
	gw, err := gatewaypkg.NewGateway(gatewaypkg.Dependencies{Config: cfg, Logger: logging.NewLogger(false)}, "test")
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}
	routes := cfg.GetAllRoutesFromServices(logging.NewLogger(false))
	now := time.Now().UTC()
	gw.RecordPolicyHitForTest(routes[0], "request_content_policy", now.Add(-2*time.Minute))
	gw.RecordPolicyHitForTest(routes[0], "request_content_policy", now.Add(-30*time.Second))
	gw.RecordPolicyHitForTest(routes[1], "tool_allowlist", now.Add(-2*time.Hour))

	api := NewManagementAPI(gw, logging.NewLogger(false), nil)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/gateway/policy-hits?window=5m", nil)
	resp := httptest.NewRecorder()
	api.getGatewayPolicyHits(resp, req)

	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.Code, resp.Body.String())
	}
	var payload struct {
		Total   int `json:"total"`
		Reasons []struct {
			Reason string `json:"reason"`
			Count  int    `json:"count"`
		} `json:"reasons"`
		Routes []struct {
			ServiceName string         `json:"service_name"`
			RoutePath   string         `json:"route_path"`
			Total       int            `json:"total"`
			ByReason    map[string]int `json:"by_reason"`
		} `json:"routes"`
		RecentWindow struct {
			Window        string `json:"window"`
			WindowSeconds int64  `json:"window_seconds"`
			Total         int    `json:"total"`
			TopReason     string `json:"top_reason"`
			TopRoutePath  string `json:"top_route_path"`
			Routes        []struct {
				RoutePath string `json:"route_path"`
				Total     int    `json:"total"`
			} `json:"routes"`
		} `json:"recent_window"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &payload); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if payload.Total != 3 {
		t.Fatalf("expected total 3, got %+v", payload)
	}
	if len(payload.Reasons) != 2 || payload.Reasons[0].Reason != "request_content_policy" || payload.Reasons[0].Count != 2 {
		t.Fatalf("unexpected reason payload: %+v", payload.Reasons)
	}
	if len(payload.Routes) != 2 || payload.Routes[0].RoutePath != "/ai/chat" || payload.Routes[0].ByReason["request_content_policy"] != 2 {
		t.Fatalf("unexpected route payload: %+v", payload.Routes)
	}
	if payload.RecentWindow.Window != "5m" || payload.RecentWindow.Total != 2 || payload.RecentWindow.TopReason != "request_content_policy" || payload.RecentWindow.TopRoutePath != "/ai/chat" {
		t.Fatalf("unexpected recent window payload: %+v", payload.RecentWindow)
	}
}

func TestGetGatewayPolicyAlertsReturnsRecentSpikeAlerts(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Services: []config.ServiceConfig{{
			Version: 1,
			Services: []config.Service{{
				Name: "agent",
				Host: "http://agent-default:8080",
				Routes: []config.RouterConfig{
					{
						Path:    "/ai/chat",
						Methods: []string{"POST"},
						Backends: []config.Backend{
							{URLPattern: "/"},
						},
					},
					{
						Path:    "/ai/tools",
						Methods: []string{"POST"},
						Backends: []config.Backend{
							{URLPattern: "/"},
						},
					},
				},
			}},
		}},
	}
	gw, err := gatewaypkg.NewGateway(gatewaypkg.Dependencies{Config: cfg, Logger: logging.NewLogger(false)}, "test")
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}
	routes := cfg.GetAllRoutesFromServices(logging.NewLogger(false))
	now := time.Now().UTC()
	gw.RecordPolicyHitForTest(routes[0], "request_content_policy", now.Add(-4*time.Minute))
	gw.RecordPolicyHitForTest(routes[0], "request_content_policy", now.Add(-3*time.Minute))
	gw.RecordPolicyHitForTest(routes[0], "request_content_policy", now.Add(-2*time.Minute))
	gw.RecordPolicyHitForTest(routes[0], "request_content_policy", now.Add(-1*time.Minute))
	gw.RecordPolicyHitForTest(routes[1], "tool_allowlist", now.Add(-30*time.Second))

	api := NewManagementAPI(gw, logging.NewLogger(false), nil)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/gateway/policy-alerts?window=5m&min_count=3", nil)
	resp := httptest.NewRecorder()
	api.getGatewayPolicyAlerts(resp, req)

	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.Code, resp.Body.String())
	}
	var payload struct {
		Window      string         `json:"window"`
		MinCount    int            `json:"min_count"`
		TotalAlerts int            `json:"total_alerts"`
		BySeverity  map[string]int `json:"by_severity"`
		Alerts      []struct {
			Severity  string `json:"severity"`
			RoutePath string `json:"route_path"`
			Reason    string `json:"reason"`
			Count     int    `json:"count"`
		} `json:"alerts"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &payload); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if payload.Window != "5m" || payload.MinCount != 3 || payload.TotalAlerts != 1 {
		t.Fatalf("unexpected alert summary: %+v", payload)
	}
	if payload.BySeverity["warning"] != 1 || len(payload.Alerts) != 1 {
		t.Fatalf("unexpected alert severity payload: %+v", payload)
	}
	if payload.Alerts[0].RoutePath != "/ai/chat" || payload.Alerts[0].Reason != "request_content_policy" || payload.Alerts[0].Count != 4 {
		t.Fatalf("unexpected alert entry: %+v", payload.Alerts[0])
	}
}

func TestNotifyGatewayPolicyAlertsEmitsDigestAndAlertEvents(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get working directory: %v", err)
	}
	tempDir := t.TempDir()
	if err := os.Chdir(tempDir); err != nil {
		t.Fatalf("failed to chdir temp dir: %v", err)
	}
	defer func() {
		_ = os.Chdir(wd)
	}()

	receivedEvents := make([]string, 0, 4)
	server := newNotificationTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		var payload map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatalf("failed to decode webhook payload: %v", err)
		}
		receivedEvents = append(receivedEvents, fmt.Sprint(payload["event"]))
		w.WriteHeader(http.StatusOK)
	})
	defer server.Close()

	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Services: []config.ServiceConfig{{
			Version: 1,
			Services: []config.Service{{
				Name: "agent",
				Host: "http://agent-default:8080",
				Routes: []config.RouterConfig{
					{
						Path:    "/ai/chat",
						Methods: []string{"POST"},
						Backends: []config.Backend{
							{URLPattern: "/"},
						},
					},
				},
			}},
		}},
		Security: config.SecurityConfig{
			NotificationWebhooks: []config.NotificationWebhook{
				{
					URL:    server.URL,
					Events: []string{"gateway.policy_alert_digest", "gateway.policy_alert"},
				},
			},
		},
	}
	gw, err := gatewaypkg.NewGateway(gatewaypkg.Dependencies{Config: cfg, Logger: logging.NewLogger(false)}, "test")
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}
	routes := cfg.GetAllRoutesFromServices(logging.NewLogger(false))
	now := time.Now().UTC()
	gw.RecordPolicyHitForTest(routes[0], "request_content_policy", now.Add(-4*time.Minute))
	gw.RecordPolicyHitForTest(routes[0], "request_content_policy", now.Add(-3*time.Minute))
	gw.RecordPolicyHitForTest(routes[0], "request_content_policy", now.Add(-2*time.Minute))

	api := NewManagementAPI(gw, logging.NewLogger(false), nil)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/gateway/policy-alerts/notify?window=5m&min_count=3", nil)
	resp := httptest.NewRecorder()
	api.notifyGatewayPolicyAlerts(resp, req)

	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.Code, resp.Body.String())
	}
	if len(receivedEvents) != 2 {
		t.Fatalf("expected 2 notification events, got %d (%v)", len(receivedEvents), receivedEvents)
	}
	if !strings.Contains(strings.Join(receivedEvents, ","), "gateway.policy_alert_digest") || !strings.Contains(strings.Join(receivedEvents, ","), "gateway.policy_alert") {
		t.Fatalf("expected gateway.policy_alert_digest and gateway.policy_alert events, got %v", receivedEvents)
	}

	deliveries, err := listNotificationDeliveryRecords()
	if err != nil {
		t.Fatalf("failed to list notification deliveries: %v", err)
	}
	if len(deliveries) != 2 {
		t.Fatalf("expected 2 persisted delivery records, got %d", len(deliveries))
	}
}

func TestReconcileGatewayPolicyAlertNotificationsAutoEmitsAndHonorsInterval(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get working directory: %v", err)
	}
	tempDir := t.TempDir()
	if err := os.Chdir(tempDir); err != nil {
		t.Fatalf("failed to chdir temp dir: %v", err)
	}
	defer func() {
		_ = os.Chdir(wd)
	}()

	receivedEvents := make([]string, 0, 8)
	server := newNotificationTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		var payload map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatalf("failed to decode webhook payload: %v", err)
		}
		receivedEvents = append(receivedEvents, fmt.Sprint(payload["event"]))
		w.WriteHeader(http.StatusOK)
	})
	defer server.Close()

	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Services: []config.ServiceConfig{{
			Version: 1,
			Services: []config.Service{{
				Name: "agent",
				Host: "http://agent-default:8080",
				Routes: []config.RouterConfig{{
					Path:    "/ai/chat",
					Methods: []string{"POST"},
					Backends: []config.Backend{
						{URLPattern: "/"},
					},
				}},
			}},
		}},
		Security: config.SecurityConfig{
			MutationPolicy: config.MutationPolicy{
				PolicyAlertNotifications: config.PolicyAlertNotificationPolicy{
					Enabled:     true,
					Interval:    "1m",
					Window:      "5m",
					MinCount:    3,
					MinSeverity: "warning",
				},
			},
			NotificationWebhooks: []config.NotificationWebhook{
				{
					URL:    server.URL,
					Events: []string{"gateway.policy_alert_digest", "gateway.policy_alert_opened"},
				},
			},
		},
	}
	gw, err := gatewaypkg.NewGateway(gatewaypkg.Dependencies{Config: cfg, Logger: logging.NewLogger(false)}, "test")
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}
	routes := cfg.GetAllRoutesFromServices(logging.NewLogger(false))
	base := time.Now().UTC()
	gw.RecordPolicyHitForTest(routes[0], "request_content_policy", base.Add(-30*time.Second))
	gw.RecordPolicyHitForTest(routes[0], "request_content_policy", base.Add(-20*time.Second))
	gw.RecordPolicyHitForTest(routes[0], "request_content_policy", base.Add(-10*time.Second))

	api := NewManagementAPI(gw, logging.NewLogger(false), nil)
	api.reconcileGatewayPolicyAlertNotifications(base)
	if len(receivedEvents) != 2 {
		t.Fatalf("expected initial digest+opened webhook events, got %d (%v)", len(receivedEvents), receivedEvents)
	}

	api.reconcileGatewayPolicyAlertNotifications(base.Add(30 * time.Second))
	if len(receivedEvents) != 2 {
		t.Fatalf("expected interval gate to suppress early re-notify, got %d (%v)", len(receivedEvents), receivedEvents)
	}
}

func TestReconcileGatewayPolicyAlertNotificationsEmitsLifecycleEvents(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get working directory: %v", err)
	}
	tempDir := t.TempDir()
	if err := os.Chdir(tempDir); err != nil {
		t.Fatalf("failed to chdir temp dir: %v", err)
	}
	defer func() {
		_ = os.Chdir(wd)
	}()

	type webhookRecord struct {
		Event      string
		IncidentID string
		Severity   string
		Previous   string
	}
	received := make([]webhookRecord, 0, 8)
	server := newNotificationTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		var payload map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatalf("failed to decode webhook payload: %v", err)
		}
		data, _ := payload["data"].(map[string]interface{})
		received = append(received, webhookRecord{
			Event:      strings.TrimSpace(fmt.Sprint(payload["event"])),
			IncidentID: strings.TrimSpace(fmt.Sprint(data["incident_id"])),
			Severity:   strings.TrimSpace(fmt.Sprint(data["severity"])),
			Previous:   strings.TrimSpace(fmt.Sprint(data["previous_severity"])),
		})
		w.WriteHeader(http.StatusOK)
	})
	defer server.Close()

	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Services: []config.ServiceConfig{{
			Version: 1,
			Services: []config.Service{{
				Name: "agent",
				Host: "http://agent-default:8080",
				Routes: []config.RouterConfig{{
					Path:    "/ai/chat",
					Methods: []string{"POST"},
					Backends: []config.Backend{
						{URLPattern: "/"},
					},
				}},
			}},
		}},
		Security: config.SecurityConfig{
			MutationPolicy: config.MutationPolicy{
				PolicyAlertNotifications: config.PolicyAlertNotificationPolicy{
					Enabled:     true,
					Interval:    "1m",
					Window:      "5m",
					MinCount:    3,
					MinSeverity: "warning",
				},
			},
			NotificationWebhooks: []config.NotificationWebhook{
				{
					URL: server.URL,
					Events: []string{
						"gateway.policy_alert_opened",
						"gateway.policy_alert_stage_changed",
						"gateway.policy_alert_resolved",
					},
				},
			},
		},
	}
	gw, err := gatewaypkg.NewGateway(gatewaypkg.Dependencies{Config: cfg, Logger: logging.NewLogger(false)}, "test")
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}
	routes := cfg.GetAllRoutesFromServices(logging.NewLogger(false))
	base := time.Now().UTC()
	gw.RecordPolicyHitForTest(routes[0], "request_content_policy", base.Add(-30*time.Second))
	gw.RecordPolicyHitForTest(routes[0], "request_content_policy", base.Add(-20*time.Second))
	gw.RecordPolicyHitForTest(routes[0], "request_content_policy", base.Add(-10*time.Second))

	api := NewManagementAPI(gw, logging.NewLogger(false), nil)
	api.reconcileGatewayPolicyAlertNotifications(base)
	if len(received) != 1 || received[0].Event != "gateway.policy_alert_opened" || strings.TrimSpace(received[0].IncidentID) == "" || received[0].Severity != "warning" {
		t.Fatalf("expected opened incident event, got %+v", received)
	}
	incidentID := received[0].IncidentID

	gw.RecordPolicyHitForTest(routes[0], "request_content_policy", time.Now().UTC())
	gw.RecordPolicyHitForTest(routes[0], "request_content_policy", time.Now().UTC())
	gw.RecordPolicyHitForTest(routes[0], "request_content_policy", time.Now().UTC())
	api.reconcileGatewayPolicyAlertNotifications(base.Add(2 * time.Minute))
	if len(received) != 2 || received[1].Event != "gateway.policy_alert_stage_changed" || received[1].Previous != "warning" || received[1].Severity != "elevated" || received[1].IncidentID != incidentID {
		t.Fatalf("expected stage change for same incident, got %+v", received)
	}

	api.reconcileGatewayPolicyAlertNotifications(base.Add(10 * time.Minute))
	if len(received) != 3 || received[2].Event != "gateway.policy_alert_resolved" || received[2].IncidentID != incidentID {
		t.Fatalf("expected resolved incident event, got %+v", received)
	}
}

func TestGetGatewayShadowReportReturnsRouteSummaries(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Services: []config.ServiceConfig{{
			Version: 1,
			Services: []config.Service{{
				Name: "identity",
				Host: "http://identity-default:8080",
				Routes: []config.RouterConfig{{
					Path:                 "/auth/{rest:.*}",
					Methods:              []string{"GET"},
					ShadowTrafficPercent: 100,
					Backends: []config.Backend{{
						URLPattern: "/v1/{rest:.*}",
						Host:       "http://identity-v1:8080",
					}},
				}},
			}},
		}},
	}
	gw, err := gatewaypkg.NewGateway(gatewaypkg.Dependencies{
		Config: cfg,
		Logger: logging.NewLogger(false),
	}, "test")
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}
	route := cfg.GetAllRoutesFromServices(logging.NewLogger(false))[0]
	backend := route.Backends[0]
	destination := strings.TrimSpace(backend.Host)
	gw.RecordBackendSuccessForTest(route, backend, destination, http.StatusOK, 100*time.Millisecond, time.Now().UTC())
	gw.RecordShadowResultForTest(route, backend, destination, http.StatusOK, 140*time.Millisecond, nil)

	api := NewManagementAPI(gw, logging.NewLogger(false), nil)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/gateway/shadow-report", nil)
	resp := httptest.NewRecorder()

	api.getGatewayShadowReport(resp, req)

	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.Code)
	}
	var payload struct {
		Routes []struct {
			ServiceName    string `json:"service_name"`
			RoutePath      string `json:"route_path"`
			ShadowRequests int    `json:"shadow_requests"`
		} `json:"routes"`
		Total int `json:"total"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &payload); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if payload.Total != 1 || len(payload.Routes) != 1 {
		t.Fatalf("expected one shadow route summary, got %+v", payload)
	}
	if payload.Routes[0].ServiceName != "identity" || payload.Routes[0].ShadowRequests != 1 {
		t.Fatalf("unexpected shadow report payload: %+v", payload.Routes[0])
	}
}

func TestGetGatewayShadowEvaluationReturnsThresholdResults(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Services: []config.ServiceConfig{{
			Version: 1,
			Services: []config.Service{{
				Name: "identity",
				Host: "http://identity-default:8080",
				Routes: []config.RouterConfig{{
					Path:                  "/auth/{rest:.*}",
					Methods:               []string{"GET"},
					ShadowTrafficPercent:  100,
					ShadowMinRequests:     1,
					ShadowMaxLatencyDelta: "10ms",
					Backends: []config.Backend{{
						URLPattern: "/v1/{rest:.*}",
						Host:       "http://identity-v1:8080",
					}},
				}},
			}},
		}},
	}
	gw, err := gatewaypkg.NewGateway(gatewaypkg.Dependencies{
		Config: cfg,
		Logger: logging.NewLogger(false),
	}, "test")
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}
	route := cfg.GetAllRoutesFromServices(logging.NewLogger(false))[0]
	backend := route.Backends[0]
	destination := strings.TrimSpace(backend.Host)
	gw.RecordBackendSuccessForTest(route, backend, destination, http.StatusOK, 100*time.Millisecond, time.Now().UTC())
	gw.RecordShadowResultForTest(route, backend, destination, http.StatusOK, 140*time.Millisecond, nil)

	api := NewManagementAPI(gw, logging.NewLogger(false), nil)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/gateway/shadow-evaluate", nil)
	resp := httptest.NewRecorder()

	api.getGatewayShadowEvaluation(resp, req)

	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.Code)
	}
	var payload struct {
		Total      int  `json:"total"`
		Failed     int  `json:"failed"`
		WithPolicy int  `json:"with_policy"`
		AllHealthy bool `json:"all_healthy"`
		Routes     []struct {
			ServiceName      string   `json:"service_name"`
			PolicyConfigured bool     `json:"policy_configured"`
			Healthy          bool     `json:"healthy"`
			Reasons          []string `json:"reasons"`
		} `json:"routes"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &payload); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if payload.Total != 1 || payload.WithPolicy != 1 || payload.Failed != 1 || payload.AllHealthy {
		t.Fatalf("unexpected shadow evaluation payload: %+v", payload)
	}
	if payload.Routes[0].ServiceName != "identity" || payload.Routes[0].Healthy || !payload.Routes[0].PolicyConfigured {
		t.Fatalf("unexpected route evaluation: %+v", payload.Routes[0])
	}
}

func TestGetProposalReadinessReportsBlockingConditions(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get working directory: %v", err)
	}
	tempDir := t.TempDir()
	if err := os.Chdir(tempDir); err != nil {
		t.Fatalf("failed to chdir temp dir: %v", err)
	}
	defer func() {
		_ = os.Chdir(wd)
	}()

	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Security: config.SecurityConfig{
			MutationPolicy: config.MutationPolicy{
				Enabled:                            true,
				MinApproversForHighImpactProposals: 2,
			},
		},
	}
	gw, err := gatewaypkg.NewGateway(gatewaypkg.Dependencies{Config: cfg, Logger: logging.NewLogger(false)}, "test")
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}
	api := NewManagementAPI(gw, logging.NewLogger(false), nil)

	proposalID, err := saveConfigProposal("services_replace", "replace", "deploy-bot", "prod", "", "", nil, nil, nil, 0, nil, 0, 0, "", false, "", "", "rollout", "readiness test", "CHG-R1", time.Now().UTC().Add(2*time.Hour), 2, map[string]interface{}{"action": "replace"}, cfg)
	if err != nil {
		t.Fatalf("failed to save proposal: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/proposals/"+proposalID+"/readiness", nil)
	req = mux.SetURLVars(req, map[string]string{"id": proposalID})
	resp := httptest.NewRecorder()
	api.getProposalReadiness(resp, req)

	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.Code, resp.Body.String())
	}
	var payload struct {
		ReadyForApply     bool     `json:"ready_for_apply"`
		ApprovalCount     int      `json:"approval_count"`
		RequiredApprovals int      `json:"required_approvals"`
		NotBeforeReady    bool     `json:"not_before_ready"`
		Blockers          []string `json:"blockers"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &payload); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if payload.ReadyForApply {
		t.Fatalf("expected proposal not to be ready for apply")
	}
	if payload.ApprovalCount != 0 || payload.RequiredApprovals != 2 {
		t.Fatalf("unexpected approval readiness payload: %+v", payload)
	}
	if payload.NotBeforeReady {
		t.Fatalf("expected not_before gate to block readiness")
	}
	if len(payload.Blockers) < 2 {
		t.Fatalf("expected multiple blockers, got %+v", payload.Blockers)
	}
}

func TestGetProposalQueueIncludesReadinessSummary(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get working directory: %v", err)
	}
	tempDir := t.TempDir()
	if err := os.Chdir(tempDir); err != nil {
		t.Fatalf("failed to chdir temp dir: %v", err)
	}
	defer func() {
		_ = os.Chdir(wd)
	}()

	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Security: config.SecurityConfig{
			MutationPolicy: config.MutationPolicy{
				Enabled: true,
				ProposalQueue: config.ProposalQueuePolicy{
					DefaultUrgency: config.ProposalQueueUrgencyThresholds{
						ReadyAgingAfter:   "3h",
						ReadyOverdueAfter: "6h",
					},
					EnvironmentUrgency: map[string]config.ProposalQueueUrgencyThresholds{
						"staging": {
							ReadyAgingAfter:   "30m",
							ReadyOverdueAfter: "4h",
						},
						"prod": {
							BlockedAgingAfter:   "30m",
							BlockedOverdueAfter: "1h",
						},
					},
				},
			},
		},
	}
	gw, err := gatewaypkg.NewGateway(gatewaypkg.Dependencies{Config: cfg, Logger: logging.NewLogger(false)}, "test")
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}
	api := NewManagementAPI(gw, logging.NewLogger(false), nil)

	readyID, err := saveConfigProposal("config_merge", "merge", "deploy-bot", "prod", "", "", nil, nil, nil, 0, nil, 0, 0, "", false, "", "", "ready", "queue ready", "CHG-Q1", time.Time{}, 1, map[string]interface{}{"action": "merge"}, cfg)
	if err != nil {
		t.Fatalf("failed to save ready proposal: %v", err)
	}
	readyRecord, err := loadConfigProposal(readyID)
	if err != nil {
		t.Fatalf("failed to load ready proposal: %v", err)
	}
	readyRecord.Status = "approved"
	readyRecord.ReviewedBy = "ops-lead"
	readyRecord.ReviewedAt = time.Now().UTC()
	readyRecord.Approvals = []proposalApproval{{
		Reviewer:   "ops-lead",
		ReviewNote: "ready for apply",
		CreatedAt:  time.Now().UTC(),
	}}
	if err := saveConfigProposalRecord(readyRecord); err != nil {
		t.Fatalf("failed to persist ready proposal status: %v", err)
	}
	blockedID, err := saveConfigProposal("services_replace", "replace", "deploy-bot", "prod", "", "", nil, nil, nil, 0, nil, 0, 0, "", false, "", "", "blocked", "queue blocked", "CHG-Q2", time.Now().UTC().Add(time.Hour), 2, map[string]interface{}{"action": "replace"}, cfg)
	if err != nil {
		t.Fatalf("failed to save blocked proposal: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/proposals/queue", nil)
	resp := httptest.NewRecorder()
	api.getProposalQueue(resp, req)

	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.Code, resp.Body.String())
	}

	var payload struct {
		Queue []struct {
			ID                string   `json:"id"`
			ReadyForApply     bool     `json:"ready_for_apply"`
			NeedsApproval     bool     `json:"needs_approval"`
			NeedsSchedule     bool     `json:"needs_schedule"`
			NeedsVerification bool     `json:"needs_verification"`
			NextAction        string   `json:"next_action"`
			PriorityScore     int      `json:"priority_score"`
			PriorityReason    string   `json:"priority_reason"`
			Blockers          []string `json:"blockers"`
			Readiness         struct {
				ReadyForApply bool `json:"ready_for_apply"`
			} `json:"readiness"`
		} `json:"queue"`
		Summary struct {
			Total                  int `json:"total"`
			ReadyCount             int `json:"ready_count"`
			BlockedCount           int `json:"blocked_count"`
			NeedsApprovalCount     int `json:"needs_approval_count"`
			NeedsScheduleCount     int `json:"needs_schedule_count"`
			NeedsVerificationCount int `json:"needs_verification_count"`
			OldestBlocked          struct {
				ProposalID string `json:"proposal_id"`
				AgeSeconds int64  `json:"age_seconds"`
			} `json:"oldest_blocked"`
			OldestReady struct {
				ProposalID      string `json:"proposal_id"`
				ReadyAgeSeconds int64  `json:"ready_age_seconds"`
			} `json:"oldest_ready"`
			HighestPriority struct {
				ProposalID string `json:"proposal_id"`
				Score      int    `json:"score"`
				Reason     string `json:"reason"`
			} `json:"highest_priority"`
		} `json:"summary"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &payload); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if payload.Summary.Total != 2 || payload.Summary.ReadyCount != 1 || payload.Summary.BlockedCount != 1 {
		t.Fatalf("unexpected queue summary: %+v", payload.Summary)
	}
	if payload.Summary.NeedsApprovalCount != 1 || payload.Summary.NeedsScheduleCount != 0 || payload.Summary.NeedsVerificationCount != 0 {
		t.Fatalf("unexpected queue action summary: %+v", payload.Summary)
	}
	if payload.Summary.OldestBlocked.ProposalID != blockedID || payload.Summary.OldestBlocked.AgeSeconds < 0 {
		t.Fatalf("unexpected oldest blocked summary: %+v", payload.Summary.OldestBlocked)
	}
	if payload.Summary.OldestReady.ProposalID != readyID || payload.Summary.OldestReady.ReadyAgeSeconds < 0 {
		t.Fatalf("unexpected oldest ready summary: %+v", payload.Summary.OldestReady)
	}
	if payload.Summary.HighestPriority.ProposalID != blockedID || payload.Summary.HighestPriority.Score <= 0 || payload.Summary.HighestPriority.Reason != "approval_blocked" {
		t.Fatalf("unexpected highest priority summary: %+v", payload.Summary.HighestPriority)
	}
	if len(payload.Queue) != 2 {
		t.Fatalf("expected 2 queue entries, got %d", len(payload.Queue))
	}
	if payload.Queue[0].ID != blockedID || payload.Queue[0].ReadyForApply || payload.Queue[0].NextAction != "needs_approval" {
		t.Fatalf("unexpected highest-priority blocked queue entry: %+v", payload.Queue[0])
	}
	if !payload.Queue[0].NeedsApproval || payload.Queue[0].NeedsSchedule || payload.Queue[0].NeedsVerification || payload.Queue[0].PriorityReason != "approval_blocked" || payload.Queue[0].PriorityScore <= 0 {
		t.Fatalf("expected blocked queue entry to carry approval priority: %+v", payload.Queue[0])
	}
	if len(payload.Queue[0].Blockers) == 0 {
		t.Fatalf("expected blocked proposal to include blockers")
	}

	if payload.Queue[1].ID != readyID || !payload.Queue[1].ReadyForApply || payload.Queue[1].NextAction != "apply" {
		t.Fatalf("unexpected ready queue entry: %+v", payload.Queue[1])
	}
	if payload.Queue[1].NeedsApproval || payload.Queue[1].NeedsSchedule || payload.Queue[1].NeedsVerification {
		t.Fatalf("did not expect ready queue entry to require follow-up: %+v", payload.Queue[1])
	}
	if payload.Queue[1].Readiness.ReadyForApply != payload.Queue[1].ReadyForApply {
		t.Fatalf("expected embedded readiness to match ready state for ready entry: %+v", payload.Queue[1])
	}
	if payload.Queue[1].PriorityReason != "ready_to_apply" && payload.Queue[1].PriorityReason != "ready_and_aging" {
		t.Fatalf("unexpected ready priority reason: %+v", payload.Queue[1])
	}
}

func TestResolveProposalQueueUrgencyThresholdsAppliesEnvironmentOverrides(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Security: config.SecurityConfig{
			MutationPolicy: config.MutationPolicy{
				ProposalQueue: config.ProposalQueuePolicy{
					DefaultUrgency: config.ProposalQueueUrgencyThresholds{
						ReadyAgingAfter:     "2h",
						ReadyOverdueAfter:   "8h",
						BlockedAgingAfter:   "6h",
						BlockedOverdueAfter: "36h",
					},
					EnvironmentUrgency: map[string]config.ProposalQueueUrgencyThresholds{
						"prod": {
							ReadyAgingAfter:     "30m",
							BlockedOverdueAfter: "12h",
						},
					},
				},
			},
		},
	}

	prod := resolveProposalQueueUrgencyThresholds(cfg, "prod")
	if prod.readyAgingAfter != 30*time.Minute || prod.readyOverdueAfter != 8*time.Hour || prod.blockedAgingAfter != 6*time.Hour || prod.blockedOverdueAfter != 12*time.Hour {
		t.Fatalf("unexpected prod urgency thresholds: %+v", prod)
	}

	staging := resolveProposalQueueUrgencyThresholds(cfg, "staging")
	if staging.readyAgingAfter != 2*time.Hour || staging.readyOverdueAfter != 8*time.Hour || staging.blockedAgingAfter != 6*time.Hour || staging.blockedOverdueAfter != 36*time.Hour {
		t.Fatalf("unexpected staging urgency thresholds: %+v", staging)
	}
}

func TestGetProposalQueueSupportsFiltersAndGroupedSummary(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get working directory: %v", err)
	}
	tempDir := t.TempDir()
	if err := os.Chdir(tempDir); err != nil {
		t.Fatalf("failed to chdir temp dir: %v", err)
	}
	defer func() {
		_ = os.Chdir(wd)
	}()

	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Security: config.SecurityConfig{
			MutationPolicy: config.MutationPolicy{
				Enabled: true,
				ProposalQueue: config.ProposalQueuePolicy{
					DefaultUrgency: config.ProposalQueueUrgencyThresholds{
						ReadyAgingAfter:   "3h",
						ReadyOverdueAfter: "6h",
					},
					EnvironmentUrgency: map[string]config.ProposalQueueUrgencyThresholds{
						"staging": {
							ReadyAgingAfter:   "30m",
							ReadyOverdueAfter: "4h",
						},
						"prod": {
							BlockedAgingAfter:   "30m",
							BlockedOverdueAfter: "1h",
						},
					},
				},
			},
		},
	}
	gw, err := gatewaypkg.NewGateway(gatewaypkg.Dependencies{Config: cfg, Logger: logging.NewLogger(false)}, "test")
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}
	api := NewManagementAPI(gw, logging.NewLogger(false), nil)

	readyID, err := saveConfigProposal("config_merge", "merge", "deploy-bot", "staging", "", "", nil, nil, nil, 0, nil, 0, 0, "", false, "", "", "ready", "queue ready", "CHG-Q3", time.Time{}, 1, map[string]interface{}{"action": "merge"}, cfg)
	if err != nil {
		t.Fatalf("failed to save ready proposal: %v", err)
	}
	readyRecord, err := loadConfigProposal(readyID)
	if err != nil {
		t.Fatalf("failed to load ready proposal: %v", err)
	}
	readyRecord.Status = "approved"
	readyRecord.ReviewedBy = "ops-lead"
	readyRecord.ReviewedAt = time.Now().UTC().Add(-2 * time.Hour)
	readyRecord.CreatedAt = time.Now().UTC().Add(-6 * time.Hour)
	readyRecord.Approvals = []proposalApproval{{
		Reviewer:   "ops-lead",
		ReviewNote: "healthy",
		CreatedAt:  time.Now().UTC().Add(-2 * time.Hour),
	}}
	if err := saveConfigProposalRecord(readyRecord); err != nil {
		t.Fatalf("failed to persist ready proposal: %v", err)
	}

	blockedID, err := saveConfigProposal("services_replace", "replace", "deploy-bot", "prod", "", "", nil, nil, nil, 0, nil, 0, 0, "", false, "", "", "blocked", "queue blocked", "CHG-Q4", time.Now().UTC().Add(time.Hour), 2, map[string]interface{}{"action": "replace"}, cfg)
	if err != nil {
		t.Fatalf("failed to save blocked proposal: %v", err)
	}
	blockedRecord, err := loadConfigProposal(blockedID)
	if err != nil {
		t.Fatalf("failed to load blocked proposal: %v", err)
	}
	blockedRecord.CreatedAt = time.Now().UTC().Add(-2 * time.Hour)
	if err := saveConfigProposalRecord(blockedRecord); err != nil {
		t.Fatalf("failed to persist blocked proposal age override: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/proposals/queue?environment=staging&ready=true", nil)
	resp := httptest.NewRecorder()
	api.getProposalQueue(resp, req)

	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.Code, resp.Body.String())
	}

	var payload struct {
		Queue []struct {
			ID            string `json:"id"`
			Environment   string `json:"environment"`
			ReadyForApply bool   `json:"ready_for_apply"`
			NextAction    string `json:"next_action"`
			Urgency       string `json:"urgency"`
			SLABreached   bool   `json:"sla_breached"`
		} `json:"queue"`
		Summary struct {
			Total                    int                    `json:"total"`
			ReadyCount               int                    `json:"ready_count"`
			BlockedCount             int                    `json:"blocked_count"`
			ByEnvironment            map[string]int         `json:"by_environment"`
			ByStatus                 map[string]int         `json:"by_status"`
			ByNextAction             map[string]int         `json:"by_next_action"`
			ByUrgency                map[string]int         `json:"by_urgency"`
			SLABreachCount           int                    `json:"sla_breach_count"`
			SLABreachesByEnvironment map[string]int         `json:"sla_breaches_by_environment"`
			OldestOverdue            map[string]interface{} `json:"oldest_overdue"`
			OldestSLABreach          map[string]interface{} `json:"oldest_sla_breach"`
			Filters                  struct {
				Environment string `json:"environment"`
				Status      string `json:"status"`
				NextAction  string `json:"next_action"`
				Urgency     string `json:"urgency"`
				Ready       *bool  `json:"ready"`
			} `json:"filters"`
		} `json:"summary"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &payload); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if payload.Summary.Total != 1 || payload.Summary.ReadyCount != 1 || payload.Summary.BlockedCount != 0 {
		t.Fatalf("unexpected filtered queue summary: %+v", payload.Summary)
	}
	if payload.Summary.Filters.Environment != "staging" || payload.Summary.Filters.Ready == nil || !*payload.Summary.Filters.Ready {
		t.Fatalf("unexpected applied filters: %+v", payload.Summary.Filters)
	}
	if payload.Summary.ByEnvironment["staging"] != 1 {
		t.Fatalf("expected staging environment count, got %+v", payload.Summary.ByEnvironment)
	}
	if payload.Summary.ByStatus["approved"] != 1 {
		t.Fatalf("expected approved status count, got %+v", payload.Summary.ByStatus)
	}
	if payload.Summary.ByNextAction["apply"] != 1 {
		t.Fatalf("expected apply next-action count, got %+v", payload.Summary.ByNextAction)
	}
	if payload.Summary.ByUrgency["aging"] != 1 {
		t.Fatalf("expected aging urgency count, got %+v", payload.Summary.ByUrgency)
	}
	if payload.Summary.SLABreachCount != 0 {
		t.Fatalf("expected no SLA breaches in ready-only filtered queue, got %+v", payload.Summary)
	}
	if len(payload.Queue) != 1 || payload.Queue[0].ID != readyID || payload.Queue[0].Environment != "staging" || !payload.Queue[0].ReadyForApply || payload.Queue[0].NextAction != "apply" || payload.Queue[0].Urgency != "aging" || payload.Queue[0].SLABreached {
		t.Fatalf("unexpected filtered queue entry: %+v", payload.Queue)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/proposals/queue?next_action=needs_approval", nil)
	resp = httptest.NewRecorder()
	api.getProposalQueue(resp, req)

	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200 for next_action filter, got %d: %s", resp.Code, resp.Body.String())
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &payload); err != nil {
		t.Fatalf("failed to decode next_action filtered response: %v", err)
	}
	if payload.Summary.Total != 1 || payload.Summary.Filters.NextAction != "needs_approval" {
		t.Fatalf("unexpected next_action filter summary: %+v", payload.Summary)
	}
	if len(payload.Queue) != 1 || payload.Queue[0].NextAction != "needs_approval" {
		t.Fatalf("unexpected next_action filtered queue: %+v", payload.Queue)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/proposals/queue?urgency=aging", nil)
	resp = httptest.NewRecorder()
	api.getProposalQueue(resp, req)

	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200 for urgency filter, got %d: %s", resp.Code, resp.Body.String())
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &payload); err != nil {
		t.Fatalf("failed to decode urgency filtered response: %v", err)
	}
	if payload.Summary.Total != 1 || payload.Summary.Filters.Urgency != "aging" {
		t.Fatalf("unexpected urgency filter summary: %+v", payload.Summary)
	}
	if len(payload.Queue) != 1 || payload.Queue[0].ID != readyID || payload.Queue[0].Urgency != "aging" {
		t.Fatalf("unexpected urgency filtered queue: %+v", payload.Queue)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/proposals/queue?urgency=overdue&status=pending", nil)
	resp = httptest.NewRecorder()
	api.getProposalQueue(resp, req)

	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200 for overdue urgency filter, got %d: %s", resp.Code, resp.Body.String())
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &payload); err != nil {
		t.Fatalf("failed to decode overdue urgency response: %v", err)
	}
	if payload.Summary.SLABreachCount != 1 || payload.Summary.SLABreachesByEnvironment["prod"] != 1 {
		t.Fatalf("unexpected SLA breach summary: %+v", payload.Summary)
	}
	if oldestID, _ := payload.Summary.OldestSLABreach["proposal_id"].(string); oldestID == "" {
		t.Fatalf("expected oldest SLA breach proposal id, got %+v", payload.Summary.OldestSLABreach)
	}
	if len(payload.Queue) != 1 || !payload.Queue[0].SLABreached || payload.Queue[0].Urgency != "overdue" {
		t.Fatalf("expected overdue queue item to be marked as SLA-breached, got %+v", payload.Queue)
	}
}

func TestApplyReadyProposalQueueAppliesOnlyReadyCandidates(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get working directory: %v", err)
	}
	tempDir := t.TempDir()
	if err := os.Chdir(tempDir); err != nil {
		t.Fatalf("failed to chdir temp dir: %v", err)
	}
	defer func() {
		_ = os.Chdir(wd)
	}()

	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Security: config.SecurityConfig{
			MutationPolicy: config.MutationPolicy{
				Enabled: true,
			},
		},
	}
	gw, err := gatewaypkg.NewGateway(gatewaypkg.Dependencies{Config: cfg, Logger: logging.NewLogger(false)}, "test")
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}
	api := NewManagementAPI(gw, logging.NewLogger(false), nil)

	readyID, err := saveConfigProposal("config_merge", "merge", "deploy-bot", "prod", "", "", nil, nil, nil, 0, nil, 0, 0, "", false, "", "", "ready", "batch apply ready", "CHG-Q5", time.Time{}, 1, map[string]interface{}{"action": "merge"}, cfg)
	if err != nil {
		t.Fatalf("failed to save ready proposal: %v", err)
	}
	readyRecord, err := loadConfigProposal(readyID)
	if err != nil {
		t.Fatalf("failed to load ready proposal: %v", err)
	}
	readyRecord.Status = "approved"
	readyRecord.ReviewedBy = "ops-lead"
	readyRecord.ReviewedAt = time.Now().UTC().Add(-2 * time.Hour)
	readyRecord.CreatedAt = time.Now().UTC().Add(-6 * time.Hour)
	readyRecord.Approvals = []proposalApproval{{
		Reviewer:   "ops-lead",
		ReviewNote: "batch ready",
		CreatedAt:  time.Now().UTC().Add(-2 * time.Hour),
	}}
	if err := saveConfigProposalRecord(readyRecord); err != nil {
		t.Fatalf("failed to persist ready proposal: %v", err)
	}

	blockedID, err := saveConfigProposal("services_replace", "replace", "deploy-bot", "prod", "", "", nil, nil, nil, 0, nil, 0, 0, "", false, "", "", "blocked", "batch apply blocked", "CHG-Q6", time.Now().UTC().Add(time.Hour), 2, map[string]interface{}{"action": "replace"}, cfg)
	if err != nil {
		t.Fatalf("failed to save blocked proposal: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/proposals/queue/apply-ready?reviewer=platform-admin&review_note=batch&status=approved&next_action=apply&urgency=aging", nil)
	resp := httptest.NewRecorder()
	api.applyReadyProposalQueue(resp, req)

	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.Code, resp.Body.String())
	}

	var payload struct {
		Success bool `json:"success"`
		Data    struct {
			CandidateCount int `json:"candidate_count"`
			AppliedCount   int `json:"applied_count"`
			FailedCount    int `json:"failed_count"`
			Results        []struct {
				ProposalID string `json:"proposal_id"`
				Success    bool   `json:"success"`
				Status     string `json:"status"`
			} `json:"results"`
		} `json:"data"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &payload); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if !payload.Success || payload.Data.CandidateCount != 1 || payload.Data.AppliedCount != 1 || payload.Data.FailedCount != 0 {
		t.Fatalf("unexpected batch apply payload: %+v", payload)
	}
	if len(payload.Data.Results) != 1 || payload.Data.Results[0].ProposalID != readyID || !payload.Data.Results[0].Success || payload.Data.Results[0].Status != "applied" {
		t.Fatalf("unexpected batch apply result: %+v", payload.Data.Results)
	}

	readyRecord, err = loadConfigProposal(readyID)
	if err != nil {
		t.Fatalf("failed to reload ready proposal: %v", err)
	}
	if readyRecord.Status != "applied" || readyRecord.AppliedAt.IsZero() {
		t.Fatalf("expected ready proposal to be applied, got status=%q applied_at=%v", readyRecord.Status, readyRecord.AppliedAt)
	}
	blockedRecord, err := loadConfigProposal(blockedID)
	if err != nil {
		t.Fatalf("failed to reload blocked proposal: %v", err)
	}
	if blockedRecord.Status != "pending" {
		t.Fatalf("expected blocked proposal to remain pending, got %q", blockedRecord.Status)
	}

	req = httptest.NewRequest(http.MethodPost, "/api/v1/proposals/queue/apply-ready?reviewer=platform-admin&next_action=needs_approval", nil)
	resp = httptest.NewRecorder()
	api.applyReadyProposalQueue(resp, req)
	if resp.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid apply-ready next_action, got %d: %s", resp.Code, resp.Body.String())
	}

	req = httptest.NewRequest(http.MethodPost, "/api/v1/proposals/queue/apply-ready?reviewer=platform-admin&urgency=invalid", nil)
	resp = httptest.NewRecorder()
	api.applyReadyProposalQueue(resp, req)
	if resp.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid apply-ready urgency, got %d: %s", resp.Code, resp.Body.String())
	}
}

func TestGetBlockedProposalQueueReportAggregatesReasons(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get working directory: %v", err)
	}
	tempDir := t.TempDir()
	if err := os.Chdir(tempDir); err != nil {
		t.Fatalf("failed to chdir temp dir: %v", err)
	}
	defer func() {
		_ = os.Chdir(wd)
	}()

	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Security: config.SecurityConfig{
			MutationPolicy: config.MutationPolicy{
				Enabled:                            true,
				MinApproversForHighImpactProposals: 2,
			},
		},
	}
	gw, err := gatewaypkg.NewGateway(gatewaypkg.Dependencies{Config: cfg, Logger: logging.NewLogger(false)}, "test")
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}
	api := NewManagementAPI(gw, logging.NewLogger(false), nil)

	firstID, err := saveConfigProposal("services_replace", "replace", "deploy-bot", "prod", "", "", nil, nil, nil, 0, nil, 0, 0, "", false, "", "", "blocked-1", "blocked report one", "CHG-B1", time.Now().UTC().Add(time.Hour), 2, map[string]interface{}{"action": "replace"}, cfg)
	if err != nil {
		t.Fatalf("failed to save first blocked proposal: %v", err)
	}
	secondID, err := saveConfigProposal("services_replace", "replace", "deploy-bot", "prod", "", "", nil, nil, nil, 0, nil, 0, 0, "", false, "", "", "blocked-2", "blocked report two", "CHG-B2", time.Now().UTC().Add(2*time.Hour), 2, map[string]interface{}{"action": "replace"}, cfg)
	if err != nil {
		t.Fatalf("failed to save second blocked proposal: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/proposals/queue/blocked-report?environment=prod", nil)
	resp := httptest.NewRecorder()
	api.getBlockedProposalQueueReport(resp, req)

	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.Code, resp.Body.String())
	}

	var payload struct {
		BlockedProposalCount int      `json:"blocked_proposal_count"`
		BlockedProposalIDs   []string `json:"blocked_proposal_ids"`
		Blockers             []struct {
			Reason      string   `json:"reason"`
			Count       int      `json:"count"`
			ProposalIDs []string `json:"proposal_ids"`
		} `json:"blockers"`
		ByAction map[string]int `json:"by_action"`
		Filters  struct {
			Environment string `json:"environment"`
		} `json:"filters"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &payload); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if payload.BlockedProposalCount != 2 || len(payload.BlockedProposalIDs) != 2 {
		t.Fatalf("unexpected blocked proposal summary: %+v", payload)
	}
	if payload.Filters.Environment != "prod" {
		t.Fatalf("unexpected filter summary: %+v", payload.Filters)
	}
	if payload.ByAction["services_replace"] != 2 {
		t.Fatalf("expected services_replace blocker count, got %+v", payload.ByAction)
	}
	if len(payload.Blockers) == 0 {
		t.Fatalf("expected aggregated blocker entries")
	}
	if payload.Blockers[0].Count < 2 {
		t.Fatalf("expected top blocker to affect both proposals, got %+v", payload.Blockers[0])
	}
	joined := strings.Join(payload.Blockers[0].ProposalIDs, ",")
	if !strings.Contains(joined, firstID) || !strings.Contains(joined, secondID) {
		t.Fatalf("expected top blocker to reference both proposal ids, got %+v", payload.Blockers[0])
	}
}

func TestExplainBlockedProposalReturnsDiagnosis(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get working directory: %v", err)
	}
	tempDir := t.TempDir()
	if err := os.Chdir(tempDir); err != nil {
		t.Fatalf("failed to chdir temp dir: %v", err)
	}
	defer func() {
		_ = os.Chdir(wd)
	}()

	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Security: config.SecurityConfig{
			MutationPolicy: config.MutationPolicy{
				Enabled:                            true,
				MinApproversForHighImpactProposals: 2,
			},
		},
	}
	gw, err := gatewaypkg.NewGateway(gatewaypkg.Dependencies{Config: cfg, Logger: logging.NewLogger(false)}, "test")
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}
	api := NewManagementAPI(gw, logging.NewLogger(false), nil)

	proposalID, err := saveConfigProposal("services_replace", "replace", "deploy-bot", "prod", "", "", nil, nil, nil, 0, nil, 0, 0, "", false, "", "", "blocked", "explain blocked", "CHG-X1", time.Now().UTC().Add(time.Hour), 2, map[string]interface{}{"action": "replace"}, cfg)
	if err != nil {
		t.Fatalf("failed to save proposal: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/proposals/"+proposalID+"/explain-blocked", nil)
	req = mux.SetURLVars(req, map[string]string{"id": proposalID})
	resp := httptest.NewRecorder()
	api.explainBlockedProposal(resp, req)

	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.Code, resp.Body.String())
	}
	var payload struct {
		ProposalID        string   `json:"proposal_id"`
		ReadyForApply     bool     `json:"ready_for_apply"`
		NextAction        string   `json:"next_action"`
		PrimaryBlocker    string   `json:"primary_blocker"`
		NeedsApproval     bool     `json:"needs_approval"`
		NeedsSchedule     bool     `json:"needs_schedule"`
		NeedsVerification bool     `json:"needs_verification"`
		Blockers          []string `json:"blockers"`
		Explanation       string   `json:"explanation"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &payload); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if payload.ProposalID != proposalID || payload.ReadyForApply {
		t.Fatalf("unexpected blocked explanation payload: %+v", payload)
	}
	if payload.NextAction != "needs_approval" || !payload.NeedsApproval || payload.NeedsSchedule || payload.NeedsVerification {
		t.Fatalf("unexpected blocked diagnosis flags: %+v", payload)
	}
	if len(payload.Blockers) == 0 || payload.PrimaryBlocker == "" || payload.Explanation == "" {
		t.Fatalf("expected blockers and explanation, got %+v", payload)
	}
}

func TestApproveReadyProposalQueueApprovesApprovalBlockedCandidates(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get working directory: %v", err)
	}
	tempDir := t.TempDir()
	if err := os.Chdir(tempDir); err != nil {
		t.Fatalf("failed to chdir temp dir: %v", err)
	}
	defer func() {
		_ = os.Chdir(wd)
	}()

	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Security: config.SecurityConfig{
			MutationPolicy: config.MutationPolicy{
				Enabled:                            true,
				MinApproversForHighImpactProposals: 2,
			},
		},
	}
	gw, err := gatewaypkg.NewGateway(gatewaypkg.Dependencies{Config: cfg, Logger: logging.NewLogger(false)}, "test")
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}
	api := NewManagementAPI(gw, logging.NewLogger(false), nil)

	approvalBlockedID, err := saveConfigProposal("services_replace", "replace", "deploy-bot", "prod", "", "", nil, nil, nil, 0, nil, 0, 0, "", false, "", "", "approval-blocked", "approve ready target", "CHG-A1", time.Time{}, 2, map[string]interface{}{"action": "replace"}, cfg)
	if err != nil {
		t.Fatalf("failed to save approval-blocked proposal: %v", err)
	}
	scheduleBlockedID, err := saveConfigProposal("config_merge", "merge", "deploy-bot", "prod", "", "", nil, nil, nil, 0, nil, 0, 0, "", false, "", "", "schedule-blocked", "approve ready skip", "CHG-A2", time.Now().UTC().Add(time.Hour), 1, map[string]interface{}{"action": "merge"}, cfg)
	if err != nil {
		t.Fatalf("failed to save schedule-blocked proposal: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/proposals/queue/approve-ready?reviewer=ops-lead&review_note=batch&status=pending&next_action=needs_approval&urgency=fresh", nil)
	resp := httptest.NewRecorder()
	api.approveReadyProposalQueue(resp, req)

	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.Code, resp.Body.String())
	}

	var payload struct {
		Success bool `json:"success"`
		Data    struct {
			CandidateCount int `json:"candidate_count"`
			ApprovedCount  int `json:"approved_count"`
			FailedCount    int `json:"failed_count"`
			Results        []struct {
				ProposalID string `json:"proposal_id"`
				Success    bool   `json:"success"`
				Status     string `json:"status"`
			} `json:"results"`
		} `json:"data"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &payload); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if !payload.Success || payload.Data.CandidateCount != 2 || payload.Data.ApprovedCount != 2 || payload.Data.FailedCount != 0 {
		t.Fatalf("unexpected batch approve payload: %+v", payload)
	}
	if len(payload.Data.Results) != 2 {
		t.Fatalf("unexpected batch approve results: %+v", payload.Data.Results)
	}
	joined := payload.Data.Results[0].ProposalID + "," + payload.Data.Results[1].ProposalID
	if !strings.Contains(joined, approvalBlockedID) || !strings.Contains(joined, scheduleBlockedID) {
		t.Fatalf("expected both proposals to be batch-approved, got %+v", payload.Data.Results)
	}

	approvalBlockedRecord, err := loadConfigProposal(approvalBlockedID)
	if err != nil {
		t.Fatalf("failed to reload approval-blocked proposal: %v", err)
	}
	if approvalBlockedRecord.Status != "pending" && approvalBlockedRecord.Status != "approved" {
		t.Fatalf("expected approval-blocked proposal to remain pending/approved after one batch approval, got %q", approvalBlockedRecord.Status)
	}
	if len(approvalBlockedRecord.Approvals) != 1 {
		t.Fatalf("expected one recorded approval on approval-blocked proposal, got %d", len(approvalBlockedRecord.Approvals))
	}
	scheduleBlockedRecord, err := loadConfigProposal(scheduleBlockedID)
	if err != nil {
		t.Fatalf("failed to reload schedule-blocked proposal: %v", err)
	}
	if len(scheduleBlockedRecord.Approvals) != 1 {
		t.Fatalf("expected schedule-blocked proposal to receive one approval, got approvals=%d", len(scheduleBlockedRecord.Approvals))
	}

	req = httptest.NewRequest(http.MethodPost, "/api/v1/proposals/queue/approve-ready?reviewer=ops-lead&next_action=apply", nil)
	resp = httptest.NewRecorder()
	api.approveReadyProposalQueue(resp, req)
	if resp.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid approve-ready next_action, got %d: %s", resp.Code, resp.Body.String())
	}

	req = httptest.NewRequest(http.MethodPost, "/api/v1/proposals/queue/approve-ready?reviewer=ops-lead&urgency=invalid", nil)
	resp = httptest.NewRecorder()
	api.approveReadyProposalQueue(resp, req)
	if resp.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid approve-ready urgency, got %d: %s", resp.Code, resp.Body.String())
	}
}
