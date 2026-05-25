package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/bhangun/iket/pkg/config"
	"github.com/bhangun/iket/pkg/core/authcontext"
	"github.com/bhangun/iket/pkg/core/credentials"
	coreerrors "github.com/bhangun/iket/pkg/core/errors"
	gatewaypkg "github.com/bhangun/iket/pkg/core/gateway"
	"github.com/bhangun/iket/pkg/logging"
	"github.com/bhangun/iket/pkg/plugin"
	apikeyplugin "github.com/bhangun/iket/pkg/plugin/apikey"
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
		Security: config.SecurityConfig{
			LimitAlertBucketClasses: map[string]config.LimitAlertBucketClassConfig{
				"vip-jwt": {
					KeyType:     "jwt_sub",
					BucketRegex: "^vip-",
				},
			},
		},
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

func TestCreateServiceDryRunDoesNotMutateLiveConfig(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Services: []config.ServiceConfig{{
			Version: 1,
			Services: []config.Service{{
				Name: "identity",
				Host: "http://identity-old:8080",
				Routes: []config.RouterConfig{{
					Path:    "/auth",
					Methods: []string{"GET"},
					Backends: []config.Backend{{
						URLPattern: "/auth",
					}},
				}},
			}},
		}},
	}
	gw := mustTestGateway(t, cfg)
	api := NewManagementAPI(gw, logging.NewLogger(false), nil)

	body := strings.NewReader(`{"services":[{"name":"identity","host":"http://identity-new:8080","routes":[{"path":"/profile","methods":["GET"]}]}]}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/services?dry_run=true", body)
	resp := httptest.NewRecorder()
	api.createService(resp, req)

	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.Code, resp.Body.String())
	}
	live := gw.GetConfig()
	service := live.Services[0].Services[0]
	if service.Host != "http://identity-old:8080" {
		t.Fatalf("dry run mutated service host: %q", service.Host)
	}
	if len(service.Routes) != 1 || service.Routes[0].Path != "/auth" {
		t.Fatalf("dry run mutated service routes: %+v", service.Routes)
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

func TestGetGatewayRoutePolicyReturnsResolvedInspection(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		AIPolicyPresets: map[string]config.AIPolicyPreset{
			"org-safe": {
				AllowedModels: []string{"gpt-4.1-mini"},
			},
		},
		Services: []config.ServiceConfig{{
			Version: 1,
			Services: []config.Service{{
				Name: "agent",
				Host: "http://agent-default:8080",
				AIPolicyPresets: map[string]config.AIPolicyPreset{
					"service-strict": {
						RequiredRequestHeaders: []string{"X-Agent-Session"},
					},
				},
				Routes: []config.RouterConfig{{
					Path:                "/ai/chat",
					Methods:             []string{"POST"},
					AIPolicyPresetChain: []string{"org-safe"},
					AIPolicyPreset:      "service-strict",
					AllowedModels:       []string{"gpt-4.1"},
					Backends: []config.Backend{
						{URLPattern: "/"},
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

	req := httptest.NewRequest(http.MethodGet, "/api/v1/gateway/route-policy?path=/ai/chat&method=POST&bucket_key=inspect", nil)
	resp := httptest.NewRecorder()
	api.getGatewayRoutePolicy(resp, req)

	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.Code, resp.Body.String())
	}
	var payload struct {
		Inspection struct {
			ServiceName      string                   `json:"service_name"`
			RoutePath        string                   `json:"route_path"`
			Method           string                   `json:"method"`
			AppliedPresets   []map[string]interface{} `json:"applied_presets"`
			EffectivePolicy  map[string]interface{}   `json:"effective_policy"`
			FieldSources     map[string]string        `json:"field_sources"`
			AvailablePresets []string                 `json:"available_presets"`
		} `json:"inspection"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &payload); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if payload.Inspection.ServiceName != "agent" || payload.Inspection.RoutePath != "/ai/chat" || payload.Inspection.Method != "POST" {
		t.Fatalf("unexpected inspection identity: %+v", payload.Inspection)
	}
	if len(payload.Inspection.AppliedPresets) != 2 {
		t.Fatalf("expected two applied presets, got %+v", payload.Inspection.AppliedPresets)
	}
	if payload.Inspection.FieldSources["AllowedModels"] != "route" {
		t.Fatalf("expected AllowedModels source route, got %+v", payload.Inspection.FieldSources)
	}
	if payload.Inspection.FieldSources["RequiredRequestHeaders"] != "preset:service-strict" {
		t.Fatalf("expected RequiredRequestHeaders source preset:service-strict, got %+v", payload.Inspection.FieldSources)
	}
	models, ok := payload.Inspection.EffectivePolicy["AllowedModels"].([]interface{})
	if !ok || len(models) != 1 || models[0] != "gpt-4.1" {
		t.Fatalf("expected route override models, got %+v", payload.Inspection.EffectivePolicy["AllowedModels"])
	}
}

func TestDiffGatewayRoutePolicyReturnsChangedFields(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Services: []config.ServiceConfig{{
			Version: 1,
			Services: []config.Service{{
				Name: "agent",
				Host: "http://agent-default:8080",
				Routes: []config.RouterConfig{
					{
						Path:          "/ai/chat",
						Methods:       []string{"POST"},
						AllowedModels: []string{"gpt-4.1"},
						Backends: []config.Backend{
							{URLPattern: "/"},
						},
					},
					{
						Path:                   "/ai/search",
						Methods:                []string{"POST"},
						AllowedModels:          []string{"gpt-4.1-mini"},
						RequiredRequestHeaders: []string{"X-Agent-Session"},
						Backends: []config.Backend{
							{URLPattern: "/"},
						},
					},
				},
			}},
		}},
		Security: config.SecurityConfig{
			LimitAlertBucketClasses: map[string]config.LimitAlertBucketClassConfig{
				"vip-jwt": {
					KeyType:     "jwt_sub",
					BucketRegex: "^vip-",
				},
			},
		},
	}
	gw, err := gatewaypkg.NewGateway(gatewaypkg.Dependencies{Config: cfg, Logger: logging.NewLogger(false)}, "test")
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}
	api := NewManagementAPI(gw, logging.NewLogger(false), nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/gateway/route-policy/diff?from_path=/ai/chat&from_method=POST&to_path=/ai/search&to_method=POST", nil)
	resp := httptest.NewRecorder()
	api.diffGatewayRoutePolicy(resp, req)

	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.Code, resp.Body.String())
	}
	var payload struct {
		Diff struct {
			ChangedFieldCount int `json:"changed_field_count"`
			ChangedFields     []struct {
				Field string `json:"field"`
			} `json:"changed_fields"`
		} `json:"diff"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &payload); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if payload.Diff.ChangedFieldCount < 2 {
		t.Fatalf("expected at least two changed fields, got %+v", payload.Diff)
	}
	fieldNames := make(map[string]struct{}, len(payload.Diff.ChangedFields))
	for _, entry := range payload.Diff.ChangedFields {
		fieldNames[entry.Field] = struct{}{}
	}
	if _, ok := fieldNames["AllowedModels"]; !ok {
		t.Fatalf("expected AllowedModels diff, got %+v", payload.Diff.ChangedFields)
	}
	if _, ok := fieldNames["RequiredRequestHeaders"]; !ok {
		t.Fatalf("expected RequiredRequestHeaders diff, got %+v", payload.Diff.ChangedFields)
	}
}

func TestGetGatewayLimitClassDigestProfileReturnsResolvedInspection(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Security: config.SecurityConfig{
			LimitClassDigestHiddenStrategyPolicyPresets: map[string]config.LimitClassDigestHiddenStrategyPolicy{
				"base-hidden":  {MinReasons: 2, PriorityCap: 3},
				"shared-exact": {DominantMode: "weighted_score", PriorityWeight: 7},
			},
			LimitClassDigestProfiles: map[string]config.LimitAlertRecipientProfile{
				"base": {
					LimitClassDigestTypes:                  []string{"alert"},
					LimitClassDigestMinSeverity:            "warning",
					LimitClassDigestMinBucketClassPriority: 4,
				},
				"overlay": {
					LimitClassDigestTypes: []string{"snooze"},
					LimitClassDigestTruncatedReasonBucketExactSeverityPolicyPresetChain: []string{"base-hidden"},
				},
				"strict": {
					LimitClassDigestMinSeverity:                                    "elevated",
					LimitClassDigestTruncatedReasonBucketExactSeverityPolicyPreset: "shared-exact",
				},
			},
			NotificationWebhooks: []config.NotificationWebhook{{
				Name:                             "pager",
				URL:                              "https://example.com/pager",
				Events:                           []string{"gateway.limit_class_alert_digest"},
				LimitClassDigestProfileChain:     []string{"base", "overlay"},
				LimitClassDigestProfile:          "strict",
				LimitClassDigestMaxBucketClasses: 2,
			}},
		},
	}
	gw, err := gatewaypkg.NewGateway(gatewaypkg.Dependencies{Config: cfg, Logger: logging.NewLogger(false)}, "test")
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}
	api := NewManagementAPI(gw, logging.NewLogger(false), nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/gateway/limit-class-digest-profile?webhook=pager", nil)
	resp := httptest.NewRecorder()
	api.getGatewayLimitClassDigestProfile(resp, req)

	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.Code, resp.Body.String())
	}
	var payload struct {
		Inspection struct {
			WebhookName       string                   `json:"webhook_name"`
			ProfileChain      []string                 `json:"profile_chain"`
			Profile           string                   `json:"profile"`
			AppliedProfiles   []map[string]interface{} `json:"applied_profiles"`
			EffectiveProfile  map[string]interface{}   `json:"effective_profile"`
			FieldSources      map[string]string        `json:"field_sources"`
			AvailableProfiles []string                 `json:"available_profiles"`
		} `json:"inspection"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &payload); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if payload.Inspection.WebhookName != "pager" || strings.Join(payload.Inspection.ProfileChain, ",") != "base,overlay" || payload.Inspection.Profile != "strict" {
		t.Fatalf("unexpected inspection identity: %+v", payload.Inspection)
	}
	if len(payload.Inspection.AppliedProfiles) != 3 {
		t.Fatalf("expected three applied profiles, got %+v", payload.Inspection.AppliedProfiles)
	}
	if payload.Inspection.FieldSources["limitClassDigestTypes"] != "profile_chain:overlay" {
		t.Fatalf("expected limitClassDigestTypes source profile_chain:overlay, got %+v", payload.Inspection.FieldSources)
	}
	if payload.Inspection.FieldSources["limitClassDigestMinSeverity"] != "profile:strict" {
		t.Fatalf("expected limitClassDigestMinSeverity source profile:strict, got %+v", payload.Inspection.FieldSources)
	}
	if payload.Inspection.FieldSources["limitClassDigestMaxBucketClasses"] != "webhook" {
		t.Fatalf("expected limitClassDigestMaxBucketClasses source webhook, got %+v", payload.Inspection.FieldSources)
	}
	if payload.Inspection.FieldSources["limitClassDigestTruncatedReasonBucketExactSeverityPolicy"] != "profile:strict" {
		t.Fatalf("expected exact severity policy source profile:strict, got %+v", payload.Inspection.FieldSources)
	}
	types, ok := payload.Inspection.EffectiveProfile["limitClassDigestTypes"].([]interface{})
	if !ok || len(types) != 1 || types[0] != "snooze" {
		t.Fatalf("expected resolved digest types snooze, got %+v", payload.Inspection.EffectiveProfile["limitClassDigestTypes"])
	}
	policy, ok := payload.Inspection.EffectiveProfile["limitClassDigestTruncatedReasonBucketExactSeverityPolicy"].(map[string]interface{})
	if !ok || policy["dominantMode"] != "weighted_score" {
		t.Fatalf("expected resolved exact severity policy from preset, got %+v", payload.Inspection.EffectiveProfile["limitClassDigestTruncatedReasonBucketExactSeverityPolicy"])
	}
	if len(payload.Inspection.AvailableProfiles) != 3 {
		t.Fatalf("expected three available profiles, got %+v", payload.Inspection.AvailableProfiles)
	}
}

func TestInspectGatewayLimitClassDigestAssertionPresetReturnsResolvedChain(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Security: config.SecurityConfig{
			LimitClassDigestAssertionPresets: map[string]config.LimitClassDigestAssertionPreset{
				"base-safety": {
					Rules: []string{"exists"},
				},
				"prod-strict": {
					PresetChain: []string{"base-safety"},
					Groups: []config.LimitClassDigestAssertionGroup{{
						Operator: "allOf",
						Rules:    []string{"regex:^crit"},
					}},
				},
			},
		},
	}
	gw, err := gatewaypkg.NewGateway(gatewaypkg.Dependencies{Config: cfg, Logger: logging.NewLogger(false)}, "test")
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}
	api := NewManagementAPI(gw, logging.NewLogger(false), nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/gateway/limit-class-digest-assertion-preset?preset=prod-strict", nil)
	resp := httptest.NewRecorder()
	api.getGatewayLimitClassDigestAssertionPreset(resp, req)

	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.Code, resp.Body.String())
	}
	var payload struct {
		Inspection struct {
			PresetName     string                   `json:"preset_name"`
			PresetChain    []string                 `json:"preset_chain"`
			AppliedPresets []map[string]interface{} `json:"applied_presets"`
			RuleSources    []string                 `json:"rule_sources"`
			GroupSources   []string                 `json:"group_sources"`
		} `json:"inspection"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &payload); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if payload.Inspection.PresetName != "prod-strict" || strings.Join(payload.Inspection.PresetChain, ",") != "base-safety" {
		t.Fatalf("unexpected preset inspection identity: %+v", payload.Inspection)
	}
	if len(payload.Inspection.AppliedPresets) != 2 {
		t.Fatalf("expected two applied presets, got %+v", payload.Inspection.AppliedPresets)
	}
	if len(payload.Inspection.RuleSources) != 1 || payload.Inspection.RuleSources[0] != "preset:base-safety" {
		t.Fatalf("expected inherited rule source, got %+v", payload.Inspection.RuleSources)
	}
	if len(payload.Inspection.GroupSources) != 1 || payload.Inspection.GroupSources[0] != "preset:prod-strict" {
		t.Fatalf("expected group source from prod-strict, got %+v", payload.Inspection.GroupSources)
	}
}

func TestExplainGatewayLimitClassDigestAssertionPresetReturnsRulesTrace(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Security: config.SecurityConfig{
			LimitClassDigestAssertionPresets: map[string]config.LimitClassDigestAssertionPreset{
				"base-safety": {
					Rules: []string{"exists"},
				},
				"prod-strict": {
					PresetChain: []string{"base-safety"},
					Rules:       []string{"not_contains:warning"},
				},
			},
		},
	}
	gw, err := gatewaypkg.NewGateway(gatewaypkg.Dependencies{Config: cfg, Logger: logging.NewLogger(false)}, "test")
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}
	api := NewManagementAPI(gw, logging.NewLogger(false), nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/gateway/limit-class-digest-assertion-preset/explain?preset=prod-strict&kind=rules", nil)
	resp := httptest.NewRecorder()
	api.explainGatewayLimitClassDigestAssertionPreset(resp, req)

	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.Code, resp.Body.String())
	}
	var payload struct {
		Explanation struct {
			Kind       string        `json:"kind"`
			FinalValue []interface{} `json:"final_value"`
			Stages     []struct {
				Stage   string        `json:"stage"`
				Value   []interface{} `json:"value"`
				Changed bool          `json:"changed"`
			} `json:"stages"`
		} `json:"explanation"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &payload); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if payload.Explanation.Kind != "rules" || len(payload.Explanation.FinalValue) != 2 {
		t.Fatalf("unexpected assertion preset explanation: %+v", payload.Explanation)
	}
	if len(payload.Explanation.Stages) != 2 || payload.Explanation.Stages[0].Stage != "preset:base-safety" || payload.Explanation.Stages[1].Stage != "preset:prod-strict" {
		t.Fatalf("unexpected preset explain stages: %+v", payload.Explanation.Stages)
	}
}

func TestGetGatewayLimitClassDigestAssertionGroupPresetReturnsInspection(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Security: config.SecurityConfig{
			LimitClassDigestAssertionGroupPresets: map[string]config.LimitClassDigestAssertionGroupPreset{
				"base-groups": {
					Groups: []config.LimitClassDigestAssertionGroup{{
						Operator: "allOf",
						Rules:    []string{"exists"},
					}},
				},
				"strict-groups": {
					PresetChain: []string{"base-groups"},
					Groups: []config.LimitClassDigestAssertionGroup{{
						Operator: "allOf",
						Rules:    []string{"contains:regex:^strict"},
					}},
				},
			},
		},
	}
	gw, err := gatewaypkg.NewGateway(gatewaypkg.Dependencies{Config: cfg, Logger: logging.NewLogger(false)}, "test")
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}
	api := NewManagementAPI(gw, logging.NewLogger(false), nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/gateway/limit-class-digest-assertion-group-preset?preset=strict-groups", nil)
	resp := httptest.NewRecorder()
	api.getGatewayLimitClassDigestAssertionGroupPreset(resp, req)

	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.Code, resp.Body.String())
	}
	var payload struct {
		Inspection struct {
			PresetName     string                   `json:"preset_name"`
			PresetChain    []string                 `json:"preset_chain"`
			AppliedPresets []map[string]interface{} `json:"applied_presets"`
			GroupSources   []string                 `json:"group_sources"`
		} `json:"inspection"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &payload); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if payload.Inspection.PresetName != "strict-groups" || strings.Join(payload.Inspection.PresetChain, ",") != "base-groups" {
		t.Fatalf("unexpected assertion group preset inspection identity: %+v", payload.Inspection)
	}
	if len(payload.Inspection.AppliedPresets) != 2 {
		t.Fatalf("expected two applied group presets, got %+v", payload.Inspection.AppliedPresets)
	}
	if len(payload.Inspection.GroupSources) != 2 || payload.Inspection.GroupSources[0] != "preset:base-groups" || payload.Inspection.GroupSources[1] != "preset:strict-groups" {
		t.Fatalf("unexpected group sources: %+v", payload.Inspection.GroupSources)
	}
}

func TestDiffGatewayLimitClassDigestAssertionGroupPresetReturnsChangedFields(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Security: config.SecurityConfig{
			LimitClassDigestAssertionGroupPresets: map[string]config.LimitClassDigestAssertionGroupPreset{
				"base-groups": {
					Groups: []config.LimitClassDigestAssertionGroup{{
						Operator: "allOf",
						Rules:    []string{"exists"},
					}},
				},
				"strict-groups": {
					PresetChain: []string{"base-groups"},
					Groups: []config.LimitClassDigestAssertionGroup{{
						Operator: "allOf",
						Rules:    []string{"contains:regex:^strict"},
					}},
				},
			},
		},
	}
	gw, err := gatewaypkg.NewGateway(gatewaypkg.Dependencies{Config: cfg, Logger: logging.NewLogger(false)}, "test")
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}
	api := NewManagementAPI(gw, logging.NewLogger(false), nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/gateway/limit-class-digest-assertion-group-preset/diff?from_preset=strict-groups&to_preset=base-groups", nil)
	resp := httptest.NewRecorder()
	api.diffGatewayLimitClassDigestAssertionGroupPreset(resp, req)

	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.Code, resp.Body.String())
	}
	var payload struct {
		Diff struct {
			From struct {
				PresetName string `json:"preset_name"`
			} `json:"from"`
			To struct {
				PresetName string `json:"preset_name"`
			} `json:"to"`
			ChangedFields map[string]struct {
				FromValue interface{} `json:"from_value"`
				ToValue   interface{} `json:"to_value"`
			} `json:"changed_fields"`
		} `json:"diff"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &payload); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if payload.Diff.From.PresetName != "strict-groups" || payload.Diff.To.PresetName != "base-groups" {
		t.Fatalf("unexpected assertion group preset diff identity: %+v", payload.Diff)
	}
	if _, ok := payload.Diff.ChangedFields["groups"]; !ok {
		t.Fatalf("expected groups diff, got %+v", payload.Diff.ChangedFields)
	}
}

func TestExplainGatewayLimitClassDigestAssertionGroupPresetReturnsTrace(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Security: config.SecurityConfig{
			LimitClassDigestAssertionGroupPresets: map[string]config.LimitClassDigestAssertionGroupPreset{
				"base-groups": {
					Groups: []config.LimitClassDigestAssertionGroup{{
						Operator: "allOf",
						Rules:    []string{"exists"},
					}},
				},
				"strict-groups": {
					PresetChain: []string{"base-groups"},
					Groups: []config.LimitClassDigestAssertionGroup{{
						Operator: "allOf",
						Rules:    []string{"contains:regex:^strict"},
					}},
				},
			},
		},
	}
	gw, err := gatewaypkg.NewGateway(gatewaypkg.Dependencies{Config: cfg, Logger: logging.NewLogger(false)}, "test")
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}
	api := NewManagementAPI(gw, logging.NewLogger(false), nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/gateway/limit-class-digest-assertion-group-preset/explain?preset=strict-groups", nil)
	resp := httptest.NewRecorder()
	api.explainGatewayLimitClassDigestAssertionGroupPreset(resp, req)

	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.Code, resp.Body.String())
	}
	var payload struct {
		Explanation struct {
			Kind       string        `json:"kind"`
			FinalValue []interface{} `json:"final_value"`
			Stages     []struct {
				Stage   string        `json:"stage"`
				Value   []interface{} `json:"value"`
				Changed bool          `json:"changed"`
			} `json:"stages"`
		} `json:"explanation"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &payload); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if payload.Explanation.Kind != "groups" || len(payload.Explanation.FinalValue) != 2 {
		t.Fatalf("unexpected assertion group preset explanation: %+v", payload.Explanation)
	}
	if len(payload.Explanation.Stages) != 2 || payload.Explanation.Stages[0].Stage != "preset:base-groups" || payload.Explanation.Stages[1].Stage != "preset:strict-groups" {
		t.Fatalf("unexpected assertion group preset explain stages: %+v", payload.Explanation.Stages)
	}
}

func TestDiffGatewayLimitClassDigestAssertionGroupPresetExplanationReturnsStageDiffs(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Security: config.SecurityConfig{
			LimitClassDigestAssertionGroupPresets: map[string]config.LimitClassDigestAssertionGroupPreset{
				"base-groups": {
					Groups: []config.LimitClassDigestAssertionGroup{{
						Operator: "allOf",
						Rules:    []string{"exists"},
					}},
				},
				"strict-groups": {
					PresetChain: []string{"base-groups"},
					Groups: []config.LimitClassDigestAssertionGroup{{
						Operator: "allOf",
						Rules:    []string{"contains:regex:^strict"},
					}},
				},
			},
		},
	}
	gw, err := gatewaypkg.NewGateway(gatewaypkg.Dependencies{Config: cfg, Logger: logging.NewLogger(false)}, "test")
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}
	api := NewManagementAPI(gw, logging.NewLogger(false), nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/gateway/limit-class-digest-assertion-group-preset/explain/diff?from_preset=strict-groups&to_preset=base-groups", nil)
	resp := httptest.NewRecorder()
	api.diffGatewayLimitClassDigestAssertionGroupPresetExplanation(resp, req)

	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.Code, resp.Body.String())
	}
	var payload struct {
		Diff struct {
			Kind         string `json:"kind"`
			FinalChanged bool   `json:"final_changed"`
			From         struct {
				FinalValue []interface{} `json:"final_value"`
			} `json:"from"`
			To struct {
				FinalValue []interface{} `json:"final_value"`
			} `json:"to"`
			ChangedStages map[string]struct {
				FromValue []interface{} `json:"from_value"`
				ToValue   []interface{} `json:"to_value"`
			} `json:"changed_stages"`
		} `json:"diff"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &payload); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if payload.Diff.Kind != "groups" || !payload.Diff.FinalChanged {
		t.Fatalf("unexpected assertion group preset explain diff: %+v", payload.Diff)
	}
	if _, ok := payload.Diff.ChangedStages["preset:strict-groups"]; !ok {
		t.Fatalf("expected strict-groups stage diff, got %+v", payload.Diff.ChangedStages)
	}
}

func TestExplainGatewayLimitClassDigestAssertionGroupPresetBundleReturnsMultiplePresets(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Security: config.SecurityConfig{
			LimitClassDigestAssertionGroupPresets: map[string]config.LimitClassDigestAssertionGroupPreset{
				"base-groups": {
					Groups: []config.LimitClassDigestAssertionGroup{{
						Operator: "allOf",
						Rules:    []string{"exists"},
					}},
				},
				"strict-groups": {
					PresetChain: []string{"base-groups"},
					Groups: []config.LimitClassDigestAssertionGroup{{
						Operator: "allOf",
						Rules:    []string{"contains:regex:^strict"},
					}},
				},
			},
			LimitClassDigestAssertionGroupPresetExplainBundles: map[string]config.LimitClassDigestAssertionGroupPresetExplainBundle{
				"core": {
					Presets: []string{"base-groups", "strict-groups"},
				},
			},
		},
	}
	gw, err := gatewaypkg.NewGateway(gatewaypkg.Dependencies{Config: cfg, Logger: logging.NewLogger(false)}, "test")
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}
	api := NewManagementAPI(gw, logging.NewLogger(false), nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/gateway/limit-class-digest-assertion-group-preset/explain/bundle?bundle=core", nil)
	resp := httptest.NewRecorder()
	api.explainGatewayLimitClassDigestAssertionGroupPresetBundle(resp, req)

	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.Code, resp.Body.String())
	}
	var payload struct {
		Bundle struct {
			Bundles      []string `json:"bundles"`
			Presets      []string `json:"presets"`
			Explanations map[string]struct {
				Kind string `json:"kind"`
			} `json:"explanations"`
		} `json:"bundle"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &payload); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if len(payload.Bundle.Bundles) != 1 || payload.Bundle.Bundles[0] != "core" {
		t.Fatalf("unexpected assertion group preset bundle names: %+v", payload.Bundle.Bundles)
	}
	if len(payload.Bundle.Presets) != 2 {
		t.Fatalf("expected two group presets in bundle, got %+v", payload.Bundle.Presets)
	}
	if payload.Bundle.Explanations["base-groups"].Kind != "groups" || payload.Bundle.Explanations["strict-groups"].Kind != "groups" {
		t.Fatalf("unexpected group preset bundle explanations: %+v", payload.Bundle.Explanations)
	}
}

func TestDiffGatewayLimitClassDigestAssertionGroupPresetExplanationBundleReturnsChangedPresets(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Security: config.SecurityConfig{
			LimitClassDigestAssertionGroupPresets: map[string]config.LimitClassDigestAssertionGroupPreset{
				"base-groups": {
					Groups: []config.LimitClassDigestAssertionGroup{{
						Operator: "allOf",
						Rules:    []string{"exists"},
					}},
				},
				"strict-groups": {
					PresetChain: []string{"base-groups"},
					Groups: []config.LimitClassDigestAssertionGroup{{
						Operator: "allOf",
						Rules:    []string{"contains:regex:^strict"},
					}},
				},
			},
			LimitClassDigestAssertionGroupPresetExplainBundles: map[string]config.LimitClassDigestAssertionGroupPresetExplainBundle{
				"base": {
					Presets: []string{"base-groups"},
				},
				"strict": {
					Presets: []string{"strict-groups"},
				},
			},
		},
	}
	gw, err := gatewaypkg.NewGateway(gatewaypkg.Dependencies{Config: cfg, Logger: logging.NewLogger(false)}, "test")
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}
	api := NewManagementAPI(gw, logging.NewLogger(false), nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/gateway/limit-class-digest-assertion-group-preset/explain/bundle/diff?from_bundle=base&to_bundle=strict", nil)
	resp := httptest.NewRecorder()
	api.diffGatewayLimitClassDigestAssertionGroupPresetExplanationBundle(resp, req)

	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.Code, resp.Body.String())
	}
	var payload struct {
		Diff struct {
			Presets        []string `json:"presets"`
			ChangedPresets []string `json:"changed_presets"`
			PresetDiffs    map[string]struct {
				FinalChanged bool `json:"final_changed"`
			} `json:"preset_diffs"`
		} `json:"diff"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &payload); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if len(payload.Diff.Presets) != 2 {
		t.Fatalf("expected two presets in diff, got %+v", payload.Diff.Presets)
	}
	if len(payload.Diff.ChangedPresets) != 2 {
		t.Fatalf("expected two changed presets, got %+v", payload.Diff.ChangedPresets)
	}
	if !payload.Diff.PresetDiffs["base-groups"].FinalChanged || !payload.Diff.PresetDiffs["strict-groups"].FinalChanged {
		t.Fatalf("unexpected group preset bundle diff detail: %+v", payload.Diff.PresetDiffs)
	}
}

func TestDiffGatewayLimitClassDigestAssertionPresetReturnsChangedFields(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Security: config.SecurityConfig{
			LimitClassDigestAssertionPresets: map[string]config.LimitClassDigestAssertionPreset{
				"base-safety": {
					Rules: []string{"exists"},
				},
				"prod-strict": {
					PresetChain: []string{"base-safety"},
					Groups: []config.LimitClassDigestAssertionGroup{{
						Operator: "allOf",
						Rules:    []string{"regex:^crit"},
					}},
				},
			},
		},
	}
	gw, err := gatewaypkg.NewGateway(gatewaypkg.Dependencies{Config: cfg, Logger: logging.NewLogger(false)}, "test")
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}
	api := NewManagementAPI(gw, logging.NewLogger(false), nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/gateway/limit-class-digest-assertion-preset/diff?from_preset=prod-strict&to_preset=base-safety", nil)
	resp := httptest.NewRecorder()
	api.diffGatewayLimitClassDigestAssertionPreset(resp, req)

	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.Code, resp.Body.String())
	}
	var payload struct {
		Diff struct {
			From struct {
				PresetName string `json:"preset_name"`
			} `json:"from"`
			To struct {
				PresetName string `json:"preset_name"`
			} `json:"to"`
			ChangedFields map[string]struct {
				FromValue interface{} `json:"from_value"`
				ToValue   interface{} `json:"to_value"`
			} `json:"changed_fields"`
		} `json:"diff"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &payload); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if payload.Diff.From.PresetName != "prod-strict" || payload.Diff.To.PresetName != "base-safety" {
		t.Fatalf("unexpected assertion preset diff identity: %+v", payload.Diff)
	}
	if _, ok := payload.Diff.ChangedFields["groups"]; !ok {
		t.Fatalf("expected groups diff, got %+v", payload.Diff.ChangedFields)
	}
}

func TestDiffGatewayLimitClassDigestAssertionPresetExplanationReturnsStageDiffs(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Security: config.SecurityConfig{
			LimitClassDigestAssertionPresets: map[string]config.LimitClassDigestAssertionPreset{
				"base-safety": {
					Rules: []string{"exists"},
				},
				"prod-strict": {
					PresetChain: []string{"base-safety"},
					Rules:       []string{"not_contains:warning"},
				},
			},
		},
	}
	gw, err := gatewaypkg.NewGateway(gatewaypkg.Dependencies{Config: cfg, Logger: logging.NewLogger(false)}, "test")
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}
	api := NewManagementAPI(gw, logging.NewLogger(false), nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/gateway/limit-class-digest-assertion-preset/explain/diff?from_preset=prod-strict&to_preset=base-safety&kind=rules", nil)
	resp := httptest.NewRecorder()
	api.diffGatewayLimitClassDigestAssertionPresetExplanation(resp, req)

	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.Code, resp.Body.String())
	}
	var payload struct {
		Diff struct {
			Kind         string `json:"kind"`
			FinalChanged bool   `json:"final_changed"`
			From         struct {
				FinalValue []interface{} `json:"final_value"`
			} `json:"from"`
			To struct {
				FinalValue []interface{} `json:"final_value"`
			} `json:"to"`
			ChangedStages map[string]struct {
				FromValue []interface{} `json:"from_value"`
				ToValue   []interface{} `json:"to_value"`
			} `json:"changed_stages"`
		} `json:"diff"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &payload); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if payload.Diff.Kind != "rules" || !payload.Diff.FinalChanged {
		t.Fatalf("unexpected assertion preset explanation diff: %+v", payload.Diff)
	}
	if len(payload.Diff.From.FinalValue) != 2 || len(payload.Diff.To.FinalValue) != 1 {
		t.Fatalf("unexpected final values in assertion preset explanation diff: %+v", payload.Diff)
	}
	stage, ok := payload.Diff.ChangedStages["preset:prod-strict"]
	if !ok {
		t.Fatalf("expected prod-strict changed stage, got %+v", payload.Diff.ChangedStages)
	}
	if len(stage.FromValue) != 1 || len(stage.ToValue) != 0 {
		t.Fatalf("unexpected changed stage values: %+v", stage)
	}
}

func TestExplainGatewayLimitClassDigestAssertionPresetBundleReturnsKinds(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Security: config.SecurityConfig{
			LimitClassDigestAssertionPresets: map[string]config.LimitClassDigestAssertionPreset{
				"base-safety": {
					Rules: []string{"exists"},
					Groups: []config.LimitClassDigestAssertionGroup{{
						Operator: "allOf",
						Rules:    []string{"regex:^crit"},
					}},
				},
				"prod-strict": {
					PresetChain: []string{"base-safety"},
					Rules:       []string{"not_contains:warning"},
				},
			},
		},
	}
	gw, err := gatewaypkg.NewGateway(gatewaypkg.Dependencies{Config: cfg, Logger: logging.NewLogger(false)}, "test")
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}
	api := NewManagementAPI(gw, logging.NewLogger(false), nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/gateway/limit-class-digest-assertion-preset/explain/bundle?preset=prod-strict&kind=rules&kind=groups", nil)
	resp := httptest.NewRecorder()
	api.explainGatewayLimitClassDigestAssertionPresetBundle(resp, req)

	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.Code, resp.Body.String())
	}
	var payload struct {
		Bundle struct {
			Inspection struct {
				PresetName string `json:"preset_name"`
			} `json:"inspection"`
			Kinds        []string `json:"kinds"`
			Explanations map[string]struct {
				Kind string `json:"kind"`
			} `json:"explanations"`
		} `json:"bundle"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &payload); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if payload.Bundle.Inspection.PresetName != "prod-strict" {
		t.Fatalf("unexpected preset bundle inspection: %+v", payload.Bundle.Inspection)
	}
	if len(payload.Bundle.Kinds) != 2 || payload.Bundle.Kinds[0] != "rules" || payload.Bundle.Kinds[1] != "groups" {
		t.Fatalf("unexpected preset bundle kinds: %+v", payload.Bundle.Kinds)
	}
	if payload.Bundle.Explanations["rules"].Kind != "rules" || payload.Bundle.Explanations["groups"].Kind != "groups" {
		t.Fatalf("unexpected preset bundle explanations: %+v", payload.Bundle.Explanations)
	}
}

func TestExplainGatewayLimitClassDigestAssertionPresetBundleResolvesNamedBundles(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Security: config.SecurityConfig{
			LimitClassDigestAssertionExplainBundles: map[string]config.LimitClassDigestAssertionExplainBundle{
				"core": {Kinds: []string{"rules"}},
			},
			LimitClassDigestAssertionPresets: map[string]config.LimitClassDigestAssertionPreset{
				"prod-strict": {
					Rules: []string{"exists"},
					Groups: []config.LimitClassDigestAssertionGroup{{
						Operator: "allOf",
						Rules:    []string{"regex:^crit"},
					}},
				},
			},
		},
	}
	gw, err := gatewaypkg.NewGateway(gatewaypkg.Dependencies{Config: cfg, Logger: logging.NewLogger(false)}, "test")
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}
	api := NewManagementAPI(gw, logging.NewLogger(false), nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/gateway/limit-class-digest-assertion-preset/explain/bundle?preset=prod-strict&bundle=core&kind=groups", nil)
	resp := httptest.NewRecorder()
	api.explainGatewayLimitClassDigestAssertionPresetBundle(resp, req)

	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.Code, resp.Body.String())
	}
	var payload struct {
		Bundle struct {
			Kinds []string `json:"kinds"`
		} `json:"bundle"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &payload); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if len(payload.Bundle.Kinds) != 2 || payload.Bundle.Kinds[0] != "rules" || payload.Bundle.Kinds[1] != "groups" {
		t.Fatalf("unexpected named preset bundle kinds: %+v", payload.Bundle.Kinds)
	}
}

func TestDiffGatewayLimitClassDigestAssertionPresetExplanationBundleReturnsChangedKinds(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Security: config.SecurityConfig{
			LimitClassDigestAssertionExplainBundles: map[string]config.LimitClassDigestAssertionExplainBundle{
				"core": {Kinds: []string{"rules", "groups"}},
			},
			LimitClassDigestAssertionPresets: map[string]config.LimitClassDigestAssertionPreset{
				"base-safety": {
					Rules: []string{"exists"},
					Groups: []config.LimitClassDigestAssertionGroup{{
						Operator: "allOf",
						Rules:    []string{"regex:^crit"},
					}},
				},
				"prod-strict": {
					PresetChain: []string{"base-safety"},
					Rules:       []string{"not_contains:warning"},
				},
			},
		},
	}
	gw, err := gatewaypkg.NewGateway(gatewaypkg.Dependencies{Config: cfg, Logger: logging.NewLogger(false)}, "test")
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}
	api := NewManagementAPI(gw, logging.NewLogger(false), nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/gateway/limit-class-digest-assertion-preset/explain/bundle/diff?from_preset=prod-strict&to_preset=base-safety&bundle=core", nil)
	resp := httptest.NewRecorder()
	api.diffGatewayLimitClassDigestAssertionPresetExplanationBundle(resp, req)

	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.Code, resp.Body.String())
	}
	var payload struct {
		Diff struct {
			Bundles      []string `json:"bundles"`
			Kinds        []string `json:"kinds"`
			ChangedKinds []string `json:"changed_kinds"`
			KindDiffs    map[string]struct {
				FinalChanged bool `json:"final_changed"`
			} `json:"kind_diffs"`
		} `json:"diff"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &payload); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if len(payload.Diff.Bundles) != 1 || payload.Diff.Bundles[0] != "core" {
		t.Fatalf("unexpected assertion preset bundle diff bundles: %+v", payload.Diff.Bundles)
	}
	if len(payload.Diff.Kinds) != 2 || payload.Diff.Kinds[0] != "rules" || payload.Diff.Kinds[1] != "groups" {
		t.Fatalf("unexpected assertion preset bundle diff kinds: %+v", payload.Diff.Kinds)
	}
	if len(payload.Diff.ChangedKinds) != 1 || payload.Diff.ChangedKinds[0] != "rules" {
		t.Fatalf("unexpected assertion preset bundle diff changed kinds: %+v", payload.Diff.ChangedKinds)
	}
	if !payload.Diff.KindDiffs["rules"].FinalChanged || payload.Diff.KindDiffs["groups"].FinalChanged {
		t.Fatalf("unexpected assertion preset bundle diff detail: %+v", payload.Diff.KindDiffs)
	}
}

func TestDiffGatewayLimitClassDigestAssertionPresetExplanationBundleSupportsDiffProfiles(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Security: config.SecurityConfig{
			LimitClassDigestAssertionExplainBundles: map[string]config.LimitClassDigestAssertionExplainBundle{
				"core": {Kinds: []string{"rules", "groups"}},
			},
			LimitClassDigestAssertionGroupPresets: map[string]config.LimitClassDigestAssertionGroupPreset{
				"shared-rules-check": {
					Groups: []config.LimitClassDigestAssertionGroup{{
						Operator: "allOf",
						Rules:    []string{"contains:not_contains:warning"},
					}},
				},
				"strict-groups-check": {
					Groups: []config.LimitClassDigestAssertionGroup{{
						Operator: "allOf",
						Rules:    []string{"contains:regex:^strict"},
					}},
				},
			},
			LimitClassDigestAssertionExplainDiffProfiles: map[string]config.LimitClassDigestAssertionExplainDiffProfile{
				"preset-audit": {
					Bundles:             []string{"core"},
					AllowedChangedKinds: []string{"rules"},
					ExpectedFromValues: map[string]string{
						"groups": `[{"operator":"allOf","rules":["regex:^strict"]}]`,
					},
					ExpectedToValues: map[string]string{
						"rules": `["exists","not_contains:warning"]`,
					},
					AssertFromRules: map[string][]string{
						"rules": {"contains:not_contains:warning"},
					},
					AssertToRules: map[string][]string{
						"groups": {"contains:regex:^strict"},
					},
					AssertFromGroupPresets: map[string][]string{
						"rules": {"shared-rules-check"},
					},
					AssertToGroupPresets: map[string][]string{
						"groups": {"strict-groups-check"},
					},
					AssertFromGroups: map[string][]config.LimitClassDigestAssertionGroup{
						"rules": {{
							Operator: "allOf",
							Rules:    []string{"exists", "contains:not_contains:warning"},
						}},
					},
					AssertToGroups: map[string][]config.LimitClassDigestAssertionGroup{
						"groups": {{
							Operator: "allOf",
							Rules:    []string{"contains:regex:^strict"},
						}},
					},
				},
			},
			LimitClassDigestAssertionPresets: map[string]config.LimitClassDigestAssertionPreset{
				"base-safety": {
					Rules: []string{"exists"},
					Groups: []config.LimitClassDigestAssertionGroup{{
						Operator: "allOf",
						Rules:    []string{"regex:^crit"},
					}},
				},
				"prod-strict": {
					PresetChain: []string{"base-safety"},
					Rules:       []string{"not_contains:warning"},
					Groups: []config.LimitClassDigestAssertionGroup{{
						Operator: "allOf",
						Rules:    []string{"regex:^strict"},
					}},
				},
			},
		},
	}
	gw, err := gatewaypkg.NewGateway(gatewaypkg.Dependencies{Config: cfg, Logger: logging.NewLogger(false)}, "test")
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}
	api := NewManagementAPI(gw, logging.NewLogger(false), nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/gateway/limit-class-digest-assertion-preset/explain/bundle/diff?from_preset=prod-strict&to_preset=base-safety&diff_profile=preset-audit", nil)
	resp := httptest.NewRecorder()
	api.diffGatewayLimitClassDigestAssertionPresetExplanationBundle(resp, req)

	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.Code, resp.Body.String())
	}
	var payload struct {
		Diff struct {
			DiffProfiles           []string `json:"diff_profiles"`
			Bundles                []string `json:"bundles"`
			Kinds                  []string `json:"kinds"`
			ChangedKinds           []string `json:"changed_kinds"`
			UnexpectedChangedKinds []string `json:"unexpected_changed_kinds"`
			AssertionFailures      []struct {
				Side  string `json:"side"`
				Field string `json:"field"`
				Rule  string `json:"rule"`
			} `json:"assertion_failures"`
		} `json:"diff"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &payload); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if len(payload.Diff.DiffProfiles) != 1 || payload.Diff.DiffProfiles[0] != "preset-audit" {
		t.Fatalf("unexpected assertion preset diff profiles: %+v", payload.Diff.DiffProfiles)
	}
	if len(payload.Diff.Bundles) != 1 || payload.Diff.Bundles[0] != "core" {
		t.Fatalf("unexpected assertion preset diff bundles: %+v", payload.Diff.Bundles)
	}
	if len(payload.Diff.Kinds) != 2 {
		t.Fatalf("unexpected assertion preset diff kinds: %+v", payload.Diff.Kinds)
	}
	if len(payload.Diff.ChangedKinds) != 2 {
		t.Fatalf("unexpected assertion preset diff changed kinds: %+v", payload.Diff.ChangedKinds)
	}
	if len(payload.Diff.UnexpectedChangedKinds) != 1 || payload.Diff.UnexpectedChangedKinds[0] != "groups" {
		t.Fatalf("unexpected assertion preset diff unexpected kinds: %+v", payload.Diff.UnexpectedChangedKinds)
	}
	if len(payload.Diff.AssertionFailures) != 5 {
		t.Fatalf("expected five assertion failures, got %+v", payload.Diff.AssertionFailures)
	}
}

func TestDiffGatewayLimitClassDigestProfileSupportsWebhookAndProfileTargets(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Security: config.SecurityConfig{
			LimitClassDigestHiddenStrategyPolicyPresets: map[string]config.LimitClassDigestHiddenStrategyPolicy{
				"shared-exact": {
					DominantMode:   "weighted_score",
					PriorityWeight: 7,
				},
			},
			LimitClassDigestProfiles: map[string]config.LimitAlertRecipientProfile{
				"base": {
					LimitClassDigestTypes:                  []string{"alert"},
					LimitClassDigestMinSeverity:            "warning",
					LimitClassDigestMinBucketClassPriority: 4,
				},
				"strict": {
					LimitClassDigestTypes:       []string{"snooze"},
					LimitClassDigestMinSeverity: "critical",
					LimitClassDigestTruncatedReasonBucketExactSeverityPolicyPreset: "shared-exact",
				},
			},
			NotificationWebhooks: []config.NotificationWebhook{{
				Name:                             "pager",
				URL:                              "https://example.com/pager",
				Events:                           []string{"gateway.limit_class_alert_digest"},
				LimitClassDigestProfileChain:     []string{"base"},
				LimitClassDigestProfile:          "strict",
				LimitClassDigestMaxBucketClasses: 2,
			}},
		},
	}
	gw, err := gatewaypkg.NewGateway(gatewaypkg.Dependencies{Config: cfg, Logger: logging.NewLogger(false)}, "test")
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}
	api := NewManagementAPI(gw, logging.NewLogger(false), nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/gateway/limit-class-digest-profile/diff?from_webhook=pager&to_profile=base", nil)
	resp := httptest.NewRecorder()
	api.diffGatewayLimitClassDigestProfile(resp, req)

	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.Code, resp.Body.String())
	}
	var payload struct {
		Diff struct {
			From struct {
				TargetType  string `json:"target_type"`
				WebhookName string `json:"webhook_name"`
			} `json:"from"`
			To struct {
				TargetType  string `json:"target_type"`
				ProfileName string `json:"profile_name"`
			} `json:"to"`
			ChangedFields map[string]struct {
				FromValue  interface{} `json:"from_value"`
				ToValue    interface{} `json:"to_value"`
				FromSource string      `json:"from_source"`
				ToSource   string      `json:"to_source"`
			} `json:"changed_fields"`
		} `json:"diff"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &payload); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if payload.Diff.From.TargetType != "webhook" || payload.Diff.From.WebhookName != "pager" {
		t.Fatalf("unexpected from inspection: %+v", payload.Diff.From)
	}
	if payload.Diff.To.TargetType != "profile" || payload.Diff.To.ProfileName != "base" {
		t.Fatalf("unexpected to inspection: %+v", payload.Diff.To)
	}
	if payload.Diff.ChangedFields["limitClassDigestMaxBucketClasses"].FromSource != "webhook" {
		t.Fatalf("expected webhook source for max bucket classes, got %+v", payload.Diff.ChangedFields["limitClassDigestMaxBucketClasses"])
	}
	if payload.Diff.ChangedFields["limitClassDigestMaxBucketClasses"].ToValue != nil {
		t.Fatalf("expected nil profile-side max bucket classes, got %+v", payload.Diff.ChangedFields["limitClassDigestMaxBucketClasses"])
	}
	if payload.Diff.ChangedFields["limitClassDigestMinSeverity"].FromSource != "profile:strict" || payload.Diff.ChangedFields["limitClassDigestMinSeverity"].ToSource != "profile:base" {
		t.Fatalf("expected strict vs base source attribution, got %+v", payload.Diff.ChangedFields["limitClassDigestMinSeverity"])
	}
	if _, ok := payload.Diff.ChangedFields["limitClassDigestTruncatedReasonBucketExactSeverityPolicy"]; !ok {
		t.Fatalf("expected exact severity policy diff, got %+v", payload.Diff.ChangedFields)
	}
}

func TestExplainGatewayLimitClassDigestProfileReturnsFieldTrace(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Security: config.SecurityConfig{
			LimitClassDigestProfiles: map[string]config.LimitAlertRecipientProfile{
				"base": {
					LimitClassDigestMinSeverity: "warning",
				},
				"strict": {
					LimitClassDigestMinSeverity: "elevated",
				},
			},
			NotificationWebhooks: []config.NotificationWebhook{{
				Name:                         "pager",
				URL:                          "https://example.com/pager",
				Events:                       []string{"gateway.limit_class_alert_digest"},
				LimitClassDigestProfileChain: []string{"base"},
				LimitClassDigestProfile:      "strict",
				LimitClassDigestMinSeverity:  "critical",
			}},
		},
	}
	gw, err := gatewaypkg.NewGateway(gatewaypkg.Dependencies{Config: cfg, Logger: logging.NewLogger(false)}, "test")
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}
	api := NewManagementAPI(gw, logging.NewLogger(false), nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/gateway/limit-class-digest-profile/explain?webhook=pager&field=limitClassDigestMinSeverity", nil)
	resp := httptest.NewRecorder()
	api.explainGatewayLimitClassDigestProfile(resp, req)

	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.Code, resp.Body.String())
	}
	var payload struct {
		Explanation struct {
			Field       string      `json:"field"`
			FinalValue  interface{} `json:"final_value"`
			FinalSource string      `json:"final_source"`
			Stages      []struct {
				Stage   string      `json:"stage"`
				Source  string      `json:"source"`
				Value   interface{} `json:"value"`
				Changed bool        `json:"changed"`
			} `json:"stages"`
		} `json:"explanation"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &payload); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if payload.Explanation.Field != "limitClassDigestMinSeverity" || payload.Explanation.FinalValue != "critical" || payload.Explanation.FinalSource != "webhook" {
		t.Fatalf("unexpected explanation identity: %+v", payload.Explanation)
	}
	if len(payload.Explanation.Stages) != 3 {
		t.Fatalf("expected three explanation stages, got %+v", payload.Explanation.Stages)
	}
	if payload.Explanation.Stages[0].Stage != "profile_chain:base" || payload.Explanation.Stages[0].Value != "warning" {
		t.Fatalf("unexpected first stage: %+v", payload.Explanation.Stages[0])
	}
	if payload.Explanation.Stages[1].Stage != "profile:strict" || payload.Explanation.Stages[1].Value != "elevated" {
		t.Fatalf("unexpected second stage: %+v", payload.Explanation.Stages[1])
	}
	if payload.Explanation.Stages[2].Stage != "webhook" || payload.Explanation.Stages[2].Value != "critical" {
		t.Fatalf("unexpected third stage: %+v", payload.Explanation.Stages[2])
	}
}

func TestDiffGatewayLimitClassDigestProfileExplanationReturnsStageDiffs(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Security: config.SecurityConfig{
			LimitClassDigestProfiles: map[string]config.LimitAlertRecipientProfile{
				"base": {
					LimitClassDigestMinSeverity: "warning",
				},
				"strict": {
					LimitClassDigestMinSeverity: "elevated",
				},
			},
			NotificationWebhooks: []config.NotificationWebhook{{
				Name:                         "pager",
				URL:                          "https://example.com/pager",
				Events:                       []string{"gateway.limit_class_alert_digest"},
				LimitClassDigestProfileChain: []string{"base"},
				LimitClassDigestProfile:      "strict",
				LimitClassDigestMinSeverity:  "critical",
			}},
		},
	}
	gw, err := gatewaypkg.NewGateway(gatewaypkg.Dependencies{Config: cfg, Logger: logging.NewLogger(false)}, "test")
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}
	api := NewManagementAPI(gw, logging.NewLogger(false), nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/gateway/limit-class-digest-profile/explain/diff?from_webhook=pager&to_profile=base&field=limitClassDigestMinSeverity", nil)
	resp := httptest.NewRecorder()
	api.diffGatewayLimitClassDigestProfileExplanation(resp, req)

	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.Code, resp.Body.String())
	}
	var payload struct {
		Diff struct {
			Field        string `json:"field"`
			FinalChanged bool   `json:"final_changed"`
			From         struct {
				FinalValue interface{} `json:"final_value"`
			} `json:"from"`
			To struct {
				FinalValue interface{} `json:"final_value"`
			} `json:"to"`
			ChangedStages map[string]struct {
				FromValue interface{} `json:"from_value"`
				ToValue   interface{} `json:"to_value"`
			} `json:"changed_stages"`
		} `json:"diff"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &payload); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if payload.Diff.Field != "limitClassDigestMinSeverity" || !payload.Diff.FinalChanged {
		t.Fatalf("unexpected explanation diff summary: %+v", payload.Diff)
	}
	if payload.Diff.From.FinalValue != "critical" || payload.Diff.To.FinalValue != "warning" {
		t.Fatalf("unexpected final values: %+v", payload.Diff)
	}
	if stage := payload.Diff.ChangedStages["profile:strict"]; stage.FromValue != "elevated" || stage.ToValue != nil {
		t.Fatalf("unexpected strict stage diff: %+v", stage)
	}
	if stage := payload.Diff.ChangedStages["webhook"]; stage.FromValue != "critical" || stage.ToValue != nil {
		t.Fatalf("unexpected webhook stage diff: %+v", stage)
	}
}

func TestExplainGatewayLimitClassDigestProfileBundleReturnsMultipleFieldTraces(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Security: config.SecurityConfig{
			LimitClassDigestExplainBundles: map[string]config.LimitClassDigestExplainBundle{
				"ops-core": {
					Fields: []string{"limitClassDigestMinSeverity"},
				},
			},
			LimitClassDigestProfiles: map[string]config.LimitAlertRecipientProfile{
				"base": {
					LimitClassDigestMinSeverity: "warning",
					LimitClassDigestTypes:       []string{"alert"},
				},
				"strict": {
					LimitClassDigestMinSeverity: "elevated",
					LimitClassDigestTypes:       []string{"snooze"},
				},
			},
			NotificationWebhooks: []config.NotificationWebhook{{
				Name:                         "pager",
				URL:                          "https://example.com/pager",
				Events:                       []string{"gateway.limit_class_alert_digest"},
				LimitClassDigestProfileChain: []string{"base"},
				LimitClassDigestProfile:      "strict",
				LimitClassDigestMinSeverity:  "critical",
			}},
		},
	}
	gw, err := gatewaypkg.NewGateway(gatewaypkg.Dependencies{Config: cfg, Logger: logging.NewLogger(false)}, "test")
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}
	api := NewManagementAPI(gw, logging.NewLogger(false), nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/gateway/limit-class-digest-profile/explain/bundle?webhook=pager&bundle=ops-core&field=limitClassDigestTypes", nil)
	resp := httptest.NewRecorder()
	api.explainGatewayLimitClassDigestProfileBundle(resp, req)

	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.Code, resp.Body.String())
	}
	var payload struct {
		Bundle struct {
			Inspection struct {
				WebhookName string `json:"webhook_name"`
			} `json:"inspection"`
			Bundles      []string `json:"bundles"`
			Fields       []string `json:"fields"`
			Explanations map[string]struct {
				Field      string      `json:"field"`
				FinalValue interface{} `json:"final_value"`
			} `json:"explanations"`
		} `json:"bundle"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &payload); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if payload.Bundle.Inspection.WebhookName != "pager" {
		t.Fatalf("unexpected inspection webhook: %+v", payload.Bundle.Inspection)
	}
	if len(payload.Bundle.Bundles) != 1 || payload.Bundle.Bundles[0] != "ops-core" {
		t.Fatalf("unexpected bundle list: %+v", payload.Bundle.Bundles)
	}
	if len(payload.Bundle.Fields) != 2 || payload.Bundle.Fields[0] != "limitClassDigestMinSeverity" || payload.Bundle.Fields[1] != "limitClassDigestTypes" {
		t.Fatalf("unexpected field list: %+v", payload.Bundle.Fields)
	}
	if payload.Bundle.Explanations["limitClassDigestMinSeverity"].FinalValue != "critical" {
		t.Fatalf("unexpected min severity explanation: %+v", payload.Bundle.Explanations["limitClassDigestMinSeverity"])
	}
	types, ok := payload.Bundle.Explanations["limitClassDigestTypes"].FinalValue.([]interface{})
	if !ok || len(types) != 1 || types[0] != "snooze" {
		t.Fatalf("unexpected types explanation: %+v", payload.Bundle.Explanations["limitClassDigestTypes"])
	}
}

func TestDiffGatewayLimitClassDigestProfileExplainBundleReturnsFieldDiffs(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Security: config.SecurityConfig{
			LimitClassDigestExplainBundles: map[string]config.LimitClassDigestExplainBundle{
				"ops-core": {
					Fields: []string{"limitClassDigestMinSeverity", "limitClassDigestTypes", "limitClassDigestMaxBucketClasses"},
				},
			},
			LimitClassDigestExplainDiffProfiles: map[string]config.LimitClassDigestExplainDiffProfile{
				"pager-audit": {
					FromRole:             "baseline",
					ToRole:               "pager",
					Bundles:              []string{"ops-core"},
					AllowedChangedFields: []string{"limitClassDigestMinSeverity"},
					ExpectedFromValues: map[string]string{
						"limitClassDigestMinSeverity": `"critical"`,
					},
					ExpectedToValues: map[string]string{
						"limitClassDigestTypes": `["snooze"]`,
					},
					AssertFromRules: map[string][]string{
						"limitClassDigestTypes": {"contains:vip-only"},
					},
					AssertToRules: map[string][]string{
						"limitClassDigestMaxBucketClasses": {"lte:0"},
					},
				},
			},
			LimitClassDigestProfiles: map[string]config.LimitAlertRecipientProfile{
				"base": {
					LimitClassDigestMinSeverity:      "warning",
					LimitClassDigestTypes:            []string{"alert"},
					LimitClassDigestMaxBucketClasses: 3,
				},
				"strict": {
					LimitClassDigestMinSeverity:      "elevated",
					LimitClassDigestTypes:            []string{"snooze"},
					LimitClassDigestMaxBucketClasses: 1,
				},
			},
			NotificationWebhooks: []config.NotificationWebhook{{
				Name:                             "pager",
				URL:                              "https://example.com/pager",
				Events:                           []string{"gateway.limit_class_alert_digest"},
				LimitClassDigestProfileChain:     []string{"base"},
				LimitClassDigestProfile:          "strict",
				LimitClassDigestMinSeverity:      "critical",
				LimitClassDigestTypes:            []string{"alert"},
				LimitClassDigestMaxBucketClasses: 2,
			}},
		},
	}
	gw, err := gatewaypkg.NewGateway(gatewaypkg.Dependencies{Config: cfg, Logger: logging.NewLogger(false)}, "test")
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}
	api := NewManagementAPI(gw, logging.NewLogger(false), nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/gateway/limit-class-digest-profile/explain/bundle/diff?from_webhook=pager&to_profile=base&diff_profile=pager-audit&from_role=baseline&to_role=pager", nil)
	resp := httptest.NewRecorder()
	api.diffGatewayLimitClassDigestProfileExplanationBundle(resp, req)

	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.Code, resp.Body.String())
	}
	var payload struct {
		Diff struct {
			DiffProfiles            []string `json:"diff_profiles"`
			Bundles                 []string `json:"bundles"`
			Fields                  []string `json:"fields"`
			ChangedFields           []string `json:"changed_fields"`
			UnexpectedChangedFields []string `json:"unexpected_changed_fields"`
			AssertionFailures       []struct {
				Side     string      `json:"side"`
				Field    string      `json:"field"`
				Rule     string      `json:"rule"`
				Expected interface{} `json:"expected"`
				Actual   interface{} `json:"actual"`
			} `json:"assertion_failures"`
			FieldDiffs map[string]struct {
				FinalChanged bool `json:"final_changed"`
			} `json:"field_diffs"`
		} `json:"diff"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &payload); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if len(payload.Diff.Bundles) != 1 || payload.Diff.Bundles[0] != "ops-core" {
		t.Fatalf("unexpected diff bundles: %+v", payload.Diff.Bundles)
	}
	if len(payload.Diff.DiffProfiles) != 1 || payload.Diff.DiffProfiles[0] != "pager-audit" {
		t.Fatalf("unexpected diff profiles: %+v", payload.Diff.DiffProfiles)
	}
	if len(payload.Diff.Fields) != 3 || payload.Diff.Fields[0] != "limitClassDigestMinSeverity" || payload.Diff.Fields[1] != "limitClassDigestTypes" || payload.Diff.Fields[2] != "limitClassDigestMaxBucketClasses" {
		t.Fatalf("unexpected diff fields: %+v", payload.Diff.Fields)
	}
	if len(payload.Diff.ChangedFields) != 3 {
		t.Fatalf("expected three changed fields, got %+v", payload.Diff.ChangedFields)
	}
	if len(payload.Diff.UnexpectedChangedFields) != 2 || payload.Diff.UnexpectedChangedFields[0] != "limitClassDigestTypes" || payload.Diff.UnexpectedChangedFields[1] != "limitClassDigestMaxBucketClasses" {
		t.Fatalf("expected unexpected change on limitClassDigestTypes, got %+v", payload.Diff.UnexpectedChangedFields)
	}
	if len(payload.Diff.AssertionFailures) != 3 {
		t.Fatalf("expected three assertion failures, got %+v", payload.Diff.AssertionFailures)
	}
	var foundFromContains, foundToExact, foundToLTE bool
	for _, failure := range payload.Diff.AssertionFailures {
		if failure.Side == "from" && failure.Field == "limitClassDigestTypes" && failure.Rule == "contains:vip-only" {
			foundFromContains = true
		}
		if failure.Side == "to" && failure.Field == "limitClassDigestTypes" && failure.Rule == "" {
			foundToExact = true
		}
		if failure.Side == "to" && failure.Field == "limitClassDigestMaxBucketClasses" && failure.Rule == "lte:0" {
			foundToLTE = true
		}
	}
	if !foundFromContains || !foundToExact || !foundToLTE {
		t.Fatalf("expected contains, exact, and lte assertion failures, got %+v", payload.Diff.AssertionFailures)
	}
	if !payload.Diff.FieldDiffs["limitClassDigestMinSeverity"].FinalChanged || !payload.Diff.FieldDiffs["limitClassDigestTypes"].FinalChanged || !payload.Diff.FieldDiffs["limitClassDigestMaxBucketClasses"].FinalChanged {
		t.Fatalf("expected final changes for all fields, got %+v", payload.Diff.FieldDiffs)
	}
}

func TestDiffGatewayLimitClassDigestProfileExplainBundleRejectsRoleMismatch(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Security: config.SecurityConfig{
			LimitClassDigestExplainBundles: map[string]config.LimitClassDigestExplainBundle{
				"ops-core": {
					Fields: []string{"limitClassDigestMinSeverity"},
				},
			},
			LimitClassDigestExplainDiffProfiles: map[string]config.LimitClassDigestExplainDiffProfile{
				"pager-audit": {
					FromRole: "baseline",
					ToRole:   "pager",
					Bundles:  []string{"ops-core"},
				},
			},
			LimitClassDigestProfiles: map[string]config.LimitAlertRecipientProfile{
				"base": {LimitClassDigestMinSeverity: "warning"},
			},
			NotificationWebhooks: []config.NotificationWebhook{{
				Name:                         "pager",
				URL:                          "https://example.com/pager",
				Events:                       []string{"gateway.limit_class_alert_digest"},
				LimitClassDigestProfileChain: []string{"base"},
				LimitClassDigestMinSeverity:  "critical",
			}},
		},
	}
	gw, err := gatewaypkg.NewGateway(gatewaypkg.Dependencies{Config: cfg, Logger: logging.NewLogger(false)}, "test")
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}
	api := NewManagementAPI(gw, logging.NewLogger(false), nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/gateway/limit-class-digest-profile/explain/bundle/diff?from_webhook=pager&to_profile=base&diff_profile=pager-audit&from_role=pager&to_role=baseline", nil)
	resp := httptest.NewRecorder()
	api.diffGatewayLimitClassDigestProfileExplanationBundle(resp, req)

	if resp.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", resp.Code, resp.Body.String())
	}
}

func TestEvaluateLimitClassDigestAssertionRuleSupportsRegexExistsAndNotContains(t *testing.T) {
	if expected, actual, passed := evaluateLimitClassDigestAssertionRule("exists", "critical"); !passed || expected != "exists" || actual != "critical" {
		t.Fatalf("expected exists rule to pass, got expected=%v actual=%v passed=%v", expected, actual, passed)
	}
	if _, _, passed := evaluateLimitClassDigestAssertionRule("exists", ""); passed {
		t.Fatalf("expected exists rule to fail on empty string")
	}
	if expected, actual, passed := evaluateLimitClassDigestAssertionRule("regex:^crit", "critical"); !passed || expected != "^crit" || actual != "critical" {
		t.Fatalf("expected regex rule to pass, got expected=%v actual=%v passed=%v", expected, actual, passed)
	}
	if _, _, passed := evaluateLimitClassDigestAssertionRule("regex:^crit", "warning"); passed {
		t.Fatalf("expected regex rule to fail on non-matching string")
	}
	if expected, actual, passed := evaluateLimitClassDigestAssertionRule("not_contains:alert", []interface{}{"snooze", "vip"}); !passed || expected != "alert" || !reflect.DeepEqual(actual, []interface{}{"snooze", "vip"}) {
		t.Fatalf("expected not_contains rule to pass, got expected=%v actual=%v passed=%v", expected, actual, passed)
	}
	if _, _, passed := evaluateLimitClassDigestAssertionRule("not_contains:alert", []interface{}{"alert", "vip"}); passed {
		t.Fatalf("expected not_contains rule to fail when value is present")
	}
}

func TestEvaluateLimitClassDigestAssertionGroupSupportsAllOfAndAnyOf(t *testing.T) {
	allOf := config.LimitClassDigestAssertionGroup{
		Operator: "allOf",
		Rules:    []string{"exists", "regex:^crit"},
	}
	if result := evaluateLimitClassDigestAssertionGroup(allOf, "critical"); !result.Passed {
		t.Fatalf("expected allOf group to pass, got %+v", result)
	}
	if result := evaluateLimitClassDigestAssertionGroup(allOf, "warning"); result.Passed || result.Expected != "allOf(exists,regex:^crit)" {
		t.Fatalf("expected allOf group to fail with formatted expectation, got %+v", result)
	}

	anyOf := config.LimitClassDigestAssertionGroup{
		Operator: "anyOf",
		Rules:    []string{"contains:vip", "contains:gold"},
	}
	if result := evaluateLimitClassDigestAssertionGroup(anyOf, []interface{}{"gold", "standard"}); !result.Passed {
		t.Fatalf("expected anyOf group to pass, got %+v", result)
	}
	if result := evaluateLimitClassDigestAssertionGroup(anyOf, []interface{}{"silver", "standard"}); result.Passed || result.Expected != "anyOf(contains:vip,contains:gold)" {
		t.Fatalf("expected anyOf group to fail with formatted expectation, got %+v", result)
	}

	noneOf := config.LimitClassDigestAssertionGroup{
		Operator: "noneOf",
		Rules:    []string{"contains:blocked", "regex:^deny"},
	}
	if result := evaluateLimitClassDigestAssertionGroup(noneOf, "allowed-value"); !result.Passed {
		t.Fatalf("expected noneOf group to pass, got %+v", result)
	}
	if result := evaluateLimitClassDigestAssertionGroup(noneOf, "deny-this"); result.Passed || result.Expected != "noneOf(contains:blocked,regex:^deny)" {
		t.Fatalf("expected noneOf group to fail with formatted expectation, got %+v", result)
	}

	nested := config.LimitClassDigestAssertionGroup{
		Operator: "allOf",
		Rules:    []string{"exists"},
		Groups: []config.LimitClassDigestAssertionGroup{
			{
				Operator: "anyOf",
				Rules:    []string{"regex:^crit", "contains:vip"},
			},
		},
	}
	if result := evaluateLimitClassDigestAssertionGroup(nested, "critical"); !result.Passed {
		t.Fatalf("expected nested group to pass, got %+v", result)
	}
	if result := evaluateLimitClassDigestAssertionGroup(nested, "standard"); result.Passed || result.Expected != "allOf(exists,anyOf(regex:^crit,contains:vip))" {
		t.Fatalf("expected nested group to fail with formatted expectation, got %+v", result)
	}
}

func TestResolveLimitClassDigestExplainBundleDiffInputsMergesAssertionPresets(t *testing.T) {
	cfg := &config.Config{
		Security: config.SecurityConfig{
			LimitClassDigestAssertionPresets: map[string]config.LimitClassDigestAssertionPreset{
				"base-safety": {
					Rules: []string{"exists"},
				},
				"strict-severity": {
					PresetChain: []string{"base-safety"},
					Groups: []config.LimitClassDigestAssertionGroup{{
						Operator: "allOf",
						Rules:    []string{"regex:^crit"},
					}},
				},
			},
			LimitClassDigestExplainDiffProfiles: map[string]config.LimitClassDigestExplainDiffProfile{
				"pager-audit": {
					AssertFromPresets: map[string][]string{
						"limitClassDigestMinSeverity": {"strict-severity"},
					},
					AssertFromRules: map[string][]string{
						"limitClassDigestMinSeverity": {"not_contains:warning"},
					},
				},
			},
		},
	}

	_, _, _, _, _, fromRules, _, fromGroups, _, _, _, ok := resolveLimitClassDigestExplainBundleDiffInputs(cfg, []string{"pager-audit"}, nil, nil)
	if !ok {
		t.Fatalf("expected resolveLimitClassDigestExplainBundleDiffInputs to succeed")
	}
	if got := fromRules["limitClassDigestMinSeverity"]; len(got) != 2 || got[0] != "exists" || got[1] != "not_contains:warning" {
		t.Fatalf("expected preset and inline rules to merge for limitClassDigestMinSeverity, got %+v", got)
	}
	if got := fromGroups["limitClassDigestMinSeverity"]; len(got) != 1 || got[0].Operator != "allOf" || len(got[0].Rules) != 1 || got[0].Rules[0] != "regex:^crit" {
		t.Fatalf("expected preset groups to merge for limitClassDigestMinSeverity, got %+v", got)
	}
}

func TestUpdateGatewayConfigReturnsManagedErrorWhenConfigUnavailable(t *testing.T) {
	api := &ManagementAPI{
		gateway: &gatewaypkg.Gateway{},
		logger:  logging.NewLogger(false),
	}

	req := httptest.NewRequest(http.MethodPut, "/api/v1/gateway/config", strings.NewReader(`{"server":{"port":8080}}`))
	resp := httptest.NewRecorder()
	api.updateGatewayConfig(resp, req)

	if resp.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d: %s", resp.Code, resp.Body.String())
	}
	var payload ErrorResponse
	if err := json.Unmarshal(resp.Body.Bytes(), &payload); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if payload.Error.Code != coreerrors.CodeConfigNotAvailable {
		t.Fatalf("expected code %s, got %s", coreerrors.CodeConfigNotAvailable, payload.Error.Code)
	}
}

func TestEnrollmentEndpointsReturnManagedErrorWhenConfigUnavailable(t *testing.T) {
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

	api := &ManagementAPI{
		gateway: &gatewaypkg.Gateway{},
		logger:  logging.NewLogger(false),
	}
	tokenRecord := enrollmentTokenRecord{
		ID:        "tok",
		Name:      "iket",
		TokenHash: hashEnrollmentSecret("secret"),
		CreatedAt: time.Now().UTC(),
		ExpiresAt: time.Now().UTC().Add(time.Hour),
	}
	if err := saveEnrollmentTokenRecord(tokenRecord); err != nil {
		t.Fatalf("failed to save test enrollment token: %v", err)
	}

	tests := []struct {
		name    string
		handler func(http.ResponseWriter, *http.Request)
		request *http.Request
	}{
		{
			name:    "create token",
			handler: api.createEnrollmentToken,
			request: httptest.NewRequest(http.MethodPost, "/api/v1/enrollment/tokens", strings.NewReader(`{"name":"iket"}`)),
		},
		{
			name:    "redeem token",
			handler: api.enrollClientCertificate,
			request: httptest.NewRequest(http.MethodPost, "/api/v1/enrollment/certificates", strings.NewReader(`{"token":"tok.secret","csr_pem":"not-a-csr"}`)),
		},
		{
			name:    "list tokens",
			handler: api.listEnrollmentTokens,
			request: httptest.NewRequest(http.MethodGet, "/api/v1/enrollment/tokens", nil),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := httptest.NewRecorder()
			tt.handler(resp, tt.request)
			if resp.Code != http.StatusInternalServerError {
				t.Fatalf("expected 500, got %d: %s", resp.Code, resp.Body.String())
			}
			var payload ErrorResponse
			if err := json.Unmarshal(resp.Body.Bytes(), &payload); err != nil {
				t.Fatalf("failed to decode response: %v", err)
			}
			if payload.Error.Code != coreerrors.CodeConfigNotAvailable {
				t.Fatalf("expected code %s, got %s", coreerrors.CodeConfigNotAvailable, payload.Error.Code)
			}
		})
	}
}

func TestBuildGatewayConfigCandidateReplaceClearsOmittedFields(t *testing.T) {
	current := gatewayConfigCandidateTestConfig()

	candidate, err := buildGatewayConfigCandidate(current, "replace", map[string]interface{}{
		"server": map[string]interface{}{"port": 9090},
	})
	if err != nil {
		t.Fatalf("failed to build replacement candidate: %v", err)
	}
	if candidate.Server.Port != 9090 {
		t.Fatalf("expected replacement port 9090, got %d", candidate.Server.Port)
	}
	if len(candidate.Services) != 0 {
		t.Fatalf("replace candidate kept omitted services: %+v", candidate.Services)
	}
	if len(current.Services) == 0 {
		t.Fatalf("source config was mutated")
	}
}

func TestBuildGatewayConfigCandidateMergeKeepsOmittedFields(t *testing.T) {
	current := gatewayConfigCandidateTestConfig()

	candidate, err := buildGatewayConfigCandidate(current, "merge", map[string]interface{}{
		"server": map[string]interface{}{"port": 9090},
	})
	if err != nil {
		t.Fatalf("failed to build merged candidate: %v", err)
	}
	if candidate.Server.Port != 9090 {
		t.Fatalf("expected merged port 9090, got %d", candidate.Server.Port)
	}
	if len(candidate.Services) != 1 || len(candidate.Services[0].Services) != 1 {
		t.Fatalf("merge candidate dropped omitted services: %+v", candidate.Services)
	}
	if current.Server.Port != 8080 {
		t.Fatalf("source config was mutated: port %d", current.Server.Port)
	}
}

func TestAddClientMutationPolicyFailureDoesNotMutateLiveConfig(t *testing.T) {
	cfg := clientMutationPolicyTestConfig()
	api := newAPIKeyManagementAPI(t, cfg)

	body := strings.NewReader(`{"id":"client-b","name":"Client B","key":"key-b","group":"ops","scopes":["read"],"tags":["blue"]}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/clients", body)
	resp := httptest.NewRecorder()
	api.addClient(resp, req)

	if resp.Code == http.StatusOK {
		t.Fatalf("expected mutation policy to reject unlabeled client add")
	}
	if got := apikeyClientCount(t, cfg); got != 1 {
		t.Fatalf("client add mutated live config despite policy rejection; got %d clients", got)
	}
}

func TestRemoveClientMutationPolicyFailureDoesNotMutateLiveConfig(t *testing.T) {
	cfg := clientMutationPolicyTestConfig()
	api := newAPIKeyManagementAPI(t, cfg)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/clients/key-a", nil)
	req = mux.SetURLVars(req, map[string]string{"key": "key-a"})
	resp := httptest.NewRecorder()
	api.removeClient(resp, req)

	if resp.Code == http.StatusOK {
		t.Fatalf("expected mutation policy to reject unlabeled client removal")
	}
	if got := apikeyClientCount(t, cfg); got != 1 {
		t.Fatalf("client removal mutated live config despite policy rejection; got %d clients", got)
	}
	if got := apikeyClientKeyAt(t, cfg, 0); got != "key-a" {
		t.Fatalf("expected original client key to remain, got %q", got)
	}
}

func TestAddClientGeneratesAPIKeyWhenOmitted(t *testing.T) {
	cfg := clientMutationPolicyTestConfig()
	hook := &recordingClientLifecycleHook{}
	api := newAPIKeyManagementAPI(t, cfg,
		WithAPIKeyGenerator(fixedAPIKeyGenerator{key: "iket_live_generated_test_key"}),
		WithClientLifecycleHook(hook),
	)

	body := strings.NewReader(`{"id":"client-b","name":"Client B","group":"ops","scopes":["read"]}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/clients?label=client-test", body)
	resp := httptest.NewRecorder()
	api.addClient(resp, req)

	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.Code, resp.Body.String())
	}
	var payload APIResponse
	if err := json.Unmarshal(resp.Body.Bytes(), &payload); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	data, ok := payload.Data.(map[string]interface{})
	if !ok {
		t.Fatalf("expected response data map, got %T", payload.Data)
	}
	if data["api_key"] != "iket_live_generated_test_key" {
		t.Fatalf("expected generated api key to be returned once, got %+v", data)
	}
	if data["generated_key"] != true || data["one_time_secret"] != true {
		t.Fatalf("expected generated one-time secret metadata, got %+v", data)
	}
	if data["key_fingerprint"] != apiKeyFingerprint("iket_live_generated_test_key") {
		t.Fatalf("expected generated key fingerprint in response, got %+v", data)
	}
	liveCfg := api.gateway.GetConfig()
	if got := apikeyClientCount(t, liveCfg); got != 2 {
		t.Fatalf("expected generated client to be persisted, got %d clients", got)
	}
	if got := apikeyClientKeyAt(t, liveCfg, 1); got != "" {
		t.Fatalf("expected generated key plaintext to stay out of config, got %q", got)
	}
	if got := apikeyClientHashAt(t, liveCfg, 1); got != credentials.APIKeyHash("iket_live_generated_test_key") {
		t.Fatalf("expected generated key hash to be persisted for plugin runtime, got %q", got)
	}
	if hook.beforeAdd.Operation != ClientLifecycleOperationAdd || hook.beforeAdd.ClientID != "client-b" {
		t.Fatalf("expected lifecycle hook to receive generated client add event, got %+v", hook.beforeAdd)
	}
	assertClientLifecycleIdentity(t, hook.beforeAdd, "client-b")
	if !hook.beforeAdd.GeneratedKey || hook.beforeAdd.KeyFingerprint != apiKeyFingerprint("iket_live_generated_test_key") {
		t.Fatalf("expected lifecycle event to carry generated key fingerprint only, got %+v", hook.beforeAdd)
	}
	if hook.afterAdd.ClientID != "client-b" {
		t.Fatalf("expected lifecycle hook to observe successful client add, got %+v", hook.afterAdd)
	}
	assertClientLifecycleIdentity(t, hook.afterAdd, "client-b")
}

func TestListClientsRedactsAPIKeys(t *testing.T) {
	cfg := clientMutationPolicyTestConfig()
	api := newAPIKeyManagementAPI(t, cfg)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/clients", nil)
	resp := httptest.NewRecorder()
	api.listClients(resp, req)

	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.Code, resp.Body.String())
	}
	var payload struct {
		Clients []map[string]interface{} `json:"clients"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &payload); err != nil {
		t.Fatalf("failed to decode client list: %v", err)
	}
	if len(payload.Clients) != 1 {
		t.Fatalf("expected one client, got %+v", payload.Clients)
	}
	client := payload.Clients[0]
	if _, ok := client["key"]; ok {
		t.Fatalf("expected client key to be redacted, got %+v", client)
	}
	if client["key_fingerprint"] != apiKeyFingerprint("key-a") || client["key_redacted"] != true {
		t.Fatalf("expected redacted key metadata, got %+v", client)
	}
}

func TestListClientsRequiresInventoryCapability(t *testing.T) {
	cfg := clientMutationPolicyTestConfig()
	registry := plugin.NewRegistry()
	if err := registry.Register(&failingAPIKeyPlugin{}); err != nil {
		t.Fatalf("failed to register api key plugin: %v", err)
	}
	api := NewManagementAPI(mustTestGateway(t, cfg), logging.NewLogger(false), registry)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/clients", nil)
	resp := httptest.NewRecorder()
	api.listClients(resp, req)

	if resp.Code != http.StatusNotImplemented {
		t.Fatalf("expected 501, got %d: %s", resp.Code, resp.Body.String())
	}
	var payload ErrorResponse
	if err := json.Unmarshal(resp.Body.Bytes(), &payload); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if payload.Error.Code != coreerrors.CodePluginUnsupported {
		t.Fatalf("expected unsupported plugin code, got %+v", payload.Error)
	}
}

func TestGetClientReturnsRedactedInventoryRecord(t *testing.T) {
	cfg := clientMutationPolicyTestConfig()
	api := newAPIKeyManagementAPI(t, cfg)
	fingerprint := credentials.APIKeyFingerprint("key-a")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/clients/"+fingerprint, nil)
	req = mux.SetURLVars(req, map[string]string{"key": fingerprint})
	resp := httptest.NewRecorder()
	api.getClient(resp, req)

	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.Code, resp.Body.String())
	}
	var payload APIResponse
	if err := json.Unmarshal(resp.Body.Bytes(), &payload); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	data, ok := payload.Data.(map[string]interface{})
	if !ok {
		t.Fatalf("expected response data map, got %T", payload.Data)
	}
	if data["id"] != "client-a" || data["key_fingerprint"] != fingerprint || data["key_redacted"] != true {
		t.Fatalf("expected redacted client profile, got %+v", data)
	}
	if _, ok := data["key"]; ok {
		t.Fatalf("expected get client response to omit raw key, got %+v", data)
	}
	if _, ok := data["key_hash"]; ok {
		t.Fatalf("expected get client response to omit key hash, got %+v", data)
	}
}

func TestGetClientReturnsNotFoundForUnknownCredential(t *testing.T) {
	cfg := clientMutationPolicyTestConfig()
	api := newAPIKeyManagementAPI(t, cfg)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/clients/missing", nil)
	req = mux.SetURLVars(req, map[string]string{"key": "missing"})
	resp := httptest.NewRecorder()
	api.getClient(resp, req)

	if resp.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", resp.Code, resp.Body.String())
	}
	var payload ErrorResponse
	if err := json.Unmarshal(resp.Body.Bytes(), &payload); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if payload.Error.Code != coreerrors.CodeClientNotFound {
		t.Fatalf("expected client not found code, got %+v", payload.Error)
	}
}

func TestGetClientIncludesRuntimeUsageTelemetry(t *testing.T) {
	cfg := clientMutationPolicyTestConfig()
	api := newAPIKeyManagementAPI(t, cfg)
	assertAPIKeyRuntimeStatus(t, api, "key-a", http.StatusNoContent)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/clients/key-a", nil)
	req = mux.SetURLVars(req, map[string]string{"key": "key-a"})
	resp := httptest.NewRecorder()
	api.getClient(resp, req)

	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.Code, resp.Body.String())
	}
	var payload APIResponse
	if err := json.Unmarshal(resp.Body.Bytes(), &payload); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	data, ok := payload.Data.(map[string]interface{})
	if !ok {
		t.Fatalf("expected response data map, got %T", payload.Data)
	}
	if data["request_count"] != float64(1) {
		t.Fatalf("expected runtime request count in client response, got %+v", data)
	}
	if stringValue(data["last_used_at"]) == "" {
		t.Fatalf("expected runtime last_used_at in client response, got %+v", data)
	}
}

func TestAddClientRejectsKeyWhenGenerateKeyRequested(t *testing.T) {
	cfg := clientMutationPolicyTestConfig()
	api := newAPIKeyManagementAPI(t, cfg)

	body := strings.NewReader(`{"id":"client-b","name":"Client B","key":"manual-key","generate_key":true}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/clients?label=client-test", body)
	resp := httptest.NewRecorder()
	api.addClient(resp, req)

	if resp.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", resp.Code, resp.Body.String())
	}
	if got := apikeyClientCount(t, cfg); got != 1 {
		t.Fatalf("conflicting generated key request mutated config; got %d clients", got)
	}
}

func TestAddClientLifecycleHookFailureDoesNotPersistConfig(t *testing.T) {
	cfg := clientMutationPolicyTestConfig()
	hook := &recordingClientLifecycleHook{
		beforeAddErr: coreerrors.New(coreerrors.CodeForbidden, "billing subscription is not active"),
	}
	api := newAPIKeyManagementAPI(t, cfg,
		WithAPIKeyGenerator(fixedAPIKeyGenerator{key: "iket_live_generated_test_key"}),
		WithClientLifecycleHook(hook),
	)

	body := strings.NewReader(`{"id":"client-b","name":"Client B"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/clients?label=client-test", body)
	resp := httptest.NewRecorder()
	api.addClient(resp, req)

	if resp.Code != http.StatusForbidden {
		t.Fatalf("expected billing hook rejection 403, got %d: %s", resp.Code, resp.Body.String())
	}
	if got := apikeyClientCount(t, cfg); got != 1 {
		t.Fatalf("client add persisted config despite billing hook rejection; got %d clients", got)
	}
	if hook.beforeAdd.ClientID != "client-b" {
		t.Fatalf("expected hook to receive client add event before rejection, got %+v", hook.beforeAdd)
	}
	if hook.afterAdd.ClientID != "" {
		t.Fatalf("expected after hook to be skipped on rejected provisioning, got %+v", hook.afterAdd)
	}
}

func TestAddClientRuntimeFailureDoesNotPersistConfig(t *testing.T) {
	cfg := clientMutationPolicyTestConfig()
	api := newFailingAPIKeyManagementAPI(t, cfg)

	body := strings.NewReader(`{"id":"client-b","name":"Client B","key":"key-b"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/clients?label=client-test", body)
	resp := httptest.NewRecorder()
	api.addClient(resp, req)

	if resp.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected runtime failure 503, got %d: %s", resp.Code, resp.Body.String())
	}
	if got := apikeyClientCount(t, cfg); got != 1 {
		t.Fatalf("client add persisted config despite runtime failure; got %d clients", got)
	}
}

func TestRemoveClientRuntimeFailureDoesNotPersistConfig(t *testing.T) {
	cfg := clientMutationPolicyTestConfig()
	api := newFailingAPIKeyManagementAPI(t, cfg)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/clients/key-a?label=client-test", nil)
	req = mux.SetURLVars(req, map[string]string{"key": "key-a"})
	resp := httptest.NewRecorder()
	api.removeClient(resp, req)

	if resp.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected runtime failure 503, got %d: %s", resp.Code, resp.Body.String())
	}
	if got := apikeyClientCount(t, cfg); got != 1 {
		t.Fatalf("client removal persisted config despite runtime failure; got %d clients", got)
	}
	if got := apikeyClientKeyAt(t, cfg, 0); got != "key-a" {
		t.Fatalf("expected original client key to remain, got %q", got)
	}
}

func TestRemoveClientAcceptsKeyFingerprint(t *testing.T) {
	cfg := clientMutationPolicyTestConfig()
	api := newAPIKeyManagementAPI(t, cfg)
	fingerprint := credentials.APIKeyFingerprint("key-a")

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/clients/"+fingerprint+"?label=client-test", nil)
	req = mux.SetURLVars(req, map[string]string{"key": fingerprint})
	resp := httptest.NewRecorder()
	api.removeClient(resp, req)

	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.Code, resp.Body.String())
	}
	if got := apikeyClientCount(t, api.gateway.GetConfig()); got != 0 {
		t.Fatalf("expected fingerprint removal to persist, got %d clients", got)
	}
}

func TestRotateClientGeneratesHashedReplacementKey(t *testing.T) {
	cfg := clientMutationPolicyTestConfig()
	hook := &recordingClientLifecycleHook{}
	api := newAPIKeyManagementAPI(t, cfg,
		WithAPIKeyGenerator(fixedAPIKeyGenerator{key: "iket_live_rotated_test_key"}),
		WithClientLifecycleHook(hook),
	)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/clients/key-a/rotate?label=client-test", strings.NewReader(`{}`))
	req = mux.SetURLVars(req, map[string]string{"key": "key-a"})
	resp := httptest.NewRecorder()
	api.rotateClient(resp, req)

	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.Code, resp.Body.String())
	}
	var payload APIResponse
	if err := json.Unmarshal(resp.Body.Bytes(), &payload); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	data, ok := payload.Data.(map[string]interface{})
	if !ok {
		t.Fatalf("expected response data map, got %T", payload.Data)
	}
	if data["api_key"] != "iket_live_rotated_test_key" || data["one_time_secret"] != true {
		t.Fatalf("expected rotated one-time secret, got %+v", data)
	}
	if data["old_key_fingerprint"] != credentials.APIKeyFingerprint("key-a") {
		t.Fatalf("expected old fingerprint, got %+v", data)
	}
	if data["key_fingerprint"] != credentials.APIKeyFingerprint("iket_live_rotated_test_key") {
		t.Fatalf("expected new fingerprint, got %+v", data)
	}
	liveCfg := api.gateway.GetConfig()
	if got := apikeyClientCount(t, liveCfg); got != 1 {
		t.Fatalf("expected one rotated client, got %d", got)
	}
	if got := apikeyClientKeyAt(t, liveCfg, 0); got != "" {
		t.Fatalf("expected rotated key plaintext to stay out of config, got %q", got)
	}
	if got := apikeyClientHashAt(t, liveCfg, 0); got != credentials.APIKeyHash("iket_live_rotated_test_key") {
		t.Fatalf("expected rotated key hash to be persisted, got %q", got)
	}
	if hook.beforeRotate.OldKeyFingerprint != credentials.APIKeyFingerprint("key-a") ||
		hook.beforeRotate.KeyFingerprint != credentials.APIKeyFingerprint("iket_live_rotated_test_key") {
		t.Fatalf("expected lifecycle hook to receive rotation fingerprints, got %+v", hook.beforeRotate)
	}
	assertClientLifecycleIdentity(t, hook.beforeRotate, "client-a")
	if hook.afterRotate.ClientID != "client-a" {
		t.Fatalf("expected lifecycle hook to observe successful rotation, got %+v", hook.afterRotate)
	}
	assertClientLifecycleIdentity(t, hook.afterRotate, "client-a")
}

func TestRotateClientAcceptsFingerprintLookup(t *testing.T) {
	cfg := clientMutationPolicyTestConfig()
	api := newAPIKeyManagementAPI(t, cfg)
	fingerprint := credentials.APIKeyFingerprint("key-a")

	req := httptest.NewRequest(http.MethodPost, "/api/v1/clients/"+fingerprint+"/rotate?label=client-test", strings.NewReader(`{"key":"manual-rotated-key"}`))
	req = mux.SetURLVars(req, map[string]string{"key": fingerprint})
	resp := httptest.NewRecorder()
	api.rotateClient(resp, req)

	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.Code, resp.Body.String())
	}
	if got := apikeyClientHashAt(t, api.gateway.GetConfig(), 0); got != credentials.APIKeyHash("manual-rotated-key") {
		t.Fatalf("expected manual rotated key hash, got %q", got)
	}
}

func TestUpdateClientProfilePreservesSecretAndRefreshesRuntime(t *testing.T) {
	cfg := clientMutationPolicyTestConfig()
	hook := &recordingClientLifecycleHook{}
	api := newAPIKeyManagementAPI(t, cfg, WithClientLifecycleHook(hook))

	body := strings.NewReader(`{"name":"Client A Prime","group":"billing","scopes":["read","write"],"tags":["gold","beta"]}`)
	req := httptest.NewRequest(http.MethodPatch, "/api/v1/clients/key-a?label=client-test", body)
	req = mux.SetURLVars(req, map[string]string{"key": "key-a"})
	resp := httptest.NewRecorder()
	api.updateClient(resp, req)

	if resp.Code != http.StatusOK {
		t.Fatalf("expected update 200, got %d: %s", resp.Code, resp.Body.String())
	}
	liveCfg := api.gateway.GetConfig()
	client := apikeyClientAt(t, liveCfg, 0)
	if got := stringValue(client["name"]); got != "Client A Prime" {
		t.Fatalf("expected updated client name, got %q", got)
	}
	if got := stringValue(client["group"]); got != "billing" {
		t.Fatalf("expected updated client group, got %q", got)
	}
	if got := stringSliceValue(client["scopes"]); !reflect.DeepEqual(got, []string{"read", "write"}) {
		t.Fatalf("expected updated scopes, got %+v", got)
	}
	if got := stringSliceValue(client["tags"]); !reflect.DeepEqual(got, []string{"gold", "beta"}) {
		t.Fatalf("expected updated tags, got %+v", got)
	}
	if got := apikeyClientKeyAt(t, liveCfg, 0); got != "key-a" {
		t.Fatalf("expected profile update to preserve existing key, got %q", got)
	}
	if hook.beforeUpdate.Operation != ClientLifecycleOperationUpdate || hook.beforeUpdate.ClientID != "client-a" {
		t.Fatalf("expected update lifecycle event, got %+v", hook.beforeUpdate)
	}
	if hook.beforeUpdate.PreviousGroup != "ops" || hook.beforeUpdate.Group != "billing" {
		t.Fatalf("expected lifecycle event to include previous and next group, got %+v", hook.beforeUpdate)
	}
	if !reflect.DeepEqual(hook.beforeUpdate.PreviousScopes, []string{"read"}) ||
		!reflect.DeepEqual(hook.beforeUpdate.Scopes, []string{"read", "write"}) {
		t.Fatalf("expected lifecycle event to include previous and next scopes, got %+v", hook.beforeUpdate)
	}
	if hook.afterUpdate.ClientID != "client-a" {
		t.Fatalf("expected lifecycle hook to observe successful update, got %+v", hook.afterUpdate)
	}
	assertAPIKeyRuntimeClient(t, api, "key-a", "billing", []string{"read", "write"})
}

func TestUpdateClientLifecycleHookFailureDoesNotPersistConfig(t *testing.T) {
	cfg := clientMutationPolicyTestConfig()
	hook := &recordingClientLifecycleHook{
		beforeUpdateErr: coreerrors.New(coreerrors.CodeForbidden, "billing account metadata is locked"),
	}
	api := newAPIKeyManagementAPI(t, cfg, WithClientLifecycleHook(hook))

	req := httptest.NewRequest(http.MethodPatch, "/api/v1/clients/key-a?label=client-test", strings.NewReader(`{"group":"billing"}`))
	req = mux.SetURLVars(req, map[string]string{"key": "key-a"})
	resp := httptest.NewRecorder()
	api.updateClient(resp, req)

	if resp.Code != http.StatusForbidden {
		t.Fatalf("expected billing hook rejection 403, got %d: %s", resp.Code, resp.Body.String())
	}
	client := apikeyClientAt(t, cfg, 0)
	if got := stringValue(client["group"]); got != "ops" {
		t.Fatalf("update persisted config despite billing hook rejection, got group %q", got)
	}
	if hook.afterUpdate.ClientID != "" {
		t.Fatalf("expected after hook to be skipped on rejected update, got %+v", hook.afterUpdate)
	}
}

func TestRotateClientLifecycleHookFailureDoesNotPersistConfig(t *testing.T) {
	cfg := clientMutationPolicyTestConfig()
	hook := &recordingClientLifecycleHook{
		beforeRotateErr: coreerrors.New(coreerrors.CodeForbidden, "billing key mapping is locked"),
	}
	api := newAPIKeyManagementAPI(t, cfg,
		WithAPIKeyGenerator(fixedAPIKeyGenerator{key: "iket_live_rotated_test_key"}),
		WithClientLifecycleHook(hook),
	)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/clients/key-a/rotate?label=client-test", strings.NewReader(`{}`))
	req = mux.SetURLVars(req, map[string]string{"key": "key-a"})
	resp := httptest.NewRecorder()
	api.rotateClient(resp, req)

	if resp.Code != http.StatusForbidden {
		t.Fatalf("expected billing hook rejection 403, got %d: %s", resp.Code, resp.Body.String())
	}
	if got := apikeyClientKeyAt(t, cfg, 0); got != "key-a" {
		t.Fatalf("expected original key to remain after rejected rotation, got %q", got)
	}
	if hook.afterRotate.ClientID != "" {
		t.Fatalf("expected after hook to be skipped on rejected rotation, got %+v", hook.afterRotate)
	}
}

func TestDisableAndEnableClientUpdateRuntimeWithoutDeletingMetadata(t *testing.T) {
	cfg := clientMutationPolicyTestConfig()
	hook := &recordingClientLifecycleHook{}
	api := newAPIKeyManagementAPI(t, cfg, WithClientLifecycleHook(hook))

	disableReq := httptest.NewRequest(http.MethodPost, "/api/v1/clients/key-a/disable?label=client-test", nil)
	disableReq = mux.SetURLVars(disableReq, map[string]string{"key": "key-a"})
	disableResp := httptest.NewRecorder()
	api.disableClient(disableResp, disableReq)

	if disableResp.Code != http.StatusOK {
		t.Fatalf("expected disable 200, got %d: %s", disableResp.Code, disableResp.Body.String())
	}
	liveCfg := api.gateway.GetConfig()
	if got := apikeyClientCount(t, liveCfg); got != 1 {
		t.Fatalf("expected disabled client metadata to remain, got %d clients", got)
	}
	if enabled := apikeyClientEnabledAt(t, liveCfg, 0); enabled {
		t.Fatalf("expected client to be disabled in live config")
	}
	if hook.beforeStatus.Operation != ClientLifecycleOperationDisable || hook.beforeStatus.Enabled {
		t.Fatalf("expected disable lifecycle event, got %+v", hook.beforeStatus)
	}
	if !hook.beforeStatus.PreviousEnabled {
		t.Fatalf("expected disable event to include previous enabled state, got %+v", hook.beforeStatus)
	}
	assertAPIKeyRuntimeStatus(t, api, "key-a", http.StatusForbidden)

	enableReq := httptest.NewRequest(http.MethodPost, "/api/v1/clients/key-a/enable?label=client-test", nil)
	enableReq = mux.SetURLVars(enableReq, map[string]string{"key": "key-a"})
	enableResp := httptest.NewRecorder()
	api.enableClient(enableResp, enableReq)

	if enableResp.Code != http.StatusOK {
		t.Fatalf("expected enable 200, got %d: %s", enableResp.Code, enableResp.Body.String())
	}
	if enabled := apikeyClientEnabledAt(t, api.gateway.GetConfig(), 0); !enabled {
		t.Fatalf("expected client to be enabled in live config")
	}
	if hook.afterStatus.Operation != ClientLifecycleOperationEnable || !hook.afterStatus.Enabled {
		t.Fatalf("expected enable lifecycle event, got %+v", hook.afterStatus)
	}
	assertAPIKeyRuntimeStatus(t, api, "key-a", http.StatusNoContent)
}

func TestDisableClientLifecycleHookFailureDoesNotPersistConfig(t *testing.T) {
	cfg := clientMutationPolicyTestConfig()
	hook := &recordingClientLifecycleHook{
		beforeStatusErr: coreerrors.New(coreerrors.CodeForbidden, "billing subscription status is locked"),
	}
	api := newAPIKeyManagementAPI(t, cfg, WithClientLifecycleHook(hook))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/clients/key-a/disable?label=client-test", nil)
	req = mux.SetURLVars(req, map[string]string{"key": "key-a"})
	resp := httptest.NewRecorder()
	api.disableClient(resp, req)

	if resp.Code != http.StatusForbidden {
		t.Fatalf("expected billing hook rejection 403, got %d: %s", resp.Code, resp.Body.String())
	}
	if enabled := apikeyClientEnabledAt(t, cfg, 0); !enabled {
		t.Fatalf("disable persisted config despite billing hook rejection")
	}
	if hook.afterStatus.ClientID != "" {
		t.Fatalf("expected after hook to be skipped on rejected status change, got %+v", hook.afterStatus)
	}
}

func TestListPluginsIncludesDiagnosticsSummary(t *testing.T) {
	cfg := apiKeyDiagnosticsTestConfig()
	api := newAPIKeyManagementAPI(t, cfg)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/plugins", nil)
	resp := httptest.NewRecorder()
	api.listPlugins(resp, req)

	if resp.Code != http.StatusOK {
		t.Fatalf("expected plugin list 200, got %d: %s", resp.Code, resp.Body.String())
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(resp.Body.Bytes(), &payload); err != nil {
		t.Fatalf("failed to decode plugin list: %v", err)
	}
	plugins, ok := payload["plugins"].([]interface{})
	if !ok {
		t.Fatalf("expected plugin list payload, got %+v", payload)
	}
	var apiKeyInfo map[string]interface{}
	for _, item := range plugins {
		pluginInfo, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		if stringValue(pluginInfo["name"]) == "apikey" {
			apiKeyInfo = pluginInfo
			break
		}
	}
	if apiKeyInfo == nil {
		t.Fatalf("expected API-key plugin in list, got %+v", plugins)
	}
	if stringValue(apiKeyInfo["type"]) != "auth" {
		t.Fatalf("expected typed API-key plugin type auth, got %+v", apiKeyInfo["type"])
	}
	expectedCapabilities := []string{"typed", "tagged", "middleware", "health", "status_reporter", "diagnostics", "client_usage_registrar"}
	if got := stringSliceValue(apiKeyInfo["capabilities"]); !reflect.DeepEqual(got, expectedCapabilities) {
		t.Fatalf("expected API-key capabilities %v, got %v", expectedCapabilities, got)
	}
	if !boolValue(apiKeyInfo["diagnostics_available"]) {
		t.Fatalf("expected diagnostics summary to be available, got %+v", apiKeyInfo)
	}
	if stringValue(apiKeyInfo["diagnostics_status"]) != "ok" {
		t.Fatalf("expected ok diagnostics status, got %+v", apiKeyInfo["diagnostics_status"])
	}
	if _, ok := apiKeyInfo["diagnostics"]; ok {
		t.Fatalf("expected plugin list to keep diagnostics compact, got full payload: %+v", apiKeyInfo["diagnostics"])
	}
	if warnings, ok := apiKeyInfo["diagnostics_warning_codes"]; ok {
		if warningCodes := stringSliceValue(warnings); len(warningCodes) != 0 {
			t.Fatalf("expected empty diagnostics warning codes, got %+v", warnings)
		}
	}
}

func TestListPluginsSupportsOperationalFilters(t *testing.T) {
	cfg := apiKeyDiagnosticsTestConfig()
	cfg.Plugins["diagnostics-only"] = map[string]interface{}{
		"enabled": false,
	}
	api := newPluginFilterManagementAPI(t, cfg)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/plugins?type=auth&enabled=true&diagnostics_status=ok&capability=diagnostics&capabilities=client_usage_registrar,status_reporter", nil)
	resp := httptest.NewRecorder()
	api.listPlugins(resp, req)

	if resp.Code != http.StatusOK {
		t.Fatalf("expected filtered plugin list 200, got %d: %s", resp.Code, resp.Body.String())
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(resp.Body.Bytes(), &payload); err != nil {
		t.Fatalf("failed to decode filtered plugin list: %v", err)
	}
	if intValue(payload["total"]) != 1 {
		t.Fatalf("expected one filtered plugin, got %+v", payload)
	}
	plugins, ok := payload["plugins"].([]interface{})
	if !ok || len(plugins) != 1 {
		t.Fatalf("expected one filtered plugin entry, got %+v", payload["plugins"])
	}
	apiKeyInfo, ok := plugins[0].(map[string]interface{})
	if !ok {
		t.Fatalf("expected plugin info map, got %T", plugins[0])
	}
	if stringValue(apiKeyInfo["name"]) != "apikey" {
		t.Fatalf("expected API-key plugin after filters, got %+v", apiKeyInfo)
	}
	filters, ok := payload["filters"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected applied filters in response, got %+v", payload)
	}
	if stringValue(filters["type"]) != "auth" ||
		!boolValue(filters["enabled"]) ||
		stringValue(filters["diagnostics_status"]) != "ok" ||
		!reflect.DeepEqual(stringSliceValue(filters["capabilities"]), []string{"diagnostics", "client_usage_registrar", "status_reporter"}) {
		t.Fatalf("unexpected applied filter summary: %+v", filters)
	}
	summary, ok := payload["summary"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected plugin inventory summary, got %+v", payload)
	}
	if intValue(summary["total"]) != 2 ||
		intValue(summary["matched"]) != 1 ||
		intValue(summary["enabled"]) != 1 ||
		intValue(summary["disabled"]) != 1 {
		t.Fatalf("unexpected plugin summary counts: %+v", summary)
	}
	byType, _ := summary["by_type"].(map[string]interface{})
	if intValue(byType["auth"]) != 1 || intValue(byType["unknown"]) != 1 {
		t.Fatalf("unexpected plugin type facets: %+v", byType)
	}
	byDiagnosticsStatus, _ := summary["by_diagnostics_status"].(map[string]interface{})
	if intValue(byDiagnosticsStatus["ok"]) != 1 || intValue(byDiagnosticsStatus["degraded"]) != 1 {
		t.Fatalf("unexpected diagnostics status facets: %+v", byDiagnosticsStatus)
	}
	byCapability, _ := summary["by_capability"].(map[string]interface{})
	if intValue(byCapability["diagnostics"]) != 2 ||
		intValue(byCapability["client_usage_registrar"]) != 1 ||
		intValue(byCapability["status_reporter"]) != 1 {
		t.Fatalf("unexpected plugin capability facets: %+v", byCapability)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/plugins?enabled=false&capability=diagnostics&diagnostics_status=degraded", nil)
	resp = httptest.NewRecorder()
	api.listPlugins(resp, req)

	if resp.Code != http.StatusOK {
		t.Fatalf("expected diagnostics-only filtered list 200, got %d: %s", resp.Code, resp.Body.String())
	}
	payload = map[string]interface{}{}
	if err := json.Unmarshal(resp.Body.Bytes(), &payload); err != nil {
		t.Fatalf("failed to decode diagnostics-only filtered list: %v", err)
	}
	plugins, ok = payload["plugins"].([]interface{})
	if intValue(payload["total"]) != 1 || !ok || len(plugins) != 1 {
		t.Fatalf("expected one diagnostics-only plugin entry, got %+v", payload)
	}
	diagnosticsOnlyInfo, ok := plugins[0].(map[string]interface{})
	if !ok || stringValue(diagnosticsOnlyInfo["name"]) != "diagnostics-only" {
		t.Fatalf("expected diagnostics-only plugin after filters, got %+v", plugins[0])
	}
	if stringValue(diagnosticsOnlyInfo["diagnostics_status"]) != "degraded" {
		t.Fatalf("expected degraded diagnostics status, got %+v", diagnosticsOnlyInfo)
	}
}

func TestListPluginsRejectsInvalidEnabledFilter(t *testing.T) {
	cfg := apiKeyDiagnosticsTestConfig()
	api := newAPIKeyManagementAPI(t, cfg)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/plugins?enabled=maybe", nil)
	resp := httptest.NewRecorder()
	api.listPlugins(resp, req)

	if resp.Code != http.StatusBadRequest {
		t.Fatalf("expected invalid enabled filter 400, got %d: %s", resp.Code, resp.Body.String())
	}
	var payload ErrorResponse
	if err := json.Unmarshal(resp.Body.Bytes(), &payload); err != nil {
		t.Fatalf("failed to decode invalid filter response: %v", err)
	}
	if payload.Error.Message != "enabled filter must be true or false" {
		t.Fatalf("unexpected invalid filter message: %+v", payload.Error)
	}
}

func TestGetPluginDetailsIncludesTypedPluginAndDiagnostics(t *testing.T) {
	cfg := apiKeyDiagnosticsTestConfig()
	api := newAPIKeyManagementAPI(t, cfg)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/plugins/apikey", nil)
	req = mux.SetURLVars(req, map[string]string{"name": "apikey"})
	resp := httptest.NewRecorder()
	api.getPluginDetails(resp, req)

	if resp.Code != http.StatusOK {
		t.Fatalf("expected plugin details 200, got %d: %s", resp.Code, resp.Body.String())
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(resp.Body.Bytes(), &payload); err != nil {
		t.Fatalf("failed to decode plugin details: %v", err)
	}
	if payload["type"] != "auth" {
		t.Fatalf("expected typed API-key plugin type auth, got %+v", payload["type"])
	}
	expectedCapabilities := []string{"typed", "tagged", "middleware", "health", "status_reporter", "diagnostics", "client_usage_registrar"}
	if got := stringSliceValue(payload["capabilities"]); !reflect.DeepEqual(got, expectedCapabilities) {
		t.Fatalf("expected API-key capabilities %v, got %v", expectedCapabilities, got)
	}
	diagnostics, ok := payload["diagnostics"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected plugin diagnostics, got %+v", payload)
	}
	if diagnostics["status"] != "ok" {
		t.Fatalf("expected ok diagnostics status, got %+v", diagnostics["status"])
	}
	if warningCodes, ok := diagnostics["warning_codes"].([]interface{}); !ok || len(warningCodes) != 0 {
		t.Fatalf("expected empty diagnostics warning codes, got %+v", diagnostics["warning_codes"])
	}
	usageObservers, ok := diagnostics["usage_observers"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected usage observer diagnostics, got %+v", diagnostics)
	}
	if usageObservers["status"] != "ok" ||
		usageObservers["delivery_mode"] != "async" ||
		intValue(usageObservers["registered"]) != 0 ||
		intValue(usageObservers["named"]) != 0 ||
		intValue(usageObservers["unnamed"]) != 0 ||
		stringValue(usageObservers["timeout"]) != "250ms" ||
		intValue(usageObservers["async_max_in_flight"]) != 7 {
		t.Fatalf("unexpected usage observer diagnostics: %+v", usageObservers)
	}
	if names, ok := usageObservers["names"].([]interface{}); !ok || len(names) != 0 {
		t.Fatalf("expected empty usage observer names, got %+v", usageObservers["names"])
	}
	if warningCodes, ok := usageObservers["warning_codes"].([]interface{}); !ok || len(warningCodes) != 0 {
		t.Fatalf("expected empty usage observer warning codes, got %+v", usageObservers["warning_codes"])
	}
}

func TestGetPluginStatusSupportsDiagnosticsOnlyPlugins(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Plugins: map[string]map[string]interface{}{
			"diagnostics-only": {
				"enabled": true,
			},
		},
	}
	registry := plugin.NewRegistry()
	if err := registry.Register(&managementDiagnosticsOnlyPlugin{
		name: "diagnostics-only",
		diagnostics: map[string]interface{}{
			"status":        "degraded",
			"warning_codes": []string{"export_backlog"},
		},
	}); err != nil {
		t.Fatalf("failed to register diagnostics-only plugin: %v", err)
	}
	api := NewManagementAPI(mustTestGateway(t, cfg), logging.NewLogger(false), registry)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/plugins/diagnostics-only/status", nil)
	req = mux.SetURLVars(req, map[string]string{"name": "diagnostics-only"})
	resp := httptest.NewRecorder()
	api.getPluginStatus(resp, req)

	if resp.Code != http.StatusOK {
		t.Fatalf("expected plugin status 200, got %d: %s", resp.Code, resp.Body.String())
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(resp.Body.Bytes(), &payload); err != nil {
		t.Fatalf("failed to decode plugin status: %v", err)
	}
	if stringValue(payload["status"]) != "degraded" {
		t.Fatalf("expected diagnostics status fallback, got %+v", payload["status"])
	}
	if stringValue(payload["status_source"]) != "diagnostics" {
		t.Fatalf("expected diagnostics status source, got %+v", payload["status_source"])
	}
	diagnostics, ok := payload["diagnostics"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected diagnostics payload, got %+v", payload)
	}
	if warningCodes := stringSliceValue(diagnostics["warning_codes"]); !reflect.DeepEqual(warningCodes, []string{"export_backlog"}) {
		t.Fatalf("expected diagnostics warning codes, got %+v", diagnostics["warning_codes"])
	}
}

func apiKeyDiagnosticsTestConfig() *config.Config {
	return &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Plugins: map[string]map[string]interface{}{
			"apikey": {
				"enabled":                            true,
				"usage_observer_async":               true,
				"usage_observer_timeout":             "250ms",
				"usage_observer_async_max_in_flight": 7,
				"clients": []interface{}{
					map[string]interface{}{
						"id":       "client-a",
						"name":     "Client A",
						"key_hash": credentials.APIKeyHash("secret"),
					},
				},
			},
		},
	}
}

func TestRemoveClientLifecycleHookFailureDoesNotPersistConfig(t *testing.T) {
	cfg := clientMutationPolicyTestConfig()
	hook := &recordingClientLifecycleHook{
		beforeRemoveErr: coreerrors.New(coreerrors.CodeForbidden, "billing subscription is locked"),
	}
	api := newAPIKeyManagementAPI(t, cfg, WithClientLifecycleHook(hook))

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/clients/key-a?label=client-test", nil)
	req = mux.SetURLVars(req, map[string]string{"key": "key-a"})
	resp := httptest.NewRecorder()
	api.removeClient(resp, req)

	if resp.Code != http.StatusForbidden {
		t.Fatalf("expected billing hook rejection 403, got %d: %s", resp.Code, resp.Body.String())
	}
	if got := apikeyClientCount(t, cfg); got != 1 {
		t.Fatalf("client removal persisted config despite billing hook rejection; got %d clients", got)
	}
	if hook.beforeRemove.ClientID != "client-a" || hook.beforeRemove.KeyFingerprint != apiKeyFingerprint("key-a") {
		t.Fatalf("expected hook to receive removed client fingerprint, got %+v", hook.beforeRemove)
	}
	assertClientLifecycleIdentity(t, hook.beforeRemove, "client-a")
	if hook.afterRemove.ClientID != "" {
		t.Fatalf("expected after hook to be skipped on rejected removal, got %+v", hook.afterRemove)
	}
}

func TestUpdatePluginConfigPolicyFailureDoesNotMutateRuntime(t *testing.T) {
	cfg := pluginMutationPolicyTestConfig()
	api, statefulPlugin := newStatefulPluginManagementAPI(t, cfg)

	req := httptest.NewRequest(http.MethodPut, "/api/v1/plugins/stateful/config", strings.NewReader(`{"enabled":false}`))
	req = mux.SetURLVars(req, map[string]string{"name": "stateful"})
	resp := httptest.NewRecorder()
	api.updatePluginConfig(resp, req)

	if resp.Code == http.StatusOK {
		t.Fatalf("expected mutation policy to reject unlabeled plugin config update")
	}
	if !statefulPlugin.enabled {
		t.Fatalf("plugin runtime was mutated despite policy rejection")
	}
	if statefulPlugin.initializeCalls != 1 {
		t.Fatalf("expected policy rejection to skip runtime initialize, got %d calls", statefulPlugin.initializeCalls)
	}
	if enabled, _ := cfg.Plugins["stateful"]["enabled"].(bool); !enabled {
		t.Fatalf("live plugin config was mutated despite policy rejection")
	}
}

func TestDisablePluginPolicyFailureDoesNotMutateRuntime(t *testing.T) {
	cfg := pluginMutationPolicyTestConfig()
	api, statefulPlugin := newStatefulPluginManagementAPI(t, cfg)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/plugins/stateful/disable", nil)
	req = mux.SetURLVars(req, map[string]string{"name": "stateful"})
	resp := httptest.NewRecorder()
	api.disablePlugin(resp, req)

	if resp.Code == http.StatusOK {
		t.Fatalf("expected mutation policy to reject unlabeled plugin disable")
	}
	if !statefulPlugin.enabled {
		t.Fatalf("plugin runtime was mutated despite policy rejection")
	}
	if statefulPlugin.initializeCalls != 1 {
		t.Fatalf("expected policy rejection to skip runtime initialize, got %d calls", statefulPlugin.initializeCalls)
	}
	if enabled, _ := cfg.Plugins["stateful"]["enabled"].(bool); !enabled {
		t.Fatalf("live plugin config was mutated despite policy rejection")
	}
}

type managementStatefulPlugin struct {
	name            string
	enabled         bool
	initializeCalls int
}

func (p *managementStatefulPlugin) Name() string {
	return p.name
}

func (p *managementStatefulPlugin) Initialize(pluginCfg map[string]interface{}) error {
	p.initializeCalls++
	enabled, ok := pluginCfg["enabled"].(bool)
	if !ok {
		enabled = true
	}
	p.enabled = enabled
	return nil
}

type managementDiagnosticsOnlyPlugin struct {
	name        string
	diagnostics map[string]interface{}
}

func (p *managementDiagnosticsOnlyPlugin) Name() string {
	return p.name
}

func (p *managementDiagnosticsOnlyPlugin) Initialize(map[string]interface{}) error {
	return nil
}

func (p *managementDiagnosticsOnlyPlugin) Diagnostics() map[string]interface{} {
	return p.diagnostics
}

func newPluginFilterManagementAPI(t *testing.T, cfg *config.Config) *ManagementAPI {
	t.Helper()
	registry := plugin.NewRegistry()
	apiKeyPlugin := &apikeyplugin.APIKeyPlugin{}
	pluginCfg, _ := cfg.GetPluginConfig("apikey")
	if err := apiKeyPlugin.Initialize(pluginCfg); err != nil {
		t.Fatalf("failed to initialize api key plugin: %v", err)
	}
	if err := registry.Register(apiKeyPlugin); err != nil {
		t.Fatalf("failed to register api key plugin: %v", err)
	}
	if err := registry.Register(&managementDiagnosticsOnlyPlugin{
		name: "diagnostics-only",
		diagnostics: map[string]interface{}{
			"status":        "degraded",
			"warning_codes": []string{"export_backlog"},
		},
	}); err != nil {
		t.Fatalf("failed to register diagnostics-only plugin: %v", err)
	}
	return NewManagementAPI(mustTestGateway(t, cfg), logging.NewLogger(false), registry)
}

func newStatefulPluginManagementAPI(t *testing.T, cfg *config.Config) (*ManagementAPI, *managementStatefulPlugin) {
	t.Helper()
	registry := plugin.NewRegistry()
	statefulPlugin := &managementStatefulPlugin{name: "stateful"}
	pluginCfg, _ := cfg.GetPluginConfig("stateful")
	if err := statefulPlugin.Initialize(pluginCfg); err != nil {
		t.Fatalf("failed to initialize stateful plugin: %v", err)
	}
	if err := registry.Register(statefulPlugin); err != nil {
		t.Fatalf("failed to register stateful plugin: %v", err)
	}
	return NewManagementAPI(mustTestGateway(t, cfg), logging.NewLogger(false), registry), statefulPlugin
}

func pluginMutationPolicyTestConfig() *config.Config {
	return &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Security: config.SecurityConfig{
			MutationPolicy: config.MutationPolicy{
				Enabled:        true,
				RequireLabel:   true,
				EnforcedScopes: []string{"plugins"},
			},
		},
		Plugins: map[string]map[string]interface{}{
			"stateful": {
				"enabled": true,
			},
		},
	}
}

func newAPIKeyManagementAPI(t *testing.T, cfg *config.Config, options ...ManagementAPIOption) *ManagementAPI {
	t.Helper()
	registry := plugin.NewRegistry()
	apiKeyPlugin := &apikeyplugin.APIKeyPlugin{}
	pluginCfg, _ := cfg.GetPluginConfig("apikey")
	if err := apiKeyPlugin.Initialize(pluginCfg); err != nil {
		t.Fatalf("failed to initialize api key plugin: %v", err)
	}
	if err := registry.Register(apiKeyPlugin); err != nil {
		t.Fatalf("failed to register api key plugin: %v", err)
	}
	return NewManagementAPI(mustTestGateway(t, cfg), logging.NewLogger(false), registry, options...)
}

type fixedAPIKeyGenerator struct {
	key string
}

func (g fixedAPIKeyGenerator) GenerateAPIKey() (string, error) {
	return g.key, nil
}

type recordingClientLifecycleHook struct {
	beforeAdd       ClientLifecycleEvent
	afterAdd        ClientLifecycleEvent
	beforeStatus    ClientLifecycleEvent
	afterStatus     ClientLifecycleEvent
	beforeUpdate    ClientLifecycleEvent
	afterUpdate     ClientLifecycleEvent
	beforeRotate    ClientLifecycleEvent
	afterRotate     ClientLifecycleEvent
	beforeRemove    ClientLifecycleEvent
	afterRemove     ClientLifecycleEvent
	beforeAddErr    error
	beforeStatusErr error
	beforeUpdateErr error
	beforeRotateErr error
	beforeRemoveErr error
}

func assertClientLifecycleIdentity(t *testing.T, event ClientLifecycleEvent, clientID string) {
	t.Helper()
	if event.Identity == nil {
		t.Fatalf("expected lifecycle event identity for %s, got nil in %+v", clientID, event)
	}
	if event.Identity.Kind != authcontext.PrincipalIdentityClient ||
		event.Identity.Source != "apikey" ||
		event.Identity.Value != clientID ||
		event.Identity.Sensitive {
		t.Fatalf("expected API-key client lifecycle identity for %s, got %+v", clientID, event.Identity)
	}
}

func (h *recordingClientLifecycleHook) BeforeClientAdd(_ context.Context, event ClientLifecycleEvent) error {
	h.beforeAdd = event
	return h.beforeAddErr
}

func (h *recordingClientLifecycleHook) AfterClientAdd(_ context.Context, event ClientLifecycleEvent) {
	h.afterAdd = event
}

func (h *recordingClientLifecycleHook) BeforeClientStatusChange(_ context.Context, event ClientLifecycleEvent) error {
	h.beforeStatus = event
	return h.beforeStatusErr
}

func (h *recordingClientLifecycleHook) AfterClientStatusChange(_ context.Context, event ClientLifecycleEvent) {
	h.afterStatus = event
}

func (h *recordingClientLifecycleHook) BeforeClientUpdate(_ context.Context, event ClientLifecycleEvent) error {
	h.beforeUpdate = event
	return h.beforeUpdateErr
}

func (h *recordingClientLifecycleHook) AfterClientUpdate(_ context.Context, event ClientLifecycleEvent) {
	h.afterUpdate = event
}

func (h *recordingClientLifecycleHook) BeforeClientRotate(_ context.Context, event ClientLifecycleEvent) error {
	h.beforeRotate = event
	return h.beforeRotateErr
}

func (h *recordingClientLifecycleHook) AfterClientRotate(_ context.Context, event ClientLifecycleEvent) {
	h.afterRotate = event
}

func (h *recordingClientLifecycleHook) BeforeClientRemove(_ context.Context, event ClientLifecycleEvent) error {
	h.beforeRemove = event
	return h.beforeRemoveErr
}

func (h *recordingClientLifecycleHook) AfterClientRemove(_ context.Context, event ClientLifecycleEvent) {
	h.afterRemove = event
}

type failingAPIKeyPlugin struct {
	initializeCalls int
}

func (p *failingAPIKeyPlugin) Name() string {
	return "apikey"
}

func (p *failingAPIKeyPlugin) Initialize(map[string]interface{}) error {
	p.initializeCalls++
	if p.initializeCalls > 1 {
		return fmt.Errorf("api key runtime reload failed")
	}
	return nil
}

func newFailingAPIKeyManagementAPI(t *testing.T, cfg *config.Config) *ManagementAPI {
	t.Helper()
	registry := plugin.NewRegistry()
	apiKeyPlugin := &failingAPIKeyPlugin{}
	pluginCfg, _ := cfg.GetPluginConfig("apikey")
	if err := apiKeyPlugin.Initialize(pluginCfg); err != nil {
		t.Fatalf("failed to initialize api key plugin: %v", err)
	}
	if err := registry.Register(apiKeyPlugin); err != nil {
		t.Fatalf("failed to register api key plugin: %v", err)
	}
	return NewManagementAPI(mustTestGateway(t, cfg), logging.NewLogger(false), registry)
}

func clientMutationPolicyTestConfig() *config.Config {
	return &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Security: config.SecurityConfig{
			MutationPolicy: config.MutationPolicy{
				Enabled:        true,
				RequireLabel:   true,
				EnforcedScopes: []string{"clients"},
			},
		},
		Plugins: map[string]map[string]interface{}{
			"apikey": {
				"enabled": true,
				"clients": []interface{}{
					map[string]interface{}{
						"id":     "client-a",
						"name":   "Client A",
						"key":    "key-a",
						"group":  "ops",
						"scopes": []interface{}{"read"},
						"tags":   []interface{}{"green"},
					},
				},
			},
		},
	}
}

func apikeyClientCount(t *testing.T, cfg *config.Config) int {
	t.Helper()
	clients, ok := cfg.Plugins["apikey"]["clients"].([]interface{})
	if !ok {
		t.Fatalf("expected api key clients slice, got %T", cfg.Plugins["apikey"]["clients"])
	}
	return len(clients)
}

func apikeyClientKeyAt(t *testing.T, cfg *config.Config, index int) string {
	t.Helper()
	client := apikeyClientAt(t, cfg, index)
	return stringValue(client["key"])
}

func apikeyClientHashAt(t *testing.T, cfg *config.Config, index int) string {
	t.Helper()
	client := apikeyClientAt(t, cfg, index)
	return stringValue(client["key_hash"])
}

func apikeyClientEnabledAt(t *testing.T, cfg *config.Config, index int) bool {
	t.Helper()
	return apikeyClientEntryEnabled(apikeyClientAt(t, cfg, index))
}

func apikeyClientAt(t *testing.T, cfg *config.Config, index int) map[string]interface{} {
	t.Helper()
	clients, ok := cfg.Plugins["apikey"]["clients"].([]interface{})
	if !ok {
		t.Fatalf("expected api key clients slice, got %T", cfg.Plugins["apikey"]["clients"])
	}
	if index < 0 || index >= len(clients) {
		t.Fatalf("client index %d out of range for %d clients", index, len(clients))
	}
	client, ok := clients[index].(map[string]interface{})
	if !ok {
		t.Fatalf("expected client map, got %T", clients[index])
	}
	return client
}

func assertAPIKeyRuntimeStatus(t *testing.T, api *ManagementAPI, key string, expectedStatus int) {
	t.Helper()
	p, err := api.registry.Get("apikey")
	if err != nil {
		t.Fatalf("failed to get api key plugin: %v", err)
	}
	apiKeyPlugin, ok := p.(*apikeyplugin.APIKeyPlugin)
	if !ok {
		t.Fatalf("expected api key plugin, got %T", p)
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-API-Key", key)
	resp := httptest.NewRecorder()
	apiKeyPlugin.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(resp, req)
	if resp.Code != expectedStatus {
		t.Fatalf("expected api key runtime status %d, got %d: %s", expectedStatus, resp.Code, resp.Body.String())
	}
}

func assertAPIKeyRuntimeClient(t *testing.T, api *ManagementAPI, key, expectedGroup string, expectedScopes []string) {
	t.Helper()
	p, err := api.registry.Get("apikey")
	if err != nil {
		t.Fatalf("failed to get api key plugin: %v", err)
	}
	apiKeyPlugin, ok := p.(*apikeyplugin.APIKeyPlugin)
	if !ok {
		t.Fatalf("expected api key plugin, got %T", p)
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-API-Key", key)
	resp := httptest.NewRecorder()
	apiKeyPlugin.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotGroup, ok := authcontext.APIKeyGroup(r.Context())
		if !ok || gotGroup != expectedGroup {
			t.Fatalf("expected runtime group %q, got %q ok=%v", expectedGroup, gotGroup, ok)
		}
		gotScopes, _ := authcontext.APIKeyScopes(r.Context())
		if !reflect.DeepEqual(gotScopes, expectedScopes) {
			t.Fatalf("expected runtime scopes %+v, got %+v", expectedScopes, gotScopes)
		}
		w.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(resp, req)
	if resp.Code != http.StatusNoContent {
		t.Fatalf("expected runtime request to pass, got %d: %s", resp.Code, resp.Body.String())
	}
}

func gatewayConfigCandidateTestConfig() *config.Config {
	return &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Services: []config.ServiceConfig{{
			Version: 1,
			Services: []config.Service{{
				Name: "identity",
				Host: "http://identity:8080",
				Routes: []config.RouterConfig{{
					Path:    "/auth",
					Methods: []string{"GET"},
					Backends: []config.Backend{{
						URLPattern: "/auth",
					}},
				}},
			}},
		}},
	}
}

func TestGetGatewayLimitHitsReturnsAggregatedCounters(t *testing.T) {
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
	}
	gw, err := gatewaypkg.NewGateway(gatewaypkg.Dependencies{Config: cfg, Logger: logging.NewLogger(false)}, "test")
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}
	api := NewManagementAPI(gw, logging.NewLogger(false), nil)
	route := cfg.Services[0].Services[0].Routes[0]
	route.ServiceName = "agent"
	gw.RecordRouteLimitHit(route, "rate_limit", "header")
	gw.RecordRouteLimitHit(route, "concurrency_limit", "jwt_sub")
	gw.RecordRouteLimitHitWithWait(route, "concurrency_queued", "jwt_sub", 120*time.Millisecond)
	gw.RecordRouteLimitHit(route, "concurrency_queue_full", "jwt_sub")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/gateway/limit-hits?window=5m", nil)
	resp := httptest.NewRecorder()
	api.getGatewayLimitHits(resp, req)

	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.Code, resp.Body.String())
	}
	var payload struct {
		Total int `json:"total"`
		Types []struct {
			Type  string `json:"type"`
			Count int    `json:"count"`
		} `json:"types"`
		Routes []struct {
			RoutePath           string         `json:"route_path"`
			ByType              map[string]int `json:"by_type"`
			QueuedAdmissions    int            `json:"queued_admissions"`
			QueueFullRejections int            `json:"queue_full_rejections"`
			AverageQueueWaitMs  int64          `json:"average_queue_wait_ms"`
			MaxQueueWaitMs      int64          `json:"max_queue_wait_ms"`
		} `json:"routes"`
		RecentWindow struct {
			Total int `json:"total"`
		} `json:"recent_window"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &payload); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if payload.Total != 4 || payload.RecentWindow.Total != 4 {
		t.Fatalf("expected total 2 in both lifetime and recent window, got %+v", payload)
	}
	if len(payload.Types) != 4 {
		t.Fatalf("expected four type summaries, got %+v", payload.Types)
	}
	if len(payload.Routes) != 1 || payload.Routes[0].RoutePath != "/ai/chat" {
		t.Fatalf("unexpected route summaries: %+v", payload.Routes)
	}
	if payload.Routes[0].ByType["rate_limit"] != 1 || payload.Routes[0].ByType["concurrency_limit"] != 1 || payload.Routes[0].ByType["concurrency_queued"] != 1 || payload.Routes[0].ByType["concurrency_queue_full"] != 1 {
		t.Fatalf("unexpected route type counters: %+v", payload.Routes[0].ByType)
	}
	if payload.Routes[0].QueuedAdmissions != 1 || payload.Routes[0].QueueFullRejections != 1 {
		t.Fatalf("unexpected queue counters: %+v", payload.Routes[0])
	}
	if payload.Routes[0].AverageQueueWaitMs < 100 || payload.Routes[0].MaxQueueWaitMs < payload.Routes[0].AverageQueueWaitMs {
		t.Fatalf("unexpected queue wait metrics: %+v", payload.Routes[0])
	}
}

func TestGetGatewayLimitBucketsReturnsRecentBucketPressure(t *testing.T) {
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
	}
	gw, err := gatewaypkg.NewGateway(gatewaypkg.Dependencies{Config: cfg, Logger: logging.NewLogger(false)}, "test")
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}
	api := NewManagementAPI(gw, logging.NewLogger(false), nil)
	route := cfg.Services[0].Services[0].Routes[0]
	route.ServiceName = "agent"
	now := time.Now().UTC()
	gw.RecordRouteLimitHitForBucketTest(route, "concurrency_queue_full", "jwt_sub", "vip-a", 0, now.Add(-2*time.Minute))
	gw.RecordRouteLimitHitForBucketTest(route, "concurrency_queue_full", "jwt_sub", "vip-a", 0, now.Add(-90*time.Second))
	gw.RecordRouteLimitHitForBucketTest(route, "concurrency_queued", "jwt_sub", "vip-a", 120*time.Millisecond, now.Add(-75*time.Second))
	gw.RecordRouteLimitHitForBucketTest(route, "rate_limit", "header", "x-agent-session:tenant-b", 0, now.Add(-30*time.Second))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/gateway/limit-buckets?window=5m&min_count=1", nil)
	resp := httptest.NewRecorder()
	api.getGatewayLimitBuckets(resp, req)

	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.Code, resp.Body.String())
	}
	var payload struct {
		Window       string `json:"window"`
		MinCount     int    `json:"min_count"`
		TotalBuckets int    `json:"total_buckets"`
		TopBucketID  string `json:"top_bucket_id"`
		Entries      []struct {
			RoutePath           string `json:"route_path"`
			LimitType           string `json:"limit_type"`
			KeyType             string `json:"key_type"`
			BucketID            string `json:"bucket_id"`
			Count               int    `json:"count"`
			QueuedAdmissions    int    `json:"queued_admissions"`
			QueueFullRejections int    `json:"queue_full_rejections"`
			AverageQueueWaitMs  int64  `json:"average_queue_wait_ms"`
		} `json:"entries"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &payload); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if payload.Window != "5m" || payload.MinCount != 1 || payload.TotalBuckets != 3 {
		t.Fatalf("unexpected bucket summary header: %+v", payload)
	}
	if len(payload.Entries) != 3 || payload.TopBucketID == "" {
		t.Fatalf("expected three bucket entries with top bucket id, got %+v", payload)
	}
	if payload.Entries[0].BucketID == "" || payload.Entries[0].KeyType != "jwt_sub" || payload.Entries[0].Count != 2 || payload.Entries[0].QueueFullRejections != 2 {
		t.Fatalf("unexpected top bucket entry: %+v", payload.Entries[0])
	}
	if payload.Entries[1].LimitType != "concurrency_queued" || payload.Entries[1].QueuedAdmissions != 1 || payload.Entries[1].AverageQueueWaitMs < 100 {
		t.Fatalf("unexpected queued bucket entry: %+v", payload.Entries[1])
	}
}

func TestGetGatewayLimitClassesReturnsRecentClassPressure(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Security: config.SecurityConfig{
			LimitAlertBucketClasses: map[string]config.LimitAlertBucketClassConfig{
				"vip-jwt": {
					KeyType:     "jwt_sub",
					BucketRegex: "^vip-",
				},
			},
			MutationPolicy: config.MutationPolicy{
				LimitClassAlertNotifications: config.PolicyAlertNotificationPolicy{
					Enabled:  true,
					Window:   "5m",
					MinCount: 3,
				},
			},
		},
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
	}
	gw, err := gatewaypkg.NewGateway(gatewaypkg.Dependencies{Config: cfg, Logger: logging.NewLogger(false)}, "test")
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}
	api := NewManagementAPI(gw, logging.NewLogger(false), nil)
	route := cfg.Services[0].Services[0].Routes[0]
	route.ServiceName = "agent"
	now := time.Now().UTC()
	gw.RecordRouteLimitHitForBucketTest(route, "concurrency_queue_full", "jwt_sub", "vip-a", 0, now.Add(-2*time.Minute))
	gw.RecordRouteLimitHitForBucketTest(route, "concurrency_queue_full", "jwt_sub", "vip-b", 0, now.Add(-90*time.Second))
	gw.RecordRouteLimitHitForBucketTest(route, "concurrency_queued", "jwt_sub", "vip-a", 120*time.Millisecond, now.Add(-75*time.Second))
	gw.RecordRouteLimitHitForBucketTest(route, "rate_limit", "api_key", "tenant-c", 0, now.Add(-30*time.Second))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/gateway/limit-classes?window=5m&min_count=1", nil)
	resp := httptest.NewRecorder()
	api.getGatewayLimitClasses(resp, req)

	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.Code, resp.Body.String())
	}
	var payload struct {
		Window         string `json:"window"`
		MinCount       int    `json:"min_count"`
		TotalClasses   int    `json:"total_classes"`
		TopBucketClass string `json:"top_bucket_class"`
		Entries        []struct {
			RoutePath           string `json:"route_path"`
			LimitType           string `json:"limit_type"`
			KeyType             string `json:"key_type"`
			BucketClass         string `json:"bucket_class"`
			Count               int    `json:"count"`
			QueuedAdmissions    int    `json:"queued_admissions"`
			QueueFullRejections int    `json:"queue_full_rejections"`
			AverageQueueWaitMs  int64  `json:"average_queue_wait_ms"`
		} `json:"entries"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &payload); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if payload.Window != "5m" || payload.MinCount != 1 || payload.TotalClasses != 2 || payload.TopBucketClass != "vip-jwt" {
		t.Fatalf("unexpected class summary header: %+v", payload)
	}
	if len(payload.Entries) != 2 {
		t.Fatalf("expected two class entries, got %+v", payload.Entries)
	}
	if payload.Entries[0].BucketClass != "vip-jwt" || payload.Entries[0].Count != 2 || payload.Entries[0].QueueFullRejections != 2 {
		t.Fatalf("unexpected top class entry: %+v", payload.Entries[0])
	}
	if payload.Entries[1].LimitType != "concurrency_queued" || payload.Entries[1].QueuedAdmissions != 1 || payload.Entries[1].AverageQueueWaitMs < 100 {
		t.Fatalf("unexpected queued class entry: %+v", payload.Entries[1])
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

func TestGetGatewayLimitClassAlertsReturnsRecentClassSpikes(t *testing.T) {
	cfg := &config.Config{
		Security: config.SecurityConfig{
			LimitAlertBucketClasses: map[string]config.LimitAlertBucketClassConfig{
				"vip-jwt": {
					KeyType:     "jwt_sub",
					BucketRegex: "^vip-",
				},
			},
		},
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
	}
	gw, err := gatewaypkg.NewGateway(gatewaypkg.Dependencies{Config: cfg, Logger: logging.NewLogger(false)}, "test")
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}
	api := NewManagementAPI(gw, logging.NewLogger(false), nil)
	route := cfg.Services[0].Services[0].Routes[0]
	route.ServiceName = "agent"
	now := time.Now().UTC()
	gw.RecordRouteLimitHitForBucketTest(route, "concurrency_queue_full", "jwt_sub", "vip-a", 0, now.Add(-2*time.Minute))
	gw.RecordRouteLimitHitForBucketTest(route, "concurrency_queue_full", "jwt_sub", "vip-b", 0, now.Add(-90*time.Second))
	gw.RecordRouteLimitHitForBucketTest(route, "concurrency_queue_full", "jwt_sub", "vip-c", 0, now.Add(-75*time.Second))
	gw.RecordRouteLimitHitForBucketTest(route, "concurrency_queued", "jwt_sub", "vip-a", 140*time.Millisecond, now.Add(-45*time.Second))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/gateway/limit-class-alerts?window=5m&min_count=2", nil)
	resp := httptest.NewRecorder()
	api.getGatewayLimitClassAlerts(resp, req)

	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.Code, resp.Body.String())
	}
	var payload struct {
		Window         string         `json:"window"`
		MinCount       int            `json:"min_count"`
		TotalAlerts    int            `json:"total_alerts"`
		TopBucketClass string         `json:"top_bucket_class"`
		BySeverity     map[string]int `json:"by_severity"`
		Alerts         []struct {
			Severity            string `json:"severity"`
			RoutePath           string `json:"route_path"`
			LimitType           string `json:"limit_type"`
			KeyType             string `json:"key_type"`
			BucketClass         string `json:"bucket_class"`
			Count               int    `json:"count"`
			QueueFullRejections int    `json:"queue_full_rejections"`
		} `json:"alerts"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &payload); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if payload.Window != "5m" || payload.MinCount != 2 || payload.TotalAlerts != 1 || payload.TopBucketClass != "vip-jwt" {
		t.Fatalf("unexpected class alert header: %+v", payload)
	}
	if payload.BySeverity["elevated"] != 1 {
		t.Fatalf("expected one elevated class alert, got %+v", payload.BySeverity)
	}
	if len(payload.Alerts) != 1 {
		t.Fatalf("expected one class alert, got %+v", payload.Alerts)
	}
	if payload.Alerts[0].BucketClass != "vip-jwt" || payload.Alerts[0].LimitType != "concurrency_queue_full" || payload.Alerts[0].Count != 3 || payload.Alerts[0].QueueFullRejections != 3 {
		t.Fatalf("unexpected class alert entry: %+v", payload.Alerts[0])
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

func TestGetGatewayLimitAlertsReturnsRecentLimiterAlerts(t *testing.T) {
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
	}
	gw, err := gatewaypkg.NewGateway(gatewaypkg.Dependencies{Config: cfg, Logger: logging.NewLogger(false)}, "test")
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}
	route := cfg.Services[0].Services[0].Routes[0]
	route.ServiceName = "agent"

	now := time.Now().UTC()
	gw.RecordRouteLimitHitForTest(route, "concurrency_queue_full", "jwt_sub", 0, now.Add(-4*time.Minute))
	gw.RecordRouteLimitHitForTest(route, "concurrency_queue_full", "jwt_sub", 0, now.Add(-3*time.Minute))
	gw.RecordRouteLimitHitForTest(route, "concurrency_queue_full", "jwt_sub", 0, now.Add(-2*time.Minute))
	gw.RecordRouteLimitHitForTest(route, "concurrency_queued", "jwt_sub", 150*time.Millisecond, now.Add(-90*time.Second))

	api := NewManagementAPI(gw, logging.NewLogger(false), nil)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/gateway/limit-alerts?window=5m&min_count=3", nil)
	resp := httptest.NewRecorder()
	api.getGatewayLimitAlerts(resp, req)

	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.Code, resp.Body.String())
	}
	var payload struct {
		Window      string         `json:"window"`
		MinCount    int            `json:"min_count"`
		TotalAlerts int            `json:"total_alerts"`
		BySeverity  map[string]int `json:"by_severity"`
		Alerts      []struct {
			Severity            string `json:"severity"`
			RoutePath           string `json:"route_path"`
			LimitType           string `json:"limit_type"`
			Count               int    `json:"count"`
			QueueFullRejections int    `json:"queue_full_rejections"`
		} `json:"alerts"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &payload); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if payload.Window != "5m" || payload.MinCount != 3 || payload.TotalAlerts != 1 {
		t.Fatalf("unexpected alert summary: %+v", payload)
	}
	if payload.BySeverity["elevated"] != 1 || len(payload.Alerts) != 1 {
		t.Fatalf("unexpected alert severity payload: %+v", payload)
	}
	if payload.Alerts[0].RoutePath != "/ai/chat" || payload.Alerts[0].LimitType != "concurrency_queue_full" || payload.Alerts[0].Count != 3 || payload.Alerts[0].QueueFullRejections != 3 {
		t.Fatalf("unexpected alert entry: %+v", payload.Alerts[0])
	}
}

func TestGetGatewayLimitAlertsAppliesTypeSpecificSeverityThresholds(t *testing.T) {
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
			MutationPolicy: config.MutationPolicy{
				LimitAlertNotifications: config.PolicyAlertNotificationPolicy{
					Enabled: true,
					LimitTypePolicies: map[string]config.LimitAlertTypePolicy{
						"concurrency_queue_full": {
							WarningCount:  2,
							ElevatedCount: 3,
							CriticalCount: 4,
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
	route := cfg.Services[0].Services[0].Routes[0]
	route.ServiceName = "agent"
	now := time.Now().UTC()
	gw.RecordRouteLimitHitForTest(route, "concurrency_queue_full", "jwt_sub", 0, now.Add(-4*time.Minute))
	gw.RecordRouteLimitHitForTest(route, "concurrency_queue_full", "jwt_sub", 0, now.Add(-3*time.Minute))
	gw.RecordRouteLimitHitForTest(route, "concurrency_queue_full", "jwt_sub", 0, now.Add(-2*time.Minute))
	gw.RecordRouteLimitHitForTest(route, "concurrency_queue_full", "jwt_sub", 0, now.Add(-1*time.Minute))

	api := NewManagementAPI(gw, logging.NewLogger(false), nil)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/gateway/limit-alerts?window=5m&min_count=3", nil)
	resp := httptest.NewRecorder()
	api.getGatewayLimitAlerts(resp, req)

	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.Code, resp.Body.String())
	}
	var payload struct {
		TotalAlerts int `json:"total_alerts"`
		Alerts      []struct {
			Severity  string `json:"severity"`
			LimitType string `json:"limit_type"`
			Count     int    `json:"count"`
		} `json:"alerts"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &payload); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if payload.TotalAlerts != 1 || len(payload.Alerts) != 1 {
		t.Fatalf("expected one limit alert, got %+v", payload)
	}
	if payload.Alerts[0].LimitType != "concurrency_queue_full" || payload.Alerts[0].Count != 4 || payload.Alerts[0].Severity != "critical" {
		t.Fatalf("expected critical queue-full alert after type policy override, got %+v", payload.Alerts[0])
	}
}

func TestGetGatewayLimitAlertsAppliesRouteSpecificPolicyOverrides(t *testing.T) {
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
						ConcurrencyLimitPolicy: &config.ConcurrencyLimitPolicyConfig{
							MaxInFlight: 4,
							KeyBy:       "global",
						},
						LimitAlertPolicy: &config.RouteLimitAlertPolicyConfig{
							MinCount: 2,
							LimitTypePolicies: map[string]config.LimitAlertTypePolicy{
								"concurrency_queue_full": {
									WarningCount:  2,
									ElevatedCount: 3,
									CriticalCount: 3,
								},
							},
						},
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
	route := cfg.Services[0].Services[0].Routes[0]
	route.ServiceName = "agent"
	now := time.Now().UTC()
	gw.RecordRouteLimitHitForTest(route, "concurrency_queue_full", "jwt_sub", 0, now.Add(-3*time.Minute))
	gw.RecordRouteLimitHitForTest(route, "concurrency_queue_full", "jwt_sub", 0, now.Add(-2*time.Minute))
	gw.RecordRouteLimitHitForTest(route, "concurrency_queue_full", "jwt_sub", 0, now.Add(-1*time.Minute))

	api := NewManagementAPI(gw, logging.NewLogger(false), nil)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/gateway/limit-alerts?window=5m&min_count=5", nil)
	resp := httptest.NewRecorder()
	api.getGatewayLimitAlerts(resp, req)

	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.Code, resp.Body.String())
	}
	var payload struct {
		TotalAlerts int `json:"total_alerts"`
		Alerts      []struct {
			Severity  string `json:"severity"`
			LimitType string `json:"limit_type"`
			Count     int    `json:"count"`
		} `json:"alerts"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &payload); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if payload.TotalAlerts != 1 || len(payload.Alerts) != 1 {
		t.Fatalf("expected one route-scoped limit alert, got %+v", payload)
	}
	if payload.Alerts[0].LimitType != "concurrency_queue_full" || payload.Alerts[0].Count != 3 || payload.Alerts[0].Severity != "critical" {
		t.Fatalf("expected critical queue-full alert from route policy override, got %+v", payload.Alerts[0])
	}
}

func TestGetGatewayLimitAlertsAppliesBucketSpecificPolicyOverrides(t *testing.T) {
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
						ConcurrencyLimitPolicy: &config.ConcurrencyLimitPolicyConfig{
							MaxInFlight: 4,
							KeyBy:       "jwt_sub",
						},
						LimitAlertPolicy: &config.RouteLimitAlertPolicyConfig{
							GroupBy:  "bucket",
							MinCount: 5,
							BucketPolicies: []config.LimitAlertBucketPolicyConfig{{
								BucketClass: "vip-jwt",
								MinCount:    2,
								MinSeverity: "critical",
								LimitTypePolicies: map[string]config.LimitAlertTypePolicy{
									"concurrency_queue_full": {
										WarningCount:  2,
										ElevatedCount: 2,
										CriticalCount: 2,
									},
								},
							}},
						},
						Backends: []config.Backend{
							{URLPattern: "/"},
						},
					},
				},
			}},
		}},
		Security: config.SecurityConfig{
			LimitAlertBucketClasses: map[string]config.LimitAlertBucketClassConfig{
				"vip-jwt": {
					KeyType:     "jwt_sub",
					BucketRegex: "^vip-",
				},
			},
		},
	}
	gw, err := gatewaypkg.NewGateway(gatewaypkg.Dependencies{Config: cfg, Logger: logging.NewLogger(false)}, "test")
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}
	route := cfg.Services[0].Services[0].Routes[0]
	route.ServiceName = "agent"
	now := time.Now().UTC()
	gw.RecordRouteLimitHitForBucketTest(route, "concurrency_queue_full", "jwt_sub", "vip-tenant-1", 0, now.Add(-2*time.Minute))
	gw.RecordRouteLimitHitForBucketTest(route, "concurrency_queue_full", "jwt_sub", "vip-tenant-1", 0, now.Add(-1*time.Minute))

	api := NewManagementAPI(gw, logging.NewLogger(false), nil)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/gateway/limit-alerts?window=5m&min_count=5", nil)
	resp := httptest.NewRecorder()
	api.getGatewayLimitAlerts(resp, req)

	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.Code, resp.Body.String())
	}
	var payload struct {
		TotalAlerts int `json:"total_alerts"`
		Alerts      []struct {
			Severity    string `json:"severity"`
			KeyType     string `json:"key_type"`
			BucketID    string `json:"bucket_id"`
			BucketClass string `json:"bucket_class"`
			Count       int    `json:"count"`
		} `json:"alerts"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &payload); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if payload.TotalAlerts != 1 || len(payload.Alerts) != 1 {
		t.Fatalf("expected one bucket-scoped alert, got %+v", payload)
	}
	if payload.Alerts[0].Severity != "critical" || payload.Alerts[0].Count != 2 || payload.Alerts[0].KeyType != "jwt_sub" || strings.TrimSpace(payload.Alerts[0].BucketID) == "" || payload.Alerts[0].BucketClass != "vip-jwt" {
		t.Fatalf("expected critical vip bucket alert, got %+v", payload.Alerts[0])
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

func TestNotifyGatewayLimitAlertsEmitsDigestAndAlertEvents(t *testing.T) {
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
					Events: []string{"gateway.limit_alert_digest", "gateway.limit_alert"},
				},
			},
		},
	}
	gw, err := gatewaypkg.NewGateway(gatewaypkg.Dependencies{Config: cfg, Logger: logging.NewLogger(false)}, "test")
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}
	route := cfg.Services[0].Services[0].Routes[0]
	route.ServiceName = "agent"
	now := time.Now().UTC()
	gw.RecordRouteLimitHitForTest(route, "concurrency_queue_full", "jwt_sub", 0, now.Add(-4*time.Minute))
	gw.RecordRouteLimitHitForTest(route, "concurrency_queue_full", "jwt_sub", 0, now.Add(-3*time.Minute))
	gw.RecordRouteLimitHitForTest(route, "concurrency_queue_full", "jwt_sub", 0, now.Add(-2*time.Minute))

	api := NewManagementAPI(gw, logging.NewLogger(false), nil)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/gateway/limit-alerts/notify?window=5m&min_count=3", nil)
	resp := httptest.NewRecorder()
	api.notifyGatewayLimitAlerts(resp, req)

	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.Code, resp.Body.String())
	}
	if len(receivedEvents) != 2 {
		t.Fatalf("expected 2 notification events, got %d (%v)", len(receivedEvents), receivedEvents)
	}
	if !strings.Contains(strings.Join(receivedEvents, ","), "gateway.limit_alert_digest") || !strings.Contains(strings.Join(receivedEvents, ","), "gateway.limit_alert") {
		t.Fatalf("expected gateway.limit_alert_digest and gateway.limit_alert events, got %v", receivedEvents)
	}

	deliveries, err := listNotificationDeliveryRecords()
	if err != nil {
		t.Fatalf("failed to list notification deliveries: %v", err)
	}
	if len(deliveries) != 2 {
		t.Fatalf("expected 2 persisted delivery records, got %d", len(deliveries))
	}
}

func TestNotifyGatewayLimitAlertsHonorsWebhookTypeSeverityAndCooldown(t *testing.T) {
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

	received := make([]string, 0, 6)
	server := newNotificationTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		var payload map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatalf("failed to decode webhook payload: %v", err)
		}
		data, _ := payload["data"].(map[string]interface{})
		received = append(received, strings.TrimSpace(fmt.Sprint(payload["event"]))+":"+strings.TrimSpace(fmt.Sprint(data["severity"]))+":"+strings.TrimSpace(fmt.Sprint(data["limit_type"])))
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
			NotificationWebhooks: []config.NotificationWebhook{
				{
					Name:                  "limit-escalation",
					URL:                   server.URL,
					Events:                []string{"gateway.limit_alert"},
					MinLimitAlertSeverity: "elevated",
					LimitAlertTypes:       []string{"concurrency_queue_full"},
					LimitAlertCooldown:    "1h",
				},
			},
		},
	}
	gw, err := gatewaypkg.NewGateway(gatewaypkg.Dependencies{Config: cfg, Logger: logging.NewLogger(false)}, "test")
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}
	route := cfg.Services[0].Services[0].Routes[0]
	route.ServiceName = "agent"
	now := time.Now().UTC()
	gw.RecordRouteLimitHitForTest(route, "concurrency_queue_full", "jwt_sub", 0, now.Add(-4*time.Minute))
	gw.RecordRouteLimitHitForTest(route, "concurrency_queue_full", "jwt_sub", 0, now.Add(-3*time.Minute))
	gw.RecordRouteLimitHitForTest(route, "concurrency_queue_full", "jwt_sub", 0, now.Add(-2*time.Minute))

	api := NewManagementAPI(gw, logging.NewLogger(false), nil)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/gateway/limit-alerts/notify?window=5m&min_count=3", nil)

	resp := httptest.NewRecorder()
	api.notifyGatewayLimitAlerts(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected first notify to return 200, got %d: %s", resp.Code, resp.Body.String())
	}
	if len(received) != 1 || received[0] != "gateway.limit_alert:elevated:concurrency_queue_full" {
		t.Fatalf("expected one elevated queue-full limit alert, got %v", received)
	}

	resp = httptest.NewRecorder()
	api.notifyGatewayLimitAlerts(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected second notify to return 200, got %d: %s", resp.Code, resp.Body.String())
	}
	if len(received) != 1 {
		t.Fatalf("expected cooldown to suppress duplicate limit alert, got %v", received)
	}

	for i := 0; i < 9; i++ {
		gw.RecordRouteLimitHitForTest(route, "concurrency_queue_full", "jwt_sub", 0, time.Now().UTC())
	}
	resp = httptest.NewRecorder()
	api.notifyGatewayLimitAlerts(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected third notify to return 200, got %d: %s", resp.Code, resp.Body.String())
	}
	if len(received) != 2 || received[1] != "gateway.limit_alert:critical:concurrency_queue_full" {
		t.Fatalf("expected critical limit alert to bypass cooldown, got %v", received)
	}
}

func TestNotifyGatewayLimitClassAlertsEmitsDigestAndAlertEvents(t *testing.T) {
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
		Security: config.SecurityConfig{
			LimitAlertBucketClasses: map[string]config.LimitAlertBucketClassConfig{
				"vip-jwt": {
					KeyType:     "jwt_sub",
					BucketRegex: "^vip-",
				},
			},
			NotificationWebhooks: []config.NotificationWebhook{
				{
					URL:    server.URL,
					Events: []string{"gateway.limit_class_alert_digest", "gateway.limit_class_alert"},
				},
			},
		},
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
	}
	gw, err := gatewaypkg.NewGateway(gatewaypkg.Dependencies{Config: cfg, Logger: logging.NewLogger(false)}, "test")
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}
	route := cfg.Services[0].Services[0].Routes[0]
	route.ServiceName = "agent"
	now := time.Now().UTC()
	gw.RecordRouteLimitHitForBucketTest(route, "concurrency_queue_full", "jwt_sub", "vip-a", 0, now.Add(-4*time.Minute))
	gw.RecordRouteLimitHitForBucketTest(route, "concurrency_queue_full", "jwt_sub", "vip-b", 0, now.Add(-3*time.Minute))
	gw.RecordRouteLimitHitForBucketTest(route, "concurrency_queue_full", "jwt_sub", "vip-c", 0, now.Add(-2*time.Minute))

	api := NewManagementAPI(gw, logging.NewLogger(false), nil)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/gateway/limit-class-alerts/notify?window=5m&min_count=3", nil)
	resp := httptest.NewRecorder()
	api.notifyGatewayLimitClassAlerts(resp, req)

	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.Code, resp.Body.String())
	}
	if len(receivedEvents) != 2 {
		t.Fatalf("expected 2 notification events, got %d (%v)", len(receivedEvents), receivedEvents)
	}
	if !strings.Contains(strings.Join(receivedEvents, ","), "gateway.limit_class_alert_digest") || !strings.Contains(strings.Join(receivedEvents, ","), "gateway.limit_class_alert") {
		t.Fatalf("expected gateway.limit_class_alert_digest and gateway.limit_class_alert events, got %v", receivedEvents)
	}

	deliveries, err := listNotificationDeliveryRecords()
	if err != nil {
		t.Fatalf("failed to list notification deliveries: %v", err)
	}
	if len(deliveries) != 2 {
		t.Fatalf("expected 2 persisted delivery records, got %d", len(deliveries))
	}
}

func TestNotifyGatewayLimitAlertsHonorsBucketAwareWebhookRoutingAndCooldown(t *testing.T) {
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

	received := make([]string, 0, 6)
	server := newNotificationTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		var payload map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatalf("failed to decode webhook payload: %v", err)
		}
		data, _ := payload["data"].(map[string]interface{})
		received = append(received,
			strings.TrimSpace(fmt.Sprint(payload["event"]))+":"+
				strings.TrimSpace(fmt.Sprint(data["bucket_id"]))+":"+
				strings.TrimSpace(fmt.Sprint(data["key_type"]))+":"+
				strings.TrimSpace(fmt.Sprint(data["bucket_class"])))
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
					LimitAlertPolicy: &config.RouteLimitAlertPolicyConfig{
						GroupBy: "bucket",
					},
					Backends: []config.Backend{
						{URLPattern: "/"},
					},
				}},
			}},
		}},
		Security: config.SecurityConfig{
			NotificationWebhooks: []config.NotificationWebhook{
				{
					Name:                    "tenant-buckets",
					URL:                     server.URL,
					Events:                  []string{"gateway.limit_alert"},
					MinLimitAlertSeverity:   "warning",
					LimitAlertTypes:         []string{"concurrency_queue_full"},
					LimitAlertKeyTypes:      []string{"jwt_sub"},
					LimitAlertBucketIDRegex: "^jwt_sub:",
					LimitAlertCooldown:      "1h",
				},
			},
		},
	}
	gw, err := gatewaypkg.NewGateway(gatewaypkg.Dependencies{Config: cfg, Logger: logging.NewLogger(false)}, "test")
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}
	route := cfg.Services[0].Services[0].Routes[0]
	route.ServiceName = "agent"
	now := time.Now().UTC()
	gw.RecordRouteLimitHitForBucketTest(route, "concurrency_queue_full", "jwt_sub", "vip-a", 0, now.Add(-4*time.Minute))
	gw.RecordRouteLimitHitForBucketTest(route, "concurrency_queue_full", "jwt_sub", "vip-a", 0, now.Add(-3*time.Minute))
	gw.RecordRouteLimitHitForBucketTest(route, "concurrency_queue_full", "jwt_sub", "vip-b", 0, now.Add(-2*time.Minute))
	gw.RecordRouteLimitHitForBucketTest(route, "concurrency_queue_full", "jwt_sub", "vip-b", 0, now.Add(-1*time.Minute))
	gw.RecordRouteLimitHitForBucketTest(route, "concurrency_queue_full", "api_key", "header:key-1", 0, now.Add(-90*time.Second))
	gw.RecordRouteLimitHitForBucketTest(route, "concurrency_queue_full", "api_key", "header:key-1", 0, now.Add(-30*time.Second))

	api := NewManagementAPI(gw, logging.NewLogger(false), nil)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/gateway/limit-alerts/notify?window=5m&min_count=2", nil)

	resp := httptest.NewRecorder()
	api.notifyGatewayLimitAlerts(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected first notify to return 200, got %d: %s", resp.Code, resp.Body.String())
	}
	if len(received) != 2 {
		t.Fatalf("expected two jwt_sub bucket deliveries, got %v", received)
	}
	if received[0] == received[1] {
		t.Fatalf("expected distinct bucket deliveries, got %v", received)
	}

	resp = httptest.NewRecorder()
	api.notifyGatewayLimitAlerts(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected second notify to return 200, got %d: %s", resp.Code, resp.Body.String())
	}
	if len(received) != 2 {
		t.Fatalf("expected cooldown to suppress duplicate per-bucket alerts, got %v", received)
	}
}

func TestNotifyGatewayLimitAlertsAppliesNamedWebhookProfile(t *testing.T) {
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
			t.Fatalf("failed to decode webhook payload: %v", err)
		}
		data, _ := payload["data"].(map[string]interface{})
		received = append(received,
			strings.TrimSpace(fmt.Sprint(payload["event"]))+":"+
				strings.TrimSpace(fmt.Sprint(data["bucket_id"]))+":"+
				strings.TrimSpace(fmt.Sprint(data["key_type"]))+":"+
				strings.TrimSpace(fmt.Sprint(data["bucket_class"])))
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
					LimitAlertPolicy: &config.RouteLimitAlertPolicyConfig{
						GroupBy: "bucket",
					},
					Backends: []config.Backend{
						{URLPattern: "/"},
					},
				}},
			}},
		}},
		Security: config.SecurityConfig{
			LimitAlertBucketClasses: map[string]config.LimitAlertBucketClassConfig{
				"vip-jwt": {
					KeyType:     "jwt_sub",
					BucketRegex: "^vip-",
				},
			},
			LimitAlertProfiles: map[string]config.LimitAlertRecipientProfile{
				"vip-jwt": {
					MinLimitAlertSeverity:   "warning",
					LimitAlertTypes:         []string{"concurrency_queue_full"},
					LimitAlertKeyTypes:      []string{"jwt_sub"},
					LimitAlertBucketClasses: []string{"vip-jwt"},
					LimitAlertCooldown:      "1h",
				},
			},
			NotificationWebhooks: []config.NotificationWebhook{
				{
					Name:              "vip-jwt-target",
					URL:               server.URL,
					Events:            []string{"gateway.limit_alert"},
					LimitAlertProfile: "vip-jwt",
				},
			},
		},
	}
	gw, err := gatewaypkg.NewGateway(gatewaypkg.Dependencies{Config: cfg, Logger: logging.NewLogger(false)}, "test")
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}
	route := cfg.Services[0].Services[0].Routes[0]
	route.ServiceName = "agent"
	now := time.Now().UTC()
	gw.RecordRouteLimitHitForBucketTest(route, "concurrency_queue_full", "jwt_sub", "vip-a", 0, now.Add(-2*time.Minute))
	gw.RecordRouteLimitHitForBucketTest(route, "concurrency_queue_full", "jwt_sub", "vip-a", 0, now.Add(-90*time.Second))
	gw.RecordRouteLimitHitForBucketTest(route, "concurrency_queue_full", "api_key", "header:key-1", 0, now.Add(-75*time.Second))
	gw.RecordRouteLimitHitForBucketTest(route, "concurrency_queue_full", "api_key", "header:key-1", 0, now.Add(-30*time.Second))

	api := NewManagementAPI(gw, logging.NewLogger(false), nil)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/gateway/limit-alerts/notify?window=5m&min_count=2", nil)
	resp := httptest.NewRecorder()
	api.notifyGatewayLimitAlerts(resp, req)

	if resp.Code != http.StatusOK {
		t.Fatalf("expected notify to return 200, got %d: %s", resp.Code, resp.Body.String())
	}
	if len(received) != 1 {
		t.Fatalf("expected one delivery from named limiter profile, got %v", received)
	}
	if !strings.Contains(received[0], "gateway.limit_alert:") || !strings.Contains(received[0], ":jwt_sub:vip-jwt") {
		t.Fatalf("expected jwt_sub bucket delivery from named profile, got %v", received)
	}
}

func TestReconcileGatewayLimitAlertNotificationsAutoEmitsAndHonorsInterval(t *testing.T) {
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

	receivedEvents := make([]string, 0, 6)
	server := newNotificationTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		var payload struct {
			Event string `json:"event"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatalf("failed to decode webhook payload: %v", err)
		}
		receivedEvents = append(receivedEvents, payload.Event)
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
				LimitAlertNotifications: config.PolicyAlertNotificationPolicy{
					Enabled:                 true,
					Interval:                "1m",
					MinNotificationInterval: "1m",
					OnlyOnChange:            true,
					Window:                  "5m",
					MinCount:                3,
					MinSeverity:             "warning",
				},
			},
			NotificationWebhooks: []config.NotificationWebhook{
				{
					URL:    server.URL,
					Events: []string{"gateway.limit_alert_digest", "gateway.limit_alert"},
				},
			},
		},
	}
	gw, err := gatewaypkg.NewGateway(gatewaypkg.Dependencies{Config: cfg, Logger: logging.NewLogger(false)}, "test")
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}
	route := cfg.Services[0].Services[0].Routes[0]
	route.ServiceName = "agent"
	base := time.Now().UTC()
	gw.RecordRouteLimitHitForTest(route, "concurrency_queue_full", "jwt_sub", 0, base.Add(-30*time.Second))
	gw.RecordRouteLimitHitForTest(route, "concurrency_queue_full", "jwt_sub", 0, base.Add(-20*time.Second))
	gw.RecordRouteLimitHitForTest(route, "concurrency_queue_full", "jwt_sub", 0, base.Add(-10*time.Second))

	api := NewManagementAPI(gw, logging.NewLogger(false), nil)
	api.reconcileGatewayLimitAlertNotifications(base)
	if len(receivedEvents) != 2 {
		t.Fatalf("expected digest plus one alert on first reconcile, got %d (%v)", len(receivedEvents), receivedEvents)
	}

	api.reconcileGatewayLimitAlertNotifications(base.Add(30 * time.Second))
	if len(receivedEvents) != 2 {
		t.Fatalf("expected min interval to suppress duplicate notifications, got %d (%v)", len(receivedEvents), receivedEvents)
	}
}

func TestReconcileGatewayLimitAlertNotificationsEmitsLifecycleEvents(t *testing.T) {
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
				LimitAlertNotifications: config.PolicyAlertNotificationPolicy{
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
						"gateway.limit_alert_opened",
						"gateway.limit_alert_stage_changed",
						"gateway.limit_alert_resolved",
					},
				},
			},
		},
	}
	gw, err := gatewaypkg.NewGateway(gatewaypkg.Dependencies{Config: cfg, Logger: logging.NewLogger(false)}, "test")
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}
	route := cfg.Services[0].Services[0].Routes[0]
	route.ServiceName = "agent"
	base := time.Now().UTC()
	gw.RecordRouteLimitHitForTest(route, "concurrency_queue_full", "jwt_sub", 0, base.Add(-30*time.Second))
	gw.RecordRouteLimitHitForTest(route, "concurrency_queue_full", "jwt_sub", 0, base.Add(-20*time.Second))
	gw.RecordRouteLimitHitForTest(route, "concurrency_queue_full", "jwt_sub", 0, base.Add(-10*time.Second))

	api := NewManagementAPI(gw, logging.NewLogger(false), nil)
	api.reconcileGatewayLimitAlertNotifications(base)
	if len(received) != 1 || received[0].Event != "gateway.limit_alert_opened" || strings.TrimSpace(received[0].IncidentID) == "" || received[0].Severity != "elevated" {
		t.Fatalf("expected opened limit incident event, got %+v", received)
	}
	incidentID := received[0].IncidentID

	for i := 0; i < 9; i++ {
		gw.RecordRouteLimitHitForTest(route, "concurrency_queue_full", "jwt_sub", 0, base.Add(90*time.Second))
	}
	api.reconcileGatewayLimitAlertNotifications(base.Add(2 * time.Minute))
	if len(received) != 2 || received[1].Event != "gateway.limit_alert_stage_changed" || received[1].Previous != "elevated" || received[1].Severity != "critical" || received[1].IncidentID != incidentID {
		t.Fatalf("expected limit alert stage change for same incident, got %+v", received)
	}

	api.reconcileGatewayLimitAlertNotifications(base.Add(10 * time.Minute))
	if len(received) != 3 || received[2].Event != "gateway.limit_alert_resolved" || received[2].IncidentID != incidentID {
		t.Fatalf("expected resolved limit incident event, got %+v", received)
	}
}

func TestReconcileGatewayLimitAlertNotificationsSplitsBucketScopedIncidents(t *testing.T) {
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
		BucketID   string
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
			BucketID:   strings.TrimSpace(fmt.Sprint(data["bucket_id"])),
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
					ConcurrencyLimitPolicy: &config.ConcurrencyLimitPolicyConfig{
						MaxInFlight: 4,
						KeyBy:       "jwt_sub",
					},
					LimitAlertPolicy: &config.RouteLimitAlertPolicyConfig{
						MinCount: 2,
						GroupBy:  "bucket",
					},
					Backends: []config.Backend{
						{URLPattern: "/"},
					},
				}},
			}},
		}},
		Security: config.SecurityConfig{
			MutationPolicy: config.MutationPolicy{
				LimitAlertNotifications: config.PolicyAlertNotificationPolicy{
					Enabled:     true,
					Interval:    "1m",
					Window:      "5m",
					MinCount:    2,
					MinSeverity: "warning",
				},
			},
			NotificationWebhooks: []config.NotificationWebhook{
				{
					URL:    server.URL,
					Events: []string{"gateway.limit_alert_opened"},
				},
			},
		},
	}
	gw, err := gatewaypkg.NewGateway(gatewaypkg.Dependencies{Config: cfg, Logger: logging.NewLogger(false)}, "test")
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}
	route := cfg.Services[0].Services[0].Routes[0]
	route.ServiceName = "agent"
	base := time.Now().UTC()
	gw.RecordRouteLimitHitForBucketTest(route, "concurrency_queue_full", "jwt_sub", "tenant-a", 0, base.Add(-30*time.Second))
	gw.RecordRouteLimitHitForBucketTest(route, "concurrency_queue_full", "jwt_sub", "tenant-a", 0, base.Add(-20*time.Second))
	gw.RecordRouteLimitHitForBucketTest(route, "concurrency_queue_full", "jwt_sub", "tenant-b", 0, base.Add(-15*time.Second))
	gw.RecordRouteLimitHitForBucketTest(route, "concurrency_queue_full", "jwt_sub", "tenant-b", 0, base.Add(-10*time.Second))

	api := NewManagementAPI(gw, logging.NewLogger(false), nil)
	api.reconcileGatewayLimitAlertNotifications(base)
	if len(received) != 2 {
		t.Fatalf("expected two opened limit incidents, got %+v", received)
	}
	if received[0].Event != "gateway.limit_alert_opened" || received[1].Event != "gateway.limit_alert_opened" {
		t.Fatalf("expected opened events, got %+v", received)
	}
	if received[0].IncidentID == "" || received[1].IncidentID == "" || received[0].IncidentID == received[1].IncidentID {
		t.Fatalf("expected distinct incident ids, got %+v", received)
	}
	if received[0].BucketID == "" || received[1].BucketID == "" || received[0].BucketID == received[1].BucketID {
		t.Fatalf("expected distinct bucket ids, got %+v", received)
	}
}

func TestReconcileGatewayLimitClassAlertNotificationsAutoEmitsAndHonorsInterval(t *testing.T) {
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
		Security: config.SecurityConfig{
			LimitAlertBucketClasses: map[string]config.LimitAlertBucketClassConfig{
				"vip-jwt": {
					KeyType:     "jwt_sub",
					BucketRegex: "^vip-",
				},
			},
			MutationPolicy: config.MutationPolicy{
				LimitClassAlertNotifications: config.PolicyAlertNotificationPolicy{
					Enabled:                 true,
					Interval:                "1m",
					MinNotificationInterval: "1m",
					OnlyOnChange:            true,
					Window:                  "5m",
					MinCount:                3,
					MinSeverity:             "warning",
				},
			},
			NotificationWebhooks: []config.NotificationWebhook{
				{
					URL:    server.URL,
					Events: []string{"gateway.limit_class_alert_digest", "gateway.limit_class_alert"},
				},
			},
		},
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
	}
	gw, err := gatewaypkg.NewGateway(gatewaypkg.Dependencies{Config: cfg, Logger: logging.NewLogger(false)}, "test")
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}
	route := cfg.Services[0].Services[0].Routes[0]
	route.ServiceName = "agent"
	base := time.Now().UTC()
	gw.RecordRouteLimitHitForBucketTest(route, "concurrency_queue_full", "jwt_sub", "vip-a", 0, base.Add(-30*time.Second))
	gw.RecordRouteLimitHitForBucketTest(route, "concurrency_queue_full", "jwt_sub", "vip-b", 0, base.Add(-20*time.Second))
	gw.RecordRouteLimitHitForBucketTest(route, "concurrency_queue_full", "jwt_sub", "vip-c", 0, base.Add(-10*time.Second))

	api := NewManagementAPI(gw, logging.NewLogger(false), nil)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/gateway/limit-class-alerts/notify?window=5m&min_count=3", nil)
	resp := httptest.NewRecorder()
	api.notifyGatewayLimitClassAlerts(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200 from notify-limit-class-alerts, got %d: %s", resp.Code, resp.Body.String())
	}
	if len(receivedEvents) != 2 {
		t.Fatalf("expected digest plus one class alert on first reconcile, got %d (%v)", len(receivedEvents), receivedEvents)
	}

	api.queueDigestNotifyMu.Lock()
	api.lastLimitClassAlertNotificationAt = base
	api.queueDigestNotifyMu.Unlock()
	api.reconcileGatewayLimitClassAlertNotifications(base.Add(30 * time.Second))
	if len(receivedEvents) != 2 {
		t.Fatalf("expected min interval to suppress duplicate class notifications, got %d (%v)", len(receivedEvents), receivedEvents)
	}
}

func TestReconcileGatewayLimitClassAlertNotificationsHonorsDetailedMinBucketClassPriority(t *testing.T) {
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

	type receivedEvent struct {
		Event                string
		Count                int
		SummarizedCount      int
		SummarizedByClassLen int
		TopSummarizedClass   string
	}
	received := make([]receivedEvent, 0, 8)
	server := newNotificationTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		var payload map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatalf("failed to decode webhook payload: %v", err)
		}
		data, _ := payload["data"].(map[string]interface{})
		count := 0
		if alerts, ok := data["alerts"].([]interface{}); ok {
			count = len(alerts)
		}
		summarizedCount := 0
		if value, ok := data["summarized_class_alert_count"]; ok {
			summarizedCount = intValue(value)
		}
		summarizedByClassLen := 0
		topSummarizedClass := ""
		if summarized, ok := data["summarized_class_alerts_by_class"].([]interface{}); ok {
			summarizedByClassLen = len(summarized)
			if len(summarized) > 0 {
				if entry, ok := summarized[0].(map[string]interface{}); ok {
					topSummarizedClass = strings.TrimSpace(fmt.Sprint(entry["bucket_class"]))
				}
			}
		}
		received = append(received, receivedEvent{
			Event:                strings.TrimSpace(fmt.Sprint(payload["event"])),
			Count:                count,
			SummarizedCount:      summarizedCount,
			SummarizedByClassLen: summarizedByClassLen,
			TopSummarizedClass:   topSummarizedClass,
		})
		w.WriteHeader(http.StatusOK)
	})
	defer server.Close()

	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Security: config.SecurityConfig{
			LimitAlertBucketClasses: map[string]config.LimitAlertBucketClassConfig{
				"vip-jwt": {
					KeyType:     "jwt_sub",
					BucketRegex: "^vip-",
					Priority:    10,
				},
				"standard-jwt": {
					KeyType:     "jwt_sub",
					BucketRegex: "^std-",
					Priority:    1,
				},
			},
			MutationPolicy: config.MutationPolicy{
				LimitClassAlertNotifications: config.PolicyAlertNotificationPolicy{
					Enabled:                        true,
					Interval:                       "1m",
					MinNotificationInterval:        "1m",
					Window:                         "5m",
					MinCount:                       3,
					MinSeverity:                    "warning",
					DetailedMinBucketClassPriority: 5,
				},
			},
			NotificationWebhooks: []config.NotificationWebhook{
				{
					URL:    server.URL,
					Events: []string{"gateway.limit_class_alert_digest", "gateway.limit_class_alert"},
				},
			},
		},
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
	}
	gw, err := gatewaypkg.NewGateway(gatewaypkg.Dependencies{Config: cfg, Logger: logging.NewLogger(false)}, "test")
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}
	route := cfg.Services[0].Services[0].Routes[0]
	route.ServiceName = "agent"
	base := time.Now().UTC()
	for _, bucket := range []string{"vip-a", "vip-b", "vip-c"} {
		gw.RecordRouteLimitHitForBucketTest(route, "concurrency_queue_full", "jwt_sub", bucket, 0, base.Add(-20*time.Second))
	}
	for _, bucket := range []string{"std-a", "std-b", "std-c"} {
		gw.RecordRouteLimitHitForBucketTest(route, "concurrency_queue_full", "jwt_sub", bucket, 0, base.Add(-10*time.Second))
	}

	api := NewManagementAPI(gw, logging.NewLogger(false), nil)
	api.reconcileGatewayLimitClassAlertNotifications(base)
	if len(received) != 3 {
		t.Fatalf("expected digest plus two class alerts, got %d (%+v)", len(received), received)
	}
	digest := received[0]
	if digest.Event != "gateway.limit_class_alert_digest" || digest.Count != 1 || digest.SummarizedCount != 1 || digest.SummarizedByClassLen != 1 || digest.TopSummarizedClass != "standard-jwt" {
		t.Fatalf("expected digest to keep one detailed class alert and summarize one lower-priority class, got %+v", digest)
	}
}

func TestReconcileGatewayLimitClassAlertNotificationsHonorsDetailedMaxBucketClasses(t *testing.T) {
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

	type receivedEvent struct {
		Event                string
		Count                int
		SummarizedCount      int
		SummarizedByClassLen int
		TopSummarizedClass   string
	}
	received := make([]receivedEvent, 0, 8)
	server := newNotificationTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		var payload map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatalf("failed to decode webhook payload: %v", err)
		}
		data, _ := payload["data"].(map[string]interface{})
		count := 0
		if alerts, ok := data["alerts"].([]interface{}); ok {
			count = len(alerts)
		}
		summarizedCount := 0
		if value, ok := data["summarized_class_alert_count"]; ok {
			summarizedCount = intValue(value)
		}
		summarizedByClassLen := 0
		topSummarizedClass := ""
		if summarized, ok := data["summarized_class_alerts_by_class"].([]interface{}); ok {
			summarizedByClassLen = len(summarized)
			if len(summarized) > 0 {
				if entry, ok := summarized[0].(map[string]interface{}); ok {
					topSummarizedClass = strings.TrimSpace(fmt.Sprint(entry["bucket_class"]))
				}
			}
		}
		received = append(received, receivedEvent{
			Event:                strings.TrimSpace(fmt.Sprint(payload["event"])),
			Count:                count,
			SummarizedCount:      summarizedCount,
			SummarizedByClassLen: summarizedByClassLen,
			TopSummarizedClass:   topSummarizedClass,
		})
		w.WriteHeader(http.StatusOK)
	})
	defer server.Close()

	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Security: config.SecurityConfig{
			LimitAlertBucketClasses: map[string]config.LimitAlertBucketClassConfig{
				"vip-jwt": {
					KeyType:     "jwt_sub",
					BucketRegex: "^vip-",
					Priority:    10,
				},
				"gold-jwt": {
					KeyType:     "jwt_sub",
					BucketRegex: "^gold-",
					Priority:    7,
				},
			},
			MutationPolicy: config.MutationPolicy{
				LimitClassAlertNotifications: config.PolicyAlertNotificationPolicy{
					Enabled:                        true,
					Interval:                       "1m",
					MinNotificationInterval:        "1m",
					Window:                         "5m",
					MinCount:                       3,
					MinSeverity:                    "warning",
					DetailedMinBucketClassPriority: 5,
					DetailedMaxBucketClasses:       1,
				},
			},
			NotificationWebhooks: []config.NotificationWebhook{
				{
					URL:    server.URL,
					Events: []string{"gateway.limit_class_alert_digest", "gateway.limit_class_alert"},
				},
			},
		},
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
	}
	gw, err := gatewaypkg.NewGateway(gatewaypkg.Dependencies{Config: cfg, Logger: logging.NewLogger(false)}, "test")
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}
	route := cfg.Services[0].Services[0].Routes[0]
	route.ServiceName = "agent"
	base := time.Now().UTC()
	for _, bucket := range []string{"vip-a", "vip-b", "vip-c"} {
		gw.RecordRouteLimitHitForBucketTest(route, "concurrency_queue_full", "jwt_sub", bucket, 0, base.Add(-20*time.Second))
	}
	for _, bucket := range []string{"gold-a", "gold-b", "gold-c"} {
		gw.RecordRouteLimitHitForBucketTest(route, "concurrency_queue_full", "jwt_sub", bucket, 0, base.Add(-10*time.Second))
	}

	api := NewManagementAPI(gw, logging.NewLogger(false), nil)
	api.reconcileGatewayLimitClassAlertNotifications(base)
	if len(received) != 3 {
		t.Fatalf("expected digest plus two class alerts, got %d (%+v)", len(received), received)
	}
	digest := received[0]
	if digest.Event != "gateway.limit_class_alert_digest" || digest.Count != 1 || digest.SummarizedCount != 1 || digest.SummarizedByClassLen != 1 || digest.TopSummarizedClass != "gold-jwt" {
		t.Fatalf("expected digest quota to keep only the top class detailed and summarize the next class, got %+v", digest)
	}
}

func TestNotifyGatewayLimitClassAlertsShapesDigestPerWebhookBudget(t *testing.T) {
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

	type digestView struct {
		Count           int
		SummarizedCount int
	}
	views := make([]digestView, 0, 2)
	serverA := newNotificationTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		var payload map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatalf("failed to decode webhook payload: %v", err)
		}
		if strings.TrimSpace(fmt.Sprint(payload["event"])) == "gateway.limit_class_alert_digest" {
			data, _ := payload["data"].(map[string]interface{})
			count := 0
			if alerts, ok := data["alerts"].([]interface{}); ok {
				count = len(alerts)
			}
			views = append(views, digestView{
				Count:           count,
				SummarizedCount: intValue(data["summarized_class_alert_count"]),
			})
		}
		w.WriteHeader(http.StatusOK)
	})
	defer serverA.Close()
	serverB := newNotificationTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		var payload map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatalf("failed to decode webhook payload: %v", err)
		}
		if strings.TrimSpace(fmt.Sprint(payload["event"])) == "gateway.limit_class_alert_digest" {
			data, _ := payload["data"].(map[string]interface{})
			count := 0
			if alerts, ok := data["alerts"].([]interface{}); ok {
				count = len(alerts)
			}
			views = append(views, digestView{
				Count:           count,
				SummarizedCount: intValue(data["summarized_class_alert_count"]),
			})
		}
		w.WriteHeader(http.StatusOK)
	})
	defer serverB.Close()

	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Security: config.SecurityConfig{
			LimitAlertBucketClasses: map[string]config.LimitAlertBucketClassConfig{
				"vip-jwt":  {KeyType: "jwt_sub", BucketRegex: "^vip-", Priority: 10},
				"gold-jwt": {KeyType: "jwt_sub", BucketRegex: "^gold-", Priority: 7},
			},
			LimitAlertProfiles: map[string]config.LimitAlertRecipientProfile{
				"top-one": {LimitClassDigestMaxBucketClasses: 1},
				"top-two": {LimitClassDigestMaxBucketClasses: 2},
			},
			NotificationWebhooks: []config.NotificationWebhook{
				{URL: serverA.URL, Events: []string{"gateway.limit_class_alert_digest"}, LimitAlertProfile: "top-one"},
				{URL: serverB.URL, Events: []string{"gateway.limit_class_alert_digest"}, LimitAlertProfile: "top-two"},
			},
		},
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
	}
	gw, err := gatewaypkg.NewGateway(gatewaypkg.Dependencies{Config: cfg, Logger: logging.NewLogger(false)}, "test")
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}
	route := cfg.Services[0].Services[0].Routes[0]
	route.ServiceName = "agent"
	now := time.Now().UTC()
	for _, bucket := range []string{"vip-a", "vip-b", "vip-c"} {
		gw.RecordRouteLimitHitForBucketTest(route, "concurrency_queue_full", "jwt_sub", bucket, 0, now.Add(-20*time.Second))
	}
	for _, bucket := range []string{"gold-a", "gold-b", "gold-c"} {
		gw.RecordRouteLimitHitForBucketTest(route, "concurrency_queue_full", "jwt_sub", bucket, 0, now.Add(-10*time.Second))
	}

	api := NewManagementAPI(gw, logging.NewLogger(false), nil)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/gateway/limit-class-alerts/notify?window=5m&min_count=3", nil)
	resp := httptest.NewRecorder()
	api.notifyGatewayLimitClassAlerts(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.Code, resp.Body.String())
	}
	if len(views) != 2 {
		t.Fatalf("expected two per-webhook digest views, got %d (%+v)", len(views), views)
	}
	if views[0].Count != 1 || views[0].SummarizedCount != 1 {
		t.Fatalf("expected top-one receiver to get one detailed class and one summarized class, got %+v", views[0])
	}
	if views[1].Count != 2 || views[1].SummarizedCount != 0 {
		t.Fatalf("expected top-two receiver to get both detailed classes, got %+v", views[1])
	}
}

func TestNotifyGatewayLimitClassAlertsShapesDigestPerWebhookSeverity(t *testing.T) {
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

	type digestView struct {
		Count           int
		SummarizedCount int
	}
	views := make([]digestView, 0, 2)
	serverA := newNotificationTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		var payload map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatalf("failed to decode webhook payload: %v", err)
		}
		if strings.TrimSpace(fmt.Sprint(payload["event"])) == "gateway.limit_class_alert_digest" {
			data, _ := payload["data"].(map[string]interface{})
			count := 0
			if alerts, ok := data["alerts"].([]interface{}); ok {
				count = len(alerts)
			}
			views = append(views, digestView{
				Count:           count,
				SummarizedCount: intValue(data["summarized_class_alert_count"]),
			})
		}
		w.WriteHeader(http.StatusOK)
	})
	defer serverA.Close()
	serverB := newNotificationTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		var payload map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatalf("failed to decode webhook payload: %v", err)
		}
		if strings.TrimSpace(fmt.Sprint(payload["event"])) == "gateway.limit_class_alert_digest" {
			data, _ := payload["data"].(map[string]interface{})
			count := 0
			if alerts, ok := data["alerts"].([]interface{}); ok {
				count = len(alerts)
			}
			views = append(views, digestView{
				Count:           count,
				SummarizedCount: intValue(data["summarized_class_alert_count"]),
			})
		}
		w.WriteHeader(http.StatusOK)
	})
	defer serverB.Close()

	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Security: config.SecurityConfig{
			LimitAlertBucketClasses: map[string]config.LimitAlertBucketClassConfig{
				"vip-jwt":  {KeyType: "jwt_sub", BucketRegex: "^vip-", Priority: 10},
				"gold-jwt": {KeyType: "jwt_sub", BucketRegex: "^gold-", Priority: 7},
			},
			LimitAlertProfiles: map[string]config.LimitAlertRecipientProfile{
				"critical-only": {LimitClassDigestMinSeverity: "critical"},
				"warning-plus":  {LimitClassDigestMinSeverity: "warning"},
			},
			NotificationWebhooks: []config.NotificationWebhook{
				{URL: serverA.URL, Events: []string{"gateway.limit_class_alert_digest"}, LimitAlertProfile: "critical-only"},
				{URL: serverB.URL, Events: []string{"gateway.limit_class_alert_digest"}, LimitAlertProfile: "warning-plus"},
			},
		},
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
	}
	gw, err := gatewaypkg.NewGateway(gatewaypkg.Dependencies{Config: cfg, Logger: logging.NewLogger(false)}, "test")
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}
	route := cfg.Services[0].Services[0].Routes[0]
	route.ServiceName = "agent"
	now := time.Now().UTC()
	for _, bucket := range []string{"vip-a", "vip-b", "vip-c", "vip-d", "vip-e", "vip-f", "vip-g", "vip-h", "vip-i", "vip-j", "vip-k", "vip-l"} {
		gw.RecordRouteLimitHitForBucketTest(route, "concurrency_queue_full", "jwt_sub", bucket, 0, now.Add(-20*time.Second))
	}
	for _, bucket := range []string{"gold-a", "gold-b", "gold-c"} {
		gw.RecordRouteLimitHitForBucketTest(route, "concurrency_queue_full", "jwt_sub", bucket, 0, now.Add(-10*time.Second))
	}

	api := NewManagementAPI(gw, logging.NewLogger(false), nil)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/gateway/limit-class-alerts/notify?window=5m&min_count=3", nil)
	resp := httptest.NewRecorder()
	api.notifyGatewayLimitClassAlerts(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.Code, resp.Body.String())
	}
	if len(views) != 2 {
		t.Fatalf("expected two per-webhook severity-shaped digest views, got %d (%+v)", len(views), views)
	}
	if views[0].Count != 1 || views[0].SummarizedCount != 1 {
		t.Fatalf("expected critical-only receiver to keep only the critical class detailed, got %+v", views[0])
	}
	if views[1].Count != 2 || views[1].SummarizedCount != 0 {
		t.Fatalf("expected warning-plus receiver to keep both classes detailed, got %+v", views[1])
	}
}

func TestReconcileGatewayLimitClassAlertNotificationsEmitsLifecycleEvents(t *testing.T) {
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
		Security: config.SecurityConfig{
			LimitAlertBucketClasses: map[string]config.LimitAlertBucketClassConfig{
				"vip-jwt": {
					KeyType:     "jwt_sub",
					BucketRegex: "^vip-",
				},
			},
			MutationPolicy: config.MutationPolicy{
				LimitClassAlertNotifications: config.PolicyAlertNotificationPolicy{
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
						"gateway.limit_class_alert_opened",
						"gateway.limit_class_alert_stage_changed",
						"gateway.limit_class_alert_resolved",
					},
				},
			},
		},
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
	}
	gw, err := gatewaypkg.NewGateway(gatewaypkg.Dependencies{Config: cfg, Logger: logging.NewLogger(false)}, "test")
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}
	route := cfg.Services[0].Services[0].Routes[0]
	route.ServiceName = "agent"
	base := time.Now().UTC()
	gw.RecordRouteLimitHitForBucketTest(route, "concurrency_queue_full", "jwt_sub", "vip-a", 0, base.Add(-30*time.Second))
	gw.RecordRouteLimitHitForBucketTest(route, "concurrency_queue_full", "jwt_sub", "vip-b", 0, base.Add(-20*time.Second))
	gw.RecordRouteLimitHitForBucketTest(route, "concurrency_queue_full", "jwt_sub", "vip-c", 0, base.Add(-10*time.Second))

	api := NewManagementAPI(gw, logging.NewLogger(false), nil)
	api.reconcileGatewayLimitClassAlertNotifications(base)
	if len(received) != 1 || received[0].Event != "gateway.limit_class_alert_opened" || strings.TrimSpace(received[0].IncidentID) == "" || received[0].Severity != "elevated" {
		t.Fatalf("expected opened limit class incident event, got %+v", received)
	}
	incidentID := received[0].IncidentID

	for i := 0; i < 9; i++ {
		gw.RecordRouteLimitHitForBucketTest(route, "concurrency_queue_full", "jwt_sub", "vip-z", 0, base.Add(90*time.Second))
	}
	api.reconcileGatewayLimitClassAlertNotifications(base.Add(2 * time.Minute))
	if len(received) != 2 || received[1].Event != "gateway.limit_class_alert_stage_changed" || received[1].Previous != "elevated" || received[1].Severity != "critical" || received[1].IncidentID != incidentID {
		t.Fatalf("expected limit class alert stage change for same incident, got %+v", received)
	}

	api.reconcileGatewayLimitClassAlertNotifications(base.Add(10 * time.Minute))
	if len(received) != 3 || received[2].Event != "gateway.limit_class_alert_resolved" || received[2].IncidentID != incidentID {
		t.Fatalf("expected resolved limit class incident event, got %+v", received)
	}
}

func TestNotifyGatewayLimitClassAlertsHonorsWebhookClassFiltersAndCooldown(t *testing.T) {
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

	received := make([]string, 0, 6)
	server := newNotificationTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		var payload map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatalf("failed to decode webhook payload: %v", err)
		}
		data, _ := payload["data"].(map[string]interface{})
		received = append(received, strings.TrimSpace(fmt.Sprint(payload["event"]))+":"+strings.TrimSpace(fmt.Sprint(data["severity"]))+":"+strings.TrimSpace(fmt.Sprint(data["bucket_class"])))
		w.WriteHeader(http.StatusOK)
	})
	defer server.Close()

	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Security: config.SecurityConfig{
			LimitAlertBucketClasses: map[string]config.LimitAlertBucketClassConfig{
				"vip-jwt": {
					KeyType:     "jwt_sub",
					BucketRegex: "^vip-",
				},
			},
			NotificationWebhooks: []config.NotificationWebhook{
				{
					URL:                     server.URL,
					Events:                  []string{"gateway.limit_class_alert"},
					MinLimitAlertSeverity:   "elevated",
					LimitAlertBucketClasses: []string{"vip-jwt"},
					LimitAlertCooldown:      "30m",
				},
			},
		},
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
	}
	gw, err := gatewaypkg.NewGateway(gatewaypkg.Dependencies{Config: cfg, Logger: logging.NewLogger(false)}, "test")
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}
	route := cfg.Services[0].Services[0].Routes[0]
	route.ServiceName = "agent"
	now := time.Now().UTC()
	gw.RecordRouteLimitHitForBucketTest(route, "concurrency_queue_full", "jwt_sub", "vip-a", 0, now.Add(-4*time.Minute))
	gw.RecordRouteLimitHitForBucketTest(route, "concurrency_queue_full", "jwt_sub", "vip-b", 0, now.Add(-3*time.Minute))
	gw.RecordRouteLimitHitForBucketTest(route, "concurrency_queue_full", "jwt_sub", "vip-c", 0, now.Add(-2*time.Minute))

	api := NewManagementAPI(gw, logging.NewLogger(false), nil)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/gateway/limit-class-alerts/notify?window=5m&min_count=3", nil)
	resp := httptest.NewRecorder()
	api.notifyGatewayLimitClassAlerts(resp, req)

	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.Code, resp.Body.String())
	}
	if len(received) != 1 || received[0] != "gateway.limit_class_alert:elevated:vip-jwt" {
		t.Fatalf("expected one filtered class alert delivery, got %v", received)
	}

	resp = httptest.NewRecorder()
	api.notifyGatewayLimitClassAlerts(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200 on repeat notify, got %d: %s", resp.Code, resp.Body.String())
	}
	if len(received) != 1 {
		t.Fatalf("expected cooldown to suppress duplicate class alert, got %v", received)
	}

	for i := 0; i < 9; i++ {
		gw.RecordRouteLimitHitForBucketTest(route, "concurrency_queue_full", "jwt_sub", "vip-z", 0, now.Add(-30*time.Second))
	}
	resp = httptest.NewRecorder()
	api.notifyGatewayLimitClassAlerts(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200 on escalated notify, got %d: %s", resp.Code, resp.Body.String())
	}
	if len(received) != 2 || received[1] != "gateway.limit_class_alert:critical:vip-jwt" {
		t.Fatalf("expected critical class alert to break cooldown, got %v", received)
	}
}

func TestNotifyGatewayLimitClassAlertsHonorsWebhookClassPriorityFloor(t *testing.T) {
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

	received := make([]string, 0, 6)
	server := newNotificationTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		var payload map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatalf("failed to decode webhook payload: %v", err)
		}
		data, _ := payload["data"].(map[string]interface{})
		received = append(received,
			strings.TrimSpace(fmt.Sprint(payload["event"]))+":"+
				strings.TrimSpace(fmt.Sprint(data["bucket_class"]))+":"+
				strings.TrimSpace(fmt.Sprint(data["bucket_class_priority"])))
		w.WriteHeader(http.StatusOK)
	})
	defer server.Close()

	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Security: config.SecurityConfig{
			LimitAlertBucketClasses: map[string]config.LimitAlertBucketClassConfig{
				"vip-jwt": {
					KeyType:     "jwt_sub",
					BucketRegex: "^vip-",
					Priority:    10,
				},
				"standard-jwt": {
					KeyType:     "jwt_sub",
					BucketRegex: "^std-",
					Priority:    1,
				},
			},
			LimitAlertProfiles: map[string]config.LimitAlertRecipientProfile{
				"high-priority-only": {
					MinLimitAlertBucketClassPriority: 5,
				},
			},
			NotificationWebhooks: []config.NotificationWebhook{
				{
					URL:               server.URL,
					Events:            []string{"gateway.limit_class_alert"},
					LimitAlertProfile: "high-priority-only",
				},
			},
		},
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
	}
	gw, err := gatewaypkg.NewGateway(gatewaypkg.Dependencies{Config: cfg, Logger: logging.NewLogger(false)}, "test")
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}
	route := cfg.Services[0].Services[0].Routes[0]
	route.ServiceName = "agent"
	now := time.Now().UTC()
	for _, bucket := range []string{"vip-a", "vip-b", "vip-c"} {
		gw.RecordRouteLimitHitForBucketTest(route, "concurrency_queue_full", "jwt_sub", bucket, 0, now.Add(-2*time.Minute))
	}
	for _, bucket := range []string{"std-a", "std-b", "std-c"} {
		gw.RecordRouteLimitHitForBucketTest(route, "concurrency_queue_full", "jwt_sub", bucket, 0, now.Add(-90*time.Second))
	}

	api := NewManagementAPI(gw, logging.NewLogger(false), nil)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/gateway/limit-class-alerts/notify?window=5m&min_count=3", nil)
	resp := httptest.NewRecorder()
	api.notifyGatewayLimitClassAlerts(resp, req)

	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.Code, resp.Body.String())
	}
	if len(received) != 1 || received[0] != "gateway.limit_class_alert:vip-jwt:10" {
		t.Fatalf("expected only high-priority class alert delivery, got %v", received)
	}
}

func TestGetGatewayLimitClassIncidentsReturnsOpenIncidents(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Security: config.SecurityConfig{
			LimitAlertBucketClasses: map[string]config.LimitAlertBucketClassConfig{
				"vip-jwt": {
					KeyType:     "jwt_sub",
					BucketRegex: "^vip-",
				},
			},
			MutationPolicy: config.MutationPolicy{
				LimitClassAlertNotifications: config.PolicyAlertNotificationPolicy{
					Enabled:  true,
					Window:   "5m",
					MinCount: 3,
				},
			},
		},
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
	}
	gw, err := gatewaypkg.NewGateway(gatewaypkg.Dependencies{Config: cfg, Logger: logging.NewLogger(false)}, "test")
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}
	base := time.Now().UTC()

	api := NewManagementAPI(gw, logging.NewLogger(false), nil)
	api.updateGatewayLimitClassAlertIncidentState([]gatewaypkg.RouteLimitClassAlert{
		{
			Severity:            "elevated",
			ServiceName:         "agent",
			RoutePath:           "/ai/chat",
			LimitType:           "concurrency_queue_full",
			KeyType:             "jwt_sub",
			BucketClass:         "vip-jwt",
			Count:               3,
			QueueFullRejections: 3,
		},
	}, base)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/gateway/limit-class-incidents", nil)
	resp := httptest.NewRecorder()
	api.getGatewayLimitClassIncidents(resp, req)

	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.Code, resp.Body.String())
	}
	var payload struct {
		TotalIncidents int `json:"total_incidents"`
		Incidents      []struct {
			IncidentID         string  `json:"incident_id"`
			Severity           string  `json:"severity"`
			ServiceName        string  `json:"service_name"`
			RoutePath          string  `json:"route_path"`
			LimitType          string  `json:"limit_type"`
			KeyType            string  `json:"key_type"`
			BucketClass        string  `json:"bucket_class"`
			Count              int     `json:"count"`
			IncidentAgeSeconds float64 `json:"incident_age_seconds"`
		} `json:"incidents"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &payload); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if payload.TotalIncidents != 1 || len(payload.Incidents) != 1 {
		t.Fatalf("expected one open class incident, got %+v", payload)
	}
	incident := payload.Incidents[0]
	if strings.TrimSpace(incident.IncidentID) == "" || incident.Severity != "elevated" || incident.ServiceName != "agent" || incident.RoutePath != "/ai/chat" || incident.LimitType != "concurrency_queue_full" || incident.KeyType != "jwt_sub" || incident.BucketClass != "vip-jwt" || incident.Count != 3 || incident.IncidentAgeSeconds < 0 {
		t.Fatalf("unexpected class incident payload: %+v", incident)
	}
}

func TestGetGatewayLimitClassIncidentsSupportsFilters(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
	}
	gw, err := gatewaypkg.NewGateway(gatewaypkg.Dependencies{Config: cfg, Logger: logging.NewLogger(false)}, "test")
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}
	base := time.Now().UTC()

	api := NewManagementAPI(gw, logging.NewLogger(false), nil)
	api.updateGatewayLimitClassAlertIncidentState([]gatewaypkg.RouteLimitClassAlert{
		{
			Severity:            "critical",
			ServiceName:         "agent",
			RoutePath:           "/ai/chat",
			LimitType:           "concurrency_queue_full",
			KeyType:             "jwt_sub",
			BucketClass:         "vip-jwt",
			Count:               5,
			QueueFullRejections: 5,
		},
		{
			Severity:            "warning",
			ServiceName:         "search",
			RoutePath:           "/ai/search",
			LimitType:           "rate_limit",
			KeyType:             "api_key",
			BucketClass:         "standard-key",
			Count:               3,
			QueueFullRejections: 0,
		},
	}, base)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/gateway/limit-class-incidents?severity=critical&bucket_class=vip-jwt&limit_type=concurrency_queue_full", nil)
	resp := httptest.NewRecorder()
	api.getGatewayLimitClassIncidents(resp, req)

	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.Code, resp.Body.String())
	}
	var payload struct {
		TotalIncidents int `json:"total_incidents"`
		Incidents      []struct {
			Severity    string `json:"severity"`
			ServiceName string `json:"service_name"`
			RoutePath   string `json:"route_path"`
			LimitType   string `json:"limit_type"`
			KeyType     string `json:"key_type"`
			BucketClass string `json:"bucket_class"`
		} `json:"incidents"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &payload); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if payload.TotalIncidents != 1 || len(payload.Incidents) != 1 {
		t.Fatalf("expected exactly one filtered class incident, got %+v", payload)
	}
	incident := payload.Incidents[0]
	if incident.Severity != "critical" || incident.ServiceName != "agent" || incident.RoutePath != "/ai/chat" || incident.LimitType != "concurrency_queue_full" || incident.KeyType != "jwt_sub" || incident.BucketClass != "vip-jwt" {
		t.Fatalf("unexpected filtered class incident payload: %+v", incident)
	}
}

func TestAcknowledgeGatewayLimitClassIncidentUpdatesStateAndEmitsEvent(t *testing.T) {
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
		Event          string
		IncidentID     string
		AcknowledgedBy string
		Note           string
	}
	received := make([]webhookRecord, 0, 2)
	server := newNotificationTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		var payload map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatalf("failed to decode webhook payload: %v", err)
		}
		data, _ := payload["data"].(map[string]interface{})
		received = append(received, webhookRecord{
			Event:          strings.TrimSpace(fmt.Sprint(payload["event"])),
			IncidentID:     strings.TrimSpace(fmt.Sprint(data["incident_id"])),
			AcknowledgedBy: strings.TrimSpace(fmt.Sprint(data["acknowledged_by"])),
			Note:           strings.TrimSpace(fmt.Sprint(data["acknowledge_note"])),
		})
		w.WriteHeader(http.StatusOK)
	})
	defer server.Close()

	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Security: config.SecurityConfig{
			NotificationWebhooks: []config.NotificationWebhook{{
				URL:    server.URL,
				Events: []string{"gateway.limit_class_alert_acknowledged"},
			}},
		},
	}
	gw, err := gatewaypkg.NewGateway(gatewaypkg.Dependencies{Config: cfg, Logger: logging.NewLogger(false)}, "test")
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}
	base := time.Now().UTC()

	api := NewManagementAPI(gw, logging.NewLogger(false), nil)
	api.updateGatewayLimitClassAlertIncidentState([]gatewaypkg.RouteLimitClassAlert{{
		Severity:            "critical",
		ServiceName:         "agent",
		RoutePath:           "/ai/chat",
		LimitType:           "concurrency_queue_full",
		KeyType:             "jwt_sub",
		BucketClass:         "vip-jwt",
		Count:               5,
		QueueFullRejections: 5,
	}}, base)

	var incidentID string
	api.queueDigestNotifyMu.Lock()
	for _, state := range api.limitClassAlertIncidentState {
		incidentID = strings.TrimSpace(state.IncidentID)
		break
	}
	api.queueDigestNotifyMu.Unlock()
	if incidentID == "" {
		t.Fatalf("expected a created limit class incident id")
	}

	body := strings.NewReader(`{"reviewer":"ops-lead","note":"tracking under incident board"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/gateway/limit-class-incidents/"+incidentID+"/acknowledge", body)
	req = mux.SetURLVars(req, map[string]string{"id": incidentID})
	resp := httptest.NewRecorder()
	api.acknowledgeGatewayLimitClassIncident(resp, req)

	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.Code, resp.Body.String())
	}
	var payload struct {
		Success bool `json:"success"`
		Data    struct {
			IncidentID      string `json:"incident_id"`
			Acknowledged    bool   `json:"acknowledged"`
			AcknowledgedBy  string `json:"acknowledged_by"`
			AcknowledgeNote string `json:"acknowledge_note"`
		} `json:"data"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &payload); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if !payload.Success || payload.Data.IncidentID != incidentID || !payload.Data.Acknowledged || payload.Data.AcknowledgedBy != "ops-lead" || payload.Data.AcknowledgeNote != "tracking under incident board" {
		t.Fatalf("unexpected acknowledge response payload: %+v", payload)
	}
	api.queueDigestNotifyMu.Lock()
	found := false
	for _, state := range api.limitClassAlertIncidentState {
		if strings.TrimSpace(state.IncidentID) != incidentID {
			continue
		}
		found = true
		if state.AcknowledgedAt.IsZero() || state.AcknowledgedBy != "ops-lead" || state.AcknowledgeNote != "tracking under incident board" {
			t.Fatalf("unexpected acknowledged state: %+v", state)
		}
	}
	api.queueDigestNotifyMu.Unlock()
	if !found {
		t.Fatalf("expected acknowledged incident to remain open in state")
	}
	if len(received) != 1 || received[0].Event != "gateway.limit_class_alert_acknowledged" || received[0].IncidentID != incidentID || received[0].AcknowledgedBy != "ops-lead" || received[0].Note != "tracking under incident board" {
		t.Fatalf("unexpected acknowledgement webhook payloads: %+v", received)
	}
}

func TestSnoozeGatewayLimitClassIncidentUpdatesStateAndSuppressesNotify(t *testing.T) {
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
		SnoozedBy  string
	}
	received := make([]webhookRecord, 0, 4)
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
			SnoozedBy:  strings.TrimSpace(fmt.Sprint(data["snoozed_by"])),
		})
		w.WriteHeader(http.StatusOK)
	})
	defer server.Close()

	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Security: config.SecurityConfig{
			LimitAlertBucketClasses: map[string]config.LimitAlertBucketClassConfig{
				"vip-jwt": {
					KeyType:     "jwt_sub",
					BucketRegex: "^vip-",
				},
			},
			NotificationWebhooks: []config.NotificationWebhook{{
				URL: server.URL,
				Events: []string{
					"gateway.limit_class_alert_snoozed",
					"gateway.limit_class_alert_digest",
					"gateway.limit_class_alert",
				},
			}},
		},
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
	}
	gw, err := gatewaypkg.NewGateway(gatewaypkg.Dependencies{Config: cfg, Logger: logging.NewLogger(false)}, "test")
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}
	route := cfg.Services[0].Services[0].Routes[0]
	route.ServiceName = "agent"
	base := time.Now().UTC()
	gw.RecordRouteLimitHitForBucketTest(route, "concurrency_queue_full", "jwt_sub", "vip-a", 0, base.Add(-30*time.Second))
	gw.RecordRouteLimitHitForBucketTest(route, "concurrency_queue_full", "jwt_sub", "vip-b", 0, base.Add(-20*time.Second))
	gw.RecordRouteLimitHitForBucketTest(route, "concurrency_queue_full", "jwt_sub", "vip-c", 0, base.Add(-10*time.Second))

	api := NewManagementAPI(gw, logging.NewLogger(false), nil)
	summary := gw.RouteLimitClassAlertSummaryAt(base, 5*time.Minute, 3)
	api.updateGatewayLimitClassAlertIncidentState(summary.Alerts, base)

	var incidentID string
	api.queueDigestNotifyMu.Lock()
	for _, state := range api.limitClassAlertIncidentState {
		incidentID = strings.TrimSpace(state.IncidentID)
		break
	}
	api.queueDigestNotifyMu.Unlock()
	if incidentID == "" {
		t.Fatalf("expected a created limit class incident id")
	}

	body := strings.NewReader(`{"reviewer":"ops-lead","duration":"15m","note":"muting repeated alerts during active mitigation"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/gateway/limit-class-incidents/"+incidentID+"/snooze", body)
	req = mux.SetURLVars(req, map[string]string{"id": incidentID})
	resp := httptest.NewRecorder()
	api.snoozeGatewayLimitClassIncident(resp, req)

	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.Code, resp.Body.String())
	}
	var snoozePayload struct {
		Success bool `json:"success"`
		Data    struct {
			IncidentID string `json:"incident_id"`
			Snoozed    bool   `json:"snoozed"`
			SnoozedBy  string `json:"snoozed_by"`
			SnoozeNote string `json:"snooze_note"`
		} `json:"data"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &snoozePayload); err != nil {
		t.Fatalf("failed to decode snooze response: %v", err)
	}
	if !snoozePayload.Success || snoozePayload.Data.IncidentID != incidentID || !snoozePayload.Data.Snoozed || snoozePayload.Data.SnoozedBy != "ops-lead" || snoozePayload.Data.SnoozeNote != "muting repeated alerts during active mitigation" {
		t.Fatalf("unexpected snooze response payload: %+v", snoozePayload)
	}

	received = received[:0]
	notifyReq := httptest.NewRequest(http.MethodPost, "/api/v1/gateway/limit-class-alerts/notify", nil)
	notifyResp := httptest.NewRecorder()
	api.notifyGatewayLimitClassAlerts(notifyResp, notifyReq)

	if notifyResp.Code != http.StatusOK {
		t.Fatalf("expected 200 from notify, got %d: %s", notifyResp.Code, notifyResp.Body.String())
	}
	var notifyPayload struct {
		TotalAlerts      int `json:"total_alerts"`
		DigestDeliveries int `json:"digest_deliveries"`
		AlertDeliveries  int `json:"alert_deliveries"`
	}
	if err := json.Unmarshal(notifyResp.Body.Bytes(), &notifyPayload); err != nil {
		t.Fatalf("failed to decode notify response: %v", err)
	}
	if notifyPayload.TotalAlerts != 0 || notifyPayload.DigestDeliveries != 0 || notifyPayload.AlertDeliveries != 0 {
		t.Fatalf("expected snoozed incident to suppress class alert notifications, got %+v", notifyPayload)
	}
	if len(received) != 0 {
		t.Fatalf("expected no class alert webhooks while snoozed, got %+v", received)
	}
}

func TestGetGatewayLimitClassSnoozesSupportsExpiringWithinFilter(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
	}
	gw, err := gatewaypkg.NewGateway(gatewaypkg.Dependencies{Config: cfg, Logger: logging.NewLogger(false)}, "test")
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}
	base := time.Now().UTC()

	api := NewManagementAPI(gw, logging.NewLogger(false), nil)
	api.updateGatewayLimitClassAlertIncidentState([]gatewaypkg.RouteLimitClassAlert{
		{
			Severity:            "critical",
			ServiceName:         "agent",
			RoutePath:           "/ai/chat",
			LimitType:           "concurrency_queue_full",
			KeyType:             "jwt_sub",
			BucketClass:         "vip-jwt",
			Count:               5,
			QueueFullRejections: 5,
		},
		{
			Severity:            "warning",
			ServiceName:         "search",
			RoutePath:           "/ai/search",
			LimitType:           "rate_limit",
			KeyType:             "api_key",
			BucketClass:         "standard-key",
			Count:               3,
			QueueFullRejections: 0,
		},
	}, base)

	api.queueDigestNotifyMu.Lock()
	for key, state := range api.limitClassAlertIncidentState {
		switch strings.TrimSpace(state.BucketClass) {
		case "vip-jwt":
			state.SnoozedUntil = base.Add(10 * time.Minute)
			state.SnoozedBy = "ops-lead"
			state.SnoozeNote = "vip mitigation"
		case "standard-key":
			state.SnoozedUntil = base.Add(45 * time.Minute)
			state.SnoozedBy = "ops-bot"
			state.SnoozeNote = "lower priority monitoring"
		}
		api.limitClassAlertIncidentState[key] = state
	}
	api.queueDigestNotifyMu.Unlock()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/gateway/limit-class-snoozes?expiring_within=15m", nil)
	resp := httptest.NewRecorder()
	api.getGatewayLimitClassSnoozes(resp, req)

	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.Code, resp.Body.String())
	}
	var payload struct {
		TotalSnoozes   int    `json:"total_snoozes"`
		ExpiringWithin string `json:"expiring_within"`
		Snoozes        []struct {
			BucketClass            string  `json:"bucket_class"`
			SnoozedBy              string  `json:"snoozed_by"`
			SnoozeNote             string  `json:"snooze_note"`
			RemainingSnoozeSeconds float64 `json:"remaining_snooze_seconds"`
			ExpiringSoon           bool    `json:"expiring_soon"`
		} `json:"snoozes"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &payload); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if payload.TotalSnoozes != 1 || payload.ExpiringWithin != "15m" || len(payload.Snoozes) != 1 {
		t.Fatalf("expected one expiring-soon snooze, got %+v", payload)
	}
	snooze := payload.Snoozes[0]
	if snooze.BucketClass != "vip-jwt" || snooze.SnoozedBy != "ops-lead" || snooze.SnoozeNote != "vip mitigation" || !snooze.ExpiringSoon || snooze.RemainingSnoozeSeconds <= 0 {
		t.Fatalf("unexpected snooze payload: %+v", snooze)
	}
}

func TestNotifyGatewayLimitClassSnoozesEmitsExpiryEvents(t *testing.T) {
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
			t.Fatalf("failed to decode webhook payload: %v", err)
		}
		received = append(received, strings.TrimSpace(fmt.Sprint(payload["event"])))
		w.WriteHeader(http.StatusOK)
	})
	defer server.Close()

	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Security: config.SecurityConfig{
			NotificationWebhooks: []config.NotificationWebhook{{
				URL: server.URL,
				Events: []string{
					"gateway.limit_class_snooze_expiring_digest",
					"gateway.limit_class_snooze_expiring",
				},
			}},
		},
	}
	gw, err := gatewaypkg.NewGateway(gatewaypkg.Dependencies{Config: cfg, Logger: logging.NewLogger(false)}, "test")
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}
	base := time.Now().UTC()

	api := NewManagementAPI(gw, logging.NewLogger(false), nil)
	api.updateGatewayLimitClassAlertIncidentState([]gatewaypkg.RouteLimitClassAlert{{
		Severity:            "critical",
		ServiceName:         "agent",
		RoutePath:           "/ai/chat",
		LimitType:           "concurrency_queue_full",
		KeyType:             "jwt_sub",
		BucketClass:         "vip-jwt",
		Count:               5,
		QueueFullRejections: 5,
	}}, base)
	api.queueDigestNotifyMu.Lock()
	for key, state := range api.limitClassAlertIncidentState {
		state.SnoozedUntil = base.Add(10 * time.Minute)
		state.SnoozedBy = "ops-lead"
		api.limitClassAlertIncidentState[key] = state
	}
	api.queueDigestNotifyMu.Unlock()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/gateway/limit-class-snoozes/notify?expiring_within=15m", nil)
	resp := httptest.NewRecorder()
	api.notifyGatewayLimitClassSnoozes(resp, req)

	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.Code, resp.Body.String())
	}
	var payload struct {
		TotalSnoozes     int `json:"total_snoozes"`
		DigestDeliveries int `json:"digest_deliveries"`
		SnoozeDeliveries int `json:"snooze_deliveries"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &payload); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if payload.TotalSnoozes != 1 || payload.DigestDeliveries != 1 || payload.SnoozeDeliveries != 1 {
		t.Fatalf("unexpected snooze notify payload: %+v", payload)
	}
	if len(received) != 2 || received[0] != "gateway.limit_class_snooze_expiring_digest" || received[1] != "gateway.limit_class_snooze_expiring" {
		t.Fatalf("expected snooze expiry digest and per-snooze events, got %v", received)
	}
}

func TestNotifyGatewayLimitClassSnoozesHonorsWebhookCooldown(t *testing.T) {
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
			t.Fatalf("failed to decode webhook payload: %v", err)
		}
		received = append(received, strings.TrimSpace(fmt.Sprint(payload["event"])))
		w.WriteHeader(http.StatusOK)
	})
	defer server.Close()

	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Security: config.SecurityConfig{
			NotificationWebhooks: []config.NotificationWebhook{{
				URL:                            server.URL,
				Events:                         []string{"gateway.limit_class_snooze_expiring"},
				LimitClassSnoozeExpiryCooldown: "30m",
			}},
		},
	}
	gw, err := gatewaypkg.NewGateway(gatewaypkg.Dependencies{Config: cfg, Logger: logging.NewLogger(false)}, "test")
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}
	base := time.Now().UTC()

	api := NewManagementAPI(gw, logging.NewLogger(false), nil)
	api.updateGatewayLimitClassAlertIncidentState([]gatewaypkg.RouteLimitClassAlert{{
		Severity:            "critical",
		ServiceName:         "agent",
		RoutePath:           "/ai/chat",
		LimitType:           "concurrency_queue_full",
		KeyType:             "jwt_sub",
		BucketClass:         "vip-jwt",
		Count:               5,
		QueueFullRejections: 5,
	}}, base)
	api.queueDigestNotifyMu.Lock()
	for key, state := range api.limitClassAlertIncidentState {
		state.SnoozedUntil = base.Add(10 * time.Minute)
		state.SnoozedBy = "ops-lead"
		api.limitClassAlertIncidentState[key] = state
	}
	api.queueDigestNotifyMu.Unlock()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/gateway/limit-class-snoozes/notify?expiring_within=15m", nil)
	resp := httptest.NewRecorder()
	api.notifyGatewayLimitClassSnoozes(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.Code, resp.Body.String())
	}
	if len(received) != 1 || received[0] != "gateway.limit_class_snooze_expiring" {
		t.Fatalf("expected first snooze expiry delivery, got %v", received)
	}

	resp = httptest.NewRecorder()
	api.notifyGatewayLimitClassSnoozes(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200 on second notify, got %d: %s", resp.Code, resp.Body.String())
	}
	if len(received) != 1 {
		t.Fatalf("expected webhook cooldown to suppress duplicate snooze expiry delivery, got %v", received)
	}
}

func TestNotifyGatewayLimitClassSnoozesHonorsWebhookRemainingThreshold(t *testing.T) {
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
			t.Fatalf("failed to decode webhook payload: %v", err)
		}
		received = append(received, strings.TrimSpace(fmt.Sprint(payload["event"])))
		w.WriteHeader(http.StatusOK)
	})
	defer server.Close()

	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Security: config.SecurityConfig{
			NotificationWebhooks: []config.NotificationWebhook{{
				URL:                          server.URL,
				Events:                       []string{"gateway.limit_class_snooze_expiring"},
				LimitClassSnoozeExpiryWithin: "5m",
			}},
		},
	}
	gw, err := gatewaypkg.NewGateway(gatewaypkg.Dependencies{Config: cfg, Logger: logging.NewLogger(false)}, "test")
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}
	base := time.Now().UTC()

	api := NewManagementAPI(gw, logging.NewLogger(false), nil)
	api.updateGatewayLimitClassAlertIncidentState([]gatewaypkg.RouteLimitClassAlert{{
		Severity:            "critical",
		ServiceName:         "agent",
		RoutePath:           "/ai/chat",
		LimitType:           "concurrency_queue_full",
		KeyType:             "jwt_sub",
		BucketClass:         "vip-jwt",
		Count:               5,
		QueueFullRejections: 5,
	}}, base)
	api.queueDigestNotifyMu.Lock()
	for key, state := range api.limitClassAlertIncidentState {
		state.SnoozedUntil = base.Add(10 * time.Minute)
		state.SnoozedBy = "ops-lead"
		api.limitClassAlertIncidentState[key] = state
	}
	api.queueDigestNotifyMu.Unlock()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/gateway/limit-class-snoozes/notify?expiring_within=15m", nil)
	resp := httptest.NewRecorder()
	api.notifyGatewayLimitClassSnoozes(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.Code, resp.Body.String())
	}
	if len(received) != 0 {
		t.Fatalf("expected webhook remaining threshold to suppress 10m snooze expiry warning, got %v", received)
	}

	api.queueDigestNotifyMu.Lock()
	for key, state := range api.limitClassAlertIncidentState {
		state.SnoozedUntil = base.Add(4 * time.Minute)
		api.limitClassAlertIncidentState[key] = state
	}
	api.queueDigestNotifyMu.Unlock()

	resp = httptest.NewRecorder()
	api.notifyGatewayLimitClassSnoozes(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200 on second notify, got %d: %s", resp.Code, resp.Body.String())
	}
	if len(received) != 1 || received[0] != "gateway.limit_class_snooze_expiring" {
		t.Fatalf("expected 4m remaining snooze to satisfy webhook threshold, got %v", received)
	}
}

func TestNotifyGatewayLimitClassSnoozesHonorsWebhookSeverityFloor(t *testing.T) {
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
			t.Fatalf("failed to decode webhook payload: %v", err)
		}
		received = append(received, strings.TrimSpace(fmt.Sprint(payload["event"]))+":"+strings.TrimSpace(fmt.Sprint(payload["data"].(map[string]interface{})["severity"])))
		w.WriteHeader(http.StatusOK)
	})
	defer server.Close()

	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Security: config.SecurityConfig{
			NotificationWebhooks: []config.NotificationWebhook{{
				URL:                   server.URL,
				Events:                []string{"gateway.limit_class_snooze_expiring"},
				MinLimitAlertSeverity: "critical",
			}},
		},
	}
	gw, err := gatewaypkg.NewGateway(gatewaypkg.Dependencies{Config: cfg, Logger: logging.NewLogger(false)}, "test")
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}
	base := time.Now().UTC()

	api := NewManagementAPI(gw, logging.NewLogger(false), nil)
	api.updateGatewayLimitClassAlertIncidentState([]gatewaypkg.RouteLimitClassAlert{{
		Severity:            "critical",
		ServiceName:         "agent",
		RoutePath:           "/ai/chat",
		LimitType:           "concurrency_queue_full",
		KeyType:             "jwt_sub",
		BucketClass:         "vip-jwt",
		Count:               5,
		QueueFullRejections: 5,
	}}, base)
	api.queueDigestNotifyMu.Lock()
	for key, state := range api.limitClassAlertIncidentState {
		state.SnoozedUntil = base.Add(10 * time.Minute)
		state.SnoozedBy = "ops-lead"
		api.limitClassAlertIncidentState[key] = state
	}
	api.queueDigestNotifyMu.Unlock()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/gateway/limit-class-snoozes/notify?expiring_within=15m", nil)
	resp := httptest.NewRecorder()
	api.notifyGatewayLimitClassSnoozes(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.Code, resp.Body.String())
	}
	if len(received) != 0 {
		t.Fatalf("expected critical floor to suppress elevated 10m snooze warning, got %v", received)
	}

	api.queueDigestNotifyMu.Lock()
	for key, state := range api.limitClassAlertIncidentState {
		state.SnoozedUntil = base.Add(4 * time.Minute)
		api.limitClassAlertIncidentState[key] = state
	}
	api.queueDigestNotifyMu.Unlock()

	resp = httptest.NewRecorder()
	api.notifyGatewayLimitClassSnoozes(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200 on second notify, got %d: %s", resp.Code, resp.Body.String())
	}
	if len(received) != 1 || received[0] != "gateway.limit_class_snooze_expiring:critical" {
		t.Fatalf("expected 4m remaining snooze to emit critical wake-up warning, got %v", received)
	}
}

func TestNotifyGatewayLimitClassSnoozesHonorsWebhookStageFilter(t *testing.T) {
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
			t.Fatalf("failed to decode webhook payload: %v", err)
		}
		data, _ := payload["data"].(map[string]interface{})
		received = append(received, strings.TrimSpace(fmt.Sprint(payload["event"]))+":"+strings.TrimSpace(fmt.Sprint(data["snooze_stage"])))
		w.WriteHeader(http.StatusOK)
	})
	defer server.Close()

	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Security: config.SecurityConfig{
			NotificationWebhooks: []config.NotificationWebhook{{
				URL:                          server.URL,
				Events:                       []string{"gateway.limit_class_snooze_expiring"},
				LimitClassSnoozeExpiryStages: []string{"critical"},
			}},
		},
	}
	gw, err := gatewaypkg.NewGateway(gatewaypkg.Dependencies{Config: cfg, Logger: logging.NewLogger(false)}, "test")
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}
	base := time.Now().UTC()

	api := NewManagementAPI(gw, logging.NewLogger(false), nil)
	api.updateGatewayLimitClassAlertIncidentState([]gatewaypkg.RouteLimitClassAlert{{
		Severity:            "critical",
		ServiceName:         "agent",
		RoutePath:           "/ai/chat",
		LimitType:           "concurrency_queue_full",
		KeyType:             "jwt_sub",
		BucketClass:         "vip-jwt",
		Count:               5,
		QueueFullRejections: 5,
	}}, base)
	api.queueDigestNotifyMu.Lock()
	for key, state := range api.limitClassAlertIncidentState {
		state.SnoozedUntil = base.Add(10 * time.Minute)
		state.SnoozedBy = "ops-lead"
		api.limitClassAlertIncidentState[key] = state
	}
	api.queueDigestNotifyMu.Unlock()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/gateway/limit-class-snoozes/notify?expiring_within=15m", nil)
	resp := httptest.NewRecorder()
	api.notifyGatewayLimitClassSnoozes(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.Code, resp.Body.String())
	}
	if len(received) != 0 {
		t.Fatalf("expected critical stage filter to suppress elevated 10m snooze warning, got %v", received)
	}

	api.queueDigestNotifyMu.Lock()
	for key, state := range api.limitClassAlertIncidentState {
		state.SnoozedUntil = base.Add(4 * time.Minute)
		api.limitClassAlertIncidentState[key] = state
	}
	api.queueDigestNotifyMu.Unlock()

	resp = httptest.NewRecorder()
	api.notifyGatewayLimitClassSnoozes(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200 on second notify, got %d: %s", resp.Code, resp.Body.String())
	}
	if len(received) != 1 || received[0] != "gateway.limit_class_snooze_expiring:critical" {
		t.Fatalf("expected 4m remaining snooze to satisfy critical stage filter, got %v", received)
	}
}

func TestNotifyGatewayLimitClassSnoozesUsesConfiguredStageThresholds(t *testing.T) {
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
			t.Fatalf("failed to decode webhook payload: %v", err)
		}
		data, _ := payload["data"].(map[string]interface{})
		received = append(received, strings.TrimSpace(fmt.Sprint(payload["event"]))+":"+strings.TrimSpace(fmt.Sprint(data["snooze_stage"])))
		w.WriteHeader(http.StatusOK)
	})
	defer server.Close()

	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Security: config.SecurityConfig{
			NotificationWebhooks: []config.NotificationWebhook{{
				URL:                          server.URL,
				Events:                       []string{"gateway.limit_class_snooze_expiring"},
				LimitClassSnoozeExpiryStages: []string{"critical"},
			}},
			MutationPolicy: config.MutationPolicy{
				LimitClassSnoozeNotifications: config.PolicyAlertNotificationPolicy{
					SnoozeElevatedWithin: "20m",
					SnoozeCriticalWithin: "12m",
				},
			},
		},
	}
	gw, err := gatewaypkg.NewGateway(gatewaypkg.Dependencies{Config: cfg, Logger: logging.NewLogger(false)}, "test")
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}
	base := time.Now().UTC()

	api := NewManagementAPI(gw, logging.NewLogger(false), nil)
	api.updateGatewayLimitClassAlertIncidentState([]gatewaypkg.RouteLimitClassAlert{{
		Severity:            "critical",
		ServiceName:         "agent",
		RoutePath:           "/ai/chat",
		LimitType:           "concurrency_queue_full",
		KeyType:             "jwt_sub",
		BucketClass:         "vip-jwt",
		Count:               5,
		QueueFullRejections: 5,
	}}, base)
	api.queueDigestNotifyMu.Lock()
	for key, state := range api.limitClassAlertIncidentState {
		state.SnoozedUntil = base.Add(10 * time.Minute)
		state.SnoozedBy = "ops-lead"
		api.limitClassAlertIncidentState[key] = state
	}
	api.queueDigestNotifyMu.Unlock()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/gateway/limit-class-snoozes/notify?expiring_within=15m", nil)
	resp := httptest.NewRecorder()
	api.notifyGatewayLimitClassSnoozes(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.Code, resp.Body.String())
	}
	if len(received) != 1 || received[0] != "gateway.limit_class_snooze_expiring:critical" {
		t.Fatalf("expected configured 12m critical threshold to classify 10m remaining snooze as critical, got %v", received)
	}
}

func TestNotifyGatewayLimitClassSnoozesUsesBucketClassStageThresholds(t *testing.T) {
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
			t.Fatalf("failed to decode webhook payload: %v", err)
		}
		data, _ := payload["data"].(map[string]interface{})
		received = append(received, strings.TrimSpace(fmt.Sprint(payload["event"]))+":"+strings.TrimSpace(fmt.Sprint(data["snooze_stage"])))
		w.WriteHeader(http.StatusOK)
	})
	defer server.Close()

	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Security: config.SecurityConfig{
			LimitAlertBucketClasses: map[string]config.LimitAlertBucketClassConfig{
				"vip-jwt": {
					KeyType:              "jwt_sub",
					BucketRegex:          "^vip-",
					SnoozeElevatedWithin: "20m",
					SnoozeCriticalWithin: "12m",
				},
			},
			NotificationWebhooks: []config.NotificationWebhook{{
				URL:                          server.URL,
				Events:                       []string{"gateway.limit_class_snooze_expiring"},
				LimitClassSnoozeExpiryStages: []string{"critical"},
			}},
			MutationPolicy: config.MutationPolicy{
				LimitClassSnoozeNotifications: config.PolicyAlertNotificationPolicy{
					SnoozeElevatedWithin: "15m",
					SnoozeCriticalWithin: "5m",
				},
			},
		},
	}
	gw, err := gatewaypkg.NewGateway(gatewaypkg.Dependencies{Config: cfg, Logger: logging.NewLogger(false)}, "test")
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}
	base := time.Now().UTC()

	api := NewManagementAPI(gw, logging.NewLogger(false), nil)
	api.updateGatewayLimitClassAlertIncidentState([]gatewaypkg.RouteLimitClassAlert{{
		Severity:            "critical",
		ServiceName:         "agent",
		RoutePath:           "/ai/chat",
		LimitType:           "concurrency_queue_full",
		KeyType:             "jwt_sub",
		BucketClass:         "vip-jwt",
		Count:               5,
		QueueFullRejections: 5,
	}}, base)
	api.queueDigestNotifyMu.Lock()
	for key, state := range api.limitClassAlertIncidentState {
		state.SnoozedUntil = base.Add(10 * time.Minute)
		state.SnoozedBy = "ops-lead"
		api.limitClassAlertIncidentState[key] = state
	}
	api.queueDigestNotifyMu.Unlock()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/gateway/limit-class-snoozes/notify?expiring_within=15m", nil)
	resp := httptest.NewRecorder()
	api.notifyGatewayLimitClassSnoozes(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.Code, resp.Body.String())
	}
	if len(received) != 1 || received[0] != "gateway.limit_class_snooze_expiring:critical" {
		t.Fatalf("expected bucket class thresholds to classify 10m remaining snooze as critical, got %v", received)
	}
}

func TestReconcileGatewayLimitClassSnoozeNotificationsAutoEmitsAndHonorsOnlyOnChange(t *testing.T) {
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
		Security: config.SecurityConfig{
			NotificationWebhooks: []config.NotificationWebhook{{
				URL: server.URL,
				Events: []string{
					"gateway.limit_class_snooze_expiring_digest",
					"gateway.limit_class_snooze_expiring",
				},
			}},
			MutationPolicy: config.MutationPolicy{
				LimitClassSnoozeNotifications: config.PolicyAlertNotificationPolicy{
					Enabled:                 true,
					Interval:                "1m",
					MinNotificationInterval: "1m",
					OnlyOnChange:            true,
					Window:                  "15m",
				},
			},
		},
	}
	gw, err := gatewaypkg.NewGateway(gatewaypkg.Dependencies{Config: cfg, Logger: logging.NewLogger(false)}, "test")
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}
	base := time.Now().UTC()

	api := NewManagementAPI(gw, logging.NewLogger(false), nil)
	api.updateGatewayLimitClassAlertIncidentState([]gatewaypkg.RouteLimitClassAlert{{
		Severity:            "critical",
		ServiceName:         "agent",
		RoutePath:           "/ai/chat",
		LimitType:           "concurrency_queue_full",
		KeyType:             "jwt_sub",
		BucketClass:         "vip-jwt",
		Count:               5,
		QueueFullRejections: 5,
	}}, base)
	api.queueDigestNotifyMu.Lock()
	for key, state := range api.limitClassAlertIncidentState {
		state.SnoozedUntil = base.Add(10 * time.Minute)
		state.SnoozedBy = "ops-lead"
		api.limitClassAlertIncidentState[key] = state
	}
	api.queueDigestNotifyMu.Unlock()

	api.reconcileGatewayLimitClassSnoozeNotifications(base)
	if len(receivedEvents) != 2 {
		t.Fatalf("expected digest plus one snooze expiry event, got %d (%v)", len(receivedEvents), receivedEvents)
	}

	api.queueDigestNotifyMu.Lock()
	api.lastLimitClassSnoozeNotificationAt = base
	api.queueDigestNotifyMu.Unlock()
	api.reconcileGatewayLimitClassSnoozeNotifications(base.Add(30 * time.Second))
	if len(receivedEvents) != 2 {
		t.Fatalf("expected min interval to suppress duplicate snooze expiry notifications, got %d (%v)", len(receivedEvents), receivedEvents)
	}

	api.queueDigestNotifyMu.Lock()
	api.lastLimitClassSnoozeNotificationAt = base.Add(-2 * time.Minute)
	api.queueDigestNotifyMu.Unlock()
	api.reconcileGatewayLimitClassSnoozeNotifications(base.Add(2 * time.Minute))
	if len(receivedEvents) != 2 {
		t.Fatalf("expected unchanged snooze expiry checksum to suppress duplicate notifications, got %d (%v)", len(receivedEvents), receivedEvents)
	}
}

func TestReconcileGatewayLimitClassSnoozeNotificationsEmitsStageChanged(t *testing.T) {
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

	type receivedEvent struct {
		Event       string
		Previous    string
		Current     string
		IncidentID  string
		SnoozeStage string
	}
	received := make([]receivedEvent, 0, 8)
	server := newNotificationTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		var payload map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatalf("failed to decode webhook payload: %v", err)
		}
		data, _ := payload["data"].(map[string]interface{})
		received = append(received, receivedEvent{
			Event:       strings.TrimSpace(fmt.Sprint(payload["event"])),
			Previous:    strings.TrimSpace(fmt.Sprint(data["previous_stage"])),
			Current:     strings.TrimSpace(fmt.Sprint(data["current_stage"])),
			IncidentID:  strings.TrimSpace(fmt.Sprint(data["incident_id"])),
			SnoozeStage: strings.TrimSpace(fmt.Sprint(data["snooze_stage"])),
		})
		w.WriteHeader(http.StatusOK)
	})
	defer server.Close()

	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Security: config.SecurityConfig{
			NotificationWebhooks: []config.NotificationWebhook{{
				URL:    server.URL,
				Events: []string{"gateway.limit_class_snooze_expiring", "gateway.limit_class_snooze_stage_changed"},
			}},
			MutationPolicy: config.MutationPolicy{
				LimitClassSnoozeNotifications: config.PolicyAlertNotificationPolicy{
					Enabled:                 true,
					Interval:                "1m",
					MinNotificationInterval: "1m",
					Window:                  "15m",
					SnoozeElevatedWithin:    "15m",
					SnoozeCriticalWithin:    "5m",
				},
			},
		},
	}
	gw, err := gatewaypkg.NewGateway(gatewaypkg.Dependencies{Config: cfg, Logger: logging.NewLogger(false)}, "test")
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}
	base := time.Now().UTC()

	api := NewManagementAPI(gw, logging.NewLogger(false), nil)
	api.updateGatewayLimitClassAlertIncidentState([]gatewaypkg.RouteLimitClassAlert{{
		Severity:            "critical",
		ServiceName:         "agent",
		RoutePath:           "/ai/chat",
		LimitType:           "concurrency_queue_full",
		KeyType:             "jwt_sub",
		BucketClass:         "vip-jwt",
		Count:               5,
		QueueFullRejections: 5,
	}}, base)
	api.queueDigestNotifyMu.Lock()
	for key, state := range api.limitClassAlertIncidentState {
		state.SnoozedUntil = base.Add(10 * time.Minute)
		state.SnoozedBy = "ops-lead"
		api.limitClassAlertIncidentState[key] = state
	}
	api.queueDigestNotifyMu.Unlock()

	api.reconcileGatewayLimitClassSnoozeNotifications(base)
	if len(received) != 1 || received[0].Event != "gateway.limit_class_snooze_expiring" || received[0].SnoozeStage != "elevated" {
		t.Fatalf("expected initial elevated snooze expiry event, got %+v", received)
	}

	api.reconcileGatewayLimitClassSnoozeNotifications(base.Add(6 * time.Minute))
	if len(received) != 3 {
		t.Fatalf("expected second expiry plus stage-changed event, got %d (%+v)", len(received), received)
	}
	stageChanged := received[2]
	if stageChanged.Event != "gateway.limit_class_snooze_stage_changed" || stageChanged.Previous != "elevated" || stageChanged.Current != "critical" || stageChanged.SnoozeStage != "critical" || stageChanged.IncidentID == "" {
		t.Fatalf("expected elevated->critical snooze stage change event, got %+v", stageChanged)
	}
}

func TestReconcileGatewayLimitClassSnoozeNotificationsEmitsResumed(t *testing.T) {
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

	type receivedEvent struct {
		Event       string
		Previous    string
		Current     string
		IncidentID  string
		SnoozeStage string
	}
	received := make([]receivedEvent, 0, 8)
	server := newNotificationTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		var payload map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatalf("failed to decode webhook payload: %v", err)
		}
		data, _ := payload["data"].(map[string]interface{})
		received = append(received, receivedEvent{
			Event:       strings.TrimSpace(fmt.Sprint(payload["event"])),
			Previous:    strings.TrimSpace(fmt.Sprint(data["previous_stage"])),
			Current:     strings.TrimSpace(fmt.Sprint(data["current_stage"])),
			IncidentID:  strings.TrimSpace(fmt.Sprint(data["incident_id"])),
			SnoozeStage: strings.TrimSpace(fmt.Sprint(data["snooze_stage"])),
		})
		w.WriteHeader(http.StatusOK)
	})
	defer server.Close()

	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Security: config.SecurityConfig{
			NotificationWebhooks: []config.NotificationWebhook{{
				URL:    server.URL,
				Events: []string{"gateway.limit_class_snooze_expiring", "gateway.limit_class_snooze_resumed"},
			}},
			MutationPolicy: config.MutationPolicy{
				LimitClassSnoozeNotifications: config.PolicyAlertNotificationPolicy{
					Enabled:                 true,
					Interval:                "1m",
					MinNotificationInterval: "1m",
					Window:                  "15m",
					SnoozeElevatedWithin:    "15m",
					SnoozeCriticalWithin:    "5m",
				},
			},
		},
	}
	gw, err := gatewaypkg.NewGateway(gatewaypkg.Dependencies{Config: cfg, Logger: logging.NewLogger(false)}, "test")
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}
	base := time.Now().UTC()

	api := NewManagementAPI(gw, logging.NewLogger(false), nil)
	api.updateGatewayLimitClassAlertIncidentState([]gatewaypkg.RouteLimitClassAlert{{
		Severity:            "critical",
		ServiceName:         "agent",
		RoutePath:           "/ai/chat",
		LimitType:           "concurrency_queue_full",
		KeyType:             "jwt_sub",
		BucketClass:         "vip-jwt",
		Count:               5,
		QueueFullRejections: 5,
	}}, base)
	api.queueDigestNotifyMu.Lock()
	for key, state := range api.limitClassAlertIncidentState {
		state.SnoozedUntil = base.Add(4 * time.Minute)
		state.SnoozedBy = "ops-lead"
		api.limitClassAlertIncidentState[key] = state
	}
	api.queueDigestNotifyMu.Unlock()

	api.reconcileGatewayLimitClassSnoozeNotifications(base)
	if len(received) != 1 || received[0].Event != "gateway.limit_class_snooze_expiring" || received[0].SnoozeStage != "critical" {
		t.Fatalf("expected initial critical snooze expiry event, got %+v", received)
	}

	api.reconcileGatewayLimitClassSnoozeNotifications(base.Add(5 * time.Minute))
	if len(received) != 2 {
		t.Fatalf("expected resumed event after snooze expiry, got %d (%+v)", len(received), received)
	}
	resumed := received[1]
	if resumed.Event != "gateway.limit_class_snooze_resumed" || resumed.Previous != "critical" || resumed.Current != "resumed" || resumed.SnoozeStage != "critical" || resumed.IncidentID == "" {
		t.Fatalf("expected snooze resumed event, got %+v", resumed)
	}
}

func TestReconcileGatewayLimitClassSnoozeNotificationsHonorsWebhookEventTypeFilter(t *testing.T) {
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

	received := make([]string, 0, 8)
	server := newNotificationTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		var payload map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatalf("failed to decode webhook payload: %v", err)
		}
		received = append(received, strings.TrimSpace(fmt.Sprint(payload["event"])))
		w.WriteHeader(http.StatusOK)
	})
	defer server.Close()

	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Security: config.SecurityConfig{
			NotificationWebhooks: []config.NotificationWebhook{{
				URL:                        server.URL,
				Events:                     []string{"gateway.limit_class_snooze_expiring", "gateway.limit_class_snooze_resumed"},
				LimitClassSnoozeEventTypes: []string{"resumed"},
			}},
			MutationPolicy: config.MutationPolicy{
				LimitClassSnoozeNotifications: config.PolicyAlertNotificationPolicy{
					Enabled:                 true,
					Interval:                "1m",
					MinNotificationInterval: "1m",
					Window:                  "15m",
					SnoozeElevatedWithin:    "15m",
					SnoozeCriticalWithin:    "5m",
				},
			},
		},
	}
	gw, err := gatewaypkg.NewGateway(gatewaypkg.Dependencies{Config: cfg, Logger: logging.NewLogger(false)}, "test")
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}
	base := time.Now().UTC()

	api := NewManagementAPI(gw, logging.NewLogger(false), nil)
	api.updateGatewayLimitClassAlertIncidentState([]gatewaypkg.RouteLimitClassAlert{{
		Severity:            "critical",
		ServiceName:         "agent",
		RoutePath:           "/ai/chat",
		LimitType:           "concurrency_queue_full",
		KeyType:             "jwt_sub",
		BucketClass:         "vip-jwt",
		Count:               5,
		QueueFullRejections: 5,
	}}, base)
	api.queueDigestNotifyMu.Lock()
	for key, state := range api.limitClassAlertIncidentState {
		state.SnoozedUntil = base.Add(4 * time.Minute)
		state.SnoozedBy = "ops-lead"
		api.limitClassAlertIncidentState[key] = state
	}
	api.queueDigestNotifyMu.Unlock()

	api.reconcileGatewayLimitClassSnoozeNotifications(base)
	if len(received) != 0 {
		t.Fatalf("expected resumed-only filter to suppress expiring event, got %v", received)
	}

	api.reconcileGatewayLimitClassSnoozeNotifications(base.Add(5 * time.Minute))
	if len(received) != 1 || received[0] != "gateway.limit_class_snooze_resumed" {
		t.Fatalf("expected resumed-only filter to deliver only resumed event, got %v", received)
	}
}

func TestReconcileGatewayLimitClassSnoozeNotificationsHonorsBucketClassEventPolicy(t *testing.T) {
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

	received := make([]string, 0, 8)
	server := newNotificationTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		var payload map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatalf("failed to decode webhook payload: %v", err)
		}
		received = append(received, strings.TrimSpace(fmt.Sprint(payload["event"])))
		w.WriteHeader(http.StatusOK)
	})
	defer server.Close()

	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Security: config.SecurityConfig{
			LimitAlertBucketClasses: map[string]config.LimitAlertBucketClassConfig{
				"vip-jwt": {
					KeyType:          "jwt_sub",
					BucketRegex:      "^vip-",
					SnoozeEventTypes: []string{"resumed"},
				},
			},
			NotificationWebhooks: []config.NotificationWebhook{{
				URL:    server.URL,
				Events: []string{"gateway.limit_class_snooze_expiring", "gateway.limit_class_snooze_resumed"},
			}},
			MutationPolicy: config.MutationPolicy{
				LimitClassSnoozeNotifications: config.PolicyAlertNotificationPolicy{
					Enabled:                 true,
					Interval:                "1m",
					MinNotificationInterval: "1m",
					Window:                  "15m",
					SnoozeElevatedWithin:    "15m",
					SnoozeCriticalWithin:    "5m",
				},
			},
		},
	}
	gw, err := gatewaypkg.NewGateway(gatewaypkg.Dependencies{Config: cfg, Logger: logging.NewLogger(false)}, "test")
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}
	base := time.Now().UTC()

	api := NewManagementAPI(gw, logging.NewLogger(false), nil)
	api.updateGatewayLimitClassAlertIncidentState([]gatewaypkg.RouteLimitClassAlert{{
		Severity:            "critical",
		ServiceName:         "agent",
		RoutePath:           "/ai/chat",
		LimitType:           "concurrency_queue_full",
		KeyType:             "jwt_sub",
		BucketClass:         "vip-jwt",
		Count:               5,
		QueueFullRejections: 5,
	}}, base)
	api.queueDigestNotifyMu.Lock()
	for key, state := range api.limitClassAlertIncidentState {
		state.SnoozedUntil = base.Add(4 * time.Minute)
		state.SnoozedBy = "ops-lead"
		api.limitClassAlertIncidentState[key] = state
	}
	api.queueDigestNotifyMu.Unlock()

	api.reconcileGatewayLimitClassSnoozeNotifications(base)
	if len(received) != 0 {
		t.Fatalf("expected bucket class resumed-only policy to suppress expiring event, got %v", received)
	}

	api.reconcileGatewayLimitClassSnoozeNotifications(base.Add(5 * time.Minute))
	if len(received) != 1 || received[0] != "gateway.limit_class_snooze_resumed" {
		t.Fatalf("expected bucket class resumed-only policy to emit only resumed event, got %v", received)
	}
}

func TestReconcileGatewayLimitClassSnoozeNotificationsHonorsBucketClassDigestExclusion(t *testing.T) {
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

	type receivedEvent struct {
		Event              string
		Count              int
		ExcludedCount      int
		ExcludedByClassLen int
		TopExcludedClass   string
	}
	received := make([]receivedEvent, 0, 8)
	server := newNotificationTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		var payload map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatalf("failed to decode webhook payload: %v", err)
		}
		data, _ := payload["data"].(map[string]interface{})
		count := 0
		if snoozes, ok := data["snoozes"].([]interface{}); ok {
			count = len(snoozes)
		}
		excludedCount := 0
		if value, ok := data["excluded_class_snooze_count"]; ok {
			excludedCount = intValue(value)
		}
		excludedByClassLen := 0
		if excluded, ok := data["excluded_class_snoozes_by_class"].([]interface{}); ok {
			excludedByClassLen = len(excluded)
		}
		topExcludedClass := ""
		if excluded, ok := data["excluded_class_snoozes_by_class"].([]interface{}); ok && len(excluded) > 0 {
			if entry, ok := excluded[0].(map[string]interface{}); ok {
				topExcludedClass = strings.TrimSpace(fmt.Sprint(entry["bucket_class"]))
			}
		}
		received = append(received, receivedEvent{
			Event:              strings.TrimSpace(fmt.Sprint(payload["event"])),
			Count:              count,
			ExcludedCount:      excludedCount,
			ExcludedByClassLen: excludedByClassLen,
			TopExcludedClass:   topExcludedClass,
		})
		w.WriteHeader(http.StatusOK)
	})
	defer server.Close()

	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Security: config.SecurityConfig{
			LimitAlertBucketClasses: map[string]config.LimitAlertBucketClassConfig{
				"vip-jwt": {
					KeyType:                 "jwt_sub",
					BucketRegex:             "^vip-",
					Priority:                10,
					SnoozeExcludeFromDigest: true,
				},
				"standard-jwt": {
					KeyType:                 "jwt_sub",
					BucketRegex:             "^standard-",
					Priority:                1,
					SnoozeExcludeFromDigest: true,
				},
			},
			NotificationWebhooks: []config.NotificationWebhook{{
				URL:    server.URL,
				Events: []string{"gateway.limit_class_snooze_expiring_digest", "gateway.limit_class_snooze_expiring"},
			}},
			MutationPolicy: config.MutationPolicy{
				LimitClassSnoozeNotifications: config.PolicyAlertNotificationPolicy{
					Enabled:                 true,
					Interval:                "1m",
					MinNotificationInterval: "1m",
					Window:                  "15m",
					SnoozeElevatedWithin:    "15m",
					SnoozeCriticalWithin:    "5m",
				},
			},
		},
	}
	gw, err := gatewaypkg.NewGateway(gatewaypkg.Dependencies{Config: cfg, Logger: logging.NewLogger(false)}, "test")
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}
	base := time.Now().UTC()

	api := NewManagementAPI(gw, logging.NewLogger(false), nil)
	api.updateGatewayLimitClassAlertIncidentState([]gatewaypkg.RouteLimitClassAlert{{
		Severity:            "critical",
		ServiceName:         "agent",
		RoutePath:           "/ai/chat",
		LimitType:           "concurrency_queue_full",
		KeyType:             "jwt_sub",
		BucketClass:         "vip-jwt",
		Count:               5,
		QueueFullRejections: 5,
	}}, base)
	api.queueDigestNotifyMu.Lock()
	for key, state := range api.limitClassAlertIncidentState {
		state.SnoozedUntil = base.Add(4 * time.Minute)
		state.SnoozedBy = "ops-lead"
		api.limitClassAlertIncidentState[key] = state
	}
	api.queueDigestNotifyMu.Unlock()

	api.reconcileGatewayLimitClassSnoozeNotifications(base)
	if len(received) != 1 || received[0].Event != "gateway.limit_class_snooze_expiring" {
		t.Fatalf("expected digest exclusion to suppress digest and keep expiring event, got %+v", received)
	}
}

func TestReconcileGatewayLimitClassSnoozeNotificationsDigestExclusionAddsSummaryCounts(t *testing.T) {
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

	type receivedEvent struct {
		Event              string
		Count              int
		ExcludedCount      int
		ExcludedByClassLen int
		TopExcludedClass   string
	}
	received := make([]receivedEvent, 0, 8)
	server := newNotificationTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		var payload map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatalf("failed to decode webhook payload: %v", err)
		}
		data, _ := payload["data"].(map[string]interface{})
		count := 0
		if snoozes, ok := data["snoozes"].([]interface{}); ok {
			count = len(snoozes)
		}
		excludedCount := 0
		if value, ok := data["excluded_class_snooze_count"]; ok {
			excludedCount = intValue(value)
		}
		excludedByClassLen := 0
		topExcludedClass := ""
		if excluded, ok := data["excluded_class_snoozes_by_class"].([]interface{}); ok {
			excludedByClassLen = len(excluded)
			if len(excluded) > 0 {
				if entry, ok := excluded[0].(map[string]interface{}); ok {
					topExcludedClass = strings.TrimSpace(fmt.Sprint(entry["bucket_class"]))
				}
			}
		}
		received = append(received, receivedEvent{
			Event:              strings.TrimSpace(fmt.Sprint(payload["event"])),
			Count:              count,
			ExcludedCount:      excludedCount,
			ExcludedByClassLen: excludedByClassLen,
			TopExcludedClass:   topExcludedClass,
		})
		w.WriteHeader(http.StatusOK)
	})
	defer server.Close()

	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Security: config.SecurityConfig{
			LimitAlertBucketClasses: map[string]config.LimitAlertBucketClassConfig{
				"vip-jwt": {
					KeyType:                 "jwt_sub",
					BucketRegex:             "^vip-",
					SnoozeExcludeFromDigest: true,
				},
			},
			NotificationWebhooks: []config.NotificationWebhook{{
				URL:    server.URL,
				Events: []string{"gateway.limit_class_snooze_expiring_digest", "gateway.limit_class_snooze_expiring"},
			}},
			MutationPolicy: config.MutationPolicy{
				LimitClassSnoozeNotifications: config.PolicyAlertNotificationPolicy{
					Enabled:                 true,
					Interval:                "1m",
					MinNotificationInterval: "1m",
					Window:                  "15m",
					SnoozeElevatedWithin:    "15m",
					SnoozeCriticalWithin:    "5m",
				},
			},
		},
	}
	gw, err := gatewaypkg.NewGateway(gatewaypkg.Dependencies{Config: cfg, Logger: logging.NewLogger(false)}, "test")
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}
	base := time.Now().UTC()

	api := NewManagementAPI(gw, logging.NewLogger(false), nil)
	api.updateGatewayLimitClassAlertIncidentState([]gatewaypkg.RouteLimitClassAlert{
		{
			Severity:            "critical",
			ServiceName:         "agent",
			RoutePath:           "/ai/chat",
			LimitType:           "concurrency_queue_full",
			KeyType:             "jwt_sub",
			BucketClass:         "vip-jwt",
			Count:               5,
			QueueFullRejections: 5,
		},
		{
			Severity:            "critical",
			ServiceName:         "agent",
			RoutePath:           "/ai/search",
			LimitType:           "concurrency_queue_full",
			KeyType:             "jwt_sub",
			BucketClass:         "standard-jwt",
			Count:               5,
			QueueFullRejections: 5,
		},
		{
			Severity:            "critical",
			ServiceName:         "agent",
			RoutePath:           "/ai/search-2",
			LimitType:           "concurrency_queue_full",
			KeyType:             "jwt_sub",
			BucketClass:         "standard-jwt",
			Count:               5,
			QueueFullRejections: 5,
		},
		{
			Severity:            "critical",
			ServiceName:         "agent",
			RoutePath:           "/ai/public",
			LimitType:           "concurrency_queue_full",
			KeyType:             "jwt_sub",
			BucketClass:         "public-jwt",
			Count:               5,
			QueueFullRejections: 5,
		},
	}, base)
	api.queueDigestNotifyMu.Lock()
	for key, state := range api.limitClassAlertIncidentState {
		state.SnoozedUntil = base.Add(4 * time.Minute)
		state.SnoozedBy = "ops-lead"
		api.limitClassAlertIncidentState[key] = state
	}
	api.queueDigestNotifyMu.Unlock()

	api.reconcileGatewayLimitClassSnoozeNotifications(base)
	if len(received) != 5 {
		t.Fatalf("expected digest plus four expiring events, got %d (%+v)", len(received), received)
	}
	digest := received[0]
	if digest.Event != "gateway.limit_class_snooze_expiring_digest" || digest.Count != 3 || digest.ExcludedCount != 1 || digest.ExcludedByClassLen != 1 || digest.TopExcludedClass != "vip-jwt" {
		t.Fatalf("expected digest to keep three visible snoozes plus one excluded-class summary, got %+v", digest)
	}
}

func TestReconcileGatewayLimitClassSnoozeNotificationsHonorsDetailedMinBucketClassPriority(t *testing.T) {
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

	type receivedEvent struct {
		Event              string
		Count              int
		ExcludedCount      int
		ExcludedByClassLen int
		TopExcludedClass   string
	}
	received := make([]receivedEvent, 0, 8)
	server := newNotificationTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		var payload map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatalf("failed to decode webhook payload: %v", err)
		}
		data, _ := payload["data"].(map[string]interface{})
		count := 0
		if snoozes, ok := data["snoozes"].([]interface{}); ok {
			count = len(snoozes)
		}
		excludedCount := 0
		if value, ok := data["excluded_class_snooze_count"]; ok {
			excludedCount = intValue(value)
		}
		excludedByClassLen := 0
		topExcludedClass := ""
		if excluded, ok := data["excluded_class_snoozes_by_class"].([]interface{}); ok {
			excludedByClassLen = len(excluded)
			if len(excluded) > 0 {
				if entry, ok := excluded[0].(map[string]interface{}); ok {
					topExcludedClass = strings.TrimSpace(fmt.Sprint(entry["bucket_class"]))
				}
			}
		}
		received = append(received, receivedEvent{
			Event:              strings.TrimSpace(fmt.Sprint(payload["event"])),
			Count:              count,
			ExcludedCount:      excludedCount,
			ExcludedByClassLen: excludedByClassLen,
			TopExcludedClass:   topExcludedClass,
		})
		w.WriteHeader(http.StatusOK)
	})
	defer server.Close()

	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Security: config.SecurityConfig{
			LimitAlertBucketClasses: map[string]config.LimitAlertBucketClassConfig{
				"vip-jwt": {
					KeyType:     "jwt_sub",
					BucketRegex: "^vip-",
					Priority:    10,
				},
				"standard-jwt": {
					KeyType:     "jwt_sub",
					BucketRegex: "^standard-",
					Priority:    1,
				},
			},
			NotificationWebhooks: []config.NotificationWebhook{{
				URL:    server.URL,
				Events: []string{"gateway.limit_class_snooze_expiring_digest", "gateway.limit_class_snooze_expiring"},
			}},
			MutationPolicy: config.MutationPolicy{
				LimitClassSnoozeNotifications: config.PolicyAlertNotificationPolicy{
					Enabled:                        true,
					Interval:                       "1m",
					MinNotificationInterval:        "1m",
					Window:                         "15m",
					SnoozeElevatedWithin:           "15m",
					SnoozeCriticalWithin:           "5m",
					DetailedMinBucketClassPriority: 5,
				},
			},
		},
	}
	gw, err := gatewaypkg.NewGateway(gatewaypkg.Dependencies{Config: cfg, Logger: logging.NewLogger(false)}, "test")
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}
	base := time.Now().UTC()

	api := NewManagementAPI(gw, logging.NewLogger(false), nil)
	api.updateGatewayLimitClassAlertIncidentState([]gatewaypkg.RouteLimitClassAlert{
		{
			Severity:            "critical",
			ServiceName:         "agent",
			RoutePath:           "/ai/chat",
			LimitType:           "concurrency_queue_full",
			KeyType:             "jwt_sub",
			BucketClass:         "vip-jwt",
			Count:               5,
			QueueFullRejections: 5,
		},
		{
			Severity:            "critical",
			ServiceName:         "agent",
			RoutePath:           "/ai/search",
			LimitType:           "concurrency_queue_full",
			KeyType:             "jwt_sub",
			BucketClass:         "standard-jwt",
			Count:               5,
			QueueFullRejections: 5,
		},
	}, base)
	api.queueDigestNotifyMu.Lock()
	for key, state := range api.limitClassAlertIncidentState {
		state.SnoozedUntil = base.Add(4 * time.Minute)
		state.SnoozedBy = "ops-lead"
		api.limitClassAlertIncidentState[key] = state
	}
	api.queueDigestNotifyMu.Unlock()

	api.reconcileGatewayLimitClassSnoozeNotifications(base)
	if len(received) != 3 {
		t.Fatalf("expected digest plus two expiring events, got %d (%+v)", len(received), received)
	}
	digest := received[0]
	if digest.Event != "gateway.limit_class_snooze_expiring_digest" || digest.Count != 1 || digest.ExcludedCount != 1 || digest.ExcludedByClassLen != 1 || digest.TopExcludedClass != "standard-jwt" {
		t.Fatalf("expected digest to keep one detailed snooze and summarize one lower-priority class, got %+v", digest)
	}
}

func TestReconcileGatewayLimitClassSnoozeNotificationsHonorsDetailedMaxBucketClasses(t *testing.T) {
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

	type receivedEvent struct {
		Event              string
		Count              int
		ExcludedCount      int
		ExcludedByClassLen int
		TopExcludedClass   string
	}
	received := make([]receivedEvent, 0, 8)
	server := newNotificationTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		var payload map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatalf("failed to decode webhook payload: %v", err)
		}
		data, _ := payload["data"].(map[string]interface{})
		count := 0
		if snoozes, ok := data["snoozes"].([]interface{}); ok {
			count = len(snoozes)
		}
		excludedCount := 0
		if value, ok := data["excluded_class_snooze_count"]; ok {
			excludedCount = intValue(value)
		}
		excludedByClassLen := 0
		topExcludedClass := ""
		if excluded, ok := data["excluded_class_snoozes_by_class"].([]interface{}); ok {
			excludedByClassLen = len(excluded)
			if len(excluded) > 0 {
				if entry, ok := excluded[0].(map[string]interface{}); ok {
					topExcludedClass = strings.TrimSpace(fmt.Sprint(entry["bucket_class"]))
				}
			}
		}
		received = append(received, receivedEvent{
			Event:              strings.TrimSpace(fmt.Sprint(payload["event"])),
			Count:              count,
			ExcludedCount:      excludedCount,
			ExcludedByClassLen: excludedByClassLen,
			TopExcludedClass:   topExcludedClass,
		})
		w.WriteHeader(http.StatusOK)
	})
	defer server.Close()

	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Security: config.SecurityConfig{
			LimitAlertBucketClasses: map[string]config.LimitAlertBucketClassConfig{
				"vip-jwt": {
					KeyType:     "jwt_sub",
					BucketRegex: "^vip-",
					Priority:    10,
				},
				"gold-jwt": {
					KeyType:     "jwt_sub",
					BucketRegex: "^gold-",
					Priority:    7,
				},
			},
			NotificationWebhooks: []config.NotificationWebhook{{
				URL:    server.URL,
				Events: []string{"gateway.limit_class_snooze_expiring_digest", "gateway.limit_class_snooze_expiring"},
			}},
			MutationPolicy: config.MutationPolicy{
				LimitClassSnoozeNotifications: config.PolicyAlertNotificationPolicy{
					Enabled:                        true,
					Interval:                       "1m",
					MinNotificationInterval:        "1m",
					Window:                         "15m",
					SnoozeElevatedWithin:           "15m",
					SnoozeCriticalWithin:           "5m",
					DetailedMinBucketClassPriority: 5,
					DetailedMaxBucketClasses:       1,
				},
			},
		},
	}
	gw, err := gatewaypkg.NewGateway(gatewaypkg.Dependencies{Config: cfg, Logger: logging.NewLogger(false)}, "test")
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}
	base := time.Now().UTC()

	api := NewManagementAPI(gw, logging.NewLogger(false), nil)
	api.updateGatewayLimitClassAlertIncidentState([]gatewaypkg.RouteLimitClassAlert{
		{
			Severity:            "critical",
			ServiceName:         "agent",
			RoutePath:           "/ai/chat",
			LimitType:           "concurrency_queue_full",
			KeyType:             "jwt_sub",
			BucketClass:         "vip-jwt",
			Count:               5,
			QueueFullRejections: 5,
		},
		{
			Severity:            "critical",
			ServiceName:         "agent",
			RoutePath:           "/ai/search",
			LimitType:           "concurrency_queue_full",
			KeyType:             "jwt_sub",
			BucketClass:         "gold-jwt",
			Count:               5,
			QueueFullRejections: 5,
		},
	}, base)
	api.queueDigestNotifyMu.Lock()
	for key, state := range api.limitClassAlertIncidentState {
		state.SnoozedUntil = base.Add(4 * time.Minute)
		state.SnoozedBy = "ops-lead"
		api.limitClassAlertIncidentState[key] = state
	}
	api.queueDigestNotifyMu.Unlock()

	api.reconcileGatewayLimitClassSnoozeNotifications(base)
	if len(received) != 3 {
		t.Fatalf("expected digest plus two expiring events, got %d (%+v)", len(received), received)
	}
	digest := received[0]
	if digest.Event != "gateway.limit_class_snooze_expiring_digest" || digest.Count != 1 || digest.ExcludedCount != 1 || digest.ExcludedByClassLen != 1 || digest.TopExcludedClass != "gold-jwt" {
		t.Fatalf("expected digest quota to keep only the top class snooze detailed and summarize the next class, got %+v", digest)
	}
}

func TestNotifyGatewayLimitClassSnoozesShapesDigestPerWebhookBudget(t *testing.T) {
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

	type digestView struct {
		Count         int
		ExcludedCount int
	}
	views := make([]digestView, 0, 2)
	serverA := newNotificationTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		var payload map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatalf("failed to decode webhook payload: %v", err)
		}
		if strings.TrimSpace(fmt.Sprint(payload["event"])) == "gateway.limit_class_snooze_expiring_digest" {
			data, _ := payload["data"].(map[string]interface{})
			count := 0
			if snoozes, ok := data["snoozes"].([]interface{}); ok {
				count = len(snoozes)
			}
			views = append(views, digestView{
				Count:         count,
				ExcludedCount: intValue(data["excluded_class_snooze_count"]),
			})
		}
		w.WriteHeader(http.StatusOK)
	})
	defer serverA.Close()
	serverB := newNotificationTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		var payload map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatalf("failed to decode webhook payload: %v", err)
		}
		if strings.TrimSpace(fmt.Sprint(payload["event"])) == "gateway.limit_class_snooze_expiring_digest" {
			data, _ := payload["data"].(map[string]interface{})
			count := 0
			if snoozes, ok := data["snoozes"].([]interface{}); ok {
				count = len(snoozes)
			}
			views = append(views, digestView{
				Count:         count,
				ExcludedCount: intValue(data["excluded_class_snooze_count"]),
			})
		}
		w.WriteHeader(http.StatusOK)
	})
	defer serverB.Close()

	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Security: config.SecurityConfig{
			LimitAlertBucketClasses: map[string]config.LimitAlertBucketClassConfig{
				"vip-jwt":  {KeyType: "jwt_sub", BucketRegex: "^vip-", Priority: 10},
				"gold-jwt": {KeyType: "jwt_sub", BucketRegex: "^gold-", Priority: 7},
			},
			LimitAlertProfiles: map[string]config.LimitAlertRecipientProfile{
				"top-one": {LimitClassDigestMaxBucketClasses: 1},
				"top-two": {LimitClassDigestMaxBucketClasses: 2},
			},
			NotificationWebhooks: []config.NotificationWebhook{
				{URL: serverA.URL, Events: []string{"gateway.limit_class_snooze_expiring_digest"}, LimitAlertProfile: "top-one"},
				{URL: serverB.URL, Events: []string{"gateway.limit_class_snooze_expiring_digest"}, LimitAlertProfile: "top-two"},
			},
		},
	}
	gw, err := gatewaypkg.NewGateway(gatewaypkg.Dependencies{Config: cfg, Logger: logging.NewLogger(false)}, "test")
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}
	base := time.Now().UTC()

	api := NewManagementAPI(gw, logging.NewLogger(false), nil)
	api.updateGatewayLimitClassAlertIncidentState([]gatewaypkg.RouteLimitClassAlert{
		{
			Severity:            "critical",
			ServiceName:         "agent",
			RoutePath:           "/ai/chat",
			LimitType:           "concurrency_queue_full",
			KeyType:             "jwt_sub",
			BucketClass:         "vip-jwt",
			Count:               5,
			QueueFullRejections: 5,
		},
		{
			Severity:            "critical",
			ServiceName:         "agent",
			RoutePath:           "/ai/search",
			LimitType:           "concurrency_queue_full",
			KeyType:             "jwt_sub",
			BucketClass:         "gold-jwt",
			Count:               5,
			QueueFullRejections: 5,
		},
	}, base)
	api.queueDigestNotifyMu.Lock()
	for key, state := range api.limitClassAlertIncidentState {
		state.SnoozedUntil = base.Add(4 * time.Minute)
		state.SnoozedBy = "ops-lead"
		api.limitClassAlertIncidentState[key] = state
	}
	api.queueDigestNotifyMu.Unlock()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/gateway/limit-class-snoozes/notify?expiring_within=15m", nil)
	resp := httptest.NewRecorder()
	api.notifyGatewayLimitClassSnoozes(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.Code, resp.Body.String())
	}
	if len(views) != 2 {
		t.Fatalf("expected two per-webhook snooze digest views, got %d (%+v)", len(views), views)
	}
	if views[0].Count != 1 || views[0].ExcludedCount != 1 {
		t.Fatalf("expected top-one receiver to get one detailed snooze and one excluded snooze, got %+v", views[0])
	}
	if views[1].Count != 2 || views[1].ExcludedCount != 0 {
		t.Fatalf("expected top-two receiver to get both detailed snoozes, got %+v", views[1])
	}
}

func TestNotifyGatewayLimitClassSnoozesShapesDigestPerWebhookSeverity(t *testing.T) {
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

	type digestView struct {
		Count         int
		ExcludedCount int
	}
	views := make([]digestView, 0, 2)
	serverA := newNotificationTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		var payload map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatalf("failed to decode webhook payload: %v", err)
		}
		if strings.TrimSpace(fmt.Sprint(payload["event"])) == "gateway.limit_class_snooze_expiring_digest" {
			data, _ := payload["data"].(map[string]interface{})
			count := 0
			if snoozes, ok := data["snoozes"].([]interface{}); ok {
				count = len(snoozes)
			}
			views = append(views, digestView{
				Count:         count,
				ExcludedCount: intValue(data["excluded_class_snooze_count"]),
			})
		}
		w.WriteHeader(http.StatusOK)
	})
	defer serverA.Close()
	serverB := newNotificationTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		var payload map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatalf("failed to decode webhook payload: %v", err)
		}
		if strings.TrimSpace(fmt.Sprint(payload["event"])) == "gateway.limit_class_snooze_expiring_digest" {
			data, _ := payload["data"].(map[string]interface{})
			count := 0
			if snoozes, ok := data["snoozes"].([]interface{}); ok {
				count = len(snoozes)
			}
			views = append(views, digestView{
				Count:         count,
				ExcludedCount: intValue(data["excluded_class_snooze_count"]),
			})
		}
		w.WriteHeader(http.StatusOK)
	})
	defer serverB.Close()

	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Security: config.SecurityConfig{
			LimitAlertBucketClasses: map[string]config.LimitAlertBucketClassConfig{
				"vip-jwt":  {KeyType: "jwt_sub", BucketRegex: "^vip-", Priority: 10},
				"gold-jwt": {KeyType: "jwt_sub", BucketRegex: "^gold-", Priority: 7},
			},
			LimitAlertProfiles: map[string]config.LimitAlertRecipientProfile{
				"critical-only": {LimitClassDigestMinSeverity: "critical"},
				"warning-plus":  {LimitClassDigestMinSeverity: "warning"},
			},
			NotificationWebhooks: []config.NotificationWebhook{
				{URL: serverA.URL, Events: []string{"gateway.limit_class_snooze_expiring_digest"}, LimitAlertProfile: "critical-only"},
				{URL: serverB.URL, Events: []string{"gateway.limit_class_snooze_expiring_digest"}, LimitAlertProfile: "warning-plus"},
			},
		},
	}
	gw, err := gatewaypkg.NewGateway(gatewaypkg.Dependencies{Config: cfg, Logger: logging.NewLogger(false)}, "test")
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}
	base := time.Now().UTC()

	api := NewManagementAPI(gw, logging.NewLogger(false), nil)
	api.updateGatewayLimitClassAlertIncidentState([]gatewaypkg.RouteLimitClassAlert{
		{
			Severity:            "critical",
			ServiceName:         "agent",
			RoutePath:           "/ai/chat",
			LimitType:           "concurrency_queue_full",
			KeyType:             "jwt_sub",
			BucketClass:         "vip-jwt",
			Count:               5,
			QueueFullRejections: 5,
		},
		{
			Severity:            "critical",
			ServiceName:         "agent",
			RoutePath:           "/ai/search",
			LimitType:           "concurrency_queue_full",
			KeyType:             "jwt_sub",
			BucketClass:         "gold-jwt",
			Count:               5,
			QueueFullRejections: 5,
		},
	}, base)
	api.queueDigestNotifyMu.Lock()
	for key, state := range api.limitClassAlertIncidentState {
		if state.BucketClass == "vip-jwt" {
			state.SnoozedUntil = base.Add(4 * time.Minute)
		} else {
			state.SnoozedUntil = base.Add(10 * time.Minute)
		}
		state.SnoozedBy = "ops-lead"
		api.limitClassAlertIncidentState[key] = state
	}
	api.queueDigestNotifyMu.Unlock()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/gateway/limit-class-snoozes/notify?expiring_within=15m", nil)
	resp := httptest.NewRecorder()
	api.notifyGatewayLimitClassSnoozes(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.Code, resp.Body.String())
	}
	if len(views) != 2 {
		t.Fatalf("expected two per-webhook severity-shaped snooze digest views, got %d (%+v)", len(views), views)
	}
	if views[0].Count != 1 || views[0].ExcludedCount != 1 {
		t.Fatalf("expected critical-only receiver to keep only the critical snooze detailed, got %+v", views[0])
	}
	if views[1].Count != 2 || views[1].ExcludedCount != 0 {
		t.Fatalf("expected warning-plus receiver to keep both snoozes detailed, got %+v", views[1])
	}
}

func TestShapeLimitClassDigestPayloadForReceiverHonorsExactSeverities(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Security: config.SecurityConfig{
			LimitAlertBucketClasses: map[string]config.LimitAlertBucketClassConfig{
				"vip-jwt":      {KeyType: "jwt_sub", BucketRegex: "^vip-", Priority: 10},
				"gold-jwt":     {KeyType: "jwt_sub", BucketRegex: "^gold-", Priority: 7},
				"standard-jwt": {KeyType: "jwt_sub", BucketRegex: "^standard-", Priority: 5},
			},
		},
	}
	api := NewManagementAPI(mustTestGateway(t, cfg), logging.NewLogger(false), nil)
	payload := managementWebhookEvent{
		Event: "gateway.limit_class_snooze_expiring_digest",
		Data: map[string]interface{}{
			"snoozes": []interface{}{
				map[string]interface{}{"severity": "critical", "bucket_class": "vip-jwt"},
				map[string]interface{}{"severity": "elevated", "bucket_class": "gold-jwt"},
				map[string]interface{}{"severity": "warning", "bucket_class": "standard-jwt"},
			},
		},
	}

	shaped := api.shapeLimitClassDigestPayloadForReceiver(config.NotificationWebhook{
		LimitClassDigestSeverities: []string{"warning", "critical"},
	}, payload)
	data := shaped.Data

	snoozes, ok := data["snoozes"].([]interface{})
	if !ok {
		t.Fatalf("expected shaped snoozes slice, got %T", data["snoozes"])
	}
	if len(snoozes) != 2 {
		t.Fatalf("expected warning and critical snoozes to remain detailed, got %d (%v)", len(snoozes), snoozes)
	}
	gotSeverities := make([]string, 0, len(snoozes))
	for _, item := range snoozes {
		entry, _ := item.(map[string]interface{})
		gotSeverities = append(gotSeverities, normalizeSLABreachTier(fmt.Sprint(entry["severity"])))
	}
	sort.Strings(gotSeverities)
	if strings.Join(gotSeverities, ",") != "critical,warning" {
		t.Fatalf("expected detailed severities critical and warning, got %v", gotSeverities)
	}
	if intValue(data["excluded_class_snooze_count"]) != 1 {
		t.Fatalf("expected one excluded snooze, got %+v", data["excluded_class_snooze_count"])
	}
	if receiverSeverities, ok := data["receiver_detailed_severities"].([]string); ok {
		sort.Strings(receiverSeverities)
		if strings.Join(receiverSeverities, ",") != "critical,warning" {
			t.Fatalf("expected receiver severities critical and warning, got %v", receiverSeverities)
		}
	} else {
		t.Fatalf("expected receiver_detailed_severities []string, got %T", data["receiver_detailed_severities"])
	}
}

func TestEffectiveNotificationWebhookLimitAlertProfileInheritsDefaults(t *testing.T) {
	profileSeverities := []string{"critical"}
	profiles := map[string]config.LimitAlertRecipientProfile{
		"ops": {
			MinLimitAlertSeverity:                  "elevated",
			MinLimitAlertBucketClassPriority:       7,
			LimitClassDigestMinSeverity:            "warning",
			LimitClassDigestTypes:                  []string{"snooze"},
			LimitClassDigestSeverities:             profileSeverities,
			LimitClassDigestMinBucketClassPriority: 5,
			LimitClassDigestMaxBucketClasses:       2,
			LimitAlertTypes:                        []string{"concurrency_queue_full"},
			LimitAlertKeyTypes:                     []string{"jwt_sub"},
			LimitAlertBucketClasses:                []string{"vip-jwt"},
			LimitAlertBucketIDRegex:                "^vip-",
			LimitAlertCooldown:                     "10m",
			LimitClassSnoozeExpiryCooldown:         "5m",
			LimitClassSnoozeExpiryWithin:           "15m",
			LimitClassSnoozeExpiryStages:           []string{"critical"},
			LimitClassSnoozeEventTypes:             []string{"expiring"},
			LimitClassDigestTruncatedReasonBucketExactSeverityPolicyPresetChain: []string{"base-hidden"},
			LimitClassDigestTruncatedReasonBucketExactSeverityPolicyPreset:      "shared-exact",
		},
	}
	webhook := effectiveNotificationWebhookLimitAlertProfile(config.NotificationWebhook{
		LimitAlertProfile:     "ops",
		MinLimitAlertSeverity: "critical",
		LimitAlertTypes:       []string{"rate_limit"},
	}, profiles)

	if webhook.MinLimitAlertSeverity != "critical" {
		t.Fatalf("expected explicit min severity to win, got %q", webhook.MinLimitAlertSeverity)
	}
	if strings.Join(webhook.LimitAlertTypes, ",") != "rate_limit" {
		t.Fatalf("expected explicit alert types to win, got %v", webhook.LimitAlertTypes)
	}
	if webhook.MinLimitAlertBucketClassPriority != 7 || webhook.LimitClassDigestMaxBucketClasses != 2 {
		t.Fatalf("expected integer profile defaults to inherit, got %+v", webhook)
	}
	if strings.Join(webhook.LimitClassDigestTypes, ",") != "snooze" || strings.Join(webhook.LimitClassDigestSeverities, ",") != "critical" {
		t.Fatalf("expected digest profile slices to inherit, got types=%v severities=%v", webhook.LimitClassDigestTypes, webhook.LimitClassDigestSeverities)
	}
	if webhook.LimitAlertCooldown != "10m" || webhook.LimitClassSnoozeExpiryWithin != "15m" {
		t.Fatalf("expected cooldown/window profile defaults to inherit, got %+v", webhook)
	}
	if strings.Join(webhook.LimitClassDigestTruncatedReasonBucketExactSeverityPolicyPresetChain, ",") != "base-hidden" {
		t.Fatalf("expected hidden strategy policy preset chain to inherit, got %v", webhook.LimitClassDigestTruncatedReasonBucketExactSeverityPolicyPresetChain)
	}
	if webhook.LimitClassDigestTruncatedReasonBucketExactSeverityPolicyPreset != "shared-exact" {
		t.Fatalf("expected hidden strategy policy preset to inherit, got %q", webhook.LimitClassDigestTruncatedReasonBucketExactSeverityPolicyPreset)
	}

	profileSeverities[0] = "warning"
	if strings.Join(webhook.LimitClassDigestSeverities, ",") != "critical" {
		t.Fatalf("expected inherited slices to be cloned, got %v", webhook.LimitClassDigestSeverities)
	}
}

func TestEffectiveNotificationWebhookLimitClassDigestProfileInheritsDefaults(t *testing.T) {
	profiles := map[string]config.LimitAlertRecipientProfile{
		"shared-digest": {
			LimitClassDigestTypes:                                               []string{"snooze"},
			LimitClassDigestSummaryOnlyTypes:                                    []string{"alert"},
			LimitClassDigestMinSeverity:                                         "elevated",
			LimitClassDigestMinBucketClassPriority:                              8,
			LimitClassDigestTruncatedReasonBucketMode:                           "detailed",
			LimitClassDigestTruncatedReasonBucketHiddenStrategyOrder:            []string{"max_reasons", "exact_severity"},
			LimitClassDigestTruncatedReasonBucketExactSeverityPolicyPresetChain: []string{"base-hidden"},
			LimitClassDigestTruncatedReasonBucketExactSeverityPolicyPreset:      "shared-exact",
		},
	}

	webhook := effectiveNotificationWebhookLimitClassDigestProfile(config.NotificationWebhook{
		LimitClassDigestProfile:          "shared-digest",
		LimitClassDigestMinSeverity:      "critical",
		LimitClassDigestSummaryOnlyTypes: []string{"snooze"},
	}, profiles)

	if webhook.LimitClassDigestMinSeverity != "critical" {
		t.Fatalf("expected explicit digest min severity to win, got %q", webhook.LimitClassDigestMinSeverity)
	}
	if strings.Join(webhook.LimitClassDigestTypes, ",") != "snooze" {
		t.Fatalf("expected digest types to inherit, got %v", webhook.LimitClassDigestTypes)
	}
	if strings.Join(webhook.LimitClassDigestSummaryOnlyTypes, ",") != "snooze" {
		t.Fatalf("expected explicit summary-only types to win, got %v", webhook.LimitClassDigestSummaryOnlyTypes)
	}
	if webhook.LimitClassDigestMinBucketClassPriority != 8 || webhook.LimitClassDigestTruncatedReasonBucketMode != "detailed" {
		t.Fatalf("expected digest defaults to inherit, got %+v", webhook)
	}
	if strings.Join(webhook.LimitClassDigestTruncatedReasonBucketHiddenStrategyOrder, ",") != "max_reasons,exact_severity" {
		t.Fatalf("expected nested strategy order to inherit, got %v", webhook.LimitClassDigestTruncatedReasonBucketHiddenStrategyOrder)
	}
	if strings.Join(webhook.LimitClassDigestTruncatedReasonBucketExactSeverityPolicyPresetChain, ",") != "base-hidden" {
		t.Fatalf("expected digest preset chain to inherit, got %v", webhook.LimitClassDigestTruncatedReasonBucketExactSeverityPolicyPresetChain)
	}
	if webhook.LimitClassDigestTruncatedReasonBucketExactSeverityPolicyPreset != "shared-exact" {
		t.Fatalf("expected digest preset name to inherit, got %q", webhook.LimitClassDigestTruncatedReasonBucketExactSeverityPolicyPreset)
	}
}

func TestEffectiveNotificationWebhookLimitClassDigestProfileChainLayersDefaults(t *testing.T) {
	profiles := map[string]config.LimitAlertRecipientProfile{
		"base": {
			LimitClassDigestTypes:                     []string{"alert"},
			LimitClassDigestMinSeverity:               "warning",
			LimitClassDigestMinBucketClassPriority:    4,
			LimitClassDigestOverflowReasons:           []string{"low_count"},
			LimitClassDigestTruncatedReasonBucketMode: "summary",
		},
		"overlay": {
			LimitClassDigestMinSeverity:                                         "elevated",
			LimitClassDigestOverflowReasons:                                     []string{"low_priority"},
			LimitClassDigestTruncatedReasonBucketExactSeverityPolicyPreset:      "shared-exact",
			LimitClassDigestTruncatedReasonBucketExactSeverityPolicyPresetChain: []string{"base-hidden"},
		},
		"strict": {
			LimitClassDigestTypes:                  []string{"snooze"},
			LimitClassDigestMinBucketClassPriority: 9,
		},
	}

	webhook := effectiveNotificationWebhookLimitClassDigestProfile(config.NotificationWebhook{
		LimitClassDigestProfileChain: []string{"base", "overlay"},
		LimitClassDigestProfile:      "strict",
		LimitClassDigestMinSeverity:  "critical",
	}, profiles)

	if strings.Join(webhook.LimitClassDigestTypes, ",") != "snooze" {
		t.Fatalf("expected single digest profile to override chain types, got %v", webhook.LimitClassDigestTypes)
	}
	if webhook.LimitClassDigestMinSeverity != "critical" {
		t.Fatalf("expected explicit digest min severity to win, got %q", webhook.LimitClassDigestMinSeverity)
	}
	if webhook.LimitClassDigestMinBucketClassPriority != 9 {
		t.Fatalf("expected single digest profile to override chain priority, got %d", webhook.LimitClassDigestMinBucketClassPriority)
	}
	if strings.Join(webhook.LimitClassDigestOverflowReasons, ",") != "low_priority" {
		t.Fatalf("expected later chain digest profile to override overflow reasons, got %v", webhook.LimitClassDigestOverflowReasons)
	}
	if webhook.LimitClassDigestTruncatedReasonBucketMode != "summary" {
		t.Fatalf("expected base chain digest profile to fill missing truncated mode, got %q", webhook.LimitClassDigestTruncatedReasonBucketMode)
	}
	if webhook.LimitClassDigestTruncatedReasonBucketExactSeverityPolicyPreset != "shared-exact" {
		t.Fatalf("expected overlay digest profile to supply preset, got %q", webhook.LimitClassDigestTruncatedReasonBucketExactSeverityPolicyPreset)
	}
	if strings.Join(webhook.LimitClassDigestTruncatedReasonBucketExactSeverityPolicyPresetChain, ",") != "base-hidden" {
		t.Fatalf("expected overlay digest profile to supply preset chain, got %v", webhook.LimitClassDigestTruncatedReasonBucketExactSeverityPolicyPresetChain)
	}
}

func TestResolveNotificationWebhookHiddenStrategyPolicyPresetsAppliesPresetWhenPolicyUnset(t *testing.T) {
	webhook := resolveNotificationWebhookHiddenStrategyPolicyPresets(config.NotificationWebhook{
		LimitClassDigestTruncatedReasonBucketExactSeverityPolicyPresetChain: []string{"base-exact"},
		LimitClassDigestTruncatedReasonBucketExactSeverityPolicyPreset:      "shared-exact",
		LimitClassDigestTruncatedReasonBucketMinSeverityPolicyPresetChain:   []string{"base-min"},
		LimitClassDigestTruncatedReasonBucketMinSeverityPolicyPreset:        "shared-min",
		LimitClassDigestTruncatedReasonBucketMaxReasonsPolicyPresetChain:    []string{"base-max"},
		LimitClassDigestTruncatedReasonBucketMaxReasonsPolicyPreset:         "shared-max",
	}, map[string]config.LimitClassDigestHiddenStrategyPolicy{
		"base-exact":   {MinReasons: 2, PriorityCap: 3},
		"shared-exact": {DominantMode: "weighted_score", PriorityWeight: 7},
		"base-min":     {MinItems: 3, PriorityWeight: 2},
		"shared-min":   {DominantMode: "most_hidden_items", ReasonCap: 5},
		"base-max":     {ItemWeight: 11},
		"shared-max":   {DominantMode: "order_first", ItemCap: 13},
	})

	if webhook.LimitClassDigestTruncatedReasonBucketExactSeverityPolicy == nil || webhook.LimitClassDigestTruncatedReasonBucketExactSeverityPolicy.PriorityWeight != 7 || webhook.LimitClassDigestTruncatedReasonBucketExactSeverityPolicy.PriorityCap != 3 || webhook.LimitClassDigestTruncatedReasonBucketExactSeverityPolicy.MinReasons != 2 {
		t.Fatalf("expected exact severity preset to resolve, got %+v", webhook.LimitClassDigestTruncatedReasonBucketExactSeverityPolicy)
	}
	if webhook.LimitClassDigestTruncatedReasonBucketMinSeverityPolicy == nil || webhook.LimitClassDigestTruncatedReasonBucketMinSeverityPolicy.ReasonCap != 5 || webhook.LimitClassDigestTruncatedReasonBucketMinSeverityPolicy.MinItems != 3 || webhook.LimitClassDigestTruncatedReasonBucketMinSeverityPolicy.PriorityWeight != 2 {
		t.Fatalf("expected min severity preset to resolve, got %+v", webhook.LimitClassDigestTruncatedReasonBucketMinSeverityPolicy)
	}
	if webhook.LimitClassDigestTruncatedReasonBucketMaxReasonsPolicy == nil || webhook.LimitClassDigestTruncatedReasonBucketMaxReasonsPolicy.ItemCap != 13 || webhook.LimitClassDigestTruncatedReasonBucketMaxReasonsPolicy.ItemWeight != 11 {
		t.Fatalf("expected max reasons preset to resolve, got %+v", webhook.LimitClassDigestTruncatedReasonBucketMaxReasonsPolicy)
	}
}

func TestResolveNotificationWebhookHiddenStrategyPolicyPresetsKeepsExplicitPolicy(t *testing.T) {
	webhook := resolveNotificationWebhookHiddenStrategyPolicyPresets(config.NotificationWebhook{
		LimitClassDigestTruncatedReasonBucketExactSeverityPolicyPresetChain: []string{"base-exact"},
		LimitClassDigestTruncatedReasonBucketExactSeverityPolicyPreset:      "shared-exact",
		LimitClassDigestTruncatedReasonBucketExactSeverityPolicy:            &config.LimitClassDigestHiddenStrategyPolicy{DominantMode: "order_first", PriorityWeight: 41},
	}, map[string]config.LimitClassDigestHiddenStrategyPolicy{
		"base-exact":   {PriorityCap: 3},
		"shared-exact": {DominantMode: "weighted_score", PriorityWeight: 7},
	})

	if webhook.LimitClassDigestTruncatedReasonBucketExactSeverityPolicy == nil {
		t.Fatal("expected exact severity policy to remain set")
	}
	if webhook.LimitClassDigestTruncatedReasonBucketExactSeverityPolicy.PriorityWeight != 41 || webhook.LimitClassDigestTruncatedReasonBucketExactSeverityPolicy.DominantMode != "order_first" || webhook.LimitClassDigestTruncatedReasonBucketExactSeverityPolicy.PriorityCap != 3 {
		t.Fatalf("expected explicit exact severity policy to win over preset, got %+v", webhook.LimitClassDigestTruncatedReasonBucketExactSeverityPolicy)
	}
}

func TestShapeLimitClassDigestPayloadForReceiverHonorsDigestTypes(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Security: config.SecurityConfig{
			LimitAlertBucketClasses: map[string]config.LimitAlertBucketClassConfig{
				"vip-jwt":  {KeyType: "jwt_sub", BucketRegex: "^vip-", Priority: 10},
				"gold-jwt": {KeyType: "jwt_sub", BucketRegex: "^gold-", Priority: 7},
			},
		},
	}
	api := NewManagementAPI(mustTestGateway(t, cfg), logging.NewLogger(false), nil)

	alertPayload := managementWebhookEvent{
		Event: "gateway.limit_class_alert_digest",
		Data: map[string]interface{}{
			"alerts": []interface{}{
				map[string]interface{}{"severity": "critical", "bucket_class": "vip-jwt"},
				map[string]interface{}{"severity": "elevated", "bucket_class": "gold-jwt"},
			},
		},
	}
	snoozePayload := managementWebhookEvent{
		Event: "gateway.limit_class_snooze_expiring_digest",
		Data: map[string]interface{}{
			"snoozes": []interface{}{
				map[string]interface{}{"severity": "critical", "bucket_class": "vip-jwt"},
				map[string]interface{}{"severity": "elevated", "bucket_class": "gold-jwt"},
			},
		},
	}

	webhook := config.NotificationWebhook{
		LimitClassDigestTypes:       []string{"alert"},
		LimitClassDigestMinSeverity: "critical",
	}

	shapedAlert := api.shapeLimitClassDigestPayloadForReceiver(webhook, alertPayload)
	alerts, ok := shapedAlert.Data["alerts"].([]interface{})
	if !ok {
		t.Fatalf("expected shaped alerts slice, got %T", shapedAlert.Data["alerts"])
	}
	if len(alerts) != 1 {
		t.Fatalf("expected alert digest shaping to keep only one alert, got %d", len(alerts))
	}
	if digestTypes, ok := shapedAlert.Data["receiver_detailed_digest_types"].([]string); !ok || len(digestTypes) != 1 || digestTypes[0] != "alert" {
		t.Fatalf("expected receiver_detailed_digest_types to show alert-only shaping, got %v", shapedAlert.Data["receiver_detailed_digest_types"])
	}

	shapedSnooze := api.shapeLimitClassDigestPayloadForReceiver(webhook, snoozePayload)
	if !reflect.DeepEqual(shapedSnooze, snoozePayload) {
		t.Fatalf("expected snooze digest payload to remain unshaped when webhook only targets alert digests")
	}
}

func TestShapeLimitClassDigestPayloadForReceiverHonorsSummaryOnlyDigestTypes(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Security: config.SecurityConfig{
			LimitAlertBucketClasses: map[string]config.LimitAlertBucketClassConfig{
				"vip-jwt":  {KeyType: "jwt_sub", BucketRegex: "^vip-", Priority: 10},
				"gold-jwt": {KeyType: "jwt_sub", BucketRegex: "^gold-", Priority: 7},
			},
		},
	}
	api := NewManagementAPI(mustTestGateway(t, cfg), logging.NewLogger(false), nil)

	alertPayload := managementWebhookEvent{
		Event: "gateway.limit_class_alert_digest",
		Data: map[string]interface{}{
			"alerts": []interface{}{
				map[string]interface{}{"severity": "critical", "bucket_class": "vip-jwt"},
				map[string]interface{}{"severity": "elevated", "bucket_class": "gold-jwt"},
			},
		},
	}
	snoozePayload := managementWebhookEvent{
		Event: "gateway.limit_class_snooze_expiring_digest",
		Data: map[string]interface{}{
			"snoozes": []interface{}{
				map[string]interface{}{"severity": "critical", "bucket_class": "vip-jwt"},
				map[string]interface{}{"severity": "elevated", "bucket_class": "gold-jwt"},
			},
		},
	}

	webhook := config.NotificationWebhook{
		LimitClassDigestSummaryOnlyTypes: []string{"snooze"},
	}

	shapedAlert := api.shapeLimitClassDigestPayloadForReceiver(webhook, alertPayload)
	if !reflect.DeepEqual(shapedAlert, alertPayload) {
		t.Fatalf("expected alert digest payload to remain unchanged when only snooze digests are summary-only")
	}

	shapedSnooze := api.shapeLimitClassDigestPayloadForReceiver(webhook, snoozePayload)
	snoozes, ok := shapedSnooze.Data["snoozes"].([]interface{})
	if !ok {
		t.Fatalf("expected shaped snoozes slice, got %T", shapedSnooze.Data["snoozes"])
	}
	if len(snoozes) != 0 {
		t.Fatalf("expected summary-only snooze digest to keep no detailed snoozes, got %d", len(snoozes))
	}
	if intValue(shapedSnooze.Data["excluded_class_snooze_count"]) != 2 {
		t.Fatalf("expected summary-only snooze digest to exclude both snoozes, got %v", shapedSnooze.Data["excluded_class_snooze_count"])
	}
	if summaryTypes, ok := shapedSnooze.Data["receiver_summary_only_digest_types"].([]string); !ok || len(summaryTypes) != 1 || summaryTypes[0] != "snooze" {
		t.Fatalf("expected receiver_summary_only_digest_types to contain snooze, got %v", shapedSnooze.Data["receiver_summary_only_digest_types"])
	}
}

func TestShapeLimitClassDigestPayloadForReceiverHonorsSummaryBudget(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Security: config.SecurityConfig{
			LimitAlertBucketClasses: map[string]config.LimitAlertBucketClassConfig{
				"vip-jwt":      {KeyType: "jwt_sub", BucketRegex: "^vip-", Priority: 10},
				"gold-jwt":     {KeyType: "jwt_sub", BucketRegex: "^gold-", Priority: 7},
				"standard-jwt": {KeyType: "jwt_sub", BucketRegex: "^standard-", Priority: 5},
			},
		},
	}
	api := NewManagementAPI(mustTestGateway(t, cfg), logging.NewLogger(false), nil)

	payload := managementWebhookEvent{
		Event: "gateway.limit_class_snooze_expiring_digest",
		Data: map[string]interface{}{
			"snoozes": []interface{}{
				map[string]interface{}{"severity": "critical", "bucket_class": "vip-jwt"},
				map[string]interface{}{"severity": "elevated", "bucket_class": "gold-jwt"},
				map[string]interface{}{"severity": "warning", "bucket_class": "standard-jwt"},
			},
		},
	}

	shaped := api.shapeLimitClassDigestPayloadForReceiver(config.NotificationWebhook{
		LimitClassDigestSummaryOnlyTypes:        []string{"snooze"},
		LimitClassDigestMaxSummaryBucketClasses: 1,
	}, payload)

	snoozes, ok := shaped.Data["snoozes"].([]interface{})
	if !ok {
		t.Fatalf("expected shaped snoozes slice, got %T", shaped.Data["snoozes"])
	}
	if len(snoozes) != 0 {
		t.Fatalf("expected summary-only snooze digest to keep no detailed snoozes, got %d", len(snoozes))
	}
	var firstRow map[string]interface{}
	switch rows := shaped.Data["excluded_class_snoozes_by_class"].(type) {
	case []interface{}:
		if len(rows) != 1 {
			t.Fatalf("expected summary budget to keep one summary class detailed, got %d", len(rows))
		}
		firstRow, _ = rows[0].(map[string]interface{})
	case []map[string]interface{}:
		if len(rows) != 1 {
			t.Fatalf("expected summary budget to keep one summary class detailed, got %d", len(rows))
		}
		firstRow = rows[0]
	default:
		t.Fatalf("expected excluded_class_snoozes_by_class summary slice, got %T", shaped.Data["excluded_class_snoozes_by_class"])
	}
	if strings.TrimSpace(fmt.Sprint(firstRow["bucket_class"])) != "vip-jwt" {
		t.Fatalf("expected top-priority class to stay in summary list, got %v", firstRow["bucket_class"])
	}
	if intValue(shaped.Data["excluded_other_bucket_class_count"]) != 2 {
		t.Fatalf("expected two overflow summary classes, got %v", shaped.Data["excluded_other_bucket_class_count"])
	}
	if intValue(shaped.Data["excluded_other_snooze_count"]) != 2 {
		t.Fatalf("expected two overflow snooze rows, got %v", shaped.Data["excluded_other_snooze_count"])
	}
	if intValue(shaped.Data["receiver_detailed_max_summary_bucket_classes"]) != 1 {
		t.Fatalf("expected receiver summary budget metadata to be 1, got %v", shaped.Data["receiver_detailed_max_summary_bucket_classes"])
	}
}

func TestShapeLimitClassDigestPayloadForReceiverHonorsSummaryPriorityFloor(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Security: config.SecurityConfig{
			LimitAlertBucketClasses: map[string]config.LimitAlertBucketClassConfig{
				"vip-jwt":      {KeyType: "jwt_sub", BucketRegex: "^vip-", Priority: 10},
				"gold-jwt":     {KeyType: "jwt_sub", BucketRegex: "^gold-", Priority: 7},
				"standard-jwt": {KeyType: "jwt_sub", BucketRegex: "^standard-", Priority: 5},
			},
		},
	}
	api := NewManagementAPI(mustTestGateway(t, cfg), logging.NewLogger(false), nil)

	payload := managementWebhookEvent{
		Event: "gateway.limit_class_snooze_expiring_digest",
		Data: map[string]interface{}{
			"snoozes": []interface{}{
				map[string]interface{}{"severity": "critical", "bucket_class": "vip-jwt"},
				map[string]interface{}{"severity": "elevated", "bucket_class": "gold-jwt"},
				map[string]interface{}{"severity": "warning", "bucket_class": "standard-jwt"},
			},
		},
	}

	shaped := api.shapeLimitClassDigestPayloadForReceiver(config.NotificationWebhook{
		LimitClassDigestSummaryOnlyTypes:              []string{"snooze"},
		LimitClassDigestMinSummaryBucketClassPriority: 8,
	}, payload)

	var excludedRows []map[string]interface{}
	switch rows := shaped.Data["excluded_class_snoozes_by_class"].(type) {
	case []interface{}:
		excludedRows = make([]map[string]interface{}, 0, len(rows))
		for _, row := range rows {
			entry, _ := row.(map[string]interface{})
			excludedRows = append(excludedRows, entry)
		}
	case []map[string]interface{}:
		excludedRows = rows
	default:
		t.Fatalf("expected excluded_class_snoozes_by_class summary slice, got %T", shaped.Data["excluded_class_snoozes_by_class"])
	}
	if len(excludedRows) != 1 {
		t.Fatalf("expected summary priority floor to keep one summary class, got %d", len(excludedRows))
	}
	if strings.TrimSpace(fmt.Sprint(excludedRows[0]["bucket_class"])) != "vip-jwt" {
		t.Fatalf("expected top-priority class to remain above summary priority floor, got %v", excludedRows[0]["bucket_class"])
	}
	if intValue(shaped.Data["excluded_other_bucket_class_count"]) != 2 {
		t.Fatalf("expected two lower-priority summary classes to roll into overflow, got %v", shaped.Data["excluded_other_bucket_class_count"])
	}
	if intValue(shaped.Data["excluded_other_snooze_count"]) != 2 {
		t.Fatalf("expected two lower-priority snoozes to roll into overflow, got %v", shaped.Data["excluded_other_snooze_count"])
	}
	if intValue(shaped.Data["receiver_detailed_min_summary_bucket_class_priority"]) != 8 {
		t.Fatalf("expected receiver summary priority floor metadata to be 8, got %v", shaped.Data["receiver_detailed_min_summary_bucket_class_priority"])
	}
}

func TestShapeLimitClassDigestPayloadForReceiverHonorsSummarySeverityFloor(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Security: config.SecurityConfig{
			LimitAlertBucketClasses: map[string]config.LimitAlertBucketClassConfig{
				"vip-jwt":      {KeyType: "jwt_sub", BucketRegex: "^vip-", Priority: 10},
				"gold-jwt":     {KeyType: "jwt_sub", BucketRegex: "^gold-", Priority: 7},
				"standard-jwt": {KeyType: "jwt_sub", BucketRegex: "^standard-", Priority: 5},
			},
		},
	}
	api := NewManagementAPI(mustTestGateway(t, cfg), logging.NewLogger(false), nil)

	payload := managementWebhookEvent{
		Event: "gateway.limit_class_snooze_expiring_digest",
		Data: map[string]interface{}{
			"snoozes": []interface{}{
				map[string]interface{}{"severity": "critical", "bucket_class": "vip-jwt"},
				map[string]interface{}{"severity": "elevated", "bucket_class": "gold-jwt"},
				map[string]interface{}{"severity": "warning", "bucket_class": "standard-jwt"},
			},
		},
	}

	shaped := api.shapeLimitClassDigestPayloadForReceiver(config.NotificationWebhook{
		LimitClassDigestSummaryOnlyTypes:   []string{"snooze"},
		LimitClassDigestMinSummarySeverity: "critical",
	}, payload)

	var excludedRows []map[string]interface{}
	switch rows := shaped.Data["excluded_class_snoozes_by_class"].(type) {
	case []interface{}:
		excludedRows = make([]map[string]interface{}, 0, len(rows))
		for _, row := range rows {
			entry, _ := row.(map[string]interface{})
			excludedRows = append(excludedRows, entry)
		}
	case []map[string]interface{}:
		excludedRows = rows
	default:
		t.Fatalf("expected excluded_class_snoozes_by_class summary slice, got %T", shaped.Data["excluded_class_snoozes_by_class"])
	}
	if len(excludedRows) != 1 {
		t.Fatalf("expected summary severity floor to keep one summary class, got %d", len(excludedRows))
	}
	if strings.TrimSpace(fmt.Sprint(excludedRows[0]["bucket_class"])) != "vip-jwt" {
		t.Fatalf("expected critical class to remain above summary severity floor, got %v", excludedRows[0]["bucket_class"])
	}
	if strings.TrimSpace(fmt.Sprint(excludedRows[0]["severity"])) != "critical" {
		t.Fatalf("expected retained summary row severity to be critical, got %v", excludedRows[0]["severity"])
	}
	if intValue(shaped.Data["excluded_other_bucket_class_count"]) != 2 {
		t.Fatalf("expected two lower-severity summary classes to roll into overflow, got %v", shaped.Data["excluded_other_bucket_class_count"])
	}
	if intValue(shaped.Data["excluded_other_snooze_count"]) != 2 {
		t.Fatalf("expected two lower-severity snoozes to roll into overflow, got %v", shaped.Data["excluded_other_snooze_count"])
	}
	if strings.TrimSpace(fmt.Sprint(shaped.Data["receiver_detailed_min_summary_severity"])) != "critical" {
		t.Fatalf("expected receiver summary severity floor metadata to be critical, got %v", shaped.Data["receiver_detailed_min_summary_severity"])
	}
}

func TestShapeLimitClassDigestPayloadForReceiverHonorsSummarySortMode(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Security: config.SecurityConfig{
			LimitAlertBucketClasses: map[string]config.LimitAlertBucketClassConfig{
				"vip-jwt":      {KeyType: "jwt_sub", BucketRegex: "^vip-", Priority: 10},
				"gold-jwt":     {KeyType: "jwt_sub", BucketRegex: "^gold-", Priority: 7},
				"standard-jwt": {KeyType: "jwt_sub", BucketRegex: "^standard-", Priority: 5},
			},
		},
	}
	api := NewManagementAPI(mustTestGateway(t, cfg), logging.NewLogger(false), nil)

	payload := managementWebhookEvent{
		Event: "gateway.limit_class_snooze_expiring_digest",
		Data: map[string]interface{}{
			"snoozes": []interface{}{
				map[string]interface{}{"severity": "elevated", "bucket_class": "vip-jwt"},
				map[string]interface{}{"severity": "critical", "bucket_class": "gold-jwt"},
				map[string]interface{}{"severity": "warning", "bucket_class": "standard-jwt"},
			},
		},
	}

	shaped := api.shapeLimitClassDigestPayloadForReceiver(config.NotificationWebhook{
		LimitClassDigestSummaryOnlyTypes: []string{"snooze"},
		LimitClassDigestSummarySortMode:  "severity_first",
	}, payload)

	var excludedRows []map[string]interface{}
	switch rows := shaped.Data["excluded_class_snoozes_by_class"].(type) {
	case []interface{}:
		excludedRows = make([]map[string]interface{}, 0, len(rows))
		for _, row := range rows {
			entry, _ := row.(map[string]interface{})
			excludedRows = append(excludedRows, entry)
		}
	case []map[string]interface{}:
		excludedRows = rows
	default:
		t.Fatalf("expected excluded_class_snoozes_by_class summary slice, got %T", shaped.Data["excluded_class_snoozes_by_class"])
	}
	if len(excludedRows) != 3 {
		t.Fatalf("expected three summary rows, got %d", len(excludedRows))
	}
	if strings.TrimSpace(fmt.Sprint(excludedRows[0]["bucket_class"])) != "gold-jwt" {
		t.Fatalf("expected severity_first summary ordering to rank critical class first, got %v", excludedRows[0]["bucket_class"])
	}
	if strings.TrimSpace(fmt.Sprint(shaped.Data["receiver_detailed_summary_sort_mode"])) != "severity_first" {
		t.Fatalf("expected receiver summary sort mode metadata to be severity_first, got %v", shaped.Data["receiver_detailed_summary_sort_mode"])
	}
}

func TestShapeLimitClassDigestPayloadForReceiverHonorsCountFirstSummarySortFallbacks(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Security: config.SecurityConfig{
			LimitAlertBucketClasses: map[string]config.LimitAlertBucketClassConfig{
				"vip-jwt":  {KeyType: "jwt_sub", BucketRegex: "^vip-", Priority: 10},
				"gold-jwt": {KeyType: "jwt_sub", BucketRegex: "^gold-", Priority: 7},
			},
		},
	}
	api := NewManagementAPI(mustTestGateway(t, cfg), logging.NewLogger(false), nil)

	payload := managementWebhookEvent{
		Event: "gateway.limit_class_snooze_expiring_digest",
		Data: map[string]interface{}{
			"snoozes": []interface{}{
				map[string]interface{}{"severity": "warning", "bucket_class": "vip-jwt"},
				map[string]interface{}{"severity": "critical", "bucket_class": "gold-jwt"},
			},
		},
	}

	shaped := api.shapeLimitClassDigestPayloadForReceiver(config.NotificationWebhook{
		LimitClassDigestSummaryOnlyTypes: []string{"snooze"},
		LimitClassDigestSummarySortMode:  "count_first",
	}, payload)

	excludedRows, ok := shaped.Data["excluded_class_snoozes_by_class"].([]interface{})
	if !ok {
		t.Fatalf("expected excluded_class_snoozes_by_class summary slice, got %T", shaped.Data["excluded_class_snoozes_by_class"])
	}
	if len(excludedRows) != 2 {
		t.Fatalf("expected two summary rows, got %d", len(excludedRows))
	}
	firstRow, _ := excludedRows[0].(map[string]interface{})
	if strings.TrimSpace(fmt.Sprint(firstRow["bucket_class"])) != "vip-jwt" {
		t.Fatalf("expected count_first tie to fall back to priority before severity, got %v", firstRow["bucket_class"])
	}
}

func TestShapeLimitClassDigestPayloadForReceiverHonorsMinSummaryCount(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Security: config.SecurityConfig{
			LimitAlertBucketClasses: map[string]config.LimitAlertBucketClassConfig{
				"vip-jwt":      {KeyType: "jwt_sub", BucketRegex: "^vip-", Priority: 10},
				"gold-jwt":     {KeyType: "jwt_sub", BucketRegex: "^gold-", Priority: 9},
				"standard-jwt": {KeyType: "jwt_sub", BucketRegex: "^standard-", Priority: 5},
			},
		},
	}
	api := NewManagementAPI(mustTestGateway(t, cfg), logging.NewLogger(false), nil)

	payload := managementWebhookEvent{
		Event: "gateway.limit_class_snooze_expiring_digest",
		Data: map[string]interface{}{
			"snoozes": []interface{}{
				map[string]interface{}{"severity": "critical", "bucket_class": "vip-jwt"},
				map[string]interface{}{"severity": "critical", "bucket_class": "vip-jwt"},
				map[string]interface{}{"severity": "critical", "bucket_class": "gold-jwt"},
				map[string]interface{}{"severity": "warning", "bucket_class": "standard-jwt"},
				map[string]interface{}{"severity": "warning", "bucket_class": "standard-jwt"},
			},
		},
	}

	shaped := api.shapeLimitClassDigestPayloadForReceiver(config.NotificationWebhook{
		LimitClassDigestSummaryOnlyTypes:              []string{"snooze"},
		LimitClassDigestMinSummaryBucketClassPriority: 8,
		LimitClassDigestMinSummaryCount:               2,
		LimitClassDigestOtherBucketLabel:              "other_low_count",
		LimitClassDigestOverflowReasons:               []string{"low_priority", "low_count"},
		LimitClassDigestOverflowReasonLabels: map[string]string{
			"low_priority":       "priority_floor",
			"low_count":          "count_floor",
			"max_summary_budget": "digest_quota",
		},
		LimitClassDigestOverflowReasonGroups: map[string][]string{
			"policy_filtered": []string{"low_priority"},
		},
		LimitClassDigestOverflowReasonOrder:        []string{"count_floor", "policy_filtered"},
		LimitClassDigestMaxOverflowReasons:         1,
		LimitClassDigestTruncatedReasonBucketLabel: "suppressed_categories",
		LimitClassDigestTruncatedReasonBucketMode:  "detailed",
	}, payload)

	excludedRows, ok := shaped.Data["excluded_class_snoozes_by_class"].([]interface{})
	if !ok {
		t.Fatalf("expected excluded_class_snoozes_by_class summary slice, got %T", shaped.Data["excluded_class_snoozes_by_class"])
	}
	if len(excludedRows) != 1 {
		t.Fatalf("expected min summary count to keep one grouped class, got %d", len(excludedRows))
	}
	firstRow, _ := excludedRows[0].(map[string]interface{})
	if strings.TrimSpace(fmt.Sprint(firstRow["bucket_class"])) != "vip-jwt" {
		t.Fatalf("expected only class meeting min summary count to remain visible, got %v", firstRow["bucket_class"])
	}
	if intValue(shaped.Data["excluded_other_bucket_class_count"]) != 2 {
		t.Fatalf("expected two low-count classes to roll into overflow, got %v", shaped.Data["excluded_other_bucket_class_count"])
	}
	if intValue(shaped.Data["excluded_other_snooze_count"]) != 3 {
		t.Fatalf("expected three overflow snoozes to roll into overflow, got %v", shaped.Data["excluded_other_snooze_count"])
	}
	if intValue(shaped.Data["receiver_detailed_min_summary_count"]) != 2 {
		t.Fatalf("expected receiver min summary count metadata to be 2, got %v", shaped.Data["receiver_detailed_min_summary_count"])
	}
	if strings.TrimSpace(fmt.Sprint(shaped.Data["receiver_detailed_other_bucket_label"])) != "other_low_count" {
		t.Fatalf("expected receiver other bucket label metadata to be preserved, got %v", shaped.Data["receiver_detailed_other_bucket_label"])
	}
	otherBucket, ok := shaped.Data["excluded_other_bucket"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected excluded_other_bucket metadata map, got %T", shaped.Data["excluded_other_bucket"])
	}
	if strings.TrimSpace(fmt.Sprint(otherBucket["label"])) != "other_low_count" {
		t.Fatalf("expected custom other bucket label, got %v", otherBucket["label"])
	}
	if intValue(otherBucket["bucket_class_count"]) != 2 {
		t.Fatalf("expected two other bucket classes, got %v", otherBucket["bucket_class_count"])
	}
	if intValue(otherBucket["snooze_count"]) != 3 {
		t.Fatalf("expected three other bucket snoozes, got %v", otherBucket["snooze_count"])
	}
	if strings.TrimSpace(fmt.Sprint(otherBucket["dominant_reason"])) != "policy_filtered" {
		t.Fatalf("expected grouped dominant overflow reason, got %v", otherBucket["dominant_reason"])
	}
	if strings.TrimSpace(fmt.Sprint(otherBucket["dominant_raw_reason"])) != "low_priority" {
		t.Fatalf("expected raw dominant overflow reason to remain low_priority, got %v", otherBucket["dominant_raw_reason"])
	}
	if intValue(otherBucket["hidden_reason_count"]) != 0 {
		t.Fatalf("expected grouped visible overflow reasons to leave no hidden reasons, got %v", otherBucket["hidden_reason_count"])
	}
	if intValue(otherBucket["hidden_bucket_class_count"]) != 0 {
		t.Fatalf("expected grouped visible overflow reasons to leave no hidden overflow classes, got %v", otherBucket["hidden_bucket_class_count"])
	}
	if intValue(otherBucket["hidden_snooze_count"]) != 0 {
		t.Fatalf("expected grouped visible overflow reasons to leave no hidden overflow snoozes, got %v", otherBucket["hidden_snooze_count"])
	}
	reasonRows, ok := otherBucket["reasons"].([]interface{})
	if !ok {
		t.Fatalf("expected structured overflow reasons, got %T", otherBucket["reasons"])
	}
	if len(reasonRows) != 1 {
		t.Fatalf("expected overflow reason cap to keep one grouped row visible, got %d", len(reasonRows))
	}
	reasonRow, _ := reasonRows[0].(map[string]interface{})
	if strings.TrimSpace(fmt.Sprint(reasonRow["reason"])) != "count_floor" {
		t.Fatalf("expected custom overflow order to surface count_floor first, got %v", reasonRow["reason"])
	}
	if strings.TrimSpace(fmt.Sprint(reasonRow["raw_reason"])) != "low_count" {
		t.Fatalf("expected first ordered raw overflow reason to be low_count, got %v", reasonRow["raw_reason"])
	}
	rawReasons, ok := reasonRow["raw_reasons"].([]string)
	if !ok {
		t.Fatalf("expected grouped raw_reasons slice, got %T", reasonRow["raw_reasons"])
	}
	if len(rawReasons) != 1 || strings.TrimSpace(rawReasons[0]) != "low_count" {
		t.Fatalf("expected first ordered raw_reasons to include only low_count, got %v", rawReasons)
	}
	if intValue(reasonRow["bucket_class_count"]) != 1 {
		t.Fatalf("expected count_floor reason to include one class, got %v", reasonRow["bucket_class_count"])
	}
	if intValue(reasonRow["snooze_count"]) != 1 {
		t.Fatalf("expected count_floor reason to include one snooze, got %v", reasonRow["snooze_count"])
	}
	if intValue(otherBucket["truncated_reason_count"]) != 1 {
		t.Fatalf("expected one truncated overflow reason row, got %v", otherBucket["truncated_reason_count"])
	}
	if intValue(otherBucket["truncated_bucket_class_count"]) != 1 {
		t.Fatalf("expected one truncated overflow class, got %v", otherBucket["truncated_bucket_class_count"])
	}
	if intValue(otherBucket["truncated_snooze_count"]) != 2 {
		t.Fatalf("expected two truncated overflow snoozes, got %v", otherBucket["truncated_snooze_count"])
	}
	truncatedBucket, ok := otherBucket["truncated_reason_bucket"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected structured truncated reason bucket, got %T", otherBucket["truncated_reason_bucket"])
	}
	if strings.TrimSpace(fmt.Sprint(truncatedBucket["label"])) != "suppressed_categories" {
		t.Fatalf("expected truncated reason bucket label, got %v", truncatedBucket["label"])
	}
	if intValue(truncatedBucket["reason_count"]) != 1 {
		t.Fatalf("expected truncated reason bucket to summarize one hidden reason row, got %v", truncatedBucket["reason_count"])
	}
	if intValue(truncatedBucket["bucket_class_count"]) != 1 {
		t.Fatalf("expected truncated reason bucket to summarize one class, got %v", truncatedBucket["bucket_class_count"])
	}
	if intValue(truncatedBucket["snooze_count"]) != 2 {
		t.Fatalf("expected truncated reason bucket to summarize two snoozes, got %v", truncatedBucket["snooze_count"])
	}
	truncatedReasonRows, ok := truncatedBucket["reasons"].([]interface{})
	if !ok {
		t.Fatalf("expected detailed truncated reason rows, got %T", truncatedBucket["reasons"])
	}
	if len(truncatedReasonRows) != 1 {
		t.Fatalf("expected one truncated reason detail row, got %d", len(truncatedReasonRows))
	}
	truncatedReasonRow, _ := truncatedReasonRows[0].(map[string]interface{})
	if strings.TrimSpace(fmt.Sprint(truncatedReasonRow["reason"])) != "policy_filtered" {
		t.Fatalf("expected truncated detailed reason to retain grouped label, got %v", truncatedReasonRow["reason"])
	}
	if strings.TrimSpace(fmt.Sprint(truncatedBucket["dominant_reason"])) != "policy_filtered" {
		t.Fatalf("expected truncated bucket dominant grouped reason, got %v", truncatedBucket["dominant_reason"])
	}
	if strings.TrimSpace(fmt.Sprint(truncatedBucket["dominant_raw_reason"])) != "low_priority" {
		t.Fatalf("expected truncated bucket dominant raw reason, got %v", truncatedBucket["dominant_raw_reason"])
	}
	if intValue(shaped.Data["receiver_detailed_min_summary_bucket_class_priority"]) != 8 {
		t.Fatalf("expected receiver min summary priority metadata to be 8, got %v", shaped.Data["receiver_detailed_min_summary_bucket_class_priority"])
	}
	receiverReasons, ok := shaped.Data["receiver_detailed_overflow_reasons"].([]string)
	if !ok {
		t.Fatalf("expected receiver overflow reasons metadata slice, got %T", shaped.Data["receiver_detailed_overflow_reasons"])
	}
	if len(receiverReasons) != 2 || strings.TrimSpace(receiverReasons[0]) != "low_priority" || strings.TrimSpace(receiverReasons[1]) != "low_count" {
		t.Fatalf("expected receiver overflow reasons metadata to keep low_priority and low_count, got %v", receiverReasons)
	}
	receiverReasonLabels, ok := shaped.Data["receiver_detailed_overflow_reason_labels"].(map[string]string)
	if !ok {
		t.Fatalf("expected receiver overflow reason label metadata map, got %T", shaped.Data["receiver_detailed_overflow_reason_labels"])
	}
	if strings.TrimSpace(receiverReasonLabels["low_priority"]) != "priority_floor" {
		t.Fatalf("expected receiver low_priority overflow reason label metadata, got %v", receiverReasonLabels["low_priority"])
	}
	receiverReasonGroups, ok := shaped.Data["receiver_detailed_overflow_reason_groups"].(map[string][]string)
	if !ok {
		t.Fatalf("expected receiver overflow reason groups metadata map, got %T", shaped.Data["receiver_detailed_overflow_reason_groups"])
	}
	groupedReasons, ok := receiverReasonGroups["policy_filtered"]
	if !ok || len(groupedReasons) != 1 || strings.TrimSpace(groupedReasons[0]) != "low_priority" {
		t.Fatalf("expected receiver overflow reason group metadata for policy_filtered, got %v", receiverReasonGroups)
	}
	receiverReasonOrder, ok := shaped.Data["receiver_detailed_overflow_reason_order"].([]string)
	if !ok {
		t.Fatalf("expected receiver overflow reason order metadata slice, got %T", shaped.Data["receiver_detailed_overflow_reason_order"])
	}
	if len(receiverReasonOrder) != 2 || strings.TrimSpace(receiverReasonOrder[0]) != "count_floor" || strings.TrimSpace(receiverReasonOrder[1]) != "policy_filtered" {
		t.Fatalf("expected receiver overflow reason order metadata to preserve explicit order, got %v", receiverReasonOrder)
	}
	if intValue(shaped.Data["receiver_detailed_max_overflow_reasons"]) != 1 {
		t.Fatalf("expected receiver overflow reason cap metadata to be 1, got %v", shaped.Data["receiver_detailed_max_overflow_reasons"])
	}
	if strings.TrimSpace(fmt.Sprint(shaped.Data["receiver_detailed_truncated_reason_bucket_label"])) != "suppressed_categories" {
		t.Fatalf("expected receiver truncated reason bucket label metadata, got %v", shaped.Data["receiver_detailed_truncated_reason_bucket_label"])
	}
	if strings.TrimSpace(fmt.Sprint(shaped.Data["receiver_detailed_truncated_reason_bucket_mode"])) != "detailed" {
		t.Fatalf("expected receiver truncated reason bucket mode metadata, got %v", shaped.Data["receiver_detailed_truncated_reason_bucket_mode"])
	}
}

func TestShapeLimitClassDigestPayloadForReceiverHonorsTruncatedReasonBucketMaxReasons(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Security: config.SecurityConfig{
			LimitAlertBucketClasses: map[string]config.LimitAlertBucketClassConfig{
				"vip-jwt":      {KeyType: "jwt_sub", BucketRegex: "^vip-", Priority: 10},
				"gold-jwt":     {KeyType: "jwt_sub", BucketRegex: "^gold-", Priority: 9},
				"silver-jwt":   {KeyType: "jwt_sub", BucketRegex: "^silver-", Priority: 9},
				"standard-jwt": {KeyType: "jwt_sub", BucketRegex: "^standard-", Priority: 5},
			},
		},
	}
	api := NewManagementAPI(mustTestGateway(t, cfg), logging.NewLogger(false), nil)

	payload := managementWebhookEvent{
		Event: "gateway.limit_class_snooze_expiring_digest",
		Data: map[string]interface{}{
			"snoozes": []interface{}{
				map[string]interface{}{"severity": "critical", "bucket_class": "vip-jwt"},
				map[string]interface{}{"severity": "critical", "bucket_class": "vip-jwt"},
				map[string]interface{}{"severity": "critical", "bucket_class": "gold-jwt"},
				map[string]interface{}{"severity": "warning", "bucket_class": "silver-jwt"},
				map[string]interface{}{"severity": "warning", "bucket_class": "silver-jwt"},
				map[string]interface{}{"severity": "critical", "bucket_class": "standard-jwt"},
				map[string]interface{}{"severity": "critical", "bucket_class": "standard-jwt"},
			},
		},
	}

	shaped := api.shapeLimitClassDigestPayloadForReceiver(config.NotificationWebhook{
		LimitClassDigestSummaryOnlyTypes:              []string{"snooze"},
		LimitClassDigestMinSummaryBucketClassPriority: 8,
		LimitClassDigestMinSummarySeverity:            "critical",
		LimitClassDigestMinSummaryCount:               2,
		LimitClassDigestOtherBucketLabel:              "other_low_count",
		LimitClassDigestOverflowReasons:               []string{"low_priority", "low_count", "low_severity"},
		LimitClassDigestOverflowReasonLabels: map[string]string{
			"low_priority": "priority_floor",
			"low_count":    "count_floor",
			"low_severity": "severity_floor",
		},
		LimitClassDigestOverflowReasonGroups: map[string][]string{
			"policy_filtered": []string{"low_priority"},
		},
		LimitClassDigestOverflowReasonOrder:                              []string{"count_floor", "severity_floor", "policy_filtered"},
		LimitClassDigestMaxOverflowReasons:                               1,
		LimitClassDigestTruncatedReasonBucketLabel:                       "suppressed_categories",
		LimitClassDigestTruncatedReasonBucketMode:                        "detailed",
		LimitClassDigestTruncatedReasonBucketMinSeverity:                 "critical",
		LimitClassDigestTruncatedReasonBucketSeverities:                  []string{"critical"},
		LimitClassDigestTruncatedReasonBucketMaxReasons:                  1,
		LimitClassDigestTruncatedReasonBucketReasonOrder:                 []string{"policy_filtered", "severity_floor"},
		LimitClassDigestTruncatedReasonBucketHiddenStrategyOrder:         []string{"max_reasons", "exact_severity", "min_severity"},
		LimitClassDigestTruncatedReasonBucketHiddenStrategyDominantMode:  "order_first",
		LimitClassDigestTruncatedReasonBucketExactSeverityPolicy:         &config.LimitClassDigestHiddenStrategyPolicy{DominantMode: "weighted_score", MinReasons: 1, MinItems: 2, PriorityCap: 2, ReasonCap: 3, ItemCap: 5, PriorityWeight: 41, ReasonWeight: 43, ItemWeight: 47},
		LimitClassDigestTruncatedReasonBucketExactSeverityPriorityCap:    2,
		LimitClassDigestTruncatedReasonBucketExactSeverityReasonCap:      3,
		LimitClassDigestTruncatedReasonBucketExactSeverityItemCap:        5,
		LimitClassDigestTruncatedReasonBucketExactSeverityPriorityWeight: 7,
		LimitClassDigestTruncatedReasonBucketExactSeverityReasonWeight:   11,
		LimitClassDigestTruncatedReasonBucketExactSeverityItemWeight:     13,
		LimitClassDigestTruncatedReasonBucketExactSeverityDominantMode:   "most_hidden_reasons",
		LimitClassDigestTruncatedReasonBucketMinSeverityPriorityCap:      7,
		LimitClassDigestTruncatedReasonBucketMinSeverityReasonCap:        11,
		LimitClassDigestTruncatedReasonBucketMinSeverityItemCap:          13,
		LimitClassDigestTruncatedReasonBucketMinSeverityPriorityWeight:   17,
		LimitClassDigestTruncatedReasonBucketMinSeverityReasonWeight:     19,
		LimitClassDigestTruncatedReasonBucketMinSeverityItemWeight:       23,
		LimitClassDigestTruncatedReasonBucketMinSeverityDominantMode:     "most_hidden_items",
		LimitClassDigestTruncatedReasonBucketMaxReasonsPriorityCap:       17,
		LimitClassDigestTruncatedReasonBucketMaxReasonsReasonCap:         19,
		LimitClassDigestTruncatedReasonBucketMaxReasonsItemCap:           23,
		LimitClassDigestTruncatedReasonBucketMaxReasonsPriorityWeight:    29,
		LimitClassDigestTruncatedReasonBucketMaxReasonsReasonWeight:      31,
		LimitClassDigestTruncatedReasonBucketMaxReasonsItemWeight:        37,
		LimitClassDigestTruncatedReasonBucketMaxReasonsDominantMode:      "weighted_score",
		LimitClassDigestTruncatedReasonBucketHiddenStrategyMinReasons:    1,
		LimitClassDigestTruncatedReasonBucketHiddenStrategyMinItems:      1,
		LimitClassDigestTruncatedReasonBucketExactSeverityMinReasons:     1,
		LimitClassDigestTruncatedReasonBucketExactSeverityMinItems:       1,
	}, payload)

	otherBucket, ok := shaped.Data["excluded_other_bucket"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected excluded_other_bucket metadata map, got %T", shaped.Data["excluded_other_bucket"])
	}
	if intValue(otherBucket["truncated_reason_count"]) != 2 {
		t.Fatalf("expected two truncated overflow reason rows before nested cap, got %v", otherBucket["truncated_reason_count"])
	}
	truncatedBucket, ok := otherBucket["truncated_reason_bucket"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected structured truncated reason bucket, got %T", otherBucket["truncated_reason_bucket"])
	}
	truncatedReasonRows, ok := truncatedBucket["reasons"].([]interface{})
	if !ok {
		t.Fatalf("expected detailed truncated reason rows, got %T", truncatedBucket["reasons"])
	}
	if len(truncatedReasonRows) != 1 {
		t.Fatalf("expected nested truncation cap to keep one detailed row, got %d", len(truncatedReasonRows))
	}
	truncatedReasonRow, _ := truncatedReasonRows[0].(map[string]interface{})
	if strings.TrimSpace(fmt.Sprint(truncatedReasonRow["reason"])) != "policy_filtered" {
		t.Fatalf("expected nested truncation cap to honor nested reason order and keep policy_filtered first, got %v", truncatedReasonRow["reason"])
	}
	if intValue(truncatedBucket["hidden_reason_count"]) != 1 {
		t.Fatalf("expected one nested hidden reason after truncated bucket cap, got %v", truncatedBucket["hidden_reason_count"])
	}
	if intValue(truncatedBucket["hidden_bucket_class_count"]) != 1 {
		t.Fatalf("expected one nested hidden class after truncated bucket cap, got %v", truncatedBucket["hidden_bucket_class_count"])
	}
	if intValue(truncatedBucket["hidden_snooze_count"]) != 2 {
		t.Fatalf("expected two nested hidden snoozes after truncated bucket cap, got %v", truncatedBucket["hidden_snooze_count"])
	}
	if intValue(truncatedBucket["hidden_by_exact_severity_reason_count"]) != 1 {
		t.Fatalf("expected one nested hidden reason from exact severity selection, got %v", truncatedBucket["hidden_by_exact_severity_reason_count"])
	}
	if intValue(truncatedBucket["hidden_by_exact_severity_bucket_class_count"]) != 1 {
		t.Fatalf("expected one nested hidden class from exact severity selection, got %v", truncatedBucket["hidden_by_exact_severity_bucket_class_count"])
	}
	if intValue(truncatedBucket["hidden_by_exact_severity_snooze_count"]) != 2 {
		t.Fatalf("expected two nested hidden snoozes from exact severity selection, got %v", truncatedBucket["hidden_by_exact_severity_snooze_count"])
	}
	if intValue(truncatedBucket["hidden_by_min_severity_reason_count"]) != 0 {
		t.Fatalf("expected no nested hidden reasons from min severity after exact severity filtering, got %v", truncatedBucket["hidden_by_min_severity_reason_count"])
	}
	if intValue(truncatedBucket["hidden_by_max_reasons_reason_count"]) != 0 {
		t.Fatalf("expected no nested hidden reasons from max reason cap after exact severity filtering, got %v", truncatedBucket["hidden_by_max_reasons_reason_count"])
	}
	hiddenStrategies, ok := truncatedBucket["active_hidden_reason_strategies"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected nested hidden reason strategy metadata map, got %T", truncatedBucket["active_hidden_reason_strategies"])
	}
	exactSeverityStrategy, ok := hiddenStrategies["exact_severity"].(map[string]interface{})
	if !ok || exactSeverityStrategy["active"] != true {
		t.Fatalf("expected exact severity hidden strategy metadata to be active, got %v", hiddenStrategies["exact_severity"])
	}
	if strings.TrimSpace(fmt.Sprint(exactSeverityStrategy["dominant_mode"])) != "weighted_score" {
		t.Fatalf("expected exact severity hidden strategy dominant mode metadata, got %v", exactSeverityStrategy["dominant_mode"])
	}
	exactContributions, ok := exactSeverityStrategy["score_contributions"].(map[string]interface{})
	if !ok || intValue(exactContributions["priority_weight"]) != 41 || intValue(exactContributions["reason_weight"]) != 43 || intValue(exactContributions["item_weight"]) != 47 || intValue(exactContributions["priority_cap"]) != 2 || intValue(exactContributions["reason_cap"]) != 3 || intValue(exactContributions["item_cap"]) != 5 {
		t.Fatalf("expected exact severity strategy to preserve per-strategy weights and caps, got %v", exactSeverityStrategy["score_contributions"])
	}
	minSeverityStrategy, ok := hiddenStrategies["min_severity"].(map[string]interface{})
	if !ok || strings.TrimSpace(fmt.Sprint(minSeverityStrategy["min_severity"])) != "critical" {
		t.Fatalf("expected min severity hidden strategy metadata to preserve critical floor, got %v", hiddenStrategies["min_severity"])
	}
	if strings.TrimSpace(fmt.Sprint(minSeverityStrategy["dominant_mode"])) != "most_hidden_items" {
		t.Fatalf("expected min severity hidden strategy dominant mode metadata, got %v", minSeverityStrategy["dominant_mode"])
	}
	minContributions, ok := minSeverityStrategy["score_contributions"].(map[string]interface{})
	if !ok || intValue(minContributions["priority_weight"]) != 17 || intValue(minContributions["reason_weight"]) != 19 || intValue(minContributions["item_weight"]) != 23 || intValue(minContributions["priority_cap"]) != 7 || intValue(minContributions["reason_cap"]) != 11 || intValue(minContributions["item_cap"]) != 13 {
		t.Fatalf("expected min severity strategy to preserve per-strategy weights and caps, got %v", minSeverityStrategy["score_contributions"])
	}
	maxReasonsStrategy, ok := hiddenStrategies["max_reasons"].(map[string]interface{})
	if !ok || intValue(maxReasonsStrategy["max_reasons"]) != 1 {
		t.Fatalf("expected max reasons hidden strategy metadata to preserve nested cap, got %v", hiddenStrategies["max_reasons"])
	}
	if strings.TrimSpace(fmt.Sprint(maxReasonsStrategy["dominant_mode"])) != "weighted_score" {
		t.Fatalf("expected max reasons hidden strategy dominant mode metadata, got %v", maxReasonsStrategy["dominant_mode"])
	}
	maxContributions, ok := maxReasonsStrategy["score_contributions"].(map[string]interface{})
	if !ok || intValue(maxContributions["priority_weight"]) != 29 || intValue(maxContributions["reason_weight"]) != 31 || intValue(maxContributions["item_weight"]) != 37 || intValue(maxContributions["priority_cap"]) != 17 || intValue(maxContributions["reason_cap"]) != 19 || intValue(maxContributions["item_cap"]) != 23 {
		t.Fatalf("expected max reasons strategy to preserve per-strategy weights and caps, got %v", maxReasonsStrategy["score_contributions"])
	}
	if intValue(maxReasonsStrategy["priority"]) != 1 || maxReasonsStrategy["affected"] != false {
		t.Fatalf("expected max reasons hidden strategy metadata to preserve explicit priority and unaffected status, got %v", hiddenStrategies["max_reasons"])
	}
	if maxReasonsStrategy["eligible_for_dominance"] != false {
		t.Fatalf("expected max reasons strategy to be ineligible when it hid nothing, got %v", maxReasonsStrategy["eligible_for_dominance"])
	}
	if intValue(exactSeverityStrategy["priority"]) != 2 || exactSeverityStrategy["affected"] != true || intValue(exactSeverityStrategy["hidden_reason_count"]) != 1 {
		t.Fatalf("expected exact severity hidden strategy metadata to preserve priority and hidden counts, got %v", hiddenStrategies["exact_severity"])
	}
	if exactSeverityStrategy["eligible_for_dominance"] != true {
		t.Fatalf("expected exact severity strategy to be eligible once it meets thresholds, got %v", exactSeverityStrategy["eligible_for_dominance"])
	}
	exactEligibility, ok := exactSeverityStrategy["eligibility_thresholds"].(map[string]interface{})
	if !ok || intValue(exactEligibility["min_reasons"]) != 1 || intValue(exactEligibility["min_items"]) != 2 {
		t.Fatalf("expected exact severity strategy to expose eligibility thresholds, got %v", exactSeverityStrategy["eligibility_thresholds"])
	}
	if strings.TrimSpace(fmt.Sprint(truncatedBucket["dominant_hidden_reason_strategy"])) != "exact_severity" {
		t.Fatalf("expected dominant hidden strategy to prefer the first strategy that actually hid rows, got %v", truncatedBucket["dominant_hidden_reason_strategy"])
	}
	hiddenStrategyOrder, ok := truncatedBucket["hidden_reason_strategy_order"].([]string)
	if !ok {
		t.Fatalf("expected hidden reason strategy order slice, got %T", truncatedBucket["hidden_reason_strategy_order"])
	}
	if len(hiddenStrategyOrder) != 3 || strings.TrimSpace(hiddenStrategyOrder[0]) != "max_reasons" || strings.TrimSpace(hiddenStrategyOrder[1]) != "exact_severity" || strings.TrimSpace(hiddenStrategyOrder[2]) != "min_severity" {
		t.Fatalf("expected hidden reason strategy order to preserve explicit receiver order, got %v", hiddenStrategyOrder)
	}
	if strings.TrimSpace(fmt.Sprint(shaped.Data["receiver_detailed_truncated_reason_bucket_mode"])) != "detailed" {
		t.Fatalf("expected receiver truncated reason bucket mode metadata, got %v", shaped.Data["receiver_detailed_truncated_reason_bucket_mode"])
	}
	if intValue(shaped.Data["receiver_detailed_truncated_reason_bucket_max_reasons"]) != 1 {
		t.Fatalf("expected receiver truncated reason bucket max reasons metadata, got %v", shaped.Data["receiver_detailed_truncated_reason_bucket_max_reasons"])
	}
	nestedReasonOrder, ok := shaped.Data["receiver_detailed_truncated_reason_bucket_reason_order"].([]string)
	if !ok {
		t.Fatalf("expected receiver truncated reason bucket reason order metadata slice, got %T", shaped.Data["receiver_detailed_truncated_reason_bucket_reason_order"])
	}
	if len(nestedReasonOrder) != 2 || strings.TrimSpace(nestedReasonOrder[0]) != "policy_filtered" || strings.TrimSpace(nestedReasonOrder[1]) != "severity_floor" {
		t.Fatalf("expected receiver truncated reason bucket reason order metadata to preserve explicit nested order, got %v", nestedReasonOrder)
	}
	if strings.TrimSpace(fmt.Sprint(shaped.Data["receiver_detailed_truncated_reason_bucket_min_severity"])) != "critical" {
		t.Fatalf("expected receiver truncated reason bucket min severity metadata, got %v", shaped.Data["receiver_detailed_truncated_reason_bucket_min_severity"])
	}
	nestedSeverities, ok := shaped.Data["receiver_detailed_truncated_reason_bucket_severities"].([]string)
	if !ok {
		t.Fatalf("expected receiver truncated reason bucket severities metadata slice, got %T", shaped.Data["receiver_detailed_truncated_reason_bucket_severities"])
	}
	if len(nestedSeverities) != 1 || strings.TrimSpace(nestedSeverities[0]) != "critical" {
		t.Fatalf("expected receiver truncated reason bucket severities metadata to preserve explicit selection, got %v", nestedSeverities)
	}
	receiverHiddenStrategyOrder, ok := shaped.Data["receiver_detailed_truncated_reason_bucket_hidden_strategy_order"].([]string)
	if !ok {
		t.Fatalf("expected receiver hidden strategy order metadata slice, got %T", shaped.Data["receiver_detailed_truncated_reason_bucket_hidden_strategy_order"])
	}
	if len(receiverHiddenStrategyOrder) != 3 || strings.TrimSpace(receiverHiddenStrategyOrder[0]) != "max_reasons" || strings.TrimSpace(receiverHiddenStrategyOrder[1]) != "exact_severity" || strings.TrimSpace(receiverHiddenStrategyOrder[2]) != "min_severity" {
		t.Fatalf("expected receiver hidden strategy order metadata to preserve explicit selection, got %v", receiverHiddenStrategyOrder)
	}
	if strings.TrimSpace(fmt.Sprint(shaped.Data["receiver_detailed_truncated_reason_bucket_hidden_strategy_dominant_mode"])) != "order_first" {
		t.Fatalf("expected receiver hidden strategy dominant mode metadata, got %v", shaped.Data["receiver_detailed_truncated_reason_bucket_hidden_strategy_dominant_mode"])
	}
	if intValue(shaped.Data["receiver_detailed_truncated_reason_bucket_exact_severity_priority_cap"]) != 2 ||
		intValue(shaped.Data["receiver_detailed_truncated_reason_bucket_exact_severity_reason_cap"]) != 3 ||
		intValue(shaped.Data["receiver_detailed_truncated_reason_bucket_exact_severity_item_cap"]) != 5 {
		t.Fatalf("expected receiver exact severity cap metadata, got %v/%v/%v",
			shaped.Data["receiver_detailed_truncated_reason_bucket_exact_severity_priority_cap"],
			shaped.Data["receiver_detailed_truncated_reason_bucket_exact_severity_reason_cap"],
			shaped.Data["receiver_detailed_truncated_reason_bucket_exact_severity_item_cap"])
	}
	if intValue(shaped.Data["receiver_detailed_truncated_reason_bucket_exact_severity_priority_weight"]) != 41 ||
		intValue(shaped.Data["receiver_detailed_truncated_reason_bucket_exact_severity_reason_weight"]) != 43 ||
		intValue(shaped.Data["receiver_detailed_truncated_reason_bucket_exact_severity_item_weight"]) != 47 {
		t.Fatalf("expected receiver exact severity weight metadata, got %v/%v/%v",
			shaped.Data["receiver_detailed_truncated_reason_bucket_exact_severity_priority_weight"],
			shaped.Data["receiver_detailed_truncated_reason_bucket_exact_severity_reason_weight"],
			shaped.Data["receiver_detailed_truncated_reason_bucket_exact_severity_item_weight"])
	}
	if strings.TrimSpace(fmt.Sprint(shaped.Data["receiver_detailed_truncated_reason_bucket_exact_severity_dominant_mode"])) != "weighted_score" {
		t.Fatalf("expected receiver exact severity dominant mode metadata, got %v", shaped.Data["receiver_detailed_truncated_reason_bucket_exact_severity_dominant_mode"])
	}
	if intValue(shaped.Data["receiver_detailed_truncated_reason_bucket_min_severity_priority_cap"]) != 7 ||
		intValue(shaped.Data["receiver_detailed_truncated_reason_bucket_min_severity_reason_cap"]) != 11 ||
		intValue(shaped.Data["receiver_detailed_truncated_reason_bucket_min_severity_item_cap"]) != 13 {
		t.Fatalf("expected receiver min severity cap metadata, got %v/%v/%v",
			shaped.Data["receiver_detailed_truncated_reason_bucket_min_severity_priority_cap"],
			shaped.Data["receiver_detailed_truncated_reason_bucket_min_severity_reason_cap"],
			shaped.Data["receiver_detailed_truncated_reason_bucket_min_severity_item_cap"])
	}
	if intValue(shaped.Data["receiver_detailed_truncated_reason_bucket_min_severity_priority_weight"]) != 17 ||
		intValue(shaped.Data["receiver_detailed_truncated_reason_bucket_min_severity_reason_weight"]) != 19 ||
		intValue(shaped.Data["receiver_detailed_truncated_reason_bucket_min_severity_item_weight"]) != 23 {
		t.Fatalf("expected receiver min severity weight metadata, got %v/%v/%v",
			shaped.Data["receiver_detailed_truncated_reason_bucket_min_severity_priority_weight"],
			shaped.Data["receiver_detailed_truncated_reason_bucket_min_severity_reason_weight"],
			shaped.Data["receiver_detailed_truncated_reason_bucket_min_severity_item_weight"])
	}
	if strings.TrimSpace(fmt.Sprint(shaped.Data["receiver_detailed_truncated_reason_bucket_min_severity_dominant_mode"])) != "most_hidden_items" {
		t.Fatalf("expected receiver min severity dominant mode metadata, got %v", shaped.Data["receiver_detailed_truncated_reason_bucket_min_severity_dominant_mode"])
	}
	if intValue(shaped.Data["receiver_detailed_truncated_reason_bucket_max_reasons_priority_cap"]) != 17 ||
		intValue(shaped.Data["receiver_detailed_truncated_reason_bucket_max_reasons_reason_cap"]) != 19 ||
		intValue(shaped.Data["receiver_detailed_truncated_reason_bucket_max_reasons_item_cap"]) != 23 {
		t.Fatalf("expected receiver max reasons cap metadata, got %v/%v/%v",
			shaped.Data["receiver_detailed_truncated_reason_bucket_max_reasons_priority_cap"],
			shaped.Data["receiver_detailed_truncated_reason_bucket_max_reasons_reason_cap"],
			shaped.Data["receiver_detailed_truncated_reason_bucket_max_reasons_item_cap"])
	}
	if intValue(shaped.Data["receiver_detailed_truncated_reason_bucket_max_reasons_priority_weight"]) != 29 ||
		intValue(shaped.Data["receiver_detailed_truncated_reason_bucket_max_reasons_reason_weight"]) != 31 ||
		intValue(shaped.Data["receiver_detailed_truncated_reason_bucket_max_reasons_item_weight"]) != 37 {
		t.Fatalf("expected receiver max reasons weight metadata, got %v/%v/%v",
			shaped.Data["receiver_detailed_truncated_reason_bucket_max_reasons_priority_weight"],
			shaped.Data["receiver_detailed_truncated_reason_bucket_max_reasons_reason_weight"],
			shaped.Data["receiver_detailed_truncated_reason_bucket_max_reasons_item_weight"])
	}
	if strings.TrimSpace(fmt.Sprint(shaped.Data["receiver_detailed_truncated_reason_bucket_max_reasons_dominant_mode"])) != "weighted_score" {
		t.Fatalf("expected receiver max reasons dominant mode metadata, got %v", shaped.Data["receiver_detailed_truncated_reason_bucket_max_reasons_dominant_mode"])
	}
	if intValue(shaped.Data["receiver_detailed_truncated_reason_bucket_hidden_strategy_min_reasons"]) != 1 {
		t.Fatalf("expected receiver hidden strategy min reasons metadata, got %v", shaped.Data["receiver_detailed_truncated_reason_bucket_hidden_strategy_min_reasons"])
	}
	if intValue(shaped.Data["receiver_detailed_truncated_reason_bucket_hidden_strategy_min_items"]) != 1 {
		t.Fatalf("expected receiver hidden strategy min items metadata, got %v", shaped.Data["receiver_detailed_truncated_reason_bucket_hidden_strategy_min_items"])
	}
}

func TestLimitClassDigestDominantHiddenStrategyNameSupportsImpactModes(t *testing.T) {
	strategies := []limitClassDigestHiddenStrategySummary{
		{name: "exact_severity", mode: "order_first", priority: 1, hiddenCount: 1, hiddenItems: 1, eligible: true},
		{name: "max_reasons", mode: "most_hidden_reasons", priority: 2, hiddenCount: 2, hiddenItems: 5, eligible: true},
		{name: "min_severity", mode: "most_hidden_items", priority: 3, hiddenCount: 1, hiddenItems: 3, eligible: true},
	}

	if dominant := limitClassDigestDominantHiddenStrategyName(strategies); dominant != "exact_severity" {
		t.Fatalf("expected per-strategy dominant mode selection to preserve order_first precedence for the first strategy, got %q", dominant)
	}
}

func TestLimitClassDigestDominantHiddenStrategyNameSupportsWeightedScore(t *testing.T) {
	strategies := []limitClassDigestHiddenStrategySummary{
		{name: "exact_severity", mode: "weighted_score", priority: 1, hiddenCount: 1, hiddenItems: 1, score: 3, eligible: true},
		{name: "max_reasons", mode: "weighted_score", priority: 2, hiddenCount: 2, hiddenItems: 5, score: 9, eligible: true},
		{name: "min_severity", mode: "weighted_score", priority: 3, hiddenCount: 1, hiddenItems: 3, score: 5, eligible: true},
	}

	if dominant := limitClassDigestDominantHiddenStrategyName(strategies); dominant != "max_reasons" {
		t.Fatalf("expected weighted_score dominant strategy to prefer highest computed score, got %q", dominant)
	}
}

func TestLimitClassDigestDominantHiddenStrategyNameIgnoresIneligibleStrategies(t *testing.T) {
	strategies := []limitClassDigestHiddenStrategySummary{
		{name: "exact_severity", mode: "weighted_score", priority: 1, hiddenCount: 10, hiddenItems: 10, score: 100, eligible: false},
		{name: "max_reasons", mode: "weighted_score", priority: 2, hiddenCount: 2, hiddenItems: 5, score: 9, eligible: true},
	}

	if dominant := limitClassDigestDominantHiddenStrategyName(strategies); dominant != "max_reasons" {
		t.Fatalf("expected dominant strategy to ignore ineligible higher-score candidates, got %q", dominant)
	}
}

func TestLimitClassDigestDominantHiddenStrategyNameReturnsEmptyWhenNoStrategyEligible(t *testing.T) {
	strategies := []limitClassDigestHiddenStrategySummary{
		{name: "exact_severity", mode: "order_first", priority: 1, hiddenCount: 1, hiddenItems: 1, score: 3, eligible: false},
		{name: "max_reasons", mode: "weighted_score", priority: 2, hiddenCount: 2, hiddenItems: 5, score: 9, eligible: false},
	}

	if dominant := limitClassDigestDominantHiddenStrategyName(strategies); dominant != "" {
		t.Fatalf("expected no dominant strategy when none are eligible, got %q", dominant)
	}
}

func TestLimitClassDigestHiddenStrategyScoreHonorsCaps(t *testing.T) {
	shape := limitClassDigestReceiverShape{
		truncatedReasonBucketHiddenStrategyPriorityWeight: 2,
		truncatedReasonBucketHiddenStrategyReasonWeight:   3,
		truncatedReasonBucketHiddenStrategyItemWeight:     5,
		truncatedReasonBucketHiddenStrategyPriorityCap:    2,
		truncatedReasonBucketHiddenStrategyReasonCap:      1,
		truncatedReasonBucketHiddenStrategyItemCap:        4,
		truncatedReasonBucketHiddenStrategyOrder:          []string{"exact_severity", "min_severity", "max_reasons"},
	}

	score, contributions := limitClassDigestHiddenStrategyScore(shape, "max_reasons", 1, 3, 10)
	if score != 27 {
		t.Fatalf("expected capped weighted score to be 27, got %d", score)
	}
	if stringValue(contributions["strategy"]) != "max_reasons" {
		t.Fatalf("expected strategy contribution to be recorded, got %v", contributions["strategy"])
	}
	if intValue(contributions["priority_capped_value"]) != 2 {
		t.Fatalf("expected capped priority contribution to be 2, got %v", contributions["priority_capped_value"])
	}
	if intValue(contributions["reason_capped_value"]) != 1 {
		t.Fatalf("expected capped reason contribution to be 1, got %v", contributions["reason_capped_value"])
	}
	if intValue(contributions["item_capped_value"]) != 4 {
		t.Fatalf("expected capped item contribution to be 4, got %v", contributions["item_capped_value"])
	}
}

func TestLimitClassDigestHiddenStrategyScoreHonorsPerStrategyWeights(t *testing.T) {
	shape := limitClassDigestReceiverShape{
		truncatedReasonBucketHiddenStrategyPriorityWeight: 2,
		truncatedReasonBucketHiddenStrategyReasonWeight:   3,
		truncatedReasonBucketHiddenStrategyItemWeight:     5,
		truncatedReasonBucketExactSeverityPriorityWeight:  7,
		truncatedReasonBucketExactSeverityReasonWeight:    11,
		truncatedReasonBucketExactSeverityItemWeight:      13,
		truncatedReasonBucketHiddenStrategyOrder:          []string{"exact_severity", "min_severity", "max_reasons"},
	}

	score, contributions := limitClassDigestHiddenStrategyScore(shape, "exact_severity", 1, 2, 3)
	if score != 82 {
		t.Fatalf("expected per-strategy weighted score to be 82, got %d", score)
	}
	if intValue(contributions["priority_weight"]) != 7 || intValue(contributions["reason_weight"]) != 11 || intValue(contributions["item_weight"]) != 13 {
		t.Fatalf("expected per-strategy weights in contributions, got %v", contributions)
	}
}

func TestLimitClassDigestHiddenStrategyScoreHonorsPerStrategyCaps(t *testing.T) {
	shape := limitClassDigestReceiverShape{
		truncatedReasonBucketHiddenStrategyPriorityWeight: 2,
		truncatedReasonBucketHiddenStrategyReasonWeight:   3,
		truncatedReasonBucketHiddenStrategyItemWeight:     5,
		truncatedReasonBucketHiddenStrategyPriorityCap:    10,
		truncatedReasonBucketHiddenStrategyReasonCap:      10,
		truncatedReasonBucketHiddenStrategyItemCap:        10,
		truncatedReasonBucketExactSeverityPriorityCap:     1,
		truncatedReasonBucketExactSeverityReasonCap:       2,
		truncatedReasonBucketExactSeverityItemCap:         3,
		truncatedReasonBucketHiddenStrategyOrder:          []string{"exact_severity", "min_severity", "max_reasons"},
	}

	score, contributions := limitClassDigestHiddenStrategyScore(shape, "exact_severity", 1, 5, 7)
	if score != 23 {
		t.Fatalf("expected per-strategy capped score to be 23, got %d", score)
	}
	if intValue(contributions["priority_cap"]) != 1 || intValue(contributions["reason_cap"]) != 2 || intValue(contributions["item_cap"]) != 3 {
		t.Fatalf("expected per-strategy caps in contributions, got %v", contributions)
	}
	if intValue(contributions["priority_capped_value"]) != 1 || intValue(contributions["reason_capped_value"]) != 2 || intValue(contributions["item_capped_value"]) != 3 {
		t.Fatalf("expected capped values to honor per-strategy caps, got %v", contributions)
	}
}

func TestLimitClassDigestHiddenStrategyEligibilityHonorsThresholds(t *testing.T) {
	shape := limitClassDigestReceiverShape{
		truncatedReasonBucketHiddenStrategyMinReasons: 2,
		truncatedReasonBucketHiddenStrategyMinItems:   3,
	}

	if limitClassDigestHiddenStrategyEligible(shape, "exact_severity", 1, 5) {
		t.Fatalf("expected strategy with too few hidden reasons to be ineligible")
	}
	if limitClassDigestHiddenStrategyEligible(shape, "exact_severity", 3, 2) {
		t.Fatalf("expected strategy with too few hidden items to be ineligible")
	}
	if !limitClassDigestHiddenStrategyEligible(shape, "exact_severity", 2, 3) {
		t.Fatalf("expected strategy meeting both thresholds to be eligible")
	}
}

func TestLimitClassDigestHiddenStrategyEligibilitySupportsPerStrategyOverrides(t *testing.T) {
	shape := limitClassDigestReceiverShape{
		truncatedReasonBucketHiddenStrategyMinReasons: 3,
		truncatedReasonBucketHiddenStrategyMinItems:   4,
		truncatedReasonBucketExactSeverityMinReasons:  1,
		truncatedReasonBucketExactSeverityMinItems:    2,
	}

	thresholds := limitClassDigestHiddenStrategyEligibilityThresholds(shape, "exact_severity")
	if intValue(thresholds["min_reasons"]) != 1 || intValue(thresholds["min_items"]) != 2 {
		t.Fatalf("expected exact severity thresholds to override shared defaults, got %v", thresholds)
	}
	if !limitClassDigestHiddenStrategyEligible(shape, "exact_severity", 1, 2) {
		t.Fatalf("expected exact severity override thresholds to make the strategy eligible")
	}
	if limitClassDigestHiddenStrategyEligible(shape, "min_severity", 1, 2) {
		t.Fatalf("expected min severity to continue using shared thresholds when it has no override")
	}
}

func TestShapeLimitClassDigestPayloadForReceiverHonorsTruncatedReasonBucketSortMode(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Security: config.SecurityConfig{
			LimitAlertBucketClasses: map[string]config.LimitAlertBucketClassConfig{
				"vip-jwt":      {KeyType: "jwt_sub", BucketRegex: "^vip-", Priority: 10},
				"gold-jwt":     {KeyType: "jwt_sub", BucketRegex: "^gold-", Priority: 9},
				"silver-jwt":   {KeyType: "jwt_sub", BucketRegex: "^silver-", Priority: 9},
				"standard-jwt": {KeyType: "jwt_sub", BucketRegex: "^standard-", Priority: 5},
			},
		},
	}
	api := NewManagementAPI(mustTestGateway(t, cfg), logging.NewLogger(false), nil)

	payload := managementWebhookEvent{
		Event: "gateway.limit_class_snooze_expiring_digest",
		Data: map[string]interface{}{
			"snoozes": []interface{}{
				map[string]interface{}{"severity": "critical", "bucket_class": "vip-jwt"},
				map[string]interface{}{"severity": "critical", "bucket_class": "vip-jwt"},
				map[string]interface{}{"severity": "critical", "bucket_class": "gold-jwt"},
				map[string]interface{}{"severity": "warning", "bucket_class": "silver-jwt"},
				map[string]interface{}{"severity": "warning", "bucket_class": "silver-jwt"},
				map[string]interface{}{"severity": "critical", "bucket_class": "standard-jwt"},
				map[string]interface{}{"severity": "critical", "bucket_class": "standard-jwt"},
			},
		},
	}

	shaped := api.shapeLimitClassDigestPayloadForReceiver(config.NotificationWebhook{
		LimitClassDigestSummaryOnlyTypes:              []string{"snooze"},
		LimitClassDigestMinSummaryBucketClassPriority: 8,
		LimitClassDigestMinSummarySeverity:            "critical",
		LimitClassDigestMinSummaryCount:               2,
		LimitClassDigestOtherBucketLabel:              "other_low_count",
		LimitClassDigestOverflowReasons:               []string{"low_priority", "low_count", "low_severity"},
		LimitClassDigestOverflowReasonLabels: map[string]string{
			"low_priority": "priority_floor",
			"low_count":    "count_floor",
			"low_severity": "severity_floor",
		},
		LimitClassDigestOverflowReasonGroups: map[string][]string{
			"policy_filtered": {"low_priority"},
		},
		LimitClassDigestOverflowReasonOrder:             []string{"count_floor", "severity_floor", "policy_filtered"},
		LimitClassDigestMaxOverflowReasons:              1,
		LimitClassDigestTruncatedReasonBucketLabel:      "suppressed_categories",
		LimitClassDigestTruncatedReasonBucketMode:       "detailed",
		LimitClassDigestTruncatedReasonBucketSortMode:   "severity_first",
		LimitClassDigestTruncatedReasonBucketMaxReasons: 1,
	}, payload)

	otherBucket, ok := shaped.Data["excluded_other_bucket"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected excluded_other_bucket metadata map, got %T", shaped.Data["excluded_other_bucket"])
	}
	truncatedBucket, ok := otherBucket["truncated_reason_bucket"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected structured truncated reason bucket, got %T", otherBucket["truncated_reason_bucket"])
	}
	truncatedReasonRows, ok := truncatedBucket["reasons"].([]interface{})
	if !ok {
		t.Fatalf("expected detailed truncated reason rows, got %T", truncatedBucket["reasons"])
	}
	if len(truncatedReasonRows) != 1 {
		t.Fatalf("expected severity-first nested cap to keep one detailed row, got %d", len(truncatedReasonRows))
	}
	truncatedReasonRow, _ := truncatedReasonRows[0].(map[string]interface{})
	if strings.TrimSpace(fmt.Sprint(truncatedReasonRow["reason"])) != "policy_filtered" {
		t.Fatalf("expected severity-first nested sort to keep critical policy_filtered first, got %v", truncatedReasonRow["reason"])
	}
	if strings.TrimSpace(fmt.Sprint(shaped.Data["receiver_detailed_truncated_reason_bucket_sort_mode"])) != "severity_first" {
		t.Fatalf("expected receiver truncated reason bucket sort mode metadata, got %v", shaped.Data["receiver_detailed_truncated_reason_bucket_sort_mode"])
	}
}

func TestShapeLimitClassDigestPayloadForReceiverHonorsTruncatedReasonBucketDominantReasonStrategy(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Security: config.SecurityConfig{
			LimitAlertBucketClasses: map[string]config.LimitAlertBucketClassConfig{
				"vip-jwt":      {KeyType: "jwt_sub", BucketRegex: "^vip-", Priority: 10},
				"gold-jwt":     {KeyType: "jwt_sub", BucketRegex: "^gold-", Priority: 9},
				"silver-jwt":   {KeyType: "jwt_sub", BucketRegex: "^silver-", Priority: 9},
				"standard-jwt": {KeyType: "jwt_sub", BucketRegex: "^standard-", Priority: 5},
			},
		},
	}
	api := NewManagementAPI(mustTestGateway(t, cfg), logging.NewLogger(false), nil)

	payload := managementWebhookEvent{
		Event: "gateway.limit_class_snooze_expiring_digest",
		Data: map[string]interface{}{
			"snoozes": []interface{}{
				map[string]interface{}{"severity": "critical", "bucket_class": "vip-jwt"},
				map[string]interface{}{"severity": "critical", "bucket_class": "vip-jwt"},
				map[string]interface{}{"severity": "critical", "bucket_class": "gold-jwt"},
				map[string]interface{}{"severity": "warning", "bucket_class": "silver-jwt"},
				map[string]interface{}{"severity": "warning", "bucket_class": "silver-jwt"},
				map[string]interface{}{"severity": "critical", "bucket_class": "standard-jwt"},
				map[string]interface{}{"severity": "critical", "bucket_class": "standard-jwt"},
			},
		},
	}

	shaped := api.shapeLimitClassDigestPayloadForReceiver(config.NotificationWebhook{
		LimitClassDigestSummaryOnlyTypes:              []string{"snooze"},
		LimitClassDigestMinSummaryBucketClassPriority: 8,
		LimitClassDigestMinSummarySeverity:            "critical",
		LimitClassDigestMinSummaryCount:               2,
		LimitClassDigestOtherBucketLabel:              "other_low_count",
		LimitClassDigestOverflowReasons:               []string{"low_priority", "low_count", "low_severity"},
		LimitClassDigestOverflowReasonLabels: map[string]string{
			"low_priority": "priority_floor",
			"low_count":    "count_floor",
			"low_severity": "severity_floor",
		},
		LimitClassDigestOverflowReasonGroups: map[string][]string{
			"policy_filtered": {"low_priority"},
		},
		LimitClassDigestOverflowReasonOrder:                         []string{"count_floor", "severity_floor", "policy_filtered"},
		LimitClassDigestMaxOverflowReasons:                          1,
		LimitClassDigestTruncatedReasonBucketLabel:                  "suppressed_categories",
		LimitClassDigestTruncatedReasonBucketMode:                   "detailed",
		LimitClassDigestTruncatedReasonBucketMaxReasons:             2,
		LimitClassDigestTruncatedReasonBucketDominantReasonStrategy: "severity_first",
	}, payload)

	otherBucket, ok := shaped.Data["excluded_other_bucket"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected excluded_other_bucket metadata map, got %T", shaped.Data["excluded_other_bucket"])
	}
	truncatedBucket, ok := otherBucket["truncated_reason_bucket"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected structured truncated reason bucket, got %T", otherBucket["truncated_reason_bucket"])
	}
	if strings.TrimSpace(fmt.Sprint(truncatedBucket["dominant_reason"])) != "policy_filtered" {
		t.Fatalf("expected severity-first dominant reason strategy to choose policy_filtered, got %v", truncatedBucket["dominant_reason"])
	}
	if strings.TrimSpace(fmt.Sprint(truncatedBucket["dominant_raw_reason"])) != "low_priority" {
		t.Fatalf("expected severity-first dominant raw reason strategy to choose low_priority, got %v", truncatedBucket["dominant_raw_reason"])
	}
	if strings.TrimSpace(fmt.Sprint(shaped.Data["receiver_detailed_truncated_reason_bucket_dominant_reason_strategy"])) != "severity_first" {
		t.Fatalf("expected receiver truncated reason bucket dominant reason strategy metadata, got %v", shaped.Data["receiver_detailed_truncated_reason_bucket_dominant_reason_strategy"])
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
