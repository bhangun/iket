package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/bhangun/iket/pkg/app"
	"github.com/gorilla/mux"
)

func TestGetGatewayEditionReturnsActiveEdition(t *testing.T) {
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/v1/gateway/edition", nil)

	(&ManagementAPI{}).getGatewayEdition(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", recorder.Code)
	}

	var info app.EditionInfo
	if err := json.NewDecoder(recorder.Body).Decode(&info); err != nil {
		t.Fatalf("failed to decode edition response: %v", err)
	}
	if info.Edition != app.EditionCommunity {
		t.Fatalf("expected community edition, got %q", info.Edition)
	}
	if len(info.Capabilities) == 0 {
		t.Fatalf("expected community capabilities")
	}
	if len(info.Categories) == 0 {
		t.Fatalf("expected community capability categories")
	}
}

func TestListGatewayCapabilitiesReturnsCatalog(t *testing.T) {
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/v1/gateway/capabilities", nil)

	(&ManagementAPI{}).listGatewayCapabilities(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", recorder.Code)
	}

	var catalog app.CapabilityCatalog
	if err := json.NewDecoder(recorder.Body).Decode(&catalog); err != nil {
		t.Fatalf("failed to decode capability catalog: %v", err)
	}
	if catalog.Edition != app.EditionCommunity {
		t.Fatalf("expected community edition, got %q", catalog.Edition)
	}
	if catalog.Total == 0 || len(catalog.Capabilities) == 0 || len(catalog.Categories) == 0 {
		t.Fatalf("expected populated capability catalog, got %+v", catalog)
	}
}

func TestListGatewayCapabilitiesFiltersByCategory(t *testing.T) {
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/v1/gateway/capabilities?category=gateway", nil)

	(&ManagementAPI{}).listGatewayCapabilities(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", recorder.Code)
	}

	var catalog app.CapabilityCatalog
	if err := json.NewDecoder(recorder.Body).Decode(&catalog); err != nil {
		t.Fatalf("failed to decode capability catalog: %v", err)
	}
	if catalog.Category != "gateway" || catalog.Total == 0 {
		t.Fatalf("expected gateway category catalog, got %+v", catalog)
	}
	for _, capability := range catalog.Capabilities {
		if capability.Category != "gateway" {
			t.Fatalf("expected only gateway capabilities, got %+v", capability)
		}
	}
}

func TestGetGatewayCapabilityReturnsCapabilityCheck(t *testing.T) {
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/v1/gateway/capabilities/gateway.runtime", nil)
	request = mux.SetURLVars(request, map[string]string{"key": app.CapabilityGatewayRuntime})

	(&ManagementAPI{}).getGatewayCapability(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", recorder.Code)
	}

	var check app.CapabilityCheck
	if err := json.NewDecoder(recorder.Body).Decode(&check); err != nil {
		t.Fatalf("failed to decode capability check: %v", err)
	}
	if !check.Supported || check.Key != app.CapabilityGatewayRuntime {
		t.Fatalf("expected supported gateway capability, got %+v", check)
	}
}

func TestGetGatewayCapabilityReportsUnsupportedCapability(t *testing.T) {
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/v1/gateway/capabilities/commercial.billing", nil)
	request = mux.SetURLVars(request, map[string]string{"key": app.CapabilityBillingIntegration})

	(&ManagementAPI{}).getGatewayCapability(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", recorder.Code)
	}

	var check app.CapabilityCheck
	if err := json.NewDecoder(recorder.Body).Decode(&check); err != nil {
		t.Fatalf("failed to decode capability check: %v", err)
	}
	if check.Supported || check.Key != app.CapabilityBillingIntegration || check.Message == "" {
		t.Fatalf("expected unsupported billing capability, got %+v", check)
	}
}

func TestPublicWithCapabilityAllowsSupportedCapability(t *testing.T) {
	called := false
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/enterprise-ready", nil)

	handler := (&ManagementAPI{}).WithCapability(app.CapabilityGatewayRuntime, func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusNoContent)
	})
	handler(recorder, request)

	if !called {
		t.Fatalf("expected wrapped handler to be called")
	}
	if recorder.Code != http.StatusNoContent {
		t.Fatalf("expected status 204, got %d", recorder.Code)
	}
}

func TestPublicWithCapabilityBlocksUnsupportedCapabilityWithDetails(t *testing.T) {
	called := false
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/enterprise-only", nil)

	handler := (&ManagementAPI{}).WithCapability(app.CapabilityBillingIntegration, func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusNoContent)
	})
	handler(recorder, request)

	if called {
		t.Fatalf("expected wrapped handler not to be called")
	}
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("expected status 403, got %d", recorder.Code)
	}

	var response ErrorResponse
	if err := json.NewDecoder(recorder.Body).Decode(&response); err != nil {
		t.Fatalf("failed to decode capability error: %v", err)
	}
	if response.Error.Code != "FORBIDDEN" {
		t.Fatalf("expected FORBIDDEN error code, got %q", response.Error.Code)
	}
	if response.Error.Details["capability"] != app.CapabilityBillingIntegration {
		t.Fatalf("expected capability detail %q, got %#v", app.CapabilityBillingIntegration, response.Error.Details)
	}
	if response.Error.Details["edition"] != app.EditionCommunity {
		t.Fatalf("expected community edition detail, got %#v", response.Error.Details)
	}
}

func TestPublicRequireCapabilityBlocksUnsupportedCapability(t *testing.T) {
	recorder := httptest.NewRecorder()

	if (&ManagementAPI{}).RequireCapability(recorder, app.CapabilityBillingIntegration) {
		t.Fatalf("expected unsupported capability to be blocked")
	}
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("expected status 403, got %d", recorder.Code)
	}
}

func TestPublicWithCapabilitiesAllowsSupportedCapabilities(t *testing.T) {
	app.RegisterEdition(app.EnterpriseEditionInfo())
	t.Cleanup(func() {
		app.RegisterEdition(app.CommunityEditionInfo())
	})
	called := false
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/enterprise-ready", nil)

	handler := (&ManagementAPI{}).WithCapabilities([]string{
		app.CapabilityBillingIntegration,
		app.CapabilityAuditTrails,
	}, func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusNoContent)
	})
	handler(recorder, request)

	if !called {
		t.Fatalf("expected wrapped handler to be called")
	}
	if recorder.Code != http.StatusNoContent {
		t.Fatalf("expected status 204, got %d", recorder.Code)
	}
}

func TestPublicWithCapabilitiesBlocksMissingCapabilitiesWithDetails(t *testing.T) {
	app.RegisterEdition(app.CommunityEditionInfo())
	called := false
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/enterprise-only", nil)

	handler := (&ManagementAPI{}).WithCapabilities([]string{
		app.CapabilityBillingIntegration,
		app.CapabilityAuditTrails,
	}, func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusNoContent)
	})
	handler(recorder, request)

	if called {
		t.Fatalf("expected wrapped handler not to be called")
	}
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("expected status 403, got %d", recorder.Code)
	}

	var response ErrorResponse
	if err := json.NewDecoder(recorder.Body).Decode(&response); err != nil {
		t.Fatalf("failed to decode capability error: %v", err)
	}
	if response.Error.Code != "FORBIDDEN" {
		t.Fatalf("expected FORBIDDEN error code, got %q", response.Error.Code)
	}
	unsupported, ok := response.Error.Details["unsupported_capabilities"].([]interface{})
	if !ok || len(unsupported) != 2 {
		t.Fatalf("expected two unsupported capability details, got %#v", response.Error.Details)
	}
	if response.Error.Details["capability"] != app.CapabilityBillingIntegration {
		t.Fatalf("expected first unsupported capability detail, got %#v", response.Error.Details)
	}
}

func TestPublicRequireCapabilitiesFailsClosedWhenEmpty(t *testing.T) {
	recorder := httptest.NewRecorder()

	if (&ManagementAPI{}).RequireCapabilities(recorder) {
		t.Fatalf("expected empty capability set to be blocked")
	}
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("expected status 403, got %d", recorder.Code)
	}
}
