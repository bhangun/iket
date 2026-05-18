package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/bhangun/iket/pkg/app"
	coreerrors "github.com/bhangun/iket/pkg/core/errors"
	"github.com/gorilla/mux"
)

func TestRegisterManagementRouteExtensionMountsRoute(t *testing.T) {
	registerManagementRouteExtensionForTest(t, "test.mount", func(api *ManagementAPI, router *mux.Router) {
		router.HandleFunc("/enterprise/ping", func(w http.ResponseWriter, r *http.Request) {
			api.writeJSON(w, map[string]string{"status": "ok"})
		}).Methods(http.MethodGet)
	})

	router := mux.NewRouter()
	(&ManagementAPI{}).RegisterRoutes(router)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/v1/enterprise/ping", nil)
	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", recorder.Code, recorder.Body.String())
	}
	var payload map[string]string
	if err := json.NewDecoder(recorder.Body).Decode(&payload); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if payload["status"] != "ok" {
		t.Fatalf("expected extension response, got %+v", payload)
	}
}

func TestRegisterManagementRouteExtensionCanUseCapabilityGuard(t *testing.T) {
	app.RegisterEdition(app.CommunityEditionInfo())
	t.Cleanup(func() {
		app.RegisterEdition(app.CommunityEditionInfo())
	})
	registerManagementRouteExtensionForTest(t, "test.capability_guard", func(api *ManagementAPI, router *mux.Router) {
		router.HandleFunc("/enterprise/billing", api.WithCapability(app.CapabilityBillingIntegration, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		})).Methods(http.MethodGet)
	})

	router := mux.NewRouter()
	(&ManagementAPI{}).RegisterRoutes(router)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/v1/enterprise/billing", nil)
	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusForbidden {
		t.Fatalf("expected status 403, got %d: %s", recorder.Code, recorder.Body.String())
	}
	var response ErrorResponse
	if err := json.NewDecoder(recorder.Body).Decode(&response); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if response.Error.Details["capability"] != app.CapabilityBillingIntegration {
		t.Fatalf("expected capability details, got %#v", response.Error.Details)
	}
}

func TestManagementRouteExtensionCatalogIncludesMetadataAndCapabilityStatus(t *testing.T) {
	app.RegisterEdition(app.CommunityEditionInfo())
	t.Cleanup(func() {
		app.RegisterEdition(app.CommunityEditionInfo())
	})
	registerManagementRouteExtensionInfoForTest(t, ManagementRouteExtensionInfo{
		Name:        "test.billing",
		Description: "Enterprise billing routes",
		Capability:  app.CapabilityBillingIntegration,
	}, func(api *ManagementAPI, router *mux.Router) {})

	catalog := CurrentManagementRouteExtensionCatalog()

	if catalog.Edition != app.EditionCommunity {
		t.Fatalf("expected community edition, got %q", catalog.Edition)
	}
	if catalog.Total != 1 {
		t.Fatalf("expected one extension, got %d", catalog.Total)
	}
	extension := catalog.Extensions[0]
	if extension.Name != "test.billing" {
		t.Fatalf("expected extension name, got %+v", extension)
	}
	if extension.Description != "Enterprise billing routes" {
		t.Fatalf("expected extension description, got %+v", extension)
	}
	if extension.Capability != app.CapabilityBillingIntegration {
		t.Fatalf("expected billing capability, got %+v", extension)
	}
	if extension.Category != "commercial" {
		t.Fatalf("expected category derived from primary capability, got %+v", extension)
	}
	if len(extension.Capabilities) != 1 || extension.Capabilities[0] != app.CapabilityBillingIntegration {
		t.Fatalf("expected normalized capability list, got %+v", extension.Capabilities)
	}
	if extension.Supported {
		t.Fatalf("expected billing extension to be unsupported in community edition")
	}
	if extension.SupportStatus != ManagementRouteExtensionStatusCapabilityUnavailable {
		t.Fatalf("expected unavailable status, got %+v", extension)
	}
	if len(extension.UnsupportedCapabilities) != 1 || extension.UnsupportedCapabilities[0].Key != app.CapabilityBillingIntegration {
		t.Fatalf("expected unsupported billing capability details, got %+v", extension.UnsupportedCapabilities)
	}
	if extension.Message == "" {
		t.Fatalf("expected unsupported capability message, got %+v", extension)
	}
}

func TestManagementRouteExtensionCatalogMarksEnterpriseCapabilitySupported(t *testing.T) {
	app.RegisterEdition(app.EnterpriseEditionInfo())
	t.Cleanup(func() {
		app.RegisterEdition(app.CommunityEditionInfo())
	})
	registerManagementRouteExtensionInfoForTest(t, ManagementRouteExtensionInfo{
		Name:       "test.enterprise_billing",
		Capability: app.CapabilityBillingIntegration,
	}, func(api *ManagementAPI, router *mux.Router) {})

	catalog := CurrentManagementRouteExtensionCatalog()

	if catalog.Edition != app.EditionEnterprise {
		t.Fatalf("expected enterprise edition, got %q", catalog.Edition)
	}
	if catalog.Total != 1 {
		t.Fatalf("expected one extension, got %d", catalog.Total)
	}
	if !catalog.Extensions[0].Supported {
		t.Fatalf("expected billing extension to be supported in enterprise edition: %+v", catalog.Extensions[0])
	}
	if catalog.Extensions[0].SupportStatus != ManagementRouteExtensionStatusAvailable {
		t.Fatalf("expected available status, got %+v", catalog.Extensions[0])
	}
	if catalog.Extensions[0].Message != "" {
		t.Fatalf("expected no unsupported message, got %+v", catalog.Extensions[0])
	}
}

func TestManagementRouteExtensionCatalogRequiresAllCapabilities(t *testing.T) {
	app.RegisterEdition(app.CommunityEditionInfo())
	t.Cleanup(func() {
		app.RegisterEdition(app.CommunityEditionInfo())
	})
	registerManagementRouteExtensionInfoForTest(t, ManagementRouteExtensionInfo{
		Name: "test.commercial_governance",
		Capabilities: []string{
			app.CapabilityBillingIntegration,
			app.CapabilityAuditTrails,
		},
	}, func(api *ManagementAPI, router *mux.Router) {})

	catalog := CurrentManagementRouteExtensionCatalog()

	if catalog.Total != 1 {
		t.Fatalf("expected one extension, got %d", catalog.Total)
	}
	extension := catalog.Extensions[0]
	if extension.Capability != app.CapabilityBillingIntegration {
		t.Fatalf("expected first capability to be primary capability, got %+v", extension)
	}
	if len(extension.Capabilities) != 2 {
		t.Fatalf("expected two capabilities, got %+v", extension.Capabilities)
	}
	if extension.Supported {
		t.Fatalf("expected extension requiring enterprise capabilities to be unsupported")
	}
	if len(extension.UnsupportedCapabilities) != 2 {
		t.Fatalf("expected both missing capabilities, got %+v", extension.UnsupportedCapabilities)
	}
	expectedCheck := app.CheckCapabilities(app.CapabilityBillingIntegration, app.CapabilityAuditTrails)
	if extension.Message != expectedCheck.Message {
		t.Fatalf("expected central capability message %q, got %q", expectedCheck.Message, extension.Message)
	}
}

func TestManagementRouteExtensionCatalogSupportsMultiCapabilityEnterpriseExtension(t *testing.T) {
	app.RegisterEdition(app.EnterpriseEditionInfo())
	t.Cleanup(func() {
		app.RegisterEdition(app.CommunityEditionInfo())
	})
	registerManagementRouteExtensionInfoForTest(t, ManagementRouteExtensionInfo{
		Name:       "test.enterprise_governance",
		Capability: app.CapabilityBillingIntegration,
		Capabilities: []string{
			app.CapabilityBillingIntegration,
			app.CapabilityAuditTrails,
		},
	}, func(api *ManagementAPI, router *mux.Router) {})

	catalog := CurrentManagementRouteExtensionCatalog()

	if catalog.Total != 1 {
		t.Fatalf("expected one extension, got %d", catalog.Total)
	}
	extension := catalog.Extensions[0]
	if !extension.Supported {
		t.Fatalf("expected enterprise extension to be supported, got %+v", extension)
	}
	if len(extension.UnsupportedCapabilities) != 0 {
		t.Fatalf("expected no missing capabilities, got %+v", extension.UnsupportedCapabilities)
	}
	if len(extension.Capabilities) != 2 {
		t.Fatalf("expected deduplicated capability list, got %+v", extension.Capabilities)
	}
}

func TestCurrentManagementRouteExtensionReturnsResolvedExtension(t *testing.T) {
	app.RegisterEdition(app.CommunityEditionInfo())
	t.Cleanup(func() {
		app.RegisterEdition(app.CommunityEditionInfo())
	})
	registerManagementRouteExtensionInfoForTest(t, ManagementRouteExtensionInfo{
		Name:        "test.detail",
		Description: "Detailed enterprise module",
		Capability:  app.CapabilityBillingIntegration,
	}, func(api *ManagementAPI, router *mux.Router) {})

	extension, ok := CurrentManagementRouteExtension(" test.detail ")

	if !ok {
		t.Fatalf("expected extension to be found")
	}
	if extension.Name != "test.detail" || extension.Description != "Detailed enterprise module" {
		t.Fatalf("expected extension metadata, got %+v", extension)
	}
	if extension.Supported {
		t.Fatalf("expected community edition to mark billing extension unsupported")
	}
	if len(extension.UnsupportedCapabilities) != 1 || extension.UnsupportedCapabilities[0].Key != app.CapabilityBillingIntegration {
		t.Fatalf("expected missing billing capability, got %+v", extension.UnsupportedCapabilities)
	}
}

func TestManagementRouteExtensionCatalogFiltersByCapabilityAndSupport(t *testing.T) {
	app.RegisterEdition(app.CommunityEditionInfo())
	t.Cleanup(func() {
		app.RegisterEdition(app.CommunityEditionInfo())
	})
	registerManagementRouteExtensionInfoForTest(t, ManagementRouteExtensionInfo{
		Name: "test.open",
	}, func(api *ManagementAPI, router *mux.Router) {})
	registerManagementRouteExtensionInfoForTest(t, ManagementRouteExtensionInfo{
		Name:       "test.billing",
		Capability: app.CapabilityBillingIntegration,
	}, func(api *ManagementAPI, router *mux.Router) {})
	registerManagementRouteExtensionInfoForTest(t, ManagementRouteExtensionInfo{
		Name:       "test.analytics",
		Capability: app.CapabilityAdvancedAnalytics,
	}, func(api *ManagementAPI, router *mux.Router) {})
	registerManagementRouteExtensionInfoForTest(t, ManagementRouteExtensionInfo{
		Name:       "test.billing_audit",
		Capability: app.CapabilityBillingIntegration,
		Capabilities: []string{
			app.CapabilityAuditTrails,
		},
	}, func(api *ManagementAPI, router *mux.Router) {})

	unsupported := false
	catalog := CurrentManagementRouteExtensionCatalog(ManagementRouteExtensionFilter{
		Supported: &unsupported,
	})

	if catalog.Total != 3 {
		t.Fatalf("expected three unsupported extensions, got %+v", catalog)
	}
	if catalog.Filters == nil || catalog.Filters.Supported == nil || *catalog.Filters.Supported {
		t.Fatalf("expected supported=false filter echo, got %+v", catalog.Filters)
	}
	names := managementRouteExtensionNamesFromCatalog(catalog)
	if names["test.open"] {
		t.Fatalf("expected open extension to be filtered out, got %+v", names)
	}
	if !names["test.billing"] || !names["test.analytics"] || !names["test.billing_audit"] {
		t.Fatalf("expected enterprise extensions in filtered catalog, got %+v", names)
	}

	billingCatalog := CurrentManagementRouteExtensionCatalog(ManagementRouteExtensionFilter{
		Capability: app.CapabilityBillingIntegration,
		Supported:  &unsupported,
	})
	if billingCatalog.Total != 2 {
		t.Fatalf("expected two billing-capability extensions, got %+v", billingCatalog)
	}
	billingNames := managementRouteExtensionNamesFromCatalog(billingCatalog)
	if !billingNames["test.billing"] || !billingNames["test.billing_audit"] {
		t.Fatalf("expected billing capability filter to match primary and required capabilities, got %+v", billingNames)
	}

	auditCatalog := CurrentManagementRouteExtensionCatalog(ManagementRouteExtensionFilter{
		Capability: app.CapabilityAuditTrails,
		Supported:  &unsupported,
	})
	if auditCatalog.Total != 1 || auditCatalog.Extensions[0].Name != "test.billing_audit" {
		t.Fatalf("expected secondary audit capability match, got %+v", auditCatalog.Extensions)
	}
}

func TestManagementRouteExtensionCatalogFiltersByCategoryAndTag(t *testing.T) {
	app.RegisterEdition(app.CommunityEditionInfo())
	t.Cleanup(func() {
		app.RegisterEdition(app.CommunityEditionInfo())
	})
	registerManagementRouteExtensionInfoForTest(t, ManagementRouteExtensionInfo{
		Name:     "test.audit",
		Category: " Governance ",
		Tags:     []string{" Audit ", "Compliance", "audit", ""},
	}, func(api *ManagementAPI, router *mux.Router) {})
	registerManagementRouteExtensionInfoForTest(t, ManagementRouteExtensionInfo{
		Name:     "test.billing",
		Category: "commercial",
		Tags:     []string{"billing"},
	}, func(api *ManagementAPI, router *mux.Router) {})

	catalog := CurrentManagementRouteExtensionCatalog(ManagementRouteExtensionFilter{
		Category: " governance ",
		Tag:      " compliance ",
	})

	if catalog.Total != 1 {
		t.Fatalf("expected one governance compliance extension, got %+v", catalog)
	}
	if catalog.Filters == nil || catalog.Filters.Category != "governance" || catalog.Filters.Tag != "compliance" {
		t.Fatalf("expected normalized category/tag filter echo, got %+v", catalog.Filters)
	}
	extension := catalog.Extensions[0]
	if extension.Name != "test.audit" {
		t.Fatalf("expected audit extension, got %+v", extension)
	}
	if extension.Category != "governance" {
		t.Fatalf("expected normalized governance category, got %+v", extension)
	}
	if len(extension.Tags) != 2 || extension.Tags[0] != "audit" || extension.Tags[1] != "compliance" {
		t.Fatalf("expected normalized unique tags, got %+v", extension.Tags)
	}
}

func TestManagementRouteExtensionCatalogFiltersBySupportStatus(t *testing.T) {
	app.RegisterEdition(app.CommunityEditionInfo())
	t.Cleanup(func() {
		app.RegisterEdition(app.CommunityEditionInfo())
	})
	registerManagementRouteExtensionInfoForTest(t, ManagementRouteExtensionInfo{
		Name: "test.open",
	}, func(api *ManagementAPI, router *mux.Router) {})
	registerManagementRouteExtensionInfoForTest(t, ManagementRouteExtensionInfo{
		Name:       "test.billing",
		Capability: app.CapabilityBillingIntegration,
	}, func(api *ManagementAPI, router *mux.Router) {})

	catalog := CurrentManagementRouteExtensionCatalog(ManagementRouteExtensionFilter{
		SupportStatus: " capability_unavailable ",
	})

	if catalog.Total != 1 {
		t.Fatalf("expected one status-filtered extension, got %+v", catalog)
	}
	if catalog.Filters == nil || catalog.Filters.SupportStatus != ManagementRouteExtensionStatusCapabilityUnavailable {
		t.Fatalf("expected normalized support status filter echo, got %+v", catalog.Filters)
	}
	if catalog.Extensions[0].Name != "test.billing" {
		t.Fatalf("expected billing extension, got %+v", catalog.Extensions)
	}
	if catalog.Support.Total != 1 || catalog.Support.Supported != 0 || catalog.Support.Unsupported != 1 {
		t.Fatalf("expected filtered support summary, got %+v", catalog.Support)
	}
}

func TestManagementRouteExtensionCatalogFiltersByUnsupportedCapability(t *testing.T) {
	app.RegisterEdition(app.CommunityEditionInfo())
	t.Cleanup(func() {
		app.RegisterEdition(app.CommunityEditionInfo())
	})
	registerManagementRouteExtensionInfoForTest(t, ManagementRouteExtensionInfo{
		Name:       "test.billing",
		Capability: app.CapabilityBillingIntegration,
	}, func(api *ManagementAPI, router *mux.Router) {})
	registerManagementRouteExtensionInfoForTest(t, ManagementRouteExtensionInfo{
		Name: "test.audit_billing",
		Capabilities: []string{
			app.CapabilityAuditTrails,
			app.CapabilityBillingIntegration,
		},
	}, func(api *ManagementAPI, router *mux.Router) {})
	registerManagementRouteExtensionInfoForTest(t, ManagementRouteExtensionInfo{
		Name:       "test.analytics",
		Capability: app.CapabilityAdvancedAnalytics,
	}, func(api *ManagementAPI, router *mux.Router) {})

	catalog := CurrentManagementRouteExtensionCatalog(ManagementRouteExtensionFilter{
		UnsupportedCapability: " Commercial.Billing ",
	})

	if catalog.Total != 2 {
		t.Fatalf("expected two billing-blocked extensions, got %+v", catalog)
	}
	if catalog.Filters == nil || catalog.Filters.UnsupportedCapability != app.CapabilityBillingIntegration {
		t.Fatalf("expected normalized unsupported capability filter echo, got %+v", catalog.Filters)
	}
	names := managementRouteExtensionNamesFromCatalog(catalog)
	if !names["test.billing"] || !names["test.audit_billing"] || names["test.analytics"] {
		t.Fatalf("expected only billing-blocked extensions, got %+v", names)
	}
	if len(catalog.Support.UnsupportedCapabilities) != 2 {
		t.Fatalf("expected filtered unsupported capability facets, got %+v", catalog.Support.UnsupportedCapabilities)
	}
}

func TestManagementRouteExtensionCatalogIncludesDiscoverySummaries(t *testing.T) {
	app.RegisterEdition(app.CommunityEditionInfo())
	t.Cleanup(func() {
		app.RegisterEdition(app.CommunityEditionInfo())
	})
	registerManagementRouteExtensionInfoForTest(t, ManagementRouteExtensionInfo{
		Name:     "test.audit",
		Category: "governance",
		Tags:     []string{"audit", "compliance"},
	}, func(api *ManagementAPI, router *mux.Router) {})
	registerManagementRouteExtensionInfoForTest(t, ManagementRouteExtensionInfo{
		Name:       "test.billing",
		Capability: app.CapabilityBillingIntegration,
		Tags:       []string{"billing", "compliance"},
	}, func(api *ManagementAPI, router *mux.Router) {})

	catalog := CurrentManagementRouteExtensionCatalog()

	if len(catalog.ExtensionCategories) != 2 {
		t.Fatalf("expected two category summaries, got %+v", catalog.ExtensionCategories)
	}
	if catalog.ExtensionCategories[0].Category != "commercial" || catalog.ExtensionCategories[0].Total != 1 {
		t.Fatalf("expected commercial category summary first, got %+v", catalog.ExtensionCategories)
	}
	if len(catalog.ExtensionCategories[0].Extensions) != 1 || catalog.ExtensionCategories[0].Extensions[0] != "test.billing" {
		t.Fatalf("expected commercial category to reference billing extension, got %+v", catalog.ExtensionCategories[0])
	}
	if catalog.ExtensionCategories[1].Category != "governance" || catalog.ExtensionCategories[1].Total != 1 {
		t.Fatalf("expected governance category summary second, got %+v", catalog.ExtensionCategories)
	}

	if len(catalog.ExtensionTags) != 3 {
		t.Fatalf("expected three tag summaries, got %+v", catalog.ExtensionTags)
	}
	if catalog.ExtensionTags[0].Tag != "audit" || catalog.ExtensionTags[0].Total != 1 {
		t.Fatalf("expected sorted audit tag summary first, got %+v", catalog.ExtensionTags)
	}
	if catalog.ExtensionTags[1].Tag != "billing" || catalog.ExtensionTags[1].Total != 1 {
		t.Fatalf("expected sorted billing tag summary second, got %+v", catalog.ExtensionTags)
	}
	if catalog.ExtensionTags[2].Tag != "compliance" || catalog.ExtensionTags[2].Total != 2 {
		t.Fatalf("expected compliance tag summary with both extensions, got %+v", catalog.ExtensionTags)
	}
	if len(catalog.ExtensionTags[2].Extensions) != 2 ||
		catalog.ExtensionTags[2].Extensions[0] != "test.audit" ||
		catalog.ExtensionTags[2].Extensions[1] != "test.billing" {
		t.Fatalf("expected sorted compliance extension names, got %+v", catalog.ExtensionTags[2])
	}
}

func TestManagementRouteExtensionCatalogIncludesSupportSummary(t *testing.T) {
	app.RegisterEdition(app.CommunityEditionInfo())
	t.Cleanup(func() {
		app.RegisterEdition(app.CommunityEditionInfo())
	})
	registerManagementRouteExtensionInfoForTest(t, ManagementRouteExtensionInfo{
		Name: "test.open",
	}, func(api *ManagementAPI, router *mux.Router) {})
	registerManagementRouteExtensionInfoForTest(t, ManagementRouteExtensionInfo{
		Name:       "test.billing",
		Capability: app.CapabilityBillingIntegration,
	}, func(api *ManagementAPI, router *mux.Router) {})
	registerManagementRouteExtensionInfoForTest(t, ManagementRouteExtensionInfo{
		Name: "test.audit_billing",
		Capabilities: []string{
			app.CapabilityAuditTrails,
			app.CapabilityBillingIntegration,
		},
	}, func(api *ManagementAPI, router *mux.Router) {})

	catalog := CurrentManagementRouteExtensionCatalog()

	if catalog.Support.Total != 3 || catalog.Support.Supported != 1 || catalog.Support.Unsupported != 2 {
		t.Fatalf("expected support totals 3/1/2, got %+v", catalog.Support)
	}
	if len(catalog.Support.Statuses) != 2 {
		t.Fatalf("expected available and unavailable status summaries, got %+v", catalog.Support.Statuses)
	}
	if catalog.Support.Statuses[0].Status != ManagementRouteExtensionStatusAvailable || catalog.Support.Statuses[0].Total != 1 {
		t.Fatalf("expected available status summary first, got %+v", catalog.Support.Statuses)
	}
	if len(catalog.Support.Statuses[0].Extensions) != 1 || catalog.Support.Statuses[0].Extensions[0] != "test.open" {
		t.Fatalf("expected open extension in available status summary, got %+v", catalog.Support.Statuses[0])
	}
	if catalog.Support.Statuses[1].Status != ManagementRouteExtensionStatusCapabilityUnavailable || catalog.Support.Statuses[1].Total != 2 {
		t.Fatalf("expected capability unavailable status summary second, got %+v", catalog.Support.Statuses)
	}
	if len(catalog.Support.UnsupportedCapabilities) != 2 {
		t.Fatalf("expected two unsupported capability summaries, got %+v", catalog.Support.UnsupportedCapabilities)
	}
	if catalog.Support.UnsupportedCapabilities[0].Capability != app.CapabilityBillingIntegration || catalog.Support.UnsupportedCapabilities[0].Total != 2 {
		t.Fatalf("expected billing capability to block two extensions, got %+v", catalog.Support.UnsupportedCapabilities)
	}
	if catalog.Support.UnsupportedCapabilities[1].Capability != app.CapabilityAuditTrails || catalog.Support.UnsupportedCapabilities[1].Total != 1 {
		t.Fatalf("expected audit capability to block one extension, got %+v", catalog.Support.UnsupportedCapabilities)
	}
}

func TestListGatewayExtensions(t *testing.T) {
	app.RegisterEdition(app.CommunityEditionInfo())
	t.Cleanup(func() {
		app.RegisterEdition(app.CommunityEditionInfo())
	})
	registerManagementRouteExtensionInfoForTest(t, ManagementRouteExtensionInfo{
		Name:        "test.analytics",
		Description: "Enterprise analytics routes",
		Capability:  app.CapabilityAdvancedAnalytics,
	}, func(api *ManagementAPI, router *mux.Router) {})

	router := mux.NewRouter()
	(&ManagementAPI{}).RegisterRoutes(router)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/v1/gateway/extensions", nil)
	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", recorder.Code, recorder.Body.String())
	}
	var catalog ManagementRouteExtensionCatalog
	if err := json.NewDecoder(recorder.Body).Decode(&catalog); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if catalog.Total != 1 {
		t.Fatalf("expected one extension, got %+v", catalog)
	}
	if catalog.Extensions[0].Name != "test.analytics" {
		t.Fatalf("expected analytics extension, got %+v", catalog.Extensions)
	}
	if catalog.Extensions[0].Supported {
		t.Fatalf("expected enterprise analytics extension to be unsupported in community edition")
	}
}

func TestGetGatewayExtension(t *testing.T) {
	app.RegisterEdition(app.CommunityEditionInfo())
	t.Cleanup(func() {
		app.RegisterEdition(app.CommunityEditionInfo())
	})
	registerManagementRouteExtensionInfoForTest(t, ManagementRouteExtensionInfo{
		Name:        "test.detail_api",
		Description: "Extension detail response",
		Capability:  app.CapabilityAdvancedAnalytics,
	}, func(api *ManagementAPI, router *mux.Router) {})

	router := mux.NewRouter()
	(&ManagementAPI{}).RegisterRoutes(router)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/v1/gateway/extensions/test.detail_api", nil)
	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", recorder.Code, recorder.Body.String())
	}
	var extension ManagementRouteExtensionInfo
	if err := json.NewDecoder(recorder.Body).Decode(&extension); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if extension.Name != "test.detail_api" {
		t.Fatalf("expected extension detail response, got %+v", extension)
	}
	if extension.Supported {
		t.Fatalf("expected analytics extension to be unsupported in community edition")
	}
}

func TestGetGatewayExtensionReturnsNotFound(t *testing.T) {
	router := mux.NewRouter()
	(&ManagementAPI{}).RegisterRoutes(router)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/v1/gateway/extensions/missing.extension", nil)
	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusNotFound {
		t.Fatalf("expected status 404, got %d: %s", recorder.Code, recorder.Body.String())
	}
	var response ErrorResponse
	if err := json.NewDecoder(recorder.Body).Decode(&response); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if response.Error.Code != coreerrors.CodeManagementExtensionNotFound {
		t.Fatalf("expected extension not found code, got %+v", response.Error)
	}
}

func TestListGatewayExtensionsAppliesFilters(t *testing.T) {
	app.RegisterEdition(app.CommunityEditionInfo())
	t.Cleanup(func() {
		app.RegisterEdition(app.CommunityEditionInfo())
	})
	registerManagementRouteExtensionInfoForTest(t, ManagementRouteExtensionInfo{
		Name: "test.open",
	}, func(api *ManagementAPI, router *mux.Router) {})
	registerManagementRouteExtensionInfoForTest(t, ManagementRouteExtensionInfo{
		Name:       "test.billing",
		Capability: app.CapabilityBillingIntegration,
	}, func(api *ManagementAPI, router *mux.Router) {})

	router := mux.NewRouter()
	(&ManagementAPI{}).RegisterRoutes(router)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/v1/gateway/extensions?capability=commercial.billing&supported=false", nil)
	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", recorder.Code, recorder.Body.String())
	}
	var catalog ManagementRouteExtensionCatalog
	if err := json.NewDecoder(recorder.Body).Decode(&catalog); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if catalog.Total != 1 {
		t.Fatalf("expected one filtered extension, got %+v", catalog)
	}
	if catalog.Filters == nil || catalog.Filters.Capability != app.CapabilityBillingIntegration {
		t.Fatalf("expected capability filter echo, got %+v", catalog.Filters)
	}
	if catalog.Extensions[0].Name != "test.billing" {
		t.Fatalf("expected billing extension, got %+v", catalog.Extensions)
	}
}

func TestListGatewayExtensionsAppliesDiscoveryFilters(t *testing.T) {
	app.RegisterEdition(app.CommunityEditionInfo())
	t.Cleanup(func() {
		app.RegisterEdition(app.CommunityEditionInfo())
	})
	registerManagementRouteExtensionInfoForTest(t, ManagementRouteExtensionInfo{
		Name:     "test.audit_api",
		Category: "governance",
		Tags:     []string{"compliance", "audit"},
	}, func(api *ManagementAPI, router *mux.Router) {})
	registerManagementRouteExtensionInfoForTest(t, ManagementRouteExtensionInfo{
		Name:     "test.billing_api",
		Category: "commercial",
		Tags:     []string{"billing"},
	}, func(api *ManagementAPI, router *mux.Router) {})

	router := mux.NewRouter()
	(&ManagementAPI{}).RegisterRoutes(router)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/v1/gateway/extensions?category=governance&tag=compliance", nil)
	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", recorder.Code, recorder.Body.String())
	}
	var catalog ManagementRouteExtensionCatalog
	if err := json.NewDecoder(recorder.Body).Decode(&catalog); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if catalog.Total != 1 {
		t.Fatalf("expected one discovery-filtered extension, got %+v", catalog)
	}
	if catalog.Filters == nil || catalog.Filters.Category != "governance" || catalog.Filters.Tag != "compliance" {
		t.Fatalf("expected discovery filters to be echoed, got %+v", catalog.Filters)
	}
	if len(catalog.ExtensionCategories) != 1 || catalog.ExtensionCategories[0].Category != "governance" {
		t.Fatalf("expected filtered category summary, got %+v", catalog.ExtensionCategories)
	}
	if len(catalog.ExtensionTags) != 2 {
		t.Fatalf("expected returned extension tag summaries, got %+v", catalog.ExtensionTags)
	}
	if catalog.Extensions[0].Name != "test.audit_api" {
		t.Fatalf("expected audit API extension, got %+v", catalog.Extensions)
	}
}

func TestListGatewayExtensionsAppliesSupportStatusFilter(t *testing.T) {
	app.RegisterEdition(app.CommunityEditionInfo())
	t.Cleanup(func() {
		app.RegisterEdition(app.CommunityEditionInfo())
	})
	registerManagementRouteExtensionInfoForTest(t, ManagementRouteExtensionInfo{
		Name: "test.open_api",
	}, func(api *ManagementAPI, router *mux.Router) {})
	registerManagementRouteExtensionInfoForTest(t, ManagementRouteExtensionInfo{
		Name:       "test.analytics_api",
		Capability: app.CapabilityAdvancedAnalytics,
	}, func(api *ManagementAPI, router *mux.Router) {})

	router := mux.NewRouter()
	(&ManagementAPI{}).RegisterRoutes(router)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/v1/gateway/extensions?support_status=capability_unavailable", nil)
	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", recorder.Code, recorder.Body.String())
	}
	var catalog ManagementRouteExtensionCatalog
	if err := json.NewDecoder(recorder.Body).Decode(&catalog); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if catalog.Total != 1 {
		t.Fatalf("expected one support-status-filtered extension, got %+v", catalog)
	}
	if catalog.Filters == nil || catalog.Filters.SupportStatus != ManagementRouteExtensionStatusCapabilityUnavailable {
		t.Fatalf("expected support status filter echo, got %+v", catalog.Filters)
	}
	if catalog.Extensions[0].Name != "test.analytics_api" {
		t.Fatalf("expected analytics extension, got %+v", catalog.Extensions)
	}
}

func TestListGatewayExtensionsAppliesUnsupportedCapabilityFilter(t *testing.T) {
	app.RegisterEdition(app.CommunityEditionInfo())
	t.Cleanup(func() {
		app.RegisterEdition(app.CommunityEditionInfo())
	})
	registerManagementRouteExtensionInfoForTest(t, ManagementRouteExtensionInfo{
		Name:       "test.billing_api",
		Capability: app.CapabilityBillingIntegration,
	}, func(api *ManagementAPI, router *mux.Router) {})
	registerManagementRouteExtensionInfoForTest(t, ManagementRouteExtensionInfo{
		Name:       "test.analytics_api",
		Capability: app.CapabilityAdvancedAnalytics,
	}, func(api *ManagementAPI, router *mux.Router) {})

	router := mux.NewRouter()
	(&ManagementAPI{}).RegisterRoutes(router)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/v1/gateway/extensions?unsupported_capability=commercial.billing", nil)
	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", recorder.Code, recorder.Body.String())
	}
	var catalog ManagementRouteExtensionCatalog
	if err := json.NewDecoder(recorder.Body).Decode(&catalog); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if catalog.Total != 1 {
		t.Fatalf("expected one unsupported-capability-filtered extension, got %+v", catalog)
	}
	if catalog.Filters == nil || catalog.Filters.UnsupportedCapability != app.CapabilityBillingIntegration {
		t.Fatalf("expected unsupported capability filter echo, got %+v", catalog.Filters)
	}
	if catalog.Extensions[0].Name != "test.billing_api" {
		t.Fatalf("expected billing extension, got %+v", catalog.Extensions)
	}
}

func TestListGatewayExtensionsRejectsInvalidSupportedFilter(t *testing.T) {
	router := mux.NewRouter()
	(&ManagementAPI{}).RegisterRoutes(router)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/v1/gateway/extensions?supported=maybe", nil)
	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d: %s", recorder.Code, recorder.Body.String())
	}
	var response ErrorResponse
	if err := json.NewDecoder(recorder.Body).Decode(&response); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if response.Error.Message != "supported filter must be true or false" {
		t.Fatalf("expected validation message, got %+v", response.Error)
	}
}

func TestRegisterManagementRouteExtensionRejectsDuplicateName(t *testing.T) {
	registerManagementRouteExtensionForTest(t, "test.duplicate", func(api *ManagementAPI, router *mux.Router) {})

	defer func() {
		if recover() == nil {
			t.Fatalf("expected duplicate extension registration to panic")
		}
	}()
	RegisterManagementRouteExtension("test.duplicate", func(api *ManagementAPI, router *mux.Router) {})
}

func registerManagementRouteExtensionForTest(t *testing.T, name string, extension ManagementRouteExtension) {
	t.Helper()
	RegisterManagementRouteExtension(name, extension)
	name = normalizeManagementRouteExtensionInfo(ManagementRouteExtensionInfo{Name: name}).Name
	t.Cleanup(func() {
		managementRouteExtensionsMu.Lock()
		delete(managementRouteExtensions, name)
		managementRouteExtensionsMu.Unlock()
	})
}

func registerManagementRouteExtensionInfoForTest(t *testing.T, info ManagementRouteExtensionInfo, extension ManagementRouteExtension) {
	t.Helper()
	RegisterManagementRouteExtensionInfo(info, extension)
	info = normalizeManagementRouteExtensionInfo(info)
	t.Cleanup(func() {
		managementRouteExtensionsMu.Lock()
		delete(managementRouteExtensions, info.Name)
		managementRouteExtensionsMu.Unlock()
	})
}

func managementRouteExtensionNamesFromCatalog(catalog ManagementRouteExtensionCatalog) map[string]bool {
	names := make(map[string]bool, len(catalog.Extensions))
	for _, extension := range catalog.Extensions {
		names[extension.Name] = true
	}
	return names
}
