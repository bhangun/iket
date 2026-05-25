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
	if extension.DisplayName != "Test Billing" {
		t.Fatalf("expected derived display name, got %+v", extension)
	}
	if extension.Description != "Enterprise billing routes" {
		t.Fatalf("expected extension description, got %+v", extension)
	}
	if extension.ReleaseStage != ManagementRouteExtensionStageStable {
		t.Fatalf("expected default stable release stage, got %+v", extension)
	}
	if extension.Compatibility.Status != ManagementRouteExtensionCompatibilityCompatible {
		t.Fatalf("expected default compatible extension, got %+v", extension.Compatibility)
	}
	if extension.Provider.Kind != ManagementRouteExtensionProviderCustom {
		t.Fatalf("expected default custom provider, got %+v", extension.Provider)
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

func TestManagementRouteExtensionCatalogIncludesRoutePrefixesAndLinks(t *testing.T) {
	app.RegisterEdition(app.CommunityEditionInfo())
	t.Cleanup(func() {
		app.RegisterEdition(app.CommunityEditionInfo())
	})
	registerManagementRouteExtensionInfoForTest(t, ManagementRouteExtensionInfo{
		Name:          "test.billing_routes",
		RoutePrefixes: []string{" enterprise/billing/ ", "/enterprise/billing", "/"},
		Links: []ManagementRouteExtensionLink{
			{
				Rel:   " Docs ",
				URL:   " /docs/enterprise/billing ",
				Label: " Billing Docs ",
			},
			{
				Rel:   ManagementRouteExtensionLinkRelDocs,
				URL:   "/docs/enterprise/billing",
				Label: "Duplicate ignored",
			},
			{
				Rel: ManagementRouteExtensionLinkRelSupport,
				URL: "mailto:support@example.com",
			},
		},
	}, func(api *ManagementAPI, router *mux.Router) {})

	catalog := CurrentManagementRouteExtensionCatalog()

	if catalog.Total != 1 {
		t.Fatalf("expected one extension, got %+v", catalog)
	}
	extension := catalog.Extensions[0]
	if len(extension.RoutePrefixes) != 1 || extension.RoutePrefixes[0] != "/enterprise/billing" {
		t.Fatalf("expected normalized unique route prefixes, got %+v", extension.RoutePrefixes)
	}
	if len(extension.Links) != 2 {
		t.Fatalf("expected normalized unique links, got %+v", extension.Links)
	}
	if extension.Links[0].Rel != ManagementRouteExtensionLinkRelDocs ||
		extension.Links[0].URL != "/docs/enterprise/billing" ||
		extension.Links[0].Label != "Billing Docs" {
		t.Fatalf("expected normalized docs link, got %+v", extension.Links[0])
	}
	if extension.Links[1].Rel != ManagementRouteExtensionLinkRelSupport ||
		extension.Links[1].URL != "mailto:support@example.com" {
		t.Fatalf("expected normalized support link, got %+v", extension.Links[1])
	}
	if len(catalog.ExtensionRoutes) != 1 ||
		catalog.ExtensionRoutes[0].RoutePrefix != "/enterprise/billing" ||
		catalog.ExtensionRoutes[0].Total != 1 {
		t.Fatalf("expected route prefix summary, got %+v", catalog.ExtensionRoutes)
	}
	if len(catalog.ExtensionLinkRels) != 2 ||
		catalog.ExtensionLinkRels[0].Rel != ManagementRouteExtensionLinkRelDocs ||
		catalog.ExtensionLinkRels[1].Rel != ManagementRouteExtensionLinkRelSupport {
		t.Fatalf("expected link rel summaries, got %+v", catalog.ExtensionLinkRels)
	}

	routeCatalog := CurrentManagementRouteExtensionCatalog(ManagementRouteExtensionFilter{
		Search: "enterprise/billing",
	})
	if routeCatalog.Total != 1 || routeCatalog.Extensions[0].Name != "test.billing_routes" {
		t.Fatalf("expected route prefix to be searchable, got %+v", routeCatalog.Extensions)
	}

	linkCatalog := CurrentManagementRouteExtensionCatalog(ManagementRouteExtensionFilter{
		Search: "billing docs",
	})
	if linkCatalog.Total != 1 || linkCatalog.Extensions[0].Name != "test.billing_routes" {
		t.Fatalf("expected link label to be searchable, got %+v", linkCatalog.Extensions)
	}
}

func TestManagementRouteExtensionCatalogFiltersByRoutePrefixAndLinkRel(t *testing.T) {
	app.RegisterEdition(app.CommunityEditionInfo())
	t.Cleanup(func() {
		app.RegisterEdition(app.CommunityEditionInfo())
	})
	registerManagementRouteExtensionInfoForTest(t, ManagementRouteExtensionInfo{
		Name:          "test.billing_routes",
		RoutePrefixes: []string{"/enterprise/billing"},
		Links: []ManagementRouteExtensionLink{
			{Rel: ManagementRouteExtensionLinkRelDocs, URL: "/docs/enterprise/billing"},
		},
	}, func(api *ManagementAPI, router *mux.Router) {})
	registerManagementRouteExtensionInfoForTest(t, ManagementRouteExtensionInfo{
		Name:          "test.audit_routes",
		RoutePrefixes: []string{"/enterprise/audit"},
		Links: []ManagementRouteExtensionLink{
			{Rel: ManagementRouteExtensionLinkRelInstall, URL: "/install/enterprise/audit"},
		},
	}, func(api *ManagementAPI, router *mux.Router) {})

	catalog := CurrentManagementRouteExtensionCatalog(ManagementRouteExtensionFilter{
		RoutePrefix: " enterprise ",
		LinkRel:     " Docs ",
	})

	if catalog.Total != 1 {
		t.Fatalf("expected one route/link-filtered extension, got %+v", catalog)
	}
	if catalog.Filters == nil ||
		catalog.Filters.RoutePrefix != "/enterprise" ||
		catalog.Filters.LinkRel != ManagementRouteExtensionLinkRelDocs {
		t.Fatalf("expected normalized route/link filter echo, got %+v", catalog.Filters)
	}
	if catalog.Extensions[0].Name != "test.billing_routes" {
		t.Fatalf("expected billing route extension, got %+v", catalog.Extensions)
	}
	if len(catalog.ExtensionRoutes) != 1 || catalog.ExtensionRoutes[0].RoutePrefix != "/enterprise/billing" {
		t.Fatalf("expected filtered route facets, got %+v", catalog.ExtensionRoutes)
	}
	if len(catalog.ExtensionLinkRels) != 1 || catalog.ExtensionLinkRels[0].Rel != ManagementRouteExtensionLinkRelDocs {
		t.Fatalf("expected filtered link rel facets, got %+v", catalog.ExtensionLinkRels)
	}
}

func TestManagementRouteExtensionCatalogFiltersByProvider(t *testing.T) {
	app.RegisterEdition(app.CommunityEditionInfo())
	t.Cleanup(func() {
		app.RegisterEdition(app.CommunityEditionInfo())
	})
	registerManagementRouteExtensionInfoForTest(t, ManagementRouteExtensionInfo{
		Name: "test.enterprise_provider",
		Provider: ManagementRouteExtensionProvider{
			Kind: ManagementRouteExtensionProviderEnterprise,
			Name: " Iket Enterprise ",
			URL:  " https://enterprise.example.com ",
		},
	}, func(api *ManagementAPI, router *mux.Router) {})
	registerManagementRouteExtensionInfoForTest(t, ManagementRouteExtensionInfo{
		Name: "test.partner_provider",
		Provider: ManagementRouteExtensionProvider{
			Kind: ManagementRouteExtensionProviderPartner,
			Name: "Partner Co",
		},
	}, func(api *ManagementAPI, router *mux.Router) {})

	catalog := CurrentManagementRouteExtensionCatalog(ManagementRouteExtensionFilter{
		ProviderKind: " Enterprise ",
		ProviderName: " iket enterprise ",
	})

	if catalog.Total != 1 {
		t.Fatalf("expected one provider-filtered extension, got %+v", catalog)
	}
	if catalog.Filters == nil ||
		catalog.Filters.ProviderKind != ManagementRouteExtensionProviderEnterprise ||
		catalog.Filters.ProviderName != "iket enterprise" {
		t.Fatalf("expected normalized provider filters, got %+v", catalog.Filters)
	}
	extension := catalog.Extensions[0]
	if extension.Name != "test.enterprise_provider" {
		t.Fatalf("expected enterprise provider extension, got %+v", catalog.Extensions)
	}
	if extension.Provider.Kind != ManagementRouteExtensionProviderEnterprise ||
		extension.Provider.Name != "Iket Enterprise" ||
		extension.Provider.URL != "https://enterprise.example.com" {
		t.Fatalf("expected normalized provider metadata, got %+v", extension.Provider)
	}
	if len(catalog.ExtensionProviders) != 1 ||
		catalog.ExtensionProviders[0].Kind != ManagementRouteExtensionProviderEnterprise ||
		catalog.ExtensionProviders[0].Total != 1 ||
		len(catalog.ExtensionProviders[0].Providers) != 1 ||
		catalog.ExtensionProviders[0].Providers[0] != "Iket Enterprise" {
		t.Fatalf("expected filtered provider summary, got %+v", catalog.ExtensionProviders)
	}

	searchCatalog := CurrentManagementRouteExtensionCatalog(ManagementRouteExtensionFilter{
		Search: "enterprise.example.com",
	})
	if searchCatalog.Total != 1 || searchCatalog.Extensions[0].Name != "test.enterprise_provider" {
		t.Fatalf("expected provider URL to be searchable, got %+v", searchCatalog.Extensions)
	}
}

func TestManagementRouteExtensionCatalogFiltersByPermission(t *testing.T) {
	app.RegisterEdition(app.CommunityEditionInfo())
	t.Cleanup(func() {
		app.RegisterEdition(app.CommunityEditionInfo())
	})
	registerManagementRouteExtensionInfoForTest(t, ManagementRouteExtensionInfo{
		Name: "test.billing_permissions",
		Permissions: []ManagementRouteExtensionPermission{
			{
				Key:         " Billing.Read ",
				Name:        " Read Billing ",
				Description: "View billing records",
			},
			{
				Key:         "billing.write",
				Description: "Update billing records",
			},
			{
				Key:  "billing.read",
				Name: "Duplicate ignored",
			},
		},
	}, func(api *ManagementAPI, router *mux.Router) {})
	registerManagementRouteExtensionInfoForTest(t, ManagementRouteExtensionInfo{
		Name: "test.audit_permissions",
		Permissions: []ManagementRouteExtensionPermission{
			{Key: "audit.read"},
		},
	}, func(api *ManagementAPI, router *mux.Router) {})

	catalog := CurrentManagementRouteExtensionCatalog(ManagementRouteExtensionFilter{
		Permission: " Billing.Read ",
	})

	if catalog.Total != 1 {
		t.Fatalf("expected one permission-filtered extension, got %+v", catalog)
	}
	if catalog.Filters == nil || catalog.Filters.Permission != "billing.read" {
		t.Fatalf("expected normalized permission filter, got %+v", catalog.Filters)
	}
	extension := catalog.Extensions[0]
	if extension.Name != "test.billing_permissions" {
		t.Fatalf("expected billing permissions extension, got %+v", catalog.Extensions)
	}
	if len(extension.Permissions) != 2 {
		t.Fatalf("expected normalized unique permissions, got %+v", extension.Permissions)
	}
	if extension.Permissions[0].Key != "billing.read" ||
		extension.Permissions[0].Name != "Read Billing" ||
		extension.Permissions[0].Description != "View billing records" {
		t.Fatalf("expected normalized read permission, got %+v", extension.Permissions[0])
	}
	if extension.Permissions[1].Key != "billing.write" ||
		extension.Permissions[1].Name != "Billing Write" {
		t.Fatalf("expected derived write permission name, got %+v", extension.Permissions[1])
	}
	permissionNames := managementRouteExtensionPermissionNamesFromCatalog(catalog)
	if !permissionNames["billing.read"] || !permissionNames["billing.write"] || permissionNames["audit.read"] {
		t.Fatalf("expected permission facets for returned extension, got %+v", permissionNames)
	}

	searchCatalog := CurrentManagementRouteExtensionCatalog(ManagementRouteExtensionFilter{
		Search: "update billing",
	})
	if searchCatalog.Total != 1 || searchCatalog.Extensions[0].Name != "test.billing_permissions" {
		t.Fatalf("expected permission description to be searchable, got %+v", searchCatalog.Extensions)
	}
}

func TestManagementRouteExtensionCatalogFiltersByCompatibility(t *testing.T) {
	previousVersion := app.Version
	app.Version = "1.4.0"
	app.RegisterEdition(app.CommunityEditionInfo())
	t.Cleanup(func() {
		app.Version = previousVersion
		app.RegisterEdition(app.CommunityEditionInfo())
	})
	registerManagementRouteExtensionInfoForTest(t, ManagementRouteExtensionInfo{
		Name:    "test.compatible_version",
		Version: "1.2.3",
		Compatibility: ManagementRouteExtensionCompatibility{
			MinimumIketVersion: "1.0.0",
			MaximumIketVersion: "1.5.0",
		},
	}, func(api *ManagementAPI, router *mux.Router) {})
	registerManagementRouteExtensionInfoForTest(t, ManagementRouteExtensionInfo{
		Name:    "test.incompatible_version",
		Version: "2.0.0",
		Compatibility: ManagementRouteExtensionCompatibility{
			MinimumIketVersion: "2.0.0",
		},
	}, func(api *ManagementAPI, router *mux.Router) {})

	catalog := CurrentManagementRouteExtensionCatalog(ManagementRouteExtensionFilter{
		CompatibilityStatus: " Incompatible ",
	})

	if catalog.Total != 1 {
		t.Fatalf("expected one compatibility-filtered extension, got %+v", catalog)
	}
	if catalog.Filters == nil || catalog.Filters.CompatibilityStatus != ManagementRouteExtensionCompatibilityIncompatible {
		t.Fatalf("expected normalized compatibility filter, got %+v", catalog.Filters)
	}
	extension := catalog.Extensions[0]
	if extension.Name != "test.incompatible_version" {
		t.Fatalf("expected incompatible extension, got %+v", catalog.Extensions)
	}
	if extension.Version != "2.0.0" {
		t.Fatalf("expected normalized extension version, got %+v", extension)
	}
	if extension.Compatibility.Status != ManagementRouteExtensionCompatibilityIncompatible ||
		extension.Compatibility.Message == "" {
		t.Fatalf("expected incompatible status and message, got %+v", extension.Compatibility)
	}
	if len(catalog.ExtensionCompatibility) != 1 ||
		catalog.ExtensionCompatibility[0].Status != ManagementRouteExtensionCompatibilityIncompatible ||
		catalog.ExtensionCompatibility[0].Total != 1 {
		t.Fatalf("expected filtered compatibility summary, got %+v", catalog.ExtensionCompatibility)
	}

	searchCatalog := CurrentManagementRouteExtensionCatalog(ManagementRouteExtensionFilter{
		Search: "2.0.0",
	})
	if searchCatalog.Total != 1 || searchCatalog.Extensions[0].Name != "test.incompatible_version" {
		t.Fatalf("expected compatibility version to be searchable, got %+v", searchCatalog.Extensions)
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

func TestManagementRouteExtensionCatalogFiltersByReleaseStage(t *testing.T) {
	app.RegisterEdition(app.CommunityEditionInfo())
	t.Cleanup(func() {
		app.RegisterEdition(app.CommunityEditionInfo())
	})
	registerManagementRouteExtensionInfoForTest(t, ManagementRouteExtensionInfo{
		Name:         "test.preview",
		ReleaseStage: " Preview ",
	}, func(api *ManagementAPI, router *mux.Router) {})
	registerManagementRouteExtensionInfoForTest(t, ManagementRouteExtensionInfo{
		Name: "test.stable",
	}, func(api *ManagementAPI, router *mux.Router) {})

	catalog := CurrentManagementRouteExtensionCatalog(ManagementRouteExtensionFilter{
		ReleaseStage: " preview ",
	})

	if catalog.Total != 1 {
		t.Fatalf("expected one release-stage-filtered extension, got %+v", catalog)
	}
	if catalog.Filters == nil || catalog.Filters.ReleaseStage != ManagementRouteExtensionStagePreview {
		t.Fatalf("expected normalized release stage filter echo, got %+v", catalog.Filters)
	}
	if catalog.Extensions[0].Name != "test.preview" {
		t.Fatalf("expected preview extension, got %+v", catalog.Extensions)
	}
	if catalog.Extensions[0].ReleaseStage != ManagementRouteExtensionStagePreview {
		t.Fatalf("expected normalized preview release stage, got %+v", catalog.Extensions[0])
	}
	if len(catalog.ExtensionStages) != 1 ||
		catalog.ExtensionStages[0].ReleaseStage != ManagementRouteExtensionStagePreview ||
		catalog.ExtensionStages[0].Total != 1 {
		t.Fatalf("expected filtered release stage summary, got %+v", catalog.ExtensionStages)
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

func TestManagementRouteExtensionCatalogFiltersBySearch(t *testing.T) {
	app.RegisterEdition(app.CommunityEditionInfo())
	t.Cleanup(func() {
		app.RegisterEdition(app.CommunityEditionInfo())
	})
	registerManagementRouteExtensionInfoForTest(t, ManagementRouteExtensionInfo{
		Name:        "test.billing",
		DisplayName: "Revenue Desk",
		Description: "Subscription automation",
		Category:    "commercial",
		Tags:        []string{"billing"},
		Capability:  app.CapabilityBillingIntegration,
	}, func(api *ManagementAPI, router *mux.Router) {})
	registerManagementRouteExtensionInfoForTest(t, ManagementRouteExtensionInfo{
		Name:        "test.audit",
		Description: "Governance event archive",
		Category:    "governance",
		Tags:        []string{"audit"},
		Capability:  app.CapabilityAuditTrails,
	}, func(api *ManagementAPI, router *mux.Router) {})

	catalog := CurrentManagementRouteExtensionCatalog(ManagementRouteExtensionFilter{
		Search: " Revenue ",
	})

	if catalog.Total != 1 {
		t.Fatalf("expected one search-filtered extension, got %+v", catalog)
	}
	if catalog.Filters == nil || catalog.Filters.Search != "revenue" {
		t.Fatalf("expected normalized search filter echo, got %+v", catalog.Filters)
	}
	if catalog.Extensions[0].Name != "test.billing" {
		t.Fatalf("expected billing extension, got %+v", catalog.Extensions)
	}
	if catalog.Extensions[0].DisplayName != "Revenue Desk" {
		t.Fatalf("expected explicit display name, got %+v", catalog.Extensions[0])
	}
	if len(catalog.ExtensionCategories) != 1 || catalog.ExtensionCategories[0].Category != "commercial" {
		t.Fatalf("expected facets to reflect filtered extensions, got %+v", catalog.ExtensionCategories)
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

func TestListGatewayExtensionsAppliesReleaseStageFilter(t *testing.T) {
	app.RegisterEdition(app.CommunityEditionInfo())
	t.Cleanup(func() {
		app.RegisterEdition(app.CommunityEditionInfo())
	})
	registerManagementRouteExtensionInfoForTest(t, ManagementRouteExtensionInfo{
		Name:         "test.preview_api",
		ReleaseStage: ManagementRouteExtensionStagePreview,
	}, func(api *ManagementAPI, router *mux.Router) {})
	registerManagementRouteExtensionInfoForTest(t, ManagementRouteExtensionInfo{
		Name:         "test.deprecated_api",
		ReleaseStage: ManagementRouteExtensionStageDeprecated,
	}, func(api *ManagementAPI, router *mux.Router) {})

	router := mux.NewRouter()
	(&ManagementAPI{}).RegisterRoutes(router)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/v1/gateway/extensions?release_stage=preview", nil)
	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", recorder.Code, recorder.Body.String())
	}
	var catalog ManagementRouteExtensionCatalog
	if err := json.NewDecoder(recorder.Body).Decode(&catalog); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if catalog.Total != 1 {
		t.Fatalf("expected one release-stage-filtered extension, got %+v", catalog)
	}
	if catalog.Filters == nil || catalog.Filters.ReleaseStage != ManagementRouteExtensionStagePreview {
		t.Fatalf("expected release stage filter echo, got %+v", catalog.Filters)
	}
	if catalog.Extensions[0].Name != "test.preview_api" {
		t.Fatalf("expected preview API extension, got %+v", catalog.Extensions)
	}
}

func TestListGatewayExtensionsAppliesRoutePrefixAndLinkRelFilters(t *testing.T) {
	app.RegisterEdition(app.CommunityEditionInfo())
	t.Cleanup(func() {
		app.RegisterEdition(app.CommunityEditionInfo())
	})
	registerManagementRouteExtensionInfoForTest(t, ManagementRouteExtensionInfo{
		Name:          "test.billing_route_api",
		RoutePrefixes: []string{"/enterprise/billing"},
		Links: []ManagementRouteExtensionLink{
			{Rel: ManagementRouteExtensionLinkRelDocs, URL: "/docs/enterprise/billing"},
		},
	}, func(api *ManagementAPI, router *mux.Router) {})
	registerManagementRouteExtensionInfoForTest(t, ManagementRouteExtensionInfo{
		Name:          "test.audit_route_api",
		RoutePrefixes: []string{"/enterprise/audit"},
		Links: []ManagementRouteExtensionLink{
			{Rel: ManagementRouteExtensionLinkRelInstall, URL: "/install/enterprise/audit"},
		},
	}, func(api *ManagementAPI, router *mux.Router) {})

	router := mux.NewRouter()
	(&ManagementAPI{}).RegisterRoutes(router)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/v1/gateway/extensions?route_prefix=enterprise&link_rel=docs", nil)
	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", recorder.Code, recorder.Body.String())
	}
	var catalog ManagementRouteExtensionCatalog
	if err := json.NewDecoder(recorder.Body).Decode(&catalog); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if catalog.Total != 1 {
		t.Fatalf("expected one route/link-filtered extension, got %+v", catalog)
	}
	if catalog.Filters == nil ||
		catalog.Filters.RoutePrefix != "/enterprise" ||
		catalog.Filters.LinkRel != ManagementRouteExtensionLinkRelDocs {
		t.Fatalf("expected route/link filter echo, got %+v", catalog.Filters)
	}
	if catalog.Extensions[0].Name != "test.billing_route_api" {
		t.Fatalf("expected billing route API extension, got %+v", catalog.Extensions)
	}
}

func TestListGatewayExtensionsAppliesProviderFilters(t *testing.T) {
	app.RegisterEdition(app.CommunityEditionInfo())
	t.Cleanup(func() {
		app.RegisterEdition(app.CommunityEditionInfo())
	})
	registerManagementRouteExtensionInfoForTest(t, ManagementRouteExtensionInfo{
		Name: "test.enterprise_provider_api",
		Provider: ManagementRouteExtensionProvider{
			Kind: ManagementRouteExtensionProviderEnterprise,
			Name: "Iket Enterprise",
		},
	}, func(api *ManagementAPI, router *mux.Router) {})
	registerManagementRouteExtensionInfoForTest(t, ManagementRouteExtensionInfo{
		Name: "test.custom_provider_api",
		Provider: ManagementRouteExtensionProvider{
			Kind: ManagementRouteExtensionProviderCustom,
			Name: "Local Ops",
		},
	}, func(api *ManagementAPI, router *mux.Router) {})

	router := mux.NewRouter()
	(&ManagementAPI{}).RegisterRoutes(router)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/v1/gateway/extensions?provider_kind=enterprise&provider=Iket%20Enterprise", nil)
	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", recorder.Code, recorder.Body.String())
	}
	var catalog ManagementRouteExtensionCatalog
	if err := json.NewDecoder(recorder.Body).Decode(&catalog); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if catalog.Total != 1 {
		t.Fatalf("expected one provider-filtered extension, got %+v", catalog)
	}
	if catalog.Filters == nil ||
		catalog.Filters.ProviderKind != ManagementRouteExtensionProviderEnterprise ||
		catalog.Filters.ProviderName != "iket enterprise" {
		t.Fatalf("expected provider filter echo, got %+v", catalog.Filters)
	}
	if catalog.Extensions[0].Name != "test.enterprise_provider_api" {
		t.Fatalf("expected enterprise provider API extension, got %+v", catalog.Extensions)
	}
}

func TestListGatewayExtensionsAppliesPermissionFilter(t *testing.T) {
	app.RegisterEdition(app.CommunityEditionInfo())
	t.Cleanup(func() {
		app.RegisterEdition(app.CommunityEditionInfo())
	})
	registerManagementRouteExtensionInfoForTest(t, ManagementRouteExtensionInfo{
		Name: "test.billing_permission_api",
		Permissions: []ManagementRouteExtensionPermission{
			{Key: "billing.read"},
		},
	}, func(api *ManagementAPI, router *mux.Router) {})
	registerManagementRouteExtensionInfoForTest(t, ManagementRouteExtensionInfo{
		Name: "test.audit_permission_api",
		Permissions: []ManagementRouteExtensionPermission{
			{Key: "audit.read"},
		},
	}, func(api *ManagementAPI, router *mux.Router) {})

	router := mux.NewRouter()
	(&ManagementAPI{}).RegisterRoutes(router)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/v1/gateway/extensions?permission=billing.read", nil)
	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", recorder.Code, recorder.Body.String())
	}
	var catalog ManagementRouteExtensionCatalog
	if err := json.NewDecoder(recorder.Body).Decode(&catalog); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if catalog.Total != 1 {
		t.Fatalf("expected one permission-filtered extension, got %+v", catalog)
	}
	if catalog.Filters == nil || catalog.Filters.Permission != "billing.read" {
		t.Fatalf("expected permission filter echo, got %+v", catalog.Filters)
	}
	if catalog.Extensions[0].Name != "test.billing_permission_api" {
		t.Fatalf("expected billing permission API extension, got %+v", catalog.Extensions)
	}
}

func TestListGatewayExtensionsAppliesCompatibilityFilter(t *testing.T) {
	previousVersion := app.Version
	app.Version = "1.4.0"
	app.RegisterEdition(app.CommunityEditionInfo())
	t.Cleanup(func() {
		app.Version = previousVersion
		app.RegisterEdition(app.CommunityEditionInfo())
	})
	registerManagementRouteExtensionInfoForTest(t, ManagementRouteExtensionInfo{
		Name: "test.compatible_api",
		Compatibility: ManagementRouteExtensionCompatibility{
			MinimumIketVersion: "1.0.0",
		},
	}, func(api *ManagementAPI, router *mux.Router) {})
	registerManagementRouteExtensionInfoForTest(t, ManagementRouteExtensionInfo{
		Name: "test.incompatible_api",
		Compatibility: ManagementRouteExtensionCompatibility{
			MaximumIketVersion: "1.0.0",
		},
	}, func(api *ManagementAPI, router *mux.Router) {})

	router := mux.NewRouter()
	(&ManagementAPI{}).RegisterRoutes(router)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/v1/gateway/extensions?compatibility_status=incompatible", nil)
	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", recorder.Code, recorder.Body.String())
	}
	var catalog ManagementRouteExtensionCatalog
	if err := json.NewDecoder(recorder.Body).Decode(&catalog); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if catalog.Total != 1 {
		t.Fatalf("expected one compatibility-filtered extension, got %+v", catalog)
	}
	if catalog.Filters == nil || catalog.Filters.CompatibilityStatus != ManagementRouteExtensionCompatibilityIncompatible {
		t.Fatalf("expected compatibility filter echo, got %+v", catalog.Filters)
	}
	if catalog.Extensions[0].Name != "test.incompatible_api" {
		t.Fatalf("expected incompatible API extension, got %+v", catalog.Extensions)
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

func TestListGatewayExtensionsAppliesSearchFilter(t *testing.T) {
	app.RegisterEdition(app.CommunityEditionInfo())
	t.Cleanup(func() {
		app.RegisterEdition(app.CommunityEditionInfo())
	})
	registerManagementRouteExtensionInfoForTest(t, ManagementRouteExtensionInfo{
		Name:        "test.billing_search_api",
		Description: "Subscription invoice operations",
		Tags:        []string{"billing"},
	}, func(api *ManagementAPI, router *mux.Router) {})
	registerManagementRouteExtensionInfoForTest(t, ManagementRouteExtensionInfo{
		Name:        "test.audit_search_api",
		Description: "Governance event archive",
		Tags:        []string{"audit"},
	}, func(api *ManagementAPI, router *mux.Router) {})

	router := mux.NewRouter()
	(&ManagementAPI{}).RegisterRoutes(router)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/v1/gateway/extensions?q=invoice", nil)
	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", recorder.Code, recorder.Body.String())
	}
	var catalog ManagementRouteExtensionCatalog
	if err := json.NewDecoder(recorder.Body).Decode(&catalog); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if catalog.Total != 1 {
		t.Fatalf("expected one search-filtered extension, got %+v", catalog)
	}
	if catalog.Filters == nil || catalog.Filters.Search != "invoice" {
		t.Fatalf("expected search filter echo, got %+v", catalog.Filters)
	}
	if catalog.Extensions[0].Name != "test.billing_search_api" {
		t.Fatalf("expected billing search extension, got %+v", catalog.Extensions)
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

func TestRegisterManagementRouteExtensionNormalizesTrimmedName(t *testing.T) {
	registerManagementRouteExtensionForTest(t, " test.trimmed_name ", func(api *ManagementAPI, router *mux.Router) {})

	extension, ok := CurrentManagementRouteExtension("test.trimmed_name")
	if !ok {
		t.Fatalf("expected trimmed extension name to be registered")
	}
	if extension.Name != "test.trimmed_name" {
		t.Fatalf("expected normalized extension name, got %+v", extension)
	}
}

func TestRegisterManagementRouteExtensionRejectsInvalidName(t *testing.T) {
	invalidNames := []string{
		"Test.Uppercase",
		"test extension",
		"test/extension",
		".test",
		"test.",
		"test:extension",
	}
	for _, name := range invalidNames {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Fatalf("expected invalid extension name %q to panic", name)
				}
			}()
			RegisterManagementRouteExtension(name, func(api *ManagementAPI, router *mux.Router) {})
		})
	}
}

func TestRegisterManagementRouteExtensionRejectsInvalidReleaseStage(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatalf("expected invalid release stage to panic")
		}
	}()
	RegisterManagementRouteExtensionInfo(ManagementRouteExtensionInfo{
		Name:         "test.bad_stage",
		ReleaseStage: "experimental",
	}, func(api *ManagementAPI, router *mux.Router) {})
}

func TestRegisterManagementRouteExtensionRejectsInvalidCompatibility(t *testing.T) {
	tests := []struct {
		name string
		info ManagementRouteExtensionInfo
	}{
		{
			name: "invalid extension version",
			info: ManagementRouteExtensionInfo{
				Name:    "test.bad_extension_version",
				Version: "1.0 beta",
			},
		},
		{
			name: "invalid minimum version",
			info: ManagementRouteExtensionInfo{
				Name: "test.bad_minimum_version",
				Compatibility: ManagementRouteExtensionCompatibility{
					MinimumIketVersion: "new",
				},
			},
		},
		{
			name: "invalid range",
			info: ManagementRouteExtensionInfo{
				Name: "test.bad_version_range",
				Compatibility: ManagementRouteExtensionCompatibility{
					MinimumIketVersion: "2.0.0",
					MaximumIketVersion: "1.0.0",
				},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Fatalf("expected invalid compatibility metadata to panic")
				}
			}()
			RegisterManagementRouteExtensionInfo(test.info, func(api *ManagementAPI, router *mux.Router) {})
		})
	}
}

func TestRegisterManagementRouteExtensionRejectsInvalidProvider(t *testing.T) {
	tests := []struct {
		name string
		info ManagementRouteExtensionInfo
	}{
		{
			name: "invalid kind",
			info: ManagementRouteExtensionInfo{
				Name: "test.bad_provider_kind",
				Provider: ManagementRouteExtensionProvider{
					Kind: "official",
				},
			},
		},
		{
			name: "invalid url",
			info: ManagementRouteExtensionInfo{
				Name: "test.bad_provider_url",
				Provider: ManagementRouteExtensionProvider{
					Kind: ManagementRouteExtensionProviderEnterprise,
					URL:  "https://enterprise.example.com/docs with spaces",
				},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Fatalf("expected invalid provider to panic")
				}
			}()
			RegisterManagementRouteExtensionInfo(test.info, func(api *ManagementAPI, router *mux.Router) {})
		})
	}
}

func TestRegisterManagementRouteExtensionRejectsInvalidPermission(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatalf("expected invalid permission to panic")
		}
	}()
	RegisterManagementRouteExtensionInfo(ManagementRouteExtensionInfo{
		Name: "test.bad_permission",
		Permissions: []ManagementRouteExtensionPermission{
			{Key: "Billing Read"},
		},
	}, func(api *ManagementAPI, router *mux.Router) {})
}

func TestRegisterManagementRouteExtensionRejectsInvalidRoutePrefix(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatalf("expected invalid route prefix to panic")
		}
	}()
	RegisterManagementRouteExtensionInfo(ManagementRouteExtensionInfo{
		Name:          "test.bad_route_prefix",
		RoutePrefixes: []string{"/enterprise billing"},
	}, func(api *ManagementAPI, router *mux.Router) {})
}

func TestRegisterManagementRouteExtensionRejectsInvalidLink(t *testing.T) {
	tests := []struct {
		name string
		info ManagementRouteExtensionInfo
	}{
		{
			name: "invalid rel",
			info: ManagementRouteExtensionInfo{
				Name: "test.bad_link_rel",
				Links: []ManagementRouteExtensionLink{
					{Rel: "docs link", URL: "/docs"},
				},
			},
		},
		{
			name: "missing url",
			info: ManagementRouteExtensionInfo{
				Name: "test.bad_link_url",
				Links: []ManagementRouteExtensionLink{
					{Rel: ManagementRouteExtensionLinkRelDocs},
				},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Fatalf("expected invalid link to panic")
				}
			}()
			RegisterManagementRouteExtensionInfo(test.info, func(api *ManagementAPI, router *mux.Router) {})
		})
	}
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

func managementRouteExtensionPermissionNamesFromCatalog(catalog ManagementRouteExtensionCatalog) map[string]bool {
	names := make(map[string]bool, len(catalog.ExtensionPermissions))
	for _, permission := range catalog.ExtensionPermissions {
		names[permission.Permission] = true
	}
	return names
}
