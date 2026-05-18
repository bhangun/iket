package app

import "testing"

func TestCurrentEditionDefaultsToCommunity(t *testing.T) {
	RegisterEdition(CommunityEditionInfo())

	info := CurrentEdition()
	if info.Edition != EditionCommunity {
		t.Fatalf("expected community edition, got %q", info.Edition)
	}
	if info.DisplayName == "" {
		t.Fatalf("expected display name")
	}
	if !SupportsCapability(CapabilityGatewayRuntime) {
		t.Fatalf("expected community gateway runtime capability")
	}
}

func TestCommunityEditionInfoReturnsDefensiveCopy(t *testing.T) {
	first := CommunityEditionInfo()
	if len(first.Capabilities) == 0 {
		t.Fatalf("expected community capabilities")
	}
	first.Capabilities[0].Key = "mutated"

	second := CommunityEditionInfo()
	if hasCapability(second, "mutated") {
		t.Fatalf("expected community edition profile to be defensive")
	}
	if !hasCapability(second, CapabilityGatewayRuntime) {
		t.Fatalf("expected gateway runtime capability")
	}
	if len(second.Categories) == 0 {
		t.Fatalf("expected community capability categories")
	}
}

func TestRegisterEditionNormalizesEnterpriseMetadata(t *testing.T) {
	defer RegisterEdition(CommunityEditionInfo())

	RegisterEdition(EditionInfo{
		Product: "iket",
		Edition: EditionEnterprise,
		Capabilities: []Capability{
			{Key: " TENANT.WORKSPACES ", Name: "Workspaces", Category: "tenancy"},
			{Key: CapabilityTenantWorkspaces, Name: "Duplicate", Category: "tenancy"},
			{Key: ""},
		},
	})

	info := CurrentEdition()
	if info.Edition != EditionEnterprise {
		t.Fatalf("expected enterprise edition, got %q", info.Edition)
	}
	if info.DisplayName != "iket Enterprise" {
		t.Fatalf("expected generated display name, got %q", info.DisplayName)
	}
	if len(info.Capabilities) != 1 {
		t.Fatalf("expected one normalized capability, got %d", len(info.Capabilities))
	}
	if !SupportsCapability(CapabilityTenantWorkspaces) {
		t.Fatalf("expected registered enterprise capability")
	}
}

func TestEnterpriseEditionInfoExtendsCommunityProfile(t *testing.T) {
	info := EnterpriseEditionInfo(Capability{
		Key:         "commercial.usage_export",
		Name:        "Usage Export",
		Category:    "commercial",
		Description: "Export tenant usage data for finance systems.",
	})

	if info.Edition != EditionEnterprise {
		t.Fatalf("expected enterprise edition, got %q", info.Edition)
	}
	if info.DisplayName != "Iket Enterprise" {
		t.Fatalf("expected enterprise display name, got %q", info.DisplayName)
	}
	if !hasCapability(info, CapabilityGatewayRuntime) {
		t.Fatalf("expected enterprise profile to keep community gateway runtime capability")
	}
	if !hasCapability(info, CapabilityBillingIntegration) {
		t.Fatalf("expected enterprise profile to include billing capability")
	}
	if !hasCapability(info, "commercial.usage_export") {
		t.Fatalf("expected enterprise profile to include extra capability")
	}
	if !hasCategory(info, "commercial") {
		t.Fatalf("expected enterprise profile to include commercial category")
	}
	if !hasCategory(info, "tenancy") {
		t.Fatalf("expected enterprise profile to include tenancy category")
	}
}

func TestCheckCapabilityNormalizesKeyAndReportsEdition(t *testing.T) {
	RegisterEdition(CommunityEditionInfo())

	check := CheckCapability("  GATEWAY.RUNTIME ")
	if !check.Supported {
		t.Fatalf("expected gateway runtime capability to be supported: %+v", check)
	}
	if check.Key != CapabilityGatewayRuntime {
		t.Fatalf("expected normalized key %q, got %q", CapabilityGatewayRuntime, check.Key)
	}
	if check.Edition != EditionCommunity || check.DisplayName == "" {
		t.Fatalf("expected community edition details, got %+v", check)
	}
}

func TestRequireCapabilityReturnsUnavailableError(t *testing.T) {
	RegisterEdition(CommunityEditionInfo())

	err := RequireCapability(CapabilityBillingIntegration)
	if err == nil {
		t.Fatalf("expected capability error")
	}
	if !IsCapabilityUnavailable(err) {
		t.Fatalf("expected capability unavailable error, got %T", err)
	}
}

func TestCheckCapabilitiesReportsAllMissingCapabilities(t *testing.T) {
	RegisterEdition(CommunityEditionInfo())

	check := CheckCapabilities(CapabilityGatewayRuntime, CapabilityBillingIntegration, CapabilityAuditTrails)

	if check.Supported {
		t.Fatalf("expected mixed community/enterprise capabilities to be unsupported")
	}
	if len(check.Capabilities) != 3 {
		t.Fatalf("expected three capability checks, got %+v", check.Capabilities)
	}
	if len(check.UnsupportedCapabilities) != 2 {
		t.Fatalf("expected two unsupported capabilities, got %+v", check.UnsupportedCapabilities)
	}
	if check.UnsupportedCapabilities[0].Key != CapabilityBillingIntegration || check.UnsupportedCapabilities[1].Key != CapabilityAuditTrails {
		t.Fatalf("expected billing and audit to be missing, got %+v", check.UnsupportedCapabilities)
	}
	if check.Message == "" {
		t.Fatalf("expected aggregate missing capability message")
	}
}

func TestCheckCapabilitiesDeduplicatesAndSupportsEnterpriseSet(t *testing.T) {
	RegisterEdition(EnterpriseEditionInfo())
	t.Cleanup(func() {
		RegisterEdition(CommunityEditionInfo())
	})

	check := CheckCapabilities(" COMMERCIAL.BILLING ", CapabilityBillingIntegration, CapabilityAuditTrails)

	if !check.Supported {
		t.Fatalf("expected enterprise capability set to be supported: %+v", check)
	}
	if len(check.Capabilities) != 2 {
		t.Fatalf("expected deduplicated capability checks, got %+v", check.Capabilities)
	}
	if len(check.UnsupportedCapabilities) != 0 {
		t.Fatalf("expected no missing capabilities, got %+v", check.UnsupportedCapabilities)
	}
}

func TestRequireCapabilitiesFailsClosedWhenEmpty(t *testing.T) {
	RegisterEdition(CommunityEditionInfo())

	err := RequireCapabilities()
	if err == nil {
		t.Fatalf("expected empty capability set to fail closed")
	}
	if !IsCapabilityUnavailable(err) {
		t.Fatalf("expected capability unavailable error, got %T", err)
	}
}

func TestMergeCapabilitiesNormalizesAndDeduplicates(t *testing.T) {
	merged := MergeCapabilities(
		[]Capability{{Key: " GATEWAY.RUNTIME ", Name: "Gateway", Category: "gateway"}},
		[]Capability{{Key: CapabilityGatewayRuntime, Name: "Duplicate", Category: "gateway"}},
		[]Capability{{Key: CapabilityBillingIntegration, Name: "Billing", Category: "commercial"}},
	)

	if len(merged) != 2 {
		t.Fatalf("expected two merged capabilities, got %d", len(merged))
	}
	if !hasCapability(EditionInfo{Capabilities: merged}, CapabilityGatewayRuntime) {
		t.Fatalf("expected normalized gateway capability")
	}
	if !hasCapability(EditionInfo{Capabilities: merged}, CapabilityBillingIntegration) {
		t.Fatalf("expected billing capability")
	}
}

func TestFindCapabilityAndBuildCapabilityCategories(t *testing.T) {
	info := EnterpriseEditionInfo()

	capability, ok := FindCapability(info, " COMMERCIAL.BILLING ")
	if !ok {
		t.Fatalf("expected to find normalized billing capability")
	}
	if capability.Key != CapabilityBillingIntegration {
		t.Fatalf("expected billing capability, got %+v", capability)
	}

	categories := BuildCapabilityCategories([]Capability{
		{Key: "z.feature", Name: "Z", Category: "beta"},
		{Key: "a.feature", Name: "A", Category: "alpha"},
		{Key: "empty.category"},
	})
	if len(categories) != 3 {
		t.Fatalf("expected three categories, got %+v", categories)
	}
	if categories[0].Category != "alpha" || categories[1].Category != "beta" || categories[2].Category != "uncategorized" {
		t.Fatalf("expected sorted categories with uncategorized fallback, got %+v", categories)
	}
}

func TestCapabilityCatalogFiltersByCategory(t *testing.T) {
	info := EnterpriseEditionInfo()

	catalog := CapabilityCatalogFor(info, " COMMERCIAL ")
	if catalog.Category != "commercial" {
		t.Fatalf("expected normalized commercial category, got %q", catalog.Category)
	}
	if catalog.Total == 0 {
		t.Fatalf("expected commercial capabilities")
	}
	for _, capability := range catalog.Capabilities {
		if capability.Category != "commercial" {
			t.Fatalf("expected only commercial capabilities, got %+v", capability)
		}
	}
	if len(catalog.Categories) != 1 || catalog.Categories[0].Category != "commercial" || catalog.Categories[0].Total != catalog.Total {
		t.Fatalf("expected one commercial category summary, got %+v", catalog.Categories)
	}
}

func TestCapabilityCatalogReturnsEmptyUnknownCategory(t *testing.T) {
	catalog := CapabilityCatalogFor(CommunityEditionInfo(), "missing")
	if catalog.Category != "missing" {
		t.Fatalf("expected requested category to be echoed, got %q", catalog.Category)
	}
	if catalog.Total != 0 || len(catalog.Capabilities) != 0 || len(catalog.Categories) != 0 {
		t.Fatalf("expected empty catalog for unknown category, got %+v", catalog)
	}
}

func TestCurrentEditionReturnsDefensiveCategoryCopy(t *testing.T) {
	RegisterEdition(EnterpriseEditionInfo())
	defer RegisterEdition(CommunityEditionInfo())

	first := CurrentEdition()
	if len(first.Categories) == 0 || len(first.Categories[0].Capabilities) == 0 {
		t.Fatalf("expected categories with capabilities")
	}
	first.Categories[0].Capabilities[0].Key = "mutated"

	second := CurrentEdition()
	if hasCategoryCapability(second, "mutated") {
		t.Fatalf("expected current edition categories to be defensive")
	}
}

func hasCapability(info EditionInfo, key string) bool {
	key = normalizeCapabilityKey(key)
	for _, capability := range info.Capabilities {
		if capability.Key == key {
			return true
		}
	}
	return false
}

func hasCategory(info EditionInfo, category string) bool {
	for _, summary := range info.Categories {
		if summary.Category == category {
			return true
		}
	}
	return false
}

func hasCategoryCapability(info EditionInfo, key string) bool {
	key = normalizeCapabilityKey(key)
	for _, summary := range info.Categories {
		for _, capability := range summary.Capabilities {
			if capability.Key == key {
				return true
			}
		}
	}
	return false
}
