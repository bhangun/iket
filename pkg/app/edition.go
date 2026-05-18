package app

import (
	"sort"
	"strings"
	"sync"
)

const (
	EditionCommunity  = "community"
	EditionEnterprise = "enterprise"
)

// Capability describes a product feature exposed by this Iket build.
type Capability struct {
	Key         string `json:"key"`
	Name        string `json:"name"`
	Category    string `json:"category"`
	Description string `json:"description,omitempty"`
}

type CapabilityCategorySummary struct {
	Category     string       `json:"category"`
	Total        int          `json:"total"`
	Capabilities []Capability `json:"capabilities"`
}

type CapabilityCatalog struct {
	Product      string                      `json:"product"`
	Edition      string                      `json:"edition"`
	DisplayName  string                      `json:"display_name"`
	Version      string                      `json:"version"`
	Category     string                      `json:"category,omitempty"`
	Total        int                         `json:"total"`
	Capabilities []Capability                `json:"capabilities"`
	Categories   []CapabilityCategorySummary `json:"capability_categories,omitempty"`
}

// EditionInfo describes the active Iket distribution.
//
// The community binary owns the default values. Enterprise builds can extend
// EnterpriseEditionInfo from an enterprise-only package during init without
// forking gateway, config, or management API code.
type EditionInfo struct {
	Product      string                      `json:"product"`
	Edition      string                      `json:"edition"`
	DisplayName  string                      `json:"display_name"`
	Version      string                      `json:"version"`
	Description  string                      `json:"description,omitempty"`
	Capabilities []Capability                `json:"capabilities"`
	Categories   []CapabilityCategorySummary `json:"capability_categories,omitempty"`
}

var (
	editionMu sync.RWMutex
	edition   = CommunityEditionInfo()
)

func communityEdition() EditionInfo {
	return EditionInfo{
		Product:     Name,
		Edition:     EditionCommunity,
		DisplayName: "Iket Community",
		Version:     Version,
		Description: "Single-tenant API gateway for individuals, education, labs, and small production deployments.",
		Capabilities: []Capability{
			{Key: CapabilityGatewayRuntime, Name: "Gateway Runtime", Category: "gateway", Description: "HTTP routing, proxying, retries, circuit breakers, shadow traffic, and transformations."},
			{Key: CapabilityConfigProviders, Name: "Config Providers", Category: "configuration", Description: "File, SQLite, PostgreSQL, and mirrored configuration storage."},
			{Key: CapabilityCommunityPlugins, Name: "Community Plugins", Category: "plugins", Description: "API key, JWT, OAuth2, mTLS, CORS, IP filtering, validation, rate limit, and WebSocket plugins."},
			{Key: CapabilityLocalManagement, Name: "Local Management API", Category: "management", Description: "Single-instance management API, CLI, config validation, revisions, proposals, and backups."},
			{Key: CapabilityBasicObservability, Name: "Basic Observability", Category: "observability", Description: "Structured logs, gateway metrics, route policy hits, and backend health status."},
			{Key: CapabilityBaselineSecurity, Name: "Baseline Security", Category: "security", Description: "TLS, mTLS enrollment, JWT, OAuth2, API key, and request validation primitives."},
		},
	}
}

func enterpriseCapabilities() []Capability {
	return []Capability{
		{Key: CapabilityTenantWorkspaces, Name: "Tenant Workspaces", Category: "tenancy", Description: "Organization and workspace boundaries for multi-tenant commercial deployments."},
		{Key: CapabilityEnterpriseRBAC, Name: "Enterprise RBAC", Category: "security", Description: "Role, permission, and policy controls for enterprise operators."},
		{Key: CapabilityAuditTrails, Name: "Audit Trails", Category: "governance", Description: "Immutable administrative audit history for compliance and incident review."},
		{Key: CapabilityBillingIntegration, Name: "Billing Integration", Category: "commercial", Description: "Usage, subscription, and billing-provider integration points."},
		{Key: CapabilityHighAvailability, Name: "High Availability", Category: "gateway", Description: "Cluster-aware runtime primitives for resilient enterprise deployments."},
		{Key: CapabilityAdvancedAnalytics, Name: "Advanced Analytics", Category: "observability", Description: "Tenant-aware analytics, reporting, and commercial usage insights."},
	}
}

// CommunityEditionInfo returns a normalized copy of the built-in community profile.
func CommunityEditionInfo() EditionInfo {
	return normalizeEditionInfo(communityEdition())
}

// EnterpriseEditionInfo returns the shared enterprise profile plus optional
// enterprise-only capabilities. The separate enterprise repository can call
// RegisterEdition(EnterpriseEditionInfo(...)) from an init package.
func EnterpriseEditionInfo(extraCapabilities ...Capability) EditionInfo {
	info := CommunityEditionInfo()
	info.Edition = EditionEnterprise
	info.DisplayName = "Iket Enterprise"
	info.Description = "Multi-tenant API gateway platform for enterprise security, governance, billing, high availability, and commercial operations."
	info.Capabilities = MergeCapabilities(info.Capabilities, enterpriseCapabilities(), extraCapabilities)
	return normalizeEditionInfo(info)
}

// RegisterEdition replaces the active edition metadata for specialized builds.
func RegisterEdition(info EditionInfo) {
	editionMu.Lock()
	defer editionMu.Unlock()

	edition = normalizeEditionInfo(info)
}

func normalizeEditionInfo(info EditionInfo) EditionInfo {
	info.Product = strings.TrimSpace(info.Product)
	if info.Product == "" {
		info.Product = Name
	}
	info.Edition = strings.TrimSpace(info.Edition)
	if info.Edition == "" {
		info.Edition = EditionCommunity
	}
	info.DisplayName = strings.TrimSpace(info.DisplayName)
	if info.DisplayName == "" {
		info.DisplayName = info.Product + " " + titleEdition(info.Edition)
	}
	info.Version = strings.TrimSpace(info.Version)
	if info.Version == "" {
		info.Version = Version
	}
	info.Capabilities = normalizeCapabilities(info.Capabilities)
	info.Categories = BuildCapabilityCategories(info.Capabilities)
	return info
}

func titleEdition(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return value
	}
	return strings.ToUpper(value[:1]) + value[1:]
}

// CurrentEdition returns a defensive copy of the active edition metadata.
func CurrentEdition() EditionInfo {
	editionMu.RLock()
	defer editionMu.RUnlock()

	info := edition
	info.Version = Version
	return cloneEditionInfo(info)
}

func SupportsCapability(key string) bool {
	return CheckCapability(key).Supported
}

func FindCapability(info EditionInfo, key string) (Capability, bool) {
	key = normalizeCapabilityKey(key)
	if key == "" {
		return Capability{}, false
	}
	for _, capability := range info.Capabilities {
		if capability.Key == key {
			return capability, true
		}
	}
	return Capability{}, false
}

func CurrentCapabilityCatalog(category string) CapabilityCatalog {
	return CapabilityCatalogFor(CurrentEdition(), category)
}

func CapabilityCatalogFor(info EditionInfo, category string) CapabilityCatalog {
	info = normalizeEditionInfo(info)
	category = normalizeCapabilityCategory(category)
	capabilities := info.Capabilities
	if category != "" {
		capabilities = filterCapabilitiesByCategory(capabilities, category)
	}
	categories := BuildCapabilityCategories(capabilities)
	return CapabilityCatalog{
		Product:      info.Product,
		Edition:      info.Edition,
		DisplayName:  info.DisplayName,
		Version:      info.Version,
		Category:     category,
		Total:        len(capabilities),
		Capabilities: append([]Capability(nil), capabilities...),
		Categories:   categories,
	}
}

func MergeCapabilities(groups ...[]Capability) []Capability {
	size := 0
	for _, group := range groups {
		size += len(group)
	}
	merged := make([]Capability, 0, size)
	for _, group := range groups {
		merged = append(merged, group...)
	}
	return normalizeCapabilities(merged)
}

func filterCapabilitiesByCategory(capabilities []Capability, category string) []Capability {
	category = normalizeCapabilityCategory(category)
	if category == "" {
		return append([]Capability(nil), capabilities...)
	}
	filtered := make([]Capability, 0, len(capabilities))
	for _, capability := range capabilities {
		if normalizeCapabilityCategory(capability.Category) == category {
			filtered = append(filtered, capability)
		}
	}
	return filtered
}

func cloneEditionInfo(info EditionInfo) EditionInfo {
	info.Capabilities = append([]Capability(nil), info.Capabilities...)
	info.Categories = cloneCapabilityCategories(info.Categories)
	return info
}

func BuildCapabilityCategories(capabilities []Capability) []CapabilityCategorySummary {
	normalized := normalizeCapabilities(capabilities)
	grouped := make(map[string][]Capability)
	for _, capability := range normalized {
		category := normalizeCapabilityCategory(capability.Category)
		if category == "" {
			category = "uncategorized"
		}
		grouped[category] = append(grouped[category], capability)
	}

	categories := make([]CapabilityCategorySummary, 0, len(grouped))
	for category, items := range grouped {
		categories = append(categories, CapabilityCategorySummary{
			Category:     category,
			Total:        len(items),
			Capabilities: append([]Capability(nil), items...),
		})
	}
	sort.Slice(categories, func(i, j int) bool {
		return categories[i].Category < categories[j].Category
	})
	return categories
}

func cloneCapabilityCategories(categories []CapabilityCategorySummary) []CapabilityCategorySummary {
	out := make([]CapabilityCategorySummary, 0, len(categories))
	for _, category := range categories {
		category.Capabilities = append([]Capability(nil), category.Capabilities...)
		out = append(out, category)
	}
	return out
}

func normalizeCapabilities(capabilities []Capability) []Capability {
	out := make([]Capability, 0, len(capabilities))
	seen := make(map[string]struct{}, len(capabilities))
	for _, capability := range capabilities {
		capability.Key = normalizeCapabilityKey(capability.Key)
		if capability.Key == "" {
			continue
		}
		if _, ok := seen[capability.Key]; ok {
			continue
		}
		capability.Name = strings.TrimSpace(capability.Name)
		capability.Category = normalizeCapabilityCategory(capability.Category)
		capability.Description = strings.TrimSpace(capability.Description)
		out = append(out, capability)
		seen[capability.Key] = struct{}{}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Category == out[j].Category {
			return out[i].Key < out[j].Key
		}
		return out[i].Category < out[j].Category
	})
	return out
}

func normalizeCapabilityCategory(category string) string {
	return strings.ToLower(strings.TrimSpace(category))
}
