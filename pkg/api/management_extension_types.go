package api

import "github.com/bhangun/iket/pkg/app"

// ManagementRouteExtensionInfo describes an optional management API module
// mounted by another package, such as iket-enterprise.
type ManagementRouteExtensionInfo struct {
	Name                    string                                `json:"name"`
	DisplayName             string                                `json:"display_name"`
	Description             string                                `json:"description,omitempty"`
	Version                 string                                `json:"version,omitempty"`
	ReleaseStage            string                                `json:"release_stage"`
	Provider                ManagementRouteExtensionProvider      `json:"provider"`
	Compatibility           ManagementRouteExtensionCompatibility `json:"compatibility"`
	Permissions             []ManagementRouteExtensionPermission  `json:"permissions,omitempty"`
	RoutePrefixes           []string                              `json:"route_prefixes,omitempty"`
	Links                   []ManagementRouteExtensionLink        `json:"links,omitempty"`
	Category                string                                `json:"category,omitempty"`
	Tags                    []string                              `json:"tags,omitempty"`
	Capability              string                                `json:"capability,omitempty"`
	Capabilities            []string                              `json:"capabilities,omitempty"`
	Supported               bool                                  `json:"supported"`
	SupportStatus           string                                `json:"support_status"`
	Message                 string                                `json:"message,omitempty"`
	UnsupportedCapabilities []app.CapabilityCheck                 `json:"unsupported_capabilities,omitempty"`
}

type ManagementRouteExtensionProvider struct {
	Kind string `json:"kind"`
	Name string `json:"name,omitempty"`
	URL  string `json:"url,omitempty"`
}

type ManagementRouteExtensionCompatibility struct {
	MinimumIketVersion string `json:"minimum_iket_version,omitempty"`
	MaximumIketVersion string `json:"maximum_iket_version,omitempty"`
	Status             string `json:"status"`
	Message            string `json:"message,omitempty"`
}

type ManagementRouteExtensionPermission struct {
	Key         string `json:"key"`
	Name        string `json:"name,omitempty"`
	Description string `json:"description,omitempty"`
}

type ManagementRouteExtensionLink struct {
	Rel   string `json:"rel"`
	URL   string `json:"url"`
	Label string `json:"label,omitempty"`
}

type ManagementRouteExtensionCatalog struct {
	Product                string                                         `json:"product"`
	Edition                string                                         `json:"edition"`
	DisplayName            string                                         `json:"display_name"`
	Version                string                                         `json:"version"`
	Total                  int                                            `json:"total"`
	Filters                *ManagementRouteExtensionFilter                `json:"filters,omitempty"`
	Support                ManagementRouteExtensionSupportSummary         `json:"support"`
	ExtensionStages        []ManagementRouteExtensionStageSummary         `json:"extension_stages,omitempty"`
	ExtensionCompatibility []ManagementRouteExtensionCompatibilitySummary `json:"extension_compatibility,omitempty"`
	ExtensionProviders     []ManagementRouteExtensionProviderSummary      `json:"extension_providers,omitempty"`
	ExtensionPermissions   []ManagementRouteExtensionPermissionSummary    `json:"extension_permissions,omitempty"`
	ExtensionRoutes        []ManagementRouteExtensionRouteSummary         `json:"extension_routes,omitempty"`
	ExtensionLinkRels      []ManagementRouteExtensionLinkRelSummary       `json:"extension_link_rels,omitempty"`
	ExtensionCategories    []ManagementRouteExtensionCategorySummary      `json:"extension_categories,omitempty"`
	ExtensionTags          []ManagementRouteExtensionTagSummary           `json:"extension_tags,omitempty"`
	Extensions             []ManagementRouteExtensionInfo                 `json:"extensions"`
}

type ManagementRouteExtensionSupportSummary struct {
	Total                   int                                                    `json:"total"`
	Supported               int                                                    `json:"supported"`
	Unsupported             int                                                    `json:"unsupported"`
	Statuses                []ManagementRouteExtensionStatusSummary                `json:"statuses,omitempty"`
	UnsupportedCapabilities []ManagementRouteExtensionUnsupportedCapabilitySummary `json:"unsupported_capabilities,omitempty"`
}

type ManagementRouteExtensionStatusSummary struct {
	Status     string   `json:"status"`
	Total      int      `json:"total"`
	Extensions []string `json:"extensions,omitempty"`
}

type ManagementRouteExtensionUnsupportedCapabilitySummary struct {
	Capability string   `json:"capability"`
	Total      int      `json:"total"`
	Extensions []string `json:"extensions,omitempty"`
}

type ManagementRouteExtensionStageSummary struct {
	ReleaseStage string   `json:"release_stage"`
	Total        int      `json:"total"`
	Extensions   []string `json:"extensions,omitempty"`
}

type ManagementRouteExtensionCompatibilitySummary struct {
	Status     string   `json:"status"`
	Total      int      `json:"total"`
	Extensions []string `json:"extensions,omitempty"`
}

type ManagementRouteExtensionProviderSummary struct {
	Kind       string   `json:"kind"`
	Total      int      `json:"total"`
	Providers  []string `json:"providers,omitempty"`
	Extensions []string `json:"extensions,omitempty"`
}

type ManagementRouteExtensionPermissionSummary struct {
	Permission string   `json:"permission"`
	Name       string   `json:"name,omitempty"`
	Total      int      `json:"total"`
	Extensions []string `json:"extensions,omitempty"`
}

type ManagementRouteExtensionRouteSummary struct {
	RoutePrefix string   `json:"route_prefix"`
	Total       int      `json:"total"`
	Extensions  []string `json:"extensions,omitempty"`
}

type ManagementRouteExtensionLinkRelSummary struct {
	Rel        string   `json:"rel"`
	Total      int      `json:"total"`
	Extensions []string `json:"extensions,omitempty"`
}

type ManagementRouteExtensionCategorySummary struct {
	Category   string   `json:"category"`
	Total      int      `json:"total"`
	Extensions []string `json:"extensions,omitempty"`
}

type ManagementRouteExtensionTagSummary struct {
	Tag        string   `json:"tag"`
	Total      int      `json:"total"`
	Extensions []string `json:"extensions,omitempty"`
}

type ManagementRouteExtensionFilter struct {
	Search                string `json:"search,omitempty"`
	ReleaseStage          string `json:"release_stage,omitempty"`
	CompatibilityStatus   string `json:"compatibility_status,omitempty"`
	ProviderKind          string `json:"provider_kind,omitempty"`
	ProviderName          string `json:"provider,omitempty"`
	Permission            string `json:"permission,omitempty"`
	RoutePrefix           string `json:"route_prefix,omitempty"`
	LinkRel               string `json:"link_rel,omitempty"`
	Category              string `json:"category,omitempty"`
	Tag                   string `json:"tag,omitempty"`
	Capability            string `json:"capability,omitempty"`
	UnsupportedCapability string `json:"unsupported_capability,omitempty"`
	SupportStatus         string `json:"support_status,omitempty"`
	Supported             *bool  `json:"supported,omitempty"`
}

const (
	ManagementRouteExtensionStatusAvailable             = "available"
	ManagementRouteExtensionStatusCapabilityUnavailable = "capability_unavailable"
)

const (
	ManagementRouteExtensionStageStable     = "stable"
	ManagementRouteExtensionStagePreview    = "preview"
	ManagementRouteExtensionStageDeprecated = "deprecated"
)

const (
	ManagementRouteExtensionCompatibilityCompatible   = "compatible"
	ManagementRouteExtensionCompatibilityIncompatible = "incompatible"
	ManagementRouteExtensionCompatibilityUnknown      = "unknown"
)

const (
	ManagementRouteExtensionProviderCommunity  = "community"
	ManagementRouteExtensionProviderEnterprise = "enterprise"
	ManagementRouteExtensionProviderPartner    = "partner"
	ManagementRouteExtensionProviderCustom     = "custom"
)

const (
	ManagementRouteExtensionLinkRelDocs      = "docs"
	ManagementRouteExtensionLinkRelSupport   = "support"
	ManagementRouteExtensionLinkRelPricing   = "pricing"
	ManagementRouteExtensionLinkRelInstall   = "install"
	ManagementRouteExtensionLinkRelChangelog = "changelog"
)
