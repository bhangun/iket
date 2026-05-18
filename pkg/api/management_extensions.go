package api

import (
	"sort"
	"sync"

	"github.com/bhangun/iket/pkg/app"
	"github.com/gorilla/mux"
)

type ManagementRouteExtension func(api *ManagementAPI, router *mux.Router)

// ManagementRouteExtensionInfo describes an optional management API module
// mounted by another package, such as iket-enterprise.
type ManagementRouteExtensionInfo struct {
	Name                    string                `json:"name"`
	Description             string                `json:"description,omitempty"`
	Category                string                `json:"category,omitempty"`
	Tags                    []string              `json:"tags,omitempty"`
	Capability              string                `json:"capability,omitempty"`
	Capabilities            []string              `json:"capabilities,omitempty"`
	Supported               bool                  `json:"supported"`
	SupportStatus           string                `json:"support_status"`
	Message                 string                `json:"message,omitempty"`
	UnsupportedCapabilities []app.CapabilityCheck `json:"unsupported_capabilities,omitempty"`
}

type ManagementRouteExtensionCatalog struct {
	Product             string                                    `json:"product"`
	Edition             string                                    `json:"edition"`
	DisplayName         string                                    `json:"display_name"`
	Version             string                                    `json:"version"`
	Total               int                                       `json:"total"`
	Filters             *ManagementRouteExtensionFilter           `json:"filters,omitempty"`
	Support             ManagementRouteExtensionSupportSummary    `json:"support"`
	ExtensionCategories []ManagementRouteExtensionCategorySummary `json:"extension_categories,omitempty"`
	ExtensionTags       []ManagementRouteExtensionTagSummary      `json:"extension_tags,omitempty"`
	Extensions          []ManagementRouteExtensionInfo            `json:"extensions"`
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

type managementRouteExtensionEntry struct {
	info      ManagementRouteExtensionInfo
	extension ManagementRouteExtension
}

var (
	managementRouteExtensionsMu sync.RWMutex
	managementRouteExtensions   = make(map[string]managementRouteExtensionEntry)
)

// RegisterManagementRouteExtension lets external packages, such as
// iket-enterprise, mount additional /api/v1 management routes without changing
// the community routing table. Call this from an init package.
func RegisterManagementRouteExtension(name string, extension ManagementRouteExtension) {
	RegisterManagementRouteExtensionInfo(ManagementRouteExtensionInfo{Name: name}, extension)
}

// RegisterManagementRouteExtensionInfo registers an extension with catalog
// metadata so admin UIs and CLIs can show which optional modules are mounted.
func RegisterManagementRouteExtensionInfo(info ManagementRouteExtensionInfo, extension ManagementRouteExtension) {
	info = normalizeManagementRouteExtensionInfo(info)
	validateManagementRouteExtension(info, extension)

	managementRouteExtensionsMu.Lock()
	defer managementRouteExtensionsMu.Unlock()

	if _, exists := managementRouteExtensions[info.Name]; exists {
		panic("management route extension already registered: " + info.Name)
	}
	managementRouteExtensions[info.Name] = managementRouteExtensionEntry{
		info:      info,
		extension: extension,
	}
}

func validateManagementRouteExtension(info ManagementRouteExtensionInfo, extension ManagementRouteExtension) {
	if info.Name == "" {
		panic("management route extension name is required")
	}
	if extension == nil {
		panic("management route extension is required")
	}
}

func ManagementRouteExtensionNames() []string {
	managementRouteExtensionsMu.RLock()
	defer managementRouteExtensionsMu.RUnlock()

	names := make([]string, 0, len(managementRouteExtensions))
	for name := range managementRouteExtensions {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func (api *ManagementAPI) registerManagementRouteExtensions(router *mux.Router) {
	managementRouteExtensionsMu.RLock()
	extensions := make([]struct {
		name      string
		extension ManagementRouteExtension
	}, 0, len(managementRouteExtensions))
	for name, entry := range managementRouteExtensions {
		extensions = append(extensions, struct {
			name      string
			extension ManagementRouteExtension
		}{name: name, extension: entry.extension})
	}
	managementRouteExtensionsMu.RUnlock()

	sort.Slice(extensions, func(i, j int) bool {
		return extensions[i].name < extensions[j].name
	})
	for _, extension := range extensions {
		extension.extension(api, router)
	}
}
