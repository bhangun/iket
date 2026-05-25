package api

import (
	"sort"
	"sync"

	"github.com/gorilla/mux"
)

type ManagementRouteExtension func(api *ManagementAPI, router *mux.Router)

type managementRouteExtensionEntry struct {
	info      ManagementRouteExtensionInfo
	extension ManagementRouteExtension
}

type managementRouteExtensionSnapshot struct {
	name      string
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

func ManagementRouteExtensionNames() []string {
	extensions := snapshotManagementRouteExtensions()
	names := make([]string, 0, len(extensions))
	for _, extension := range extensions {
		names = append(names, extension.name)
	}
	return names
}

func lookupManagementRouteExtension(name string) (managementRouteExtensionEntry, bool) {
	managementRouteExtensionsMu.RLock()
	defer managementRouteExtensionsMu.RUnlock()

	entry, ok := managementRouteExtensions[name]
	return entry, ok
}

func snapshotManagementRouteExtensions() []managementRouteExtensionSnapshot {
	managementRouteExtensionsMu.RLock()
	defer managementRouteExtensionsMu.RUnlock()

	extensions := make([]managementRouteExtensionSnapshot, 0, len(managementRouteExtensions))
	for name, entry := range managementRouteExtensions {
		extensions = append(extensions, managementRouteExtensionSnapshot{
			name:      name,
			info:      entry.info,
			extension: entry.extension,
		})
	}
	sort.Slice(extensions, func(i, j int) bool {
		return extensions[i].name < extensions[j].name
	})
	return extensions
}

func (api *ManagementAPI) registerManagementRouteExtensions(router *mux.Router) {
	extensions := snapshotManagementRouteExtensions()
	for _, extension := range extensions {
		extension.extension(api, router)
	}
}
