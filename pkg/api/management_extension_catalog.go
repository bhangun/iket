package api

import (
	"sort"
	"strings"

	"github.com/bhangun/iket/pkg/app"
)

func CurrentManagementRouteExtensionCatalog(filters ...ManagementRouteExtensionFilter) ManagementRouteExtensionCatalog {
	edition := app.CurrentEdition()
	filter := normalizeManagementRouteExtensionFilter(firstManagementRouteExtensionFilter(filters))
	extensions := managementRouteExtensionInfos()
	for index := range extensions {
		extensions[index] = resolveManagementRouteExtensionSupport(extensions[index])
	}
	extensions = filterManagementRouteExtensions(extensions, filter)

	return ManagementRouteExtensionCatalog{
		Product:             edition.Product,
		Edition:             edition.Edition,
		DisplayName:         edition.DisplayName,
		Version:             edition.Version,
		Total:               len(extensions),
		Filters:             managementRouteExtensionFilterPointer(filter),
		Support:             buildManagementRouteExtensionSupportSummary(extensions),
		ExtensionCategories: buildManagementRouteExtensionCategorySummaries(extensions),
		ExtensionTags:       buildManagementRouteExtensionTagSummaries(extensions),
		Extensions:          extensions,
	}
}

func CurrentManagementRouteExtension(name string) (ManagementRouteExtensionInfo, bool) {
	name = strings.TrimSpace(name)
	if name == "" {
		return ManagementRouteExtensionInfo{}, false
	}

	managementRouteExtensionsMu.RLock()
	entry, ok := managementRouteExtensions[name]
	managementRouteExtensionsMu.RUnlock()
	if !ok {
		return ManagementRouteExtensionInfo{}, false
	}
	return resolveManagementRouteExtensionSupport(entry.info), true
}

func managementRouteExtensionInfos() []ManagementRouteExtensionInfo {
	managementRouteExtensionsMu.RLock()
	defer managementRouteExtensionsMu.RUnlock()

	extensions := make([]ManagementRouteExtensionInfo, 0, len(managementRouteExtensions))
	for _, entry := range managementRouteExtensions {
		extensions = append(extensions, entry.info)
	}
	sort.Slice(extensions, func(i, j int) bool {
		return extensions[i].Name < extensions[j].Name
	})
	return extensions
}

func resolveManagementRouteExtensionSupport(info ManagementRouteExtensionInfo) ManagementRouteExtensionInfo {
	if len(info.Capabilities) == 0 {
		info.Supported = true
		info.SupportStatus = ManagementRouteExtensionStatusAvailable
		info.Message = ""
		info.UnsupportedCapabilities = nil
		return info
	}

	check := app.CheckCapabilities(info.Capabilities...)
	info.Supported = check.Supported
	if info.Supported {
		info.SupportStatus = ManagementRouteExtensionStatusAvailable
		info.Message = ""
		info.UnsupportedCapabilities = nil
		return info
	}
	info.SupportStatus = ManagementRouteExtensionStatusCapabilityUnavailable
	info.UnsupportedCapabilities = check.UnsupportedCapabilities
	info.Message = check.Message
	return info
}
