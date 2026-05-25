package api

import (
	"strings"

	"github.com/bhangun/iket/pkg/app"
)

func CurrentManagementRouteExtensionCatalog(filters ...ManagementRouteExtensionFilter) ManagementRouteExtensionCatalog {
	edition := app.CurrentEdition()
	filter := normalizeManagementRouteExtensionFilter(firstManagementRouteExtensionFilter(filters))
	extensions := managementRouteExtensionCatalogEntries(edition, filter)
	return buildManagementRouteExtensionCatalog(edition, filter, extensions)
}

func managementRouteExtensionCatalogEntries(edition app.EditionInfo, filter ManagementRouteExtensionFilter) []ManagementRouteExtensionInfo {
	extensions := resolveManagementRouteExtensions(managementRouteExtensionInfos(), edition)
	return filterManagementRouteExtensions(extensions, filter)
}

func CurrentManagementRouteExtension(name string) (ManagementRouteExtensionInfo, bool) {
	name = strings.TrimSpace(name)
	if name == "" {
		return ManagementRouteExtensionInfo{}, false
	}

	entry, ok := lookupManagementRouteExtension(name)
	if !ok {
		return ManagementRouteExtensionInfo{}, false
	}
	return resolveManagementRouteExtension(entry.info, app.CurrentEdition()), true
}

func managementRouteExtensionInfos() []ManagementRouteExtensionInfo {
	snapshots := snapshotManagementRouteExtensions()
	extensions := make([]ManagementRouteExtensionInfo, 0, len(snapshots))
	for _, snapshot := range snapshots {
		extensions = append(extensions, snapshot.info)
	}
	return extensions
}
