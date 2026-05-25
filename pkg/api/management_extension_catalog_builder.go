package api

import "github.com/bhangun/iket/pkg/app"

func buildManagementRouteExtensionCatalog(
	edition app.EditionInfo,
	filter ManagementRouteExtensionFilter,
	extensions []ManagementRouteExtensionInfo,
) ManagementRouteExtensionCatalog {
	return ManagementRouteExtensionCatalog{
		Product:                edition.Product,
		Edition:                edition.Edition,
		DisplayName:            edition.DisplayName,
		Version:                edition.Version,
		Total:                  len(extensions),
		Filters:                managementRouteExtensionFilterPointer(filter),
		Support:                buildManagementRouteExtensionSupportSummary(extensions),
		ExtensionStages:        buildManagementRouteExtensionStageSummaries(extensions),
		ExtensionCompatibility: buildManagementRouteExtensionCompatibilitySummaries(extensions),
		ExtensionProviders:     buildManagementRouteExtensionProviderSummaries(extensions),
		ExtensionPermissions:   buildManagementRouteExtensionPermissionSummaries(extensions),
		ExtensionRoutes:        buildManagementRouteExtensionRouteSummaries(extensions),
		ExtensionLinkRels:      buildManagementRouteExtensionLinkRelSummaries(extensions),
		ExtensionCategories:    buildManagementRouteExtensionCategorySummaries(extensions),
		ExtensionTags:          buildManagementRouteExtensionTagSummaries(extensions),
		Extensions:             extensions,
	}
}
