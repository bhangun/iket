package api

func validateManagementRouteExtension(info ManagementRouteExtensionInfo, extension ManagementRouteExtension) {
	validateManagementRouteExtensionIdentity(info)
	validateManagementRouteExtensionLifecycle(info)
	validateManagementRouteExtensionPermissions(info.Permissions)
	validateManagementRouteExtensionProvider(info.Provider)
	validateManagementRouteExtensionRoutes(info.RoutePrefixes)
	validateManagementRouteExtensionLinks(info.Links)
	validateManagementRouteExtensionHandler(extension)
}

func validateManagementRouteExtensionIdentity(info ManagementRouteExtensionInfo) {
	if info.Name == "" {
		panic("management route extension name is required")
	}
	if !isValidManagementRouteExtensionName(info.Name) {
		panic("management route extension name must use lowercase letters, numbers, dots, underscores, or hyphens, and start/end with a letter or number: " + info.Name)
	}
}

func validateManagementRouteExtensionLifecycle(info ManagementRouteExtensionInfo) {
	if !isValidManagementRouteExtensionReleaseStage(info.ReleaseStage) {
		panic("management route extension release stage must be stable, preview, or deprecated: " + info.ReleaseStage)
	}
	if !isValidManagementRouteExtensionVersion(info.Version) {
		panic("management route extension version must not contain whitespace: " + info.Version)
	}
	if err := validateManagementRouteExtensionCompatibility(info.Compatibility); err != nil {
		panic(err.Error())
	}
}

func validateManagementRouteExtensionPermissions(permissions []ManagementRouteExtensionPermission) {
	for _, permission := range permissions {
		if !isValidManagementRouteExtensionPermissionKey(permission.Key) {
			panic("management route extension permission key must use lowercase letters, numbers, dots, underscores, or hyphens, and start/end with a letter or number: " + permission.Key)
		}
	}
}

func validateManagementRouteExtensionProvider(provider ManagementRouteExtensionProvider) {
	if !isValidManagementRouteExtensionProviderKind(provider.Kind) {
		panic("management route extension provider kind must be community, enterprise, partner, or custom: " + provider.Kind)
	}
	if !isValidManagementRouteExtensionProviderURL(provider.URL) {
		panic("management route extension provider URL must not contain whitespace: " + provider.URL)
	}
}

func validateManagementRouteExtensionRoutes(routePrefixes []string) {
	for _, prefix := range routePrefixes {
		if !isValidManagementRouteExtensionRoutePrefix(prefix) {
			panic("management route extension route prefix must start with / and must not contain whitespace: " + prefix)
		}
	}
}

func validateManagementRouteExtensionLinks(links []ManagementRouteExtensionLink) {
	for _, link := range links {
		if !isValidManagementRouteExtensionLinkRel(link.Rel) {
			panic("management route extension link rel must use lowercase letters, numbers, dots, underscores, or hyphens, and start/end with a letter or number: " + link.Rel)
		}
		if link.URL == "" {
			panic("management route extension link URL is required for rel: " + link.Rel)
		}
	}
}

func validateManagementRouteExtensionHandler(extension ManagementRouteExtension) {
	if extension == nil {
		panic("management route extension is required")
	}
}
