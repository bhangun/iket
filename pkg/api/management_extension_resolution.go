package api

import "github.com/bhangun/iket/pkg/app"

func resolveManagementRouteExtensions(extensions []ManagementRouteExtensionInfo, edition app.EditionInfo) []ManagementRouteExtensionInfo {
	resolved := make([]ManagementRouteExtensionInfo, len(extensions))
	for index, extension := range extensions {
		resolved[index] = resolveManagementRouteExtension(extension, edition)
	}
	return resolved
}

func resolveManagementRouteExtension(info ManagementRouteExtensionInfo, edition app.EditionInfo) ManagementRouteExtensionInfo {
	info = resolveManagementRouteExtensionSupport(info)
	info = resolveManagementRouteExtensionCompatibility(info, edition.Version)
	return info
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
