package api

import (
	"strings"
)

func normalizeManagementRouteExtensionInfo(info ManagementRouteExtensionInfo) ManagementRouteExtensionInfo {
	info.Name = strings.TrimSpace(info.Name)
	info.Description = strings.TrimSpace(info.Description)
	info.Capabilities = normalizeManagementRouteExtensionCapabilities(info.Capability, info.Capabilities)
	info.Capability = firstManagementRouteExtensionCapability(info.Capabilities)
	info.Category = normalizeManagementRouteExtensionCategory(info.Category, info.Capability)
	info.Tags = normalizeManagementRouteExtensionTags(info.Tags)
	info.Supported = false
	info.SupportStatus = ""
	info.Message = ""
	info.UnsupportedCapabilities = nil
	return info
}

func normalizeManagementRouteExtensionCapabilities(primary string, capabilities []string) []string {
	values := make([]string, 0, len(capabilities)+1)
	if primary = strings.ToLower(strings.TrimSpace(primary)); primary != "" {
		values = append(values, primary)
	}
	values = append(values, capabilities...)

	out := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, capability := range values {
		capability = strings.ToLower(strings.TrimSpace(capability))
		if capability == "" {
			continue
		}
		if _, exists := seen[capability]; exists {
			continue
		}
		out = append(out, capability)
		seen[capability] = struct{}{}
	}
	return out
}

func firstManagementRouteExtensionCapability(capabilities []string) string {
	if len(capabilities) == 0 {
		return ""
	}
	return capabilities[0]
}

func normalizeManagementRouteExtensionCategory(category string, primaryCapability string) string {
	category = strings.ToLower(strings.TrimSpace(category))
	if category != "" {
		return category
	}
	index := strings.Index(primaryCapability, ".")
	if index <= 0 {
		return ""
	}
	return primaryCapability[:index]
}

func normalizeManagementRouteExtensionTags(tags []string) []string {
	out := make([]string, 0, len(tags))
	seen := make(map[string]struct{}, len(tags))
	for _, tag := range tags {
		tag = strings.ToLower(strings.TrimSpace(tag))
		if tag == "" {
			continue
		}
		if _, exists := seen[tag]; exists {
			continue
		}
		out = append(out, tag)
		seen[tag] = struct{}{}
	}
	return out
}

func firstManagementRouteExtensionFilter(filters []ManagementRouteExtensionFilter) ManagementRouteExtensionFilter {
	if len(filters) == 0 {
		return ManagementRouteExtensionFilter{}
	}
	return filters[0]
}

func normalizeManagementRouteExtensionFilter(filter ManagementRouteExtensionFilter) ManagementRouteExtensionFilter {
	filter.Category = strings.ToLower(strings.TrimSpace(filter.Category))
	filter.Tag = strings.ToLower(strings.TrimSpace(filter.Tag))
	filter.Capability = strings.ToLower(strings.TrimSpace(filter.Capability))
	filter.UnsupportedCapability = strings.ToLower(strings.TrimSpace(filter.UnsupportedCapability))
	filter.SupportStatus = strings.ToLower(strings.TrimSpace(filter.SupportStatus))
	return filter
}

func filterManagementRouteExtensions(extensions []ManagementRouteExtensionInfo, filter ManagementRouteExtensionFilter) []ManagementRouteExtensionInfo {
	if !hasManagementRouteExtensionFilter(filter) {
		return extensions
	}
	filtered := make([]ManagementRouteExtensionInfo, 0, len(extensions))
	for _, extension := range extensions {
		if filter.Category != "" && extension.Category != filter.Category {
			continue
		}
		if filter.Tag != "" && !managementRouteExtensionHasTag(extension, filter.Tag) {
			continue
		}
		if filter.Capability != "" && !managementRouteExtensionHasCapability(extension, filter.Capability) {
			continue
		}
		if filter.UnsupportedCapability != "" && !managementRouteExtensionHasUnsupportedCapability(extension, filter.UnsupportedCapability) {
			continue
		}
		if filter.SupportStatus != "" && extension.SupportStatus != filter.SupportStatus {
			continue
		}
		if filter.Supported != nil && extension.Supported != *filter.Supported {
			continue
		}
		filtered = append(filtered, extension)
	}
	return filtered
}

func managementRouteExtensionHasCapability(extension ManagementRouteExtensionInfo, capability string) bool {
	capability = strings.ToLower(strings.TrimSpace(capability))
	if capability == "" {
		return false
	}
	for _, candidate := range extension.Capabilities {
		if candidate == capability {
			return true
		}
	}
	return false
}

func managementRouteExtensionHasUnsupportedCapability(extension ManagementRouteExtensionInfo, capability string) bool {
	capability = strings.ToLower(strings.TrimSpace(capability))
	if capability == "" {
		return false
	}
	for _, candidate := range extension.UnsupportedCapabilities {
		if candidate.Key == capability {
			return true
		}
	}
	return false
}

func managementRouteExtensionHasTag(extension ManagementRouteExtensionInfo, tag string) bool {
	tag = strings.ToLower(strings.TrimSpace(tag))
	if tag == "" {
		return false
	}
	for _, candidate := range extension.Tags {
		if candidate == tag {
			return true
		}
	}
	return false
}

func hasManagementRouteExtensionFilter(filter ManagementRouteExtensionFilter) bool {
	return filter.Category != "" ||
		filter.Tag != "" ||
		filter.Capability != "" ||
		filter.UnsupportedCapability != "" ||
		filter.SupportStatus != "" ||
		filter.Supported != nil
}

func managementRouteExtensionFilterPointer(filter ManagementRouteExtensionFilter) *ManagementRouteExtensionFilter {
	if !hasManagementRouteExtensionFilter(filter) {
		return nil
	}
	return &filter
}
