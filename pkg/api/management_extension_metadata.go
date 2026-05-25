package api

import (
	"strings"
)

func normalizeManagementRouteExtensionInfo(info ManagementRouteExtensionInfo) ManagementRouteExtensionInfo {
	info.Name = strings.TrimSpace(info.Name)
	info.DisplayName = normalizeManagementRouteExtensionDisplayName(info.DisplayName, info.Name)
	info.Description = strings.TrimSpace(info.Description)
	info.Version = strings.TrimSpace(info.Version)
	info.ReleaseStage = normalizeManagementRouteExtensionReleaseStage(info.ReleaseStage)
	info.Provider = normalizeManagementRouteExtensionProvider(info.Provider)
	info.Compatibility = normalizeManagementRouteExtensionCompatibility(info.Compatibility)
	info.Permissions = normalizeManagementRouteExtensionPermissions(info.Permissions)
	info.RoutePrefixes = normalizeManagementRouteExtensionRoutePrefixes(info.RoutePrefixes)
	info.Links = normalizeManagementRouteExtensionLinks(info.Links)
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

func normalizeManagementRouteExtensionDisplayName(displayName string, name string) string {
	displayName = strings.TrimSpace(displayName)
	if displayName != "" {
		return displayName
	}
	parts := strings.FieldsFunc(name, func(r rune) bool {
		return r == '.' || r == '_' || r == '-'
	})
	for index, part := range parts {
		parts[index] = titleManagementRouteExtensionNamePart(part)
	}
	return strings.Join(parts, " ")
}

func titleManagementRouteExtensionNamePart(part string) string {
	part = strings.TrimSpace(part)
	if part == "" {
		return ""
	}
	return strings.ToUpper(part[:1]) + part[1:]
}

func normalizeManagementRouteExtensionReleaseStage(stage string) string {
	stage = strings.ToLower(strings.TrimSpace(stage))
	if stage == "" {
		return ManagementRouteExtensionStageStable
	}
	return stage
}

func isValidManagementRouteExtensionReleaseStage(stage string) bool {
	switch stage {
	case ManagementRouteExtensionStageStable,
		ManagementRouteExtensionStagePreview,
		ManagementRouteExtensionStageDeprecated:
		return true
	default:
		return false
	}
}

func isValidManagementRouteExtensionName(name string) bool {
	if name == "" {
		return false
	}
	if !isManagementRouteExtensionNameAlnum(name[0]) || !isManagementRouteExtensionNameAlnum(name[len(name)-1]) {
		return false
	}
	for index := 0; index < len(name); index++ {
		char := name[index]
		if isManagementRouteExtensionNameAlnum(char) || char == '.' || char == '_' || char == '-' {
			continue
		}
		return false
	}
	return true
}

func isManagementRouteExtensionNameAlnum(char byte) bool {
	return (char >= 'a' && char <= 'z') || (char >= '0' && char <= '9')
}

func normalizeManagementRouteExtensionProvider(provider ManagementRouteExtensionProvider) ManagementRouteExtensionProvider {
	provider.Kind = strings.ToLower(strings.TrimSpace(provider.Kind))
	if provider.Kind == "" {
		provider.Kind = ManagementRouteExtensionProviderCustom
	}
	provider.Name = strings.TrimSpace(provider.Name)
	provider.URL = strings.TrimSpace(provider.URL)
	return provider
}

func isValidManagementRouteExtensionProviderKind(kind string) bool {
	switch kind {
	case ManagementRouteExtensionProviderCommunity,
		ManagementRouteExtensionProviderEnterprise,
		ManagementRouteExtensionProviderPartner,
		ManagementRouteExtensionProviderCustom:
		return true
	default:
		return false
	}
}

func isValidManagementRouteExtensionProviderURL(rawURL string) bool {
	return !strings.ContainsAny(rawURL, " \t\r\n")
}

func normalizeManagementRouteExtensionPermissions(permissions []ManagementRouteExtensionPermission) []ManagementRouteExtensionPermission {
	out := make([]ManagementRouteExtensionPermission, 0, len(permissions))
	seen := make(map[string]struct{}, len(permissions))
	for _, permission := range permissions {
		permission.Key = strings.ToLower(strings.TrimSpace(permission.Key))
		permission.Name = normalizeManagementRouteExtensionPermissionName(permission.Name, permission.Key)
		permission.Description = strings.TrimSpace(permission.Description)
		if permission.Key == "" {
			continue
		}
		if _, exists := seen[permission.Key]; exists {
			continue
		}
		out = append(out, permission)
		seen[permission.Key] = struct{}{}
	}
	return out
}

func normalizeManagementRouteExtensionPermissionName(name string, key string) string {
	name = strings.TrimSpace(name)
	if name != "" {
		return name
	}
	return normalizeManagementRouteExtensionDisplayName("", key)
}

func isValidManagementRouteExtensionPermissionKey(key string) bool {
	return isValidManagementRouteExtensionName(key)
}

func normalizeManagementRouteExtensionRoutePrefixes(prefixes []string) []string {
	out := make([]string, 0, len(prefixes))
	seen := make(map[string]struct{}, len(prefixes))
	for _, prefix := range prefixes {
		prefix = normalizeManagementRouteExtensionRoutePrefix(prefix)
		if prefix == "" {
			continue
		}
		if _, exists := seen[prefix]; exists {
			continue
		}
		out = append(out, prefix)
		seen[prefix] = struct{}{}
	}
	return out
}

func normalizeManagementRouteExtensionRoutePrefix(prefix string) string {
	prefix = strings.TrimSpace(prefix)
	if prefix == "" {
		return ""
	}
	prefix = "/" + strings.Trim(prefix, "/")
	if prefix == "/" {
		return ""
	}
	return prefix
}

func isValidManagementRouteExtensionRoutePrefix(prefix string) bool {
	return strings.HasPrefix(prefix, "/") && !strings.ContainsAny(prefix, " \t\r\n")
}

func normalizeManagementRouteExtensionLinks(links []ManagementRouteExtensionLink) []ManagementRouteExtensionLink {
	out := make([]ManagementRouteExtensionLink, 0, len(links))
	seen := make(map[string]struct{}, len(links))
	for _, link := range links {
		link.Rel = strings.ToLower(strings.TrimSpace(link.Rel))
		link.URL = strings.TrimSpace(link.URL)
		link.Label = strings.TrimSpace(link.Label)
		if link.Rel == "" && link.URL == "" && link.Label == "" {
			continue
		}
		key := link.Rel + "\x00" + link.URL
		if _, exists := seen[key]; exists {
			continue
		}
		out = append(out, link)
		seen[key] = struct{}{}
	}
	return out
}

func isValidManagementRouteExtensionLinkRel(rel string) bool {
	return isValidManagementRouteExtensionName(rel)
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
