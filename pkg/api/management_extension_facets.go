package api

import (
	"sort"
	"strings"
)

func buildManagementRouteExtensionGroupedSummaries[T any](
	grouped map[string][]string,
	build func(key string, names []string) T,
	less func(left T, right T) bool,
) []T {
	summaries := make([]T, 0, len(grouped))
	for key, names := range grouped {
		sort.Strings(names)
		summaries = append(summaries, build(key, names))
	}
	sort.Slice(summaries, func(i, j int) bool {
		return less(summaries[i], summaries[j])
	})
	return summaries
}

func buildManagementRouteExtensionSupportSummary(extensions []ManagementRouteExtensionInfo) ManagementRouteExtensionSupportSummary {
	summary := ManagementRouteExtensionSupportSummary{Total: len(extensions)}
	statuses := make(map[string][]string)
	missingCapabilities := make(map[string][]string)

	for _, extension := range extensions {
		if extension.Supported {
			summary.Supported++
		} else {
			summary.Unsupported++
		}

		status := strings.ToLower(strings.TrimSpace(extension.SupportStatus))
		if status == "" {
			status = ManagementRouteExtensionStatusAvailable
		}
		statuses[status] = append(statuses[status], extension.Name)

		for _, capability := range extension.UnsupportedCapabilities {
			key := strings.ToLower(strings.TrimSpace(capability.Key))
			if key == "" {
				continue
			}
			missingCapabilities[key] = append(missingCapabilities[key], extension.Name)
		}
	}

	summary.Statuses = buildManagementRouteExtensionStatusSummaries(statuses)
	summary.UnsupportedCapabilities = buildManagementRouteExtensionUnsupportedCapabilitySummaries(missingCapabilities)
	return summary
}

func buildManagementRouteExtensionStatusSummaries(grouped map[string][]string) []ManagementRouteExtensionStatusSummary {
	return buildManagementRouteExtensionGroupedSummaries(
		grouped,
		func(status string, names []string) ManagementRouteExtensionStatusSummary {
			return ManagementRouteExtensionStatusSummary{
				Status:     status,
				Total:      len(names),
				Extensions: names,
			}
		},
		func(left ManagementRouteExtensionStatusSummary, right ManagementRouteExtensionStatusSummary) bool {
			return left.Status < right.Status
		},
	)
}

func buildManagementRouteExtensionUnsupportedCapabilitySummaries(grouped map[string][]string) []ManagementRouteExtensionUnsupportedCapabilitySummary {
	return buildManagementRouteExtensionGroupedSummaries(
		grouped,
		func(capability string, names []string) ManagementRouteExtensionUnsupportedCapabilitySummary {
			return ManagementRouteExtensionUnsupportedCapabilitySummary{
				Capability: capability,
				Total:      len(names),
				Extensions: names,
			}
		},
		func(left ManagementRouteExtensionUnsupportedCapabilitySummary, right ManagementRouteExtensionUnsupportedCapabilitySummary) bool {
			return left.Capability < right.Capability
		},
	)
}

func buildManagementRouteExtensionStageSummaries(extensions []ManagementRouteExtensionInfo) []ManagementRouteExtensionStageSummary {
	grouped := make(map[string][]string)
	for _, extension := range extensions {
		stage := normalizeManagementRouteExtensionReleaseStage(extension.ReleaseStage)
		grouped[stage] = append(grouped[stage], extension.Name)
	}

	return buildManagementRouteExtensionGroupedSummaries(
		grouped,
		func(stage string, names []string) ManagementRouteExtensionStageSummary {
			return ManagementRouteExtensionStageSummary{
				ReleaseStage: stage,
				Total:        len(names),
				Extensions:   names,
			}
		},
		func(left ManagementRouteExtensionStageSummary, right ManagementRouteExtensionStageSummary) bool {
			return left.ReleaseStage < right.ReleaseStage
		},
	)
}

func buildManagementRouteExtensionCompatibilitySummaries(extensions []ManagementRouteExtensionInfo) []ManagementRouteExtensionCompatibilitySummary {
	grouped := make(map[string][]string)
	for _, extension := range extensions {
		status := strings.ToLower(strings.TrimSpace(extension.Compatibility.Status))
		if status == "" {
			status = ManagementRouteExtensionCompatibilityCompatible
		}
		grouped[status] = append(grouped[status], extension.Name)
	}

	return buildManagementRouteExtensionGroupedSummaries(
		grouped,
		func(status string, names []string) ManagementRouteExtensionCompatibilitySummary {
			return ManagementRouteExtensionCompatibilitySummary{
				Status:     status,
				Total:      len(names),
				Extensions: names,
			}
		},
		func(left ManagementRouteExtensionCompatibilitySummary, right ManagementRouteExtensionCompatibilitySummary) bool {
			return left.Status < right.Status
		},
	)
}

func buildManagementRouteExtensionProviderSummaries(extensions []ManagementRouteExtensionInfo) []ManagementRouteExtensionProviderSummary {
	grouped := make(map[string][]ManagementRouteExtensionInfo)
	for _, extension := range extensions {
		provider := normalizeManagementRouteExtensionProvider(extension.Provider)
		grouped[provider.Kind] = append(grouped[provider.Kind], extension)
	}

	summaries := make([]ManagementRouteExtensionProviderSummary, 0, len(grouped))
	for kind, extensions := range grouped {
		names := make([]string, 0, len(extensions))
		providerNames := make([]string, 0, len(extensions))
		seenProviders := make(map[string]struct{}, len(extensions))
		for _, extension := range extensions {
			names = append(names, extension.Name)
			providerName := strings.TrimSpace(extension.Provider.Name)
			if providerName == "" {
				continue
			}
			if _, exists := seenProviders[providerName]; exists {
				continue
			}
			providerNames = append(providerNames, providerName)
			seenProviders[providerName] = struct{}{}
		}
		sort.Strings(names)
		sort.Strings(providerNames)
		summaries = append(summaries, ManagementRouteExtensionProviderSummary{
			Kind:       kind,
			Total:      len(names),
			Providers:  providerNames,
			Extensions: names,
		})
	}
	sort.Slice(summaries, func(i, j int) bool {
		return summaries[i].Kind < summaries[j].Kind
	})
	return summaries
}

func buildManagementRouteExtensionPermissionSummaries(extensions []ManagementRouteExtensionInfo) []ManagementRouteExtensionPermissionSummary {
	type groupedPermission struct {
		names       []string
		displayName string
	}
	grouped := make(map[string]groupedPermission)
	for _, extension := range extensions {
		seen := make(map[string]struct{}, len(extension.Permissions))
		for _, permission := range extension.Permissions {
			permission.Key = strings.ToLower(strings.TrimSpace(permission.Key))
			permission.Name = strings.TrimSpace(permission.Name)
			if permission.Key == "" {
				continue
			}
			if _, exists := seen[permission.Key]; exists {
				continue
			}
			seen[permission.Key] = struct{}{}

			entry := grouped[permission.Key]
			entry.names = append(entry.names, extension.Name)
			if entry.displayName == "" {
				entry.displayName = permission.Name
			}
			grouped[permission.Key] = entry
		}
	}

	summaries := make([]ManagementRouteExtensionPermissionSummary, 0, len(grouped))
	for permission, entry := range grouped {
		sort.Strings(entry.names)
		summaries = append(summaries, ManagementRouteExtensionPermissionSummary{
			Permission: permission,
			Name:       entry.displayName,
			Total:      len(entry.names),
			Extensions: entry.names,
		})
	}
	sort.Slice(summaries, func(i, j int) bool {
		return summaries[i].Permission < summaries[j].Permission
	})
	return summaries
}

func buildManagementRouteExtensionRouteSummaries(extensions []ManagementRouteExtensionInfo) []ManagementRouteExtensionRouteSummary {
	grouped := make(map[string][]string)
	for _, extension := range extensions {
		seen := make(map[string]struct{}, len(extension.RoutePrefixes))
		for _, prefix := range extension.RoutePrefixes {
			prefix = normalizeManagementRouteExtensionRoutePrefix(prefix)
			if prefix == "" {
				continue
			}
			if _, exists := seen[prefix]; exists {
				continue
			}
			seen[prefix] = struct{}{}
			grouped[prefix] = append(grouped[prefix], extension.Name)
		}
	}

	return buildManagementRouteExtensionGroupedSummaries(
		grouped,
		func(prefix string, names []string) ManagementRouteExtensionRouteSummary {
			return ManagementRouteExtensionRouteSummary{
				RoutePrefix: prefix,
				Total:       len(names),
				Extensions:  names,
			}
		},
		func(left ManagementRouteExtensionRouteSummary, right ManagementRouteExtensionRouteSummary) bool {
			return left.RoutePrefix < right.RoutePrefix
		},
	)
}

func buildManagementRouteExtensionLinkRelSummaries(extensions []ManagementRouteExtensionInfo) []ManagementRouteExtensionLinkRelSummary {
	grouped := make(map[string][]string)
	for _, extension := range extensions {
		seen := make(map[string]struct{}, len(extension.Links))
		for _, link := range extension.Links {
			rel := strings.ToLower(strings.TrimSpace(link.Rel))
			if rel == "" {
				continue
			}
			if _, exists := seen[rel]; exists {
				continue
			}
			seen[rel] = struct{}{}
			grouped[rel] = append(grouped[rel], extension.Name)
		}
	}

	return buildManagementRouteExtensionGroupedSummaries(
		grouped,
		func(rel string, names []string) ManagementRouteExtensionLinkRelSummary {
			return ManagementRouteExtensionLinkRelSummary{
				Rel:        rel,
				Total:      len(names),
				Extensions: names,
			}
		},
		func(left ManagementRouteExtensionLinkRelSummary, right ManagementRouteExtensionLinkRelSummary) bool {
			return left.Rel < right.Rel
		},
	)
}

func buildManagementRouteExtensionCategorySummaries(extensions []ManagementRouteExtensionInfo) []ManagementRouteExtensionCategorySummary {
	grouped := make(map[string][]string)
	for _, extension := range extensions {
		category := strings.ToLower(strings.TrimSpace(extension.Category))
		if category == "" {
			category = "uncategorized"
		}
		grouped[category] = append(grouped[category], extension.Name)
	}

	return buildManagementRouteExtensionGroupedSummaries(
		grouped,
		func(category string, names []string) ManagementRouteExtensionCategorySummary {
			return ManagementRouteExtensionCategorySummary{
				Category:   category,
				Total:      len(names),
				Extensions: names,
			}
		},
		func(left ManagementRouteExtensionCategorySummary, right ManagementRouteExtensionCategorySummary) bool {
			return left.Category < right.Category
		},
	)
}

func buildManagementRouteExtensionTagSummaries(extensions []ManagementRouteExtensionInfo) []ManagementRouteExtensionTagSummary {
	grouped := make(map[string][]string)
	for _, extension := range extensions {
		for _, tag := range extension.Tags {
			tag = strings.ToLower(strings.TrimSpace(tag))
			if tag == "" {
				continue
			}
			grouped[tag] = append(grouped[tag], extension.Name)
		}
	}

	return buildManagementRouteExtensionGroupedSummaries(
		grouped,
		func(tag string, names []string) ManagementRouteExtensionTagSummary {
			return ManagementRouteExtensionTagSummary{
				Tag:        tag,
				Total:      len(names),
				Extensions: names,
			}
		},
		func(left ManagementRouteExtensionTagSummary, right ManagementRouteExtensionTagSummary) bool {
			return left.Tag < right.Tag
		},
	)
}
