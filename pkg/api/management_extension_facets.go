package api

import (
	"sort"
	"strings"
)

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
	summaries := make([]ManagementRouteExtensionStatusSummary, 0, len(grouped))
	for status, names := range grouped {
		sort.Strings(names)
		summaries = append(summaries, ManagementRouteExtensionStatusSummary{
			Status:     status,
			Total:      len(names),
			Extensions: names,
		})
	}
	sort.Slice(summaries, func(i, j int) bool {
		return summaries[i].Status < summaries[j].Status
	})
	return summaries
}

func buildManagementRouteExtensionUnsupportedCapabilitySummaries(grouped map[string][]string) []ManagementRouteExtensionUnsupportedCapabilitySummary {
	summaries := make([]ManagementRouteExtensionUnsupportedCapabilitySummary, 0, len(grouped))
	for capability, names := range grouped {
		sort.Strings(names)
		summaries = append(summaries, ManagementRouteExtensionUnsupportedCapabilitySummary{
			Capability: capability,
			Total:      len(names),
			Extensions: names,
		})
	}
	sort.Slice(summaries, func(i, j int) bool {
		return summaries[i].Capability < summaries[j].Capability
	})
	return summaries
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

	summaries := make([]ManagementRouteExtensionCategorySummary, 0, len(grouped))
	for category, names := range grouped {
		sort.Strings(names)
		summaries = append(summaries, ManagementRouteExtensionCategorySummary{
			Category:   category,
			Total:      len(names),
			Extensions: names,
		})
	}
	sort.Slice(summaries, func(i, j int) bool {
		return summaries[i].Category < summaries[j].Category
	})
	return summaries
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

	summaries := make([]ManagementRouteExtensionTagSummary, 0, len(grouped))
	for tag, names := range grouped {
		sort.Strings(names)
		summaries = append(summaries, ManagementRouteExtensionTagSummary{
			Tag:        tag,
			Total:      len(names),
			Extensions: names,
		})
	}
	sort.Slice(summaries, func(i, j int) bool {
		return summaries[i].Tag < summaries[j].Tag
	})
	return summaries
}
