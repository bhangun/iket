package api

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

type pluginListFilter struct {
	Type              string
	Enabled           *bool
	Status            string
	DiagnosticsStatus string
	Capabilities      []string
}

func pluginListFilterFromRequest(r *http.Request) (pluginListFilter, error) {
	if r == nil || r.URL == nil {
		return pluginListFilter{}, nil
	}
	query := r.URL.Query()
	filter := pluginListFilter{
		Type:              normalizePluginFilterValue(firstPluginListQueryValue(query, "type", "plugin_type")),
		Status:            normalizePluginFilterValue(firstPluginListQueryValue(query, "status")),
		DiagnosticsStatus: normalizePluginFilterValue(firstPluginListQueryValue(query, "diagnostics_status", "diagnostic_status")),
		Capabilities:      pluginListCapabilityFilterValues(query),
	}
	if rawEnabled := firstPluginListQueryValue(query, "enabled"); strings.TrimSpace(rawEnabled) != "" {
		enabled, err := strconv.ParseBool(rawEnabled)
		if err != nil {
			return pluginListFilter{}, managedValidationError("enabled filter must be true or false", err)
		}
		filter.Enabled = &enabled
	}
	return filter, nil
}

func pluginInfoMatchesFilter(info PluginInfo, filter pluginListFilter) bool {
	if filter.Type != "" && normalizePluginFilterValue(info.Type) != filter.Type {
		return false
	}
	if filter.Enabled != nil && info.Enabled != *filter.Enabled {
		return false
	}
	if filter.Status != "" && normalizePluginFilterValue(info.Status) != filter.Status {
		return false
	}
	if filter.DiagnosticsStatus != "" && normalizePluginFilterValue(info.DiagnosticsStatus) != filter.DiagnosticsStatus {
		return false
	}
	for _, capability := range filter.Capabilities {
		if !pluginCapabilitiesContain(info.Capabilities, capability) {
			return false
		}
	}
	return true
}

func pluginCapabilitiesContain(capabilities []string, capability string) bool {
	capability = normalizePluginFilterValue(capability)
	if capability == "" {
		return true
	}
	for _, candidate := range capabilities {
		if normalizePluginFilterValue(candidate) == capability {
			return true
		}
	}
	return false
}

func pluginListCapabilityFilterValues(query url.Values) []string {
	capabilities := make([]string, 0)
	for _, key := range []string{"capability", "capabilities"} {
		for _, rawValue := range query[key] {
			for _, part := range strings.Split(rawValue, ",") {
				capability := normalizePluginFilterValue(part)
				if capability == "" || pluginCapabilitiesContain(capabilities, capability) {
					continue
				}
				capabilities = append(capabilities, capability)
			}
		}
	}
	return capabilities
}

func firstPluginListQueryValue(query url.Values, keys ...string) string {
	for _, key := range keys {
		if value := strings.TrimSpace(query.Get(key)); value != "" {
			return value
		}
	}
	return ""
}

func normalizePluginFilterValue(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func pluginListFilterActive(filter pluginListFilter) bool {
	return filter.Type != "" ||
		filter.Enabled != nil ||
		filter.Status != "" ||
		filter.DiagnosticsStatus != "" ||
		len(filter.Capabilities) > 0
}

func pluginListFilterResponse(filter pluginListFilter) map[string]interface{} {
	response := make(map[string]interface{})
	if filter.Type != "" {
		response["type"] = filter.Type
	}
	if filter.Enabled != nil {
		response["enabled"] = *filter.Enabled
	}
	if filter.Status != "" {
		response["status"] = filter.Status
	}
	if filter.DiagnosticsStatus != "" {
		response["diagnostics_status"] = filter.DiagnosticsStatus
	}
	if len(filter.Capabilities) > 0 {
		response["capabilities"] = append([]string(nil), filter.Capabilities...)
	}
	return response
}
