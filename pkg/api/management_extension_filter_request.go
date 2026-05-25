package api

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

type managementRouteExtensionFilterQueryField struct {
	keys []string
	set  func(*ManagementRouteExtensionFilter, string)
}

var managementRouteExtensionFilterQueryFields = []managementRouteExtensionFilterQueryField{
	{keys: []string{"q", "search"}, set: func(filter *ManagementRouteExtensionFilter, value string) { filter.Search = value }},
	{keys: []string{"release_stage", "stage"}, set: func(filter *ManagementRouteExtensionFilter, value string) { filter.ReleaseStage = value }},
	{keys: []string{"compatibility_status", "compatibility"}, set: func(filter *ManagementRouteExtensionFilter, value string) { filter.CompatibilityStatus = value }},
	{keys: []string{"provider_kind", "source"}, set: func(filter *ManagementRouteExtensionFilter, value string) { filter.ProviderKind = value }},
	{keys: []string{"provider", "provider_name"}, set: func(filter *ManagementRouteExtensionFilter, value string) { filter.ProviderName = value }},
	{keys: []string{"permission", "scope"}, set: func(filter *ManagementRouteExtensionFilter, value string) { filter.Permission = value }},
	{keys: []string{"route_prefix", "route"}, set: func(filter *ManagementRouteExtensionFilter, value string) { filter.RoutePrefix = value }},
	{keys: []string{"link_rel", "rel"}, set: func(filter *ManagementRouteExtensionFilter, value string) { filter.LinkRel = value }},
	{keys: []string{"category"}, set: func(filter *ManagementRouteExtensionFilter, value string) { filter.Category = value }},
	{keys: []string{"tag"}, set: func(filter *ManagementRouteExtensionFilter, value string) { filter.Tag = value }},
	{keys: []string{"capability"}, set: func(filter *ManagementRouteExtensionFilter, value string) { filter.Capability = value }},
	{keys: []string{"unsupported_capability", "missing_capability"}, set: func(filter *ManagementRouteExtensionFilter, value string) { filter.UnsupportedCapability = value }},
	{keys: []string{"support_status", "status"}, set: func(filter *ManagementRouteExtensionFilter, value string) { filter.SupportStatus = value }},
}

func managementRouteExtensionFilterFromRequest(r *http.Request) (ManagementRouteExtensionFilter, error) {
	query := r.URL.Query()
	filter := ManagementRouteExtensionFilter{}
	for _, field := range managementRouteExtensionFilterQueryFields {
		field.set(&filter, firstManagementRouteExtensionQueryValue(query, field.keys...))
	}

	if rawSupported := strings.TrimSpace(query.Get("supported")); rawSupported != "" {
		supported, err := strconv.ParseBool(rawSupported)
		if err != nil {
			return ManagementRouteExtensionFilter{}, managedValidationError("supported filter must be true or false", err)
		}
		filter.Supported = &supported
	}
	return filter, nil
}

func firstManagementRouteExtensionQueryValue(query url.Values, keys ...string) string {
	for _, key := range keys {
		value := query.Get(key)
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}
