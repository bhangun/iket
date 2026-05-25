package api

import "strings"

type managementRouteExtensionPredicate func(ManagementRouteExtensionInfo) bool

type managementRouteExtensionSearchField func(ManagementRouteExtensionInfo) []string

type managementRouteExtensionFilterPredicateSpec struct {
	active    func(ManagementRouteExtensionFilter) bool
	predicate func(ManagementRouteExtensionFilter) managementRouteExtensionPredicate
}

var managementRouteExtensionSearchFields = []managementRouteExtensionSearchField{
	func(extension ManagementRouteExtensionInfo) []string {
		return []string{
			extension.Name,
			extension.DisplayName,
			extension.Description,
			extension.Version,
			extension.ReleaseStage,
			extension.Compatibility.MinimumIketVersion,
			extension.Compatibility.MaximumIketVersion,
			extension.Compatibility.Status,
			extension.Compatibility.Message,
			extension.Provider.Kind,
			extension.Provider.Name,
			extension.Provider.URL,
			extension.Category,
			extension.SupportStatus,
		}
	},
	func(extension ManagementRouteExtensionInfo) []string {
		values := make([]string, 0, len(extension.Permissions)*3)
		for _, permission := range extension.Permissions {
			values = append(values, permission.Key, permission.Name, permission.Description)
		}
		return values
	},
	func(extension ManagementRouteExtensionInfo) []string {
		return extension.RoutePrefixes
	},
	func(extension ManagementRouteExtensionInfo) []string {
		values := make([]string, 0, len(extension.Links)*3)
		for _, link := range extension.Links {
			values = append(values, link.Rel, link.URL, link.Label)
		}
		return values
	},
	func(extension ManagementRouteExtensionInfo) []string {
		return extension.Tags
	},
	func(extension ManagementRouteExtensionInfo) []string {
		return extension.Capabilities
	},
}

var managementRouteExtensionFilterPredicateSpecs = []managementRouteExtensionFilterPredicateSpec{
	{
		active: func(filter ManagementRouteExtensionFilter) bool { return filter.Search != "" },
		predicate: func(filter ManagementRouteExtensionFilter) managementRouteExtensionPredicate {
			search := filter.Search
			return func(extension ManagementRouteExtensionInfo) bool {
				return managementRouteExtensionMatchesSearch(extension, search)
			}
		},
	},
	{
		active: func(filter ManagementRouteExtensionFilter) bool { return filter.ReleaseStage != "" },
		predicate: func(filter ManagementRouteExtensionFilter) managementRouteExtensionPredicate {
			stage := filter.ReleaseStage
			return func(extension ManagementRouteExtensionInfo) bool {
				return extension.ReleaseStage == stage
			}
		},
	},
	{
		active: func(filter ManagementRouteExtensionFilter) bool { return filter.CompatibilityStatus != "" },
		predicate: func(filter ManagementRouteExtensionFilter) managementRouteExtensionPredicate {
			status := filter.CompatibilityStatus
			return func(extension ManagementRouteExtensionInfo) bool {
				return extension.Compatibility.Status == status
			}
		},
	},
	{
		active: func(filter ManagementRouteExtensionFilter) bool { return filter.ProviderKind != "" },
		predicate: func(filter ManagementRouteExtensionFilter) managementRouteExtensionPredicate {
			kind := filter.ProviderKind
			return func(extension ManagementRouteExtensionInfo) bool {
				return extension.Provider.Kind == kind
			}
		},
	},
	{
		active: func(filter ManagementRouteExtensionFilter) bool { return filter.ProviderName != "" },
		predicate: func(filter ManagementRouteExtensionFilter) managementRouteExtensionPredicate {
			provider := filter.ProviderName
			return func(extension ManagementRouteExtensionInfo) bool {
				return managementRouteExtensionHasProviderName(extension, provider)
			}
		},
	},
	{
		active: func(filter ManagementRouteExtensionFilter) bool { return filter.Permission != "" },
		predicate: func(filter ManagementRouteExtensionFilter) managementRouteExtensionPredicate {
			permission := filter.Permission
			return func(extension ManagementRouteExtensionInfo) bool {
				return managementRouteExtensionHasPermission(extension, permission)
			}
		},
	},
	{
		active: func(filter ManagementRouteExtensionFilter) bool { return filter.RoutePrefix != "" },
		predicate: func(filter ManagementRouteExtensionFilter) managementRouteExtensionPredicate {
			prefix := filter.RoutePrefix
			return func(extension ManagementRouteExtensionInfo) bool {
				return managementRouteExtensionHasRoutePrefix(extension, prefix)
			}
		},
	},
	{
		active: func(filter ManagementRouteExtensionFilter) bool { return filter.LinkRel != "" },
		predicate: func(filter ManagementRouteExtensionFilter) managementRouteExtensionPredicate {
			rel := filter.LinkRel
			return func(extension ManagementRouteExtensionInfo) bool {
				return managementRouteExtensionHasLinkRel(extension, rel)
			}
		},
	},
	{
		active: func(filter ManagementRouteExtensionFilter) bool { return filter.Category != "" },
		predicate: func(filter ManagementRouteExtensionFilter) managementRouteExtensionPredicate {
			category := filter.Category
			return func(extension ManagementRouteExtensionInfo) bool {
				return extension.Category == category
			}
		},
	},
	{
		active: func(filter ManagementRouteExtensionFilter) bool { return filter.Tag != "" },
		predicate: func(filter ManagementRouteExtensionFilter) managementRouteExtensionPredicate {
			tag := filter.Tag
			return func(extension ManagementRouteExtensionInfo) bool {
				return managementRouteExtensionHasTag(extension, tag)
			}
		},
	},
	{
		active: func(filter ManagementRouteExtensionFilter) bool { return filter.Capability != "" },
		predicate: func(filter ManagementRouteExtensionFilter) managementRouteExtensionPredicate {
			capability := filter.Capability
			return func(extension ManagementRouteExtensionInfo) bool {
				return managementRouteExtensionHasCapability(extension, capability)
			}
		},
	},
	{
		active: func(filter ManagementRouteExtensionFilter) bool { return filter.UnsupportedCapability != "" },
		predicate: func(filter ManagementRouteExtensionFilter) managementRouteExtensionPredicate {
			capability := filter.UnsupportedCapability
			return func(extension ManagementRouteExtensionInfo) bool {
				return managementRouteExtensionHasUnsupportedCapability(extension, capability)
			}
		},
	},
	{
		active: func(filter ManagementRouteExtensionFilter) bool { return filter.SupportStatus != "" },
		predicate: func(filter ManagementRouteExtensionFilter) managementRouteExtensionPredicate {
			status := filter.SupportStatus
			return func(extension ManagementRouteExtensionInfo) bool {
				return extension.SupportStatus == status
			}
		},
	},
	{
		active: func(filter ManagementRouteExtensionFilter) bool { return filter.Supported != nil },
		predicate: func(filter ManagementRouteExtensionFilter) managementRouteExtensionPredicate {
			supported := *filter.Supported
			return func(extension ManagementRouteExtensionInfo) bool {
				return extension.Supported == supported
			}
		},
	},
}

func firstManagementRouteExtensionFilter(filters []ManagementRouteExtensionFilter) ManagementRouteExtensionFilter {
	if len(filters) == 0 {
		return ManagementRouteExtensionFilter{}
	}
	return filters[0]
}

func normalizeManagementRouteExtensionFilter(filter ManagementRouteExtensionFilter) ManagementRouteExtensionFilter {
	filter.Search = strings.ToLower(strings.TrimSpace(filter.Search))
	filter.ReleaseStage = strings.ToLower(strings.TrimSpace(filter.ReleaseStage))
	filter.CompatibilityStatus = strings.ToLower(strings.TrimSpace(filter.CompatibilityStatus))
	filter.ProviderKind = strings.ToLower(strings.TrimSpace(filter.ProviderKind))
	filter.ProviderName = strings.ToLower(strings.TrimSpace(filter.ProviderName))
	filter.Permission = strings.ToLower(strings.TrimSpace(filter.Permission))
	filter.RoutePrefix = normalizeManagementRouteExtensionRoutePrefix(filter.RoutePrefix)
	filter.LinkRel = strings.ToLower(strings.TrimSpace(filter.LinkRel))
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

	predicates := managementRouteExtensionFilterPredicates(filter)
	filtered := make([]ManagementRouteExtensionInfo, 0, len(extensions))
	for _, extension := range extensions {
		if !managementRouteExtensionMatchesPredicates(extension, predicates) {
			continue
		}
		filtered = append(filtered, extension)
	}
	return filtered
}

func managementRouteExtensionFilterPredicates(filter ManagementRouteExtensionFilter) []managementRouteExtensionPredicate {
	predicates := make([]managementRouteExtensionPredicate, 0, len(managementRouteExtensionFilterPredicateSpecs))
	for _, spec := range managementRouteExtensionFilterPredicateSpecs {
		if !spec.active(filter) {
			continue
		}
		predicates = append(predicates, spec.predicate(filter))
	}
	return predicates
}

func managementRouteExtensionMatchesPredicates(extension ManagementRouteExtensionInfo, predicates []managementRouteExtensionPredicate) bool {
	for _, predicate := range predicates {
		if !predicate(extension) {
			return false
		}
	}
	return true
}

func managementRouteExtensionMatchesSearch(extension ManagementRouteExtensionInfo, search string) bool {
	search = strings.ToLower(strings.TrimSpace(search))
	if search == "" {
		return true
	}

	for _, field := range managementRouteExtensionSearchFields {
		if managementRouteExtensionSearchValuesContain(field(extension), search) {
			return true
		}
	}
	return false
}

func managementRouteExtensionSearchValuesContain(values []string, search string) bool {
	for _, value := range values {
		if strings.Contains(strings.ToLower(value), search) {
			return true
		}
	}
	return false
}

func managementRouteExtensionHasProviderName(extension ManagementRouteExtensionInfo, provider string) bool {
	provider = strings.ToLower(strings.TrimSpace(provider))
	if provider == "" {
		return false
	}
	return strings.ToLower(strings.TrimSpace(extension.Provider.Name)) == provider
}

func managementRouteExtensionHasPermission(extension ManagementRouteExtensionInfo, permission string) bool {
	permission = strings.ToLower(strings.TrimSpace(permission))
	if permission == "" {
		return false
	}
	for _, candidate := range extension.Permissions {
		if candidate.Key == permission {
			return true
		}
	}
	return false
}

func managementRouteExtensionHasRoutePrefix(extension ManagementRouteExtensionInfo, prefix string) bool {
	prefix = normalizeManagementRouteExtensionRoutePrefix(prefix)
	if prefix == "" {
		return false
	}
	for _, candidate := range extension.RoutePrefixes {
		candidate = normalizeManagementRouteExtensionRoutePrefix(candidate)
		if candidate == prefix || strings.HasPrefix(candidate, prefix+"/") {
			return true
		}
	}
	return false
}

func managementRouteExtensionHasLinkRel(extension ManagementRouteExtensionInfo, rel string) bool {
	rel = strings.ToLower(strings.TrimSpace(rel))
	if rel == "" {
		return false
	}
	for _, link := range extension.Links {
		if strings.ToLower(strings.TrimSpace(link.Rel)) == rel {
			return true
		}
	}
	return false
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
	for _, spec := range managementRouteExtensionFilterPredicateSpecs {
		if spec.active(filter) {
			return true
		}
	}
	return false
}

func managementRouteExtensionFilterPointer(filter ManagementRouteExtensionFilter) *ManagementRouteExtensionFilter {
	if !hasManagementRouteExtensionFilter(filter) {
		return nil
	}
	return &filter
}
