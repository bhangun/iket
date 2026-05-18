package gateway

import (
	"fmt"
	"net/http"
	"reflect"
	"sort"
	"strings"

	"github.com/bhangun/iket/pkg/config"
)

type RoutePolicyPresetStep struct {
	Name   string   `json:"name"`
	Layer  string   `json:"layer"`
	Fields []string `json:"fields,omitempty"`
}

type RoutePolicyInspection struct {
	ServiceName      string                  `json:"service_name,omitempty"`
	RoutePath        string                  `json:"route_path"`
	Method           string                  `json:"method"`
	Protocol         string                  `json:"protocol,omitempty"`
	BucketKey        string                  `json:"bucket_key,omitempty"`
	AvailablePresets []string                `json:"available_presets,omitempty"`
	AppliedPresets   []RoutePolicyPresetStep `json:"applied_presets,omitempty"`
	EffectivePolicy  map[string]interface{}  `json:"effective_policy,omitempty"`
	FieldSources     map[string]string       `json:"field_sources,omitempty"`
}

type RoutePolicyDiffEntry struct {
	Field      string      `json:"field"`
	FromValue  interface{} `json:"from_value,omitempty"`
	ToValue    interface{} `json:"to_value,omitempty"`
	FromSource string      `json:"from_source,omitempty"`
	ToSource   string      `json:"to_source,omitempty"`
}

type RoutePolicyDiff struct {
	From                RoutePolicyInspection  `json:"from"`
	To                  RoutePolicyInspection  `json:"to"`
	ChangedFields       []RoutePolicyDiffEntry `json:"changed_fields,omitempty"`
	ChangedFieldCount   int                    `json:"changed_field_count"`
	AvailableOnlyOnFrom []string               `json:"available_only_on_from,omitempty"`
	AvailableOnlyOnTo   []string               `json:"available_only_on_to,omitempty"`
}

func (g *Gateway) InspectRoutePolicy(method, path string, headers http.Header, bucketKey string) (*RoutePolicyInspection, bool) {
	match := ResolveRouteMatch(g.config.GetAllRoutesFromServices(g.logger), strings.ToUpper(strings.TrimSpace(method)), strings.TrimSpace(path), headers, strings.TrimSpace(bucketKey))
	if !match.Matched {
		return nil, false
	}
	report := inspectRoutePolicy(match.Route, strings.ToUpper(strings.TrimSpace(method)), strings.TrimSpace(bucketKey))
	return &report, true
}

func (g *Gateway) DiffRoutePolicy(fromMethod, fromPath string, fromHeaders http.Header, fromBucketKey string, toMethod, toPath string, toHeaders http.Header, toBucketKey string) (*RoutePolicyDiff, bool) {
	fromInspection, ok := g.InspectRoutePolicy(fromMethod, fromPath, fromHeaders, fromBucketKey)
	if !ok {
		return nil, false
	}
	toInspection, ok := g.InspectRoutePolicy(toMethod, toPath, toHeaders, toBucketKey)
	if !ok {
		return nil, false
	}
	diff := buildRoutePolicyDiff(*fromInspection, *toInspection)
	return &diff, true
}

func inspectRoutePolicy(route config.RouterConfig, method string, bucketKey string) RoutePolicyInspection {
	effectiveRoute := route
	clearRouteAIPolicyFields(&effectiveRoute)
	availablePresets := make([]string, 0, len(route.AIPolicyPresets))
	for name := range route.AIPolicyPresets {
		availablePresets = append(availablePresets, strings.TrimSpace(name))
	}
	sort.Strings(availablePresets)
	applied := make([]RoutePolicyPresetStep, 0, len(route.AIPolicyPresetChain)+1)
	fieldSources := make(map[string]string)
	for _, presetName := range route.AIPolicyPresetChain {
		if preset := resolveNamedAIPolicyPreset(route, presetName); preset != nil {
			effectiveRoute = applyAIPolicyToRoute(effectiveRoute, preset)
			fields := populatedAIPolicyFields(*preset)
			applied = append(applied, RoutePolicyPresetStep{Name: strings.TrimSpace(presetName), Layer: "chain", Fields: fields})
			for _, field := range fields {
				fieldSources[field] = "preset_chain:" + strings.TrimSpace(presetName)
			}
		}
	}
	if preset := resolveAIPolicyPreset(route); preset != nil {
		effectiveRoute = applyAIPolicyToRoute(effectiveRoute, preset)
		fields := populatedAIPolicyFields(*preset)
		applied = append(applied, RoutePolicyPresetStep{Name: strings.TrimSpace(route.AIPolicyPreset), Layer: "preset", Fields: fields})
		for _, field := range fields {
			fieldSources[field] = "preset:" + strings.TrimSpace(route.AIPolicyPreset)
		}
	}
	for _, field := range populatedRouteAIPolicyFields(route) {
		fieldSources[field] = "route"
	}
	effectiveRoute = overlayDirectRouteAIPolicyFields(effectiveRoute, route)
	return RoutePolicyInspection{
		ServiceName:      route.ServiceName,
		RoutePath:        route.Path,
		Method:           method,
		Protocol:         strings.TrimSpace(route.Protocol),
		BucketKey:        strings.TrimSpace(bucketKey),
		AvailablePresets: availablePresets,
		AppliedPresets:   applied,
		EffectivePolicy:  extractRouteAIPolicyFields(effectiveRoute),
		FieldSources:     fieldSources,
	}
}

func populatedAIPolicyFields(policy config.AIPolicyPreset) []string {
	return populatedStructFields(policy)
}

func populatedRouteAIPolicyFields(route config.RouterConfig) []string {
	fields := populatedStructFields(route)
	allowed := make(map[string]struct{}, len(populatedAIPolicyFields(config.AIPolicyPreset{})))
	presetType := reflect.TypeOf(config.AIPolicyPreset{})
	for i := 0; i < presetType.NumField(); i++ {
		allowed[presetType.Field(i).Name] = struct{}{}
	}
	filtered := make([]string, 0, len(fields))
	for _, field := range fields {
		if _, ok := allowed[field]; ok {
			filtered = append(filtered, field)
		}
	}
	return filtered
}

func populatedStructFields(value interface{}) []string {
	structValue := reflect.ValueOf(value)
	structType := structValue.Type()
	fields := make([]string, 0, structValue.NumField())
	for i := 0; i < structValue.NumField(); i++ {
		fieldValue := structValue.Field(i)
		if !fieldValue.IsZero() {
			fields = append(fields, structType.Field(i).Name)
		}
	}
	sort.Strings(fields)
	return fields
}

func extractRouteAIPolicyFields(route config.RouterConfig) map[string]interface{} {
	routeValue := reflect.ValueOf(route)
	presetType := reflect.TypeOf(config.AIPolicyPreset{})
	fields := make(map[string]interface{})
	for i := 0; i < presetType.NumField(); i++ {
		fieldName := presetType.Field(i).Name
		fieldValue := routeValue.FieldByName(fieldName)
		if fieldValue.IsValid() && !fieldValue.IsZero() {
			fields[fieldName] = fieldValue.Interface()
		}
	}
	return fields
}

func buildRoutePolicyDiff(from RoutePolicyInspection, to RoutePolicyInspection) RoutePolicyDiff {
	fieldSet := make(map[string]struct{}, len(from.EffectivePolicy)+len(to.EffectivePolicy))
	for field := range from.EffectivePolicy {
		fieldSet[field] = struct{}{}
	}
	for field := range to.EffectivePolicy {
		fieldSet[field] = struct{}{}
	}
	fieldNames := make([]string, 0, len(fieldSet))
	for field := range fieldSet {
		fieldNames = append(fieldNames, field)
	}
	sort.Strings(fieldNames)

	changed := make([]RoutePolicyDiffEntry, 0)
	for _, field := range fieldNames {
		fromValue, fromOK := from.EffectivePolicy[field]
		toValue, toOK := to.EffectivePolicy[field]
		if fromOK && toOK && reflect.DeepEqual(fromValue, toValue) && strings.TrimSpace(from.FieldSources[field]) == strings.TrimSpace(to.FieldSources[field]) {
			continue
		}
		entry := RoutePolicyDiffEntry{
			Field:      field,
			FromSource: strings.TrimSpace(from.FieldSources[field]),
			ToSource:   strings.TrimSpace(to.FieldSources[field]),
		}
		if fromOK {
			entry.FromValue = fromValue
		}
		if toOK {
			entry.ToValue = toValue
		}
		changed = append(changed, entry)
	}

	return RoutePolicyDiff{
		From:                from,
		To:                  to,
		ChangedFields:       changed,
		ChangedFieldCount:   len(changed),
		AvailableOnlyOnFrom: diffStringSlices(from.AvailablePresets, to.AvailablePresets),
		AvailableOnlyOnTo:   diffStringSlices(to.AvailablePresets, from.AvailablePresets),
	}
}

func diffStringSlices(left []string, right []string) []string {
	rightSet := make(map[string]struct{}, len(right))
	for _, item := range right {
		rightSet[strings.TrimSpace(item)] = struct{}{}
	}
	diff := make([]string, 0)
	for _, item := range left {
		trimmed := strings.TrimSpace(item)
		if trimmed == "" {
			continue
		}
		if _, ok := rightSet[trimmed]; ok {
			continue
		}
		diff = append(diff, trimmed)
	}
	sort.Strings(diff)
	return diff
}

func ParseRoutePolicyHeaderParams(values []string) (http.Header, error) {
	headers := make(http.Header)
	for _, raw := range values {
		name, value, ok := strings.Cut(raw, ":")
		if !ok || strings.TrimSpace(name) == "" {
			return nil, fmt.Errorf("header query parameters must use Name:Value format")
		}
		headers.Add(strings.TrimSpace(name), strings.TrimSpace(value))
	}
	return headers, nil
}
