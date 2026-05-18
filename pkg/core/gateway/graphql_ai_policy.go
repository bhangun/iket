package gateway

import (
	"reflect"
	"strings"

	"github.com/bhangun/iket/pkg/config"
)

func resolveAIPolicyPreset(route config.RouterConfig) *config.AIPolicyPreset {
	resolvedName := strings.TrimSpace(route.AIPolicyPreset)
	if resolvedName == "" || len(route.AIPolicyPresets) == 0 {
		return nil
	}
	for configuredName, policy := range route.AIPolicyPresets {
		if strings.EqualFold(strings.TrimSpace(configuredName), resolvedName) {
			policyCopy := policy
			return &policyCopy
		}
	}
	return nil
}

func resolveNamedAIPolicyPreset(route config.RouterConfig, presetName string) *config.AIPolicyPreset {
	resolvedName := strings.TrimSpace(presetName)
	if resolvedName == "" || len(route.AIPolicyPresets) == 0 {
		return nil
	}
	for configuredName, policy := range route.AIPolicyPresets {
		if strings.EqualFold(strings.TrimSpace(configuredName), resolvedName) {
			policyCopy := policy
			return &policyCopy
		}
	}
	return nil
}

func clearRouteAIPolicyFields(route *config.RouterConfig) {
	if route == nil {
		return
	}
	routeValue := reflect.ValueOf(route).Elem()
	presetType := reflect.TypeOf(config.AIPolicyPreset{})
	for i := 0; i < presetType.NumField(); i++ {
		fieldName := presetType.Field(i).Name
		targetField := routeValue.FieldByName(fieldName)
		if targetField.IsValid() && targetField.CanSet() {
			targetField.Set(reflect.Zero(targetField.Type()))
		}
	}
}

func overlayDirectRouteAIPolicyFields(base config.RouterConfig, override config.RouterConfig) config.RouterConfig {
	baseValue := reflect.ValueOf(&base).Elem()
	overrideValue := reflect.ValueOf(override)
	presetType := reflect.TypeOf(config.AIPolicyPreset{})
	for i := 0; i < presetType.NumField(); i++ {
		fieldName := presetType.Field(i).Name
		targetField := baseValue.FieldByName(fieldName)
		overrideField := overrideValue.FieldByName(fieldName)
		if targetField.IsValid() && targetField.CanSet() && overrideField.IsValid() && !overrideField.IsZero() {
			targetField.Set(overrideField)
		}
	}
	return base
}

func applyAIPolicyToRoute(route config.RouterConfig, policy *config.AIPolicyPreset) config.RouterConfig {
	if policy == nil {
		return route
	}
	effectiveRoute := route
	if len(policy.RequiredRequestHeaders) > 0 {
		effectiveRoute.RequiredRequestHeaders = policy.RequiredRequestHeaders
	}
	if len(policy.RequiredRequestHeaderRegex) > 0 {
		effectiveRoute.RequiredRequestHeaderRegex = policy.RequiredRequestHeaderRegex
	}
	if len(policy.RequestHeaders) > 0 {
		effectiveRoute.RequestHeaders = policy.RequestHeaders
	}
	if len(policy.RemoveRequestHeaders) > 0 {
		effectiveRoute.RemoveRequestHeaders = policy.RemoveRequestHeaders
	}
	if len(policy.RequestRedactHeaders) > 0 {
		effectiveRoute.RequestRedactHeaders = policy.RequestRedactHeaders
	}
	if len(policy.QueryParams) > 0 {
		effectiveRoute.QueryParams = policy.QueryParams
	}
	if len(policy.RemoveQueryParams) > 0 {
		effectiveRoute.RemoveQueryParams = policy.RemoveQueryParams
	}
	if len(policy.RequestJSONFields) > 0 {
		effectiveRoute.RequestJSONFields = policy.RequestJSONFields
	}
	if len(policy.RemoveRequestJSONFields) > 0 {
		effectiveRoute.RemoveRequestJSONFields = policy.RemoveRequestJSONFields
	}
	if len(policy.RequestRedactJSONFields) > 0 {
		effectiveRoute.RequestRedactJSONFields = policy.RequestRedactJSONFields
	}
	if len(policy.RequestBodyBlockRegex) > 0 {
		effectiveRoute.RequestBodyBlockRegex = policy.RequestBodyBlockRegex
	}
	if len(policy.RequestBodyRequireRegex) > 0 {
		effectiveRoute.RequestBodyRequireRegex = policy.RequestBodyRequireRegex
	}
	if len(policy.RequestPIIBlockTypes) > 0 {
		effectiveRoute.RequestPIIBlockTypes = policy.RequestPIIBlockTypes
	}
	if len(policy.TransformWhenHeaders) > 0 {
		effectiveRoute.TransformWhenHeaders = policy.TransformWhenHeaders
	}
	if len(policy.TransformWhenQueryParams) > 0 {
		effectiveRoute.TransformWhenQueryParams = policy.TransformWhenQueryParams
	}
	if len(policy.TransformWhenHeaderRegex) > 0 {
		effectiveRoute.TransformWhenHeaderRegex = policy.TransformWhenHeaderRegex
	}
	if len(policy.TransformWhenQueryRegex) > 0 {
		effectiveRoute.TransformWhenQueryRegex = policy.TransformWhenQueryRegex
	}
	if len(policy.TransformMethods) > 0 {
		effectiveRoute.TransformMethods = policy.TransformMethods
	}
	if len(policy.AllowedModels) > 0 {
		effectiveRoute.AllowedModels = policy.AllowedModels
	}
	if strings.TrimSpace(policy.ModelField) != "" {
		effectiveRoute.ModelField = policy.ModelField
	}
	if len(policy.AllowedToolNames) > 0 {
		effectiveRoute.AllowedToolNames = policy.AllowedToolNames
	}
	if strings.TrimSpace(policy.ToolField) != "" {
		effectiveRoute.ToolField = policy.ToolField
	}
	if policy.MaxMessages > 0 {
		effectiveRoute.MaxMessages = policy.MaxMessages
	}
	if strings.TrimSpace(policy.MessagesField) != "" {
		effectiveRoute.MessagesField = policy.MessagesField
	}
	if policy.MaxToolCalls > 0 {
		effectiveRoute.MaxToolCalls = policy.MaxToolCalls
	}
	if strings.TrimSpace(policy.ToolCallsField) != "" {
		effectiveRoute.ToolCallsField = policy.ToolCallsField
	}
	if policy.MaxInputTokens > 0 {
		effectiveRoute.MaxInputTokens = policy.MaxInputTokens
	}
	if strings.TrimSpace(policy.InputTokensField) != "" {
		effectiveRoute.InputTokensField = policy.InputTokensField
	}
	if policy.MaxOutputTokens > 0 {
		effectiveRoute.MaxOutputTokens = policy.MaxOutputTokens
	}
	if strings.TrimSpace(policy.OutputTokensField) != "" {
		effectiveRoute.OutputTokensField = policy.OutputTokensField
	}
	if len(policy.AllowedUpstreamHosts) > 0 {
		effectiveRoute.AllowedUpstreamHosts = policy.AllowedUpstreamHosts
	}
	if len(policy.SuccessResponseFields) > 0 {
		effectiveRoute.SuccessResponseFields = policy.SuccessResponseFields
	}
	if len(policy.ErrorResponseFields) > 0 {
		effectiveRoute.ErrorResponseFields = policy.ErrorResponseFields
	}
	if len(policy.ResponseHeaders) > 0 {
		effectiveRoute.ResponseHeaders = policy.ResponseHeaders
	}
	if len(policy.RemoveResponseHeaders) > 0 {
		effectiveRoute.RemoveResponseHeaders = policy.RemoveResponseHeaders
	}
	if len(policy.ResponseRedactHeaders) > 0 {
		effectiveRoute.ResponseRedactHeaders = policy.ResponseRedactHeaders
	}
	if len(policy.ResponseTransformStatusCodes) > 0 {
		effectiveRoute.ResponseTransformStatusCodes = policy.ResponseTransformStatusCodes
	}
	if len(policy.ResponseTransformStatusClasses) > 0 {
		effectiveRoute.ResponseTransformStatusClasses = policy.ResponseTransformStatusClasses
	}
	if len(policy.ResponseTransformWhenHeaders) > 0 {
		effectiveRoute.ResponseTransformWhenHeaders = policy.ResponseTransformWhenHeaders
	}
	if len(policy.ResponseTransformHeaderRegex) > 0 {
		effectiveRoute.ResponseTransformHeaderRegex = policy.ResponseTransformHeaderRegex
	}
	if len(policy.ResponseJSONFields) > 0 {
		effectiveRoute.ResponseJSONFields = policy.ResponseJSONFields
	}
	if len(policy.RemoveResponseJSONFields) > 0 {
		effectiveRoute.RemoveResponseJSONFields = policy.RemoveResponseJSONFields
	}
	if len(policy.ResponseRedactJSONFields) > 0 {
		effectiveRoute.ResponseRedactJSONFields = policy.ResponseRedactJSONFields
	}
	if len(policy.ResponseBodyBlockRegex) > 0 {
		effectiveRoute.ResponseBodyBlockRegex = policy.ResponseBodyBlockRegex
	}
	if len(policy.ResponseBodyRequireRegex) > 0 {
		effectiveRoute.ResponseBodyRequireRegex = policy.ResponseBodyRequireRegex
	}
	if len(policy.ResponsePIIBlockTypes) > 0 {
		effectiveRoute.ResponsePIIBlockTypes = policy.ResponsePIIBlockTypes
	}
	return effectiveRoute
}

func applyRouteAIPreset(route config.RouterConfig) config.RouterConfig {
	effectiveRoute := route
	clearRouteAIPolicyFields(&effectiveRoute)
	for _, presetName := range route.AIPolicyPresetChain {
		effectiveRoute = applyAIPolicyToRoute(effectiveRoute, resolveNamedAIPolicyPreset(route, presetName))
	}
	effectiveRoute = applyAIPolicyToRoute(effectiveRoute, resolveAIPolicyPreset(route))
	return overlayDirectRouteAIPolicyFields(effectiveRoute, route)
}
