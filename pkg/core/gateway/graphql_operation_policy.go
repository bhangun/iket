package gateway

import (
	"context"
	"net/http"
	"reflect"
	"strings"

	"github.com/bhangun/iket/pkg/config"
)

func resolveGraphQLOperationPolicy(route config.RouterConfig, operationName string, queryText string) *config.GraphQLOperationPolicy {
	resolvedName := strings.TrimSpace(operationName)
	if resolvedName == "" {
		resolvedName = inferGraphQLOperationName(queryText)
	}
	if resolvedName == "" || len(route.GraphQLOperationPolicies) == 0 {
		return nil
	}
	for configuredName, policy := range route.GraphQLOperationPolicies {
		if strings.EqualFold(strings.TrimSpace(configuredName), resolvedName) {
			policyCopy := policy
			if preset := resolveGraphQLOperationPreset(route, policy.Preset); preset != nil {
				policyCopy = mergeGraphQLOperationPolicy(*preset, policyCopy)
			}
			policyCopy.Preset = ""
			return &policyCopy
		}
	}
	return nil
}

func resolveGraphQLOperationPreset(route config.RouterConfig, presetName string) *config.GraphQLOperationPolicy {
	resolvedName := strings.TrimSpace(presetName)
	if resolvedName == "" || len(route.GraphQLOperationPresets) == 0 {
		return nil
	}
	for configuredName, policy := range route.GraphQLOperationPresets {
		if strings.EqualFold(strings.TrimSpace(configuredName), resolvedName) {
			policyCopy := policy
			return &policyCopy
		}
	}
	return nil
}

func mergeGraphQLOperationPolicy(base, override config.GraphQLOperationPolicy) config.GraphQLOperationPolicy {
	merged := base
	mergedValue := reflect.ValueOf(&merged).Elem()
	overrideValue := reflect.ValueOf(override)
	for i := 0; i < overrideValue.NumField(); i++ {
		field := overrideValue.Field(i)
		if !field.IsZero() {
			mergedValue.Field(i).Set(field)
		}
	}
	return merged
}

func resolveGraphQLOperationPolicyForRequest(route config.RouterConfig, req *http.Request) *config.GraphQLOperationPolicy {
	if req == nil {
		return nil
	}
	operationName := graphQLOperationNameFromRequest(req)
	queryText := ""
	if strings.TrimSpace(operationName) == "" && strings.EqualFold(strings.TrimSpace(route.Protocol), "graphql") {
		if extractedQuery, _, extractedOperationName, _, err := extractGraphQLRouteMetadata(req, route); err == nil {
			queryText = extractedQuery
			operationName = extractedOperationName
		}
	}
	return resolveGraphQLOperationPolicy(route, operationName, queryText)
}

func graphQLOperationNameFromRequest(req *http.Request) string {
	if req == nil {
		return ""
	}
	if value, ok := req.Context().Value(graphQLOperationKey).(string); ok {
		return strings.TrimSpace(value)
	}
	return ""
}

func primeGraphQLOperationContext(req *http.Request, route config.RouterConfig) {
	if req == nil || !strings.EqualFold(strings.TrimSpace(route.Protocol), "graphql") {
		return
	}
	queryText, _, operationName, _, err := extractGraphQLRouteMetadata(req, route)
	if err != nil {
		return
	}
	resolvedOperationName := strings.TrimSpace(operationName)
	if resolvedOperationName == "" {
		resolvedOperationName = inferGraphQLOperationName(queryText)
	}
	if resolvedOperationName != "" {
		*req = *req.WithContext(context.WithValue(req.Context(), graphQLOperationKey, resolvedOperationName))
	}
}

func graphQLOperationRequestRoute(route config.RouterConfig, req *http.Request) config.RouterConfig {
	effectiveRoute := applyRouteAIPreset(route)
	operationPolicy := resolveGraphQLOperationPolicyForRequest(route, req)
	if operationPolicy == nil {
		return effectiveRoute
	}
	return applyAIPolicyToRoute(effectiveRoute, operationPolicy)
}

func graphQLOperationAIRequestRoute(route config.RouterConfig, req *http.Request) config.RouterConfig {
	return graphQLOperationRequestRoute(route, req)
}
