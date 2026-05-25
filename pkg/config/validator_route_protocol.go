package config

import (
	"fmt"
	"strings"
)

func validateRouteQueryAndProtocolPolicy(ctx serviceValidationContext) error {
	route := ctx.route
	if err := validateMapKeysNonEmpty(ctx.routeField("queryParams"), route.QueryParams, "queryParams must not contain empty parameter names"); err != nil {
		return err
	}
	if strings.TrimSpace(route.Protocol) != "" {
		switch strings.ToLower(strings.TrimSpace(route.Protocol)) {
		case "http", "graphql", "grpc", "grpc-web", "websocket", "sse", "bff":
		default:
			return validationError(ctx.routeField("protocol"), "protocol must be one of http, graphql, grpc, grpc-web, websocket, sse, or bff")
		}
	}
	if strings.EqualFold(strings.TrimSpace(route.Protocol), "sse") {
		return validateRouteSSECompatibility(ctx)
	}
	return nil
}

func validateRouteSSECompatibility(ctx serviceValidationContext) error {
	route := ctx.route
	if len(route.ResponseJSONFields) > 0 || len(route.RemoveResponseJSONFields) > 0 {
		return validationError(ctx.routeField("responseJSONFields"), "sse routes do not support response JSON body transforms")
	}
	if len(route.SuccessResponseFields) > 0 || len(route.ErrorResponseFields) > 0 {
		return validationError(ctx.routeField("successResponseFields"), "sse routes do not support response body envelopes")
	}
	if len(route.ResponseBodyBlockRegex) > 0 || len(route.ResponseBodyRequireRegex) > 0 || len(route.ResponsePIIBlockTypes) > 0 {
		return validationError(ctx.routeField("responseBodyBlockRegex"), "sse routes do not support buffered response body inspection policies")
	}
	if route.MaxResponseBodyBytes > 0 {
		return validationError(ctx.routeField("maxResponseBodyBytes"), "sse routes do not support maxResponseBodyBytes because responses are streamed")
	}
	return nil
}

func validateRouteGraphQLPolicy(ctx serviceValidationContext) error {
	route := ctx.route
	if !strings.EqualFold(strings.TrimSpace(route.Protocol), "graphql") {
		return nil
	}

	if strings.TrimSpace(route.GraphQLPersistedQueryField) != "" && !isValidJSONFieldPath(route.GraphQLPersistedQueryField, false) {
		return validationError(ctx.routeField("graphqlPersistedQueryField"), "graphqlPersistedQueryField must be a valid JSON field path")
	}
	if err := validateNonEmptyStringSlice(ctx.routeField("graphqlAllowedPersistedQueries"), route.GraphQLAllowedPersistedQueries, "graphqlAllowedPersistedQueries must not contain empty values"); err != nil {
		return err
	}
	if err := validateNonEmptyStringSlice(ctx.routeField("graphqlAllowedOperations"), route.GraphQLAllowedOperations, "graphqlAllowedOperations must not contain empty values"); err != nil {
		return err
	}
	if err := validateNonEmptyStringSlice(ctx.routeField("graphqlAllowedVariables"), route.GraphQLAllowedVariables, "graphqlAllowedVariables must not contain empty values"); err != nil {
		return err
	}
	if err := validateNonEmptyStringSlice(ctx.routeField("graphqlRequiredVariables"), route.GraphQLRequiredVariables, "graphqlRequiredVariables must not contain empty values"); err != nil {
		return err
	}
	if err := validateRegexMap(ctx.routeField("graphqlVariableRegex"), route.GraphQLVariableRegex, "graphqlVariableRegex must not contain empty variable names", "graphqlVariableRegex must contain valid regex patterns"); err != nil {
		return err
	}
	if err := validateGraphQLVariableAllowedValues(ctx); err != nil {
		return err
	}
	if err := validateGraphQLOperationPresetMap(ctx); err != nil {
		return err
	}
	if err := validateGraphQLOperationPolicyMap(ctx); err != nil {
		return err
	}
	if route.GraphQLMaxDepth < 0 {
		return validationError(ctx.routeField("graphqlMaxDepth"), "graphqlMaxDepth must be zero or greater")
	}
	if route.GraphQLMaxFields < 0 {
		return validationError(ctx.routeField("graphqlMaxFields"), "graphqlMaxFields must be zero or greater")
	}
	return nil
}

func validateGraphQLVariableAllowedValues(ctx serviceValidationContext) error {
	for name, allowedValues := range ctx.route.GraphQLVariableAllowedValues {
		if strings.TrimSpace(name) == "" {
			return validationError(ctx.routeField("graphqlVariableAllowedValues"), "graphqlVariableAllowedValues must not contain empty variable names")
		}
		if len(allowedValues) == 0 {
			return validationError(ctx.routeField("graphqlVariableAllowedValues"), "graphqlVariableAllowedValues must not contain empty allowlists")
		}
		if err := validateNonEmptyStringSlice(ctx.routeField("graphqlVariableAllowedValues"), allowedValues, "graphqlVariableAllowedValues must not contain empty values"); err != nil {
			return err
		}
	}
	return nil
}

func validateGraphQLOperationPresetMap(ctx serviceValidationContext) error {
	for presetName, presetPolicy := range ctx.route.GraphQLOperationPresets {
		trimmedName := strings.TrimSpace(presetName)
		if trimmedName == "" {
			return validationError(ctx.routeField("graphqlOperationPresets"), "graphqlOperationPresets must not contain empty preset names")
		}
		if err := validateGraphQLOperationPolicyField(fmt.Sprintf("%s.%s", ctx.routeField("graphqlOperationPresets"), trimmedName), presetPolicy, false); err != nil {
			return err
		}
	}
	return nil
}

func validateGraphQLOperationPolicyMap(ctx serviceValidationContext) error {
	for operationName, policy := range ctx.route.GraphQLOperationPolicies {
		trimmedName := strings.TrimSpace(operationName)
		if trimmedName == "" {
			return validationError(ctx.routeField("graphqlOperationPolicies"), "graphqlOperationPolicies must not contain empty operation names")
		}
		if presetName := strings.TrimSpace(policy.Preset); presetName != "" {
			if _, ok := ctx.route.GraphQLOperationPresets[presetName]; !ok {
				return validationError(fmt.Sprintf("%s.%s.preset", ctx.routeField("graphqlOperationPolicies"), trimmedName), "graphql operation policy preset must reference a defined graphqlOperationPresets entry")
			}
		}
		if err := validateGraphQLOperationPolicyField(fmt.Sprintf("%s.%s", ctx.routeField("graphqlOperationPolicies"), trimmedName), policy, true); err != nil {
			return err
		}
	}
	return nil
}
