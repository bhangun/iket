package gateway

import (
	"context"
	"net/http"
	"strings"

	"github.com/bhangun/iket/pkg/config"
	coreerrors "github.com/bhangun/iket/pkg/core/errors"
)

func enforceGraphQLRoutePolicy(req *http.Request, route config.RouterConfig) error {
	if req == nil || !strings.EqualFold(strings.TrimSpace(route.Protocol), "graphql") {
		return nil
	}
	queryText, persistedQueryID, operationName, variables, err := extractGraphQLRouteMetadata(req, route)
	if err != nil {
		return err
	}
	if !routeGraphQLIntrospectionAllowed(route) && graphQLQueryLooksLikeIntrospection(queryText) {
		return coreerrors.NewCodeError(coreerrors.CodeValidationError, "graphql introspection is not allowed on this route", nil)
	}
	if route.GraphQLRequirePersistedQuery && strings.TrimSpace(persistedQueryID) == "" {
		return coreerrors.NewRequiredFieldError("graphql persisted query is required on this route")
	}

	allowedPersistedQueries := route.GraphQLAllowedPersistedQueries
	maxDepth := route.GraphQLMaxDepth
	maxFields := route.GraphQLMaxFields
	if operationPolicy := resolveGraphQLOperationPolicy(route, operationName, queryText); operationPolicy != nil {
		if len(operationPolicy.AllowedPersistedQueries) > 0 {
			allowedPersistedQueries = operationPolicy.AllowedPersistedQueries
		}
		if operationPolicy.MaxDepth > 0 {
			maxDepth = operationPolicy.MaxDepth
		}
		if operationPolicy.MaxFields > 0 {
			maxFields = operationPolicy.MaxFields
		}
	}
	if len(allowedPersistedQueries) > 0 {
		if strings.TrimSpace(persistedQueryID) == "" {
			return coreerrors.NewRequiredFieldError("graphql persisted query is required to evaluate route allowlist")
		}
		if !graphQLPersistedQueryAllowed(allowedPersistedQueries, persistedQueryID) {
			return coreerrors.NewCodeError(coreerrors.CodeValidationError, "graphql persisted query is not allowed on this route", nil)
		}
	}
	if route.GraphQLOperationNameRequired && strings.TrimSpace(operationName) == "" {
		return coreerrors.NewRequiredFieldError("graphql operation name is required on this route")
	}
	if len(route.GraphQLAllowedOperations) > 0 {
		resolvedName := strings.TrimSpace(operationName)
		if resolvedName == "" {
			resolvedName = inferGraphQLOperationName(queryText)
		}
		if strings.TrimSpace(resolvedName) == "" {
			return coreerrors.NewRequiredFieldError("graphql operation name is required to evaluate route allowlist")
		}
		if !graphQLOperationAllowed(route.GraphQLAllowedOperations, resolvedName) {
			return coreerrors.NewCodeError(coreerrors.CodeValidationError, "graphql operation is not allowed on this route", nil)
		}
	}

	resolvedOperationName := strings.TrimSpace(operationName)
	if resolvedOperationName == "" {
		resolvedOperationName = inferGraphQLOperationName(queryText)
	}
	if resolvedOperationName != "" {
		*req = *req.WithContext(context.WithValue(req.Context(), graphQLOperationKey, resolvedOperationName))
	}

	operationPolicy := resolveGraphQLOperationPolicy(route, operationName, queryText)
	requiredVariables := route.GraphQLRequiredVariables
	allowedVariables := route.GraphQLAllowedVariables
	variableRegex := route.GraphQLVariableRegex
	variableAllowedValues := route.GraphQLVariableAllowedValues
	if operationPolicy != nil {
		if len(operationPolicy.RequiredVariables) > 0 {
			requiredVariables = operationPolicy.RequiredVariables
		}
		if len(operationPolicy.AllowedVariables) > 0 {
			allowedVariables = operationPolicy.AllowedVariables
		}
		if len(operationPolicy.VariableRegex) > 0 {
			variableRegex = operationPolicy.VariableRegex
		}
		if len(operationPolicy.VariableAllowedValues) > 0 {
			variableAllowedValues = operationPolicy.VariableAllowedValues
		}
	}
	if len(requiredVariables) > 0 {
		for _, variable := range requiredVariables {
			name := strings.TrimSpace(variable)
			if _, ok := variables[name]; !ok {
				return coreerrors.NewRequiredFieldError("graphql variable is required on this route")
			}
		}
	}
	if len(allowedVariables) > 0 {
		for variable := range variables {
			if !graphQLVariableAllowed(allowedVariables, variable) {
				return coreerrors.NewCodeError(coreerrors.CodeValidationError, "graphql variable is not allowed on this route", nil)
			}
		}
	}
	if err := enforceGraphQLVariableValuePolicy(variableRegex, variableAllowedValues, variables); err != nil {
		return err
	}
	if maxDepth > 0 {
		depth := graphQLQueryDepth(queryText)
		if depth > maxDepth {
			return coreerrors.NewCodeError(coreerrors.CodeValidationError, "graphql query depth exceeds configured route limit", nil)
		}
	}
	if maxFields > 0 {
		fields := graphQLFieldCount(queryText)
		if fields > maxFields {
			return coreerrors.NewCodeError(coreerrors.CodeValidationError, "graphql field count exceeds configured route limit", nil)
		}
	}
	return nil
}

func routeGraphQLIntrospectionAllowed(route config.RouterConfig) bool {
	return route.GraphQLAllowIntrospection == nil || *route.GraphQLAllowIntrospection
}
