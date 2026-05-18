package gateway

import (
	"fmt"
	"regexp"
	"strings"

	coreerrors "github.com/bhangun/iket/pkg/core/errors"
)

func graphQLVariableAllowed(allowed []string, variableName string) bool {
	variableName = strings.TrimSpace(variableName)
	if variableName == "" {
		return false
	}
	for _, allowedName := range allowed {
		if strings.EqualFold(strings.TrimSpace(allowedName), variableName) {
			return true
		}
	}
	return false
}

func enforceGraphQLVariableValuePolicy(variableRegex map[string]string, variableAllowedValues map[string][]string, variables map[string]interface{}) error {
	if len(variables) == 0 {
		return nil
	}
	for variableName, pattern := range variableRegex {
		value, ok := variables[variableName]
		if !ok {
			continue
		}
		compiled, err := regexp.Compile(pattern)
		if err != nil {
			return coreerrors.NewCodeError(coreerrors.CodeValidationError, "graphql variable policy is invalid", err)
		}
		if !compiled.MatchString(graphQLVariableStringValue(value)) {
			return coreerrors.NewCodeError(coreerrors.CodeValidationError, "graphql variable does not match the configured route pattern", nil)
		}
	}
	for variableName, allowedValues := range variableAllowedValues {
		value, ok := variables[variableName]
		if !ok {
			continue
		}
		if !graphQLVariableValueAllowed(allowedValues, graphQLVariableStringValue(value)) {
			return coreerrors.NewCodeError(coreerrors.CodeValidationError, "graphql variable is not in the configured route allowlist", nil)
		}
	}
	return nil
}

func graphQLVariableValueAllowed(allowedValues []string, actual string) bool {
	for _, allowedValue := range allowedValues {
		if strings.EqualFold(strings.TrimSpace(allowedValue), strings.TrimSpace(actual)) {
			return true
		}
	}
	return false
}

func graphQLVariableStringValue(value interface{}) string {
	switch typed := value.(type) {
	case nil:
		return ""
	case string:
		return typed
	default:
		return fmt.Sprint(typed)
	}
}
