package config

import (
	"github.com/bhangun/iket/pkg/core/errors"
	"regexp"
	"strings"
)

func validateGraphQLOperationPolicyField(field string, policy GraphQLOperationPolicy, allowPresetRef bool) error {
	if !allowPresetRef && strings.TrimSpace(policy.Preset) != "" {
		return errors.NewValidationError(field, "graphql operation presets must not declare nested preset references")
	}
	for _, variable := range policy.AllowedVariables {
		if strings.TrimSpace(variable) == "" {
			return errors.NewValidationError(field, "graphql operation policy allowedVariables must not contain empty values")
		}
	}
	for _, variable := range policy.RequiredVariables {
		if strings.TrimSpace(variable) == "" {
			return errors.NewValidationError(field, "graphql operation policy requiredVariables must not contain empty values")
		}
	}
	for key := range policy.RequestHeaders {
		if strings.TrimSpace(key) == "" {
			return errors.NewValidationError(field, "graphql operation policy requestHeaders must not contain empty header names")
		}
	}
	for _, header := range policy.RemoveRequestHeaders {
		if strings.TrimSpace(header) == "" {
			return errors.NewValidationError(field, "graphql operation policy removeRequestHeaders must not contain empty values")
		}
	}
	for _, header := range policy.RequestRedactHeaders {
		if strings.TrimSpace(header) == "" {
			return errors.NewValidationError(field, "graphql operation policy requestRedactHeaders must not contain empty values")
		}
	}
	for _, header := range policy.RequiredRequestHeaders {
		if strings.TrimSpace(header) == "" {
			return errors.NewValidationError(field, "graphql operation policy requiredRequestHeaders must not contain empty values")
		}
	}
	for key, pattern := range policy.RequiredRequestHeaderRegex {
		if strings.TrimSpace(key) == "" {
			return errors.NewValidationError(field, "graphql operation policy requiredRequestHeaderRegex must not contain empty header names")
		}
		if _, err := regexp.Compile(pattern); err != nil {
			return errors.NewValidationError(field, "graphql operation policy requiredRequestHeaderRegex must contain valid regex patterns")
		}
	}
	for key := range policy.QueryParams {
		if strings.TrimSpace(key) == "" {
			return errors.NewValidationError(field, "graphql operation policy queryParams must not contain empty parameter names")
		}
	}
	for _, key := range policy.RemoveQueryParams {
		if strings.TrimSpace(key) == "" {
			return errors.NewValidationError(field, "graphql operation policy removeQueryParams must not contain empty values")
		}
	}
	for key := range policy.RequestJSONFields {
		if !isValidJSONFieldPath(key, true) {
			return errors.NewValidationError(field, "graphql operation policy requestJSONFields must not contain empty field names")
		}
	}
	for _, value := range policy.RequestJSONFields {
		if err := validateJSONTransformLiteral(value); err != nil {
			return errors.NewValidationError(field, err.Error())
		}
	}
	for _, fieldPath := range policy.RemoveRequestJSONFields {
		if !isValidJSONFieldPath(fieldPath, false) {
			return errors.NewValidationError(field, "graphql operation policy removeRequestJSONFields must not contain empty values")
		}
	}
	for _, fieldPath := range policy.RequestRedactJSONFields {
		if !isValidJSONFieldPath(fieldPath, false) {
			return errors.NewValidationError(field, "graphql operation policy requestRedactJSONFields must not contain empty values")
		}
	}
	for _, pattern := range policy.RequestBodyBlockRegex {
		if strings.TrimSpace(pattern) == "" {
			return errors.NewValidationError(field, "graphql operation policy requestBodyBlockRegex must not contain empty values")
		}
		if _, err := regexp.Compile(pattern); err != nil {
			return errors.NewValidationError(field, "graphql operation policy requestBodyBlockRegex must contain valid regex patterns")
		}
	}
	for _, pattern := range policy.RequestBodyRequireRegex {
		if strings.TrimSpace(pattern) == "" {
			return errors.NewValidationError(field, "graphql operation policy requestBodyRequireRegex must not contain empty values")
		}
		if _, err := regexp.Compile(pattern); err != nil {
			return errors.NewValidationError(field, "graphql operation policy requestBodyRequireRegex must contain valid regex patterns")
		}
	}
	for _, piiType := range policy.RequestPIIBlockTypes {
		if !isAllowedPIIType(piiType) {
			return errors.NewValidationError(field, "graphql operation policy requestPIIBlockTypes must only contain email, phone, api_key, or card")
		}
	}
	for key := range policy.TransformWhenHeaders {
		if strings.TrimSpace(key) == "" {
			return errors.NewValidationError(field, "graphql operation policy transformWhenHeaders must not contain empty header names")
		}
	}
	for key := range policy.TransformWhenQueryParams {
		if strings.TrimSpace(key) == "" {
			return errors.NewValidationError(field, "graphql operation policy transformWhenQueryParams must not contain empty parameter names")
		}
	}
	for key, pattern := range policy.TransformWhenHeaderRegex {
		if strings.TrimSpace(key) == "" {
			return errors.NewValidationError(field, "graphql operation policy transformWhenHeaderRegex must not contain empty header names")
		}
		if _, err := regexp.Compile(pattern); err != nil {
			return errors.NewValidationError(field, "graphql operation policy transformWhenHeaderRegex must contain valid regex patterns")
		}
	}
	for key, pattern := range policy.TransformWhenQueryRegex {
		if strings.TrimSpace(key) == "" {
			return errors.NewValidationError(field, "graphql operation policy transformWhenQueryRegex must not contain empty parameter names")
		}
		if _, err := regexp.Compile(pattern); err != nil {
			return errors.NewValidationError(field, "graphql operation policy transformWhenQueryRegex must contain valid regex patterns")
		}
	}
	for _, method := range policy.TransformMethods {
		if !isValidHTTPMethod(method) {
			return errors.NewValidationError(field, "graphql operation policy transformMethods must only contain valid HTTP methods")
		}
	}
	for _, hash := range policy.AllowedPersistedQueries {
		if strings.TrimSpace(hash) == "" {
			return errors.NewValidationError(field, "graphql operation policy allowedPersistedQueries must not contain empty values")
		}
	}
	if policy.MaxDepth < 0 {
		return errors.NewValidationError(field, "graphql operation policy maxDepth must be zero or greater")
	}
	if policy.MaxFields < 0 {
		return errors.NewValidationError(field, "graphql operation policy maxFields must be zero or greater")
	}
	for variableName, pattern := range policy.VariableRegex {
		if strings.TrimSpace(variableName) == "" {
			return errors.NewValidationError(field, "graphql operation policy variableRegex must not contain empty variable names")
		}
		if _, err := regexp.Compile(pattern); err != nil {
			return errors.NewValidationError(field, "graphql operation policy variableRegex must contain valid regex patterns")
		}
	}
	for variableName, allowedValues := range policy.VariableAllowedValues {
		if strings.TrimSpace(variableName) == "" {
			return errors.NewValidationError(field, "graphql operation policy variableAllowedValues must not contain empty variable names")
		}
		if len(allowedValues) == 0 {
			return errors.NewValidationError(field, "graphql operation policy variableAllowedValues must not contain empty allowlists")
		}
		for _, allowedValue := range allowedValues {
			if strings.TrimSpace(allowedValue) == "" {
				return errors.NewValidationError(field, "graphql operation policy variableAllowedValues must not contain empty values")
			}
		}
	}
	for _, pattern := range policy.ResponseBodyBlockRegex {
		if strings.TrimSpace(pattern) == "" {
			return errors.NewValidationError(field, "graphql operation policy responseBodyBlockRegex must not contain empty values")
		}
		if _, err := regexp.Compile(pattern); err != nil {
			return errors.NewValidationError(field, "graphql operation policy responseBodyBlockRegex must contain valid regex patterns")
		}
	}
	for _, pattern := range policy.ResponseBodyRequireRegex {
		if strings.TrimSpace(pattern) == "" {
			return errors.NewValidationError(field, "graphql operation policy responseBodyRequireRegex must not contain empty values")
		}
		if _, err := regexp.Compile(pattern); err != nil {
			return errors.NewValidationError(field, "graphql operation policy responseBodyRequireRegex must contain valid regex patterns")
		}
	}
	for _, piiType := range policy.ResponsePIIBlockTypes {
		if !isAllowedPIIType(piiType) {
			return errors.NewValidationError(field, "graphql operation policy responsePIIBlockTypes must only contain email, phone, api_key, or card")
		}
	}
	for key := range policy.SuccessResponseFields {
		if !isValidJSONFieldPath(key, false) {
			return errors.NewValidationError(field, "graphql operation policy successResponseFields must not contain empty field names")
		}
	}
	for _, value := range policy.SuccessResponseFields {
		if err := validateJSONTransformLiteral(value); err != nil {
			return errors.NewValidationError(field, err.Error())
		}
	}
	for key := range policy.ErrorResponseFields {
		if !isValidJSONFieldPath(key, false) {
			return errors.NewValidationError(field, "graphql operation policy errorResponseFields must not contain empty field names")
		}
	}
	for _, value := range policy.ErrorResponseFields {
		if err := validateJSONTransformLiteral(value); err != nil {
			return errors.NewValidationError(field, err.Error())
		}
	}
	for key := range policy.ResponseHeaders {
		if strings.TrimSpace(key) == "" {
			return errors.NewValidationError(field, "graphql operation policy responseHeaders must not contain empty header names")
		}
	}
	for _, header := range policy.RemoveResponseHeaders {
		if strings.TrimSpace(header) == "" {
			return errors.NewValidationError(field, "graphql operation policy removeResponseHeaders must not contain empty values")
		}
	}
	for _, header := range policy.ResponseRedactHeaders {
		if strings.TrimSpace(header) == "" {
			return errors.NewValidationError(field, "graphql operation policy responseRedactHeaders must not contain empty values")
		}
	}
	for _, statusCode := range policy.ResponseTransformStatusCodes {
		if statusCode < 100 || statusCode > 599 {
			return errors.NewValidationError(field, "graphql operation policy responseTransformStatusCodes must only contain valid HTTP status codes")
		}
	}
	for _, statusClass := range policy.ResponseTransformStatusClasses {
		statusClass = strings.ToLower(strings.TrimSpace(statusClass))
		if _, ok := allowedResponseTransformStatusClasses[statusClass]; !ok {
			return errors.NewValidationError(field, "graphql operation policy responseTransformStatusClasses must only contain 1xx, 2xx, 3xx, 4xx, or 5xx")
		}
	}
	for key := range policy.ResponseTransformWhenHeaders {
		if strings.TrimSpace(key) == "" {
			return errors.NewValidationError(field, "graphql operation policy responseTransformWhenHeaders must not contain empty header names")
		}
	}
	for key, pattern := range policy.ResponseTransformHeaderRegex {
		if strings.TrimSpace(key) == "" {
			return errors.NewValidationError(field, "graphql operation policy responseTransformHeaderRegex must not contain empty header names")
		}
		if _, err := regexp.Compile(pattern); err != nil {
			return errors.NewValidationError(field, "graphql operation policy responseTransformHeaderRegex must contain valid regex patterns")
		}
	}
	for key := range policy.ResponseJSONFields {
		if !isValidJSONFieldPath(key, true) {
			return errors.NewValidationError(field, "graphql operation policy responseJSONFields must not contain empty field names")
		}
	}
	for _, value := range policy.ResponseJSONFields {
		if err := validateJSONTransformLiteral(value); err != nil {
			return errors.NewValidationError(field, err.Error())
		}
	}
	for _, fieldPath := range policy.RemoveResponseJSONFields {
		if !isValidJSONFieldPath(fieldPath, false) {
			return errors.NewValidationError(field, "graphql operation policy removeResponseJSONFields must not contain empty values")
		}
	}
	for _, fieldPath := range policy.ResponseRedactJSONFields {
		if !isValidJSONFieldPath(fieldPath, false) {
			return errors.NewValidationError(field, "graphql operation policy responseRedactJSONFields must not contain empty values")
		}
	}
	for _, model := range policy.AllowedModels {
		if strings.TrimSpace(model) == "" {
			return errors.NewValidationError(field, "graphql operation policy allowedModels must not contain empty values")
		}
	}
	if strings.TrimSpace(policy.ModelField) != "" && !isValidJSONFieldPath(policy.ModelField, false) {
		return errors.NewValidationError(field, "graphql operation policy modelField must be a valid JSON field path")
	}
	for _, tool := range policy.AllowedToolNames {
		if strings.TrimSpace(tool) == "" {
			return errors.NewValidationError(field, "graphql operation policy allowedToolNames must not contain empty values")
		}
	}
	if strings.TrimSpace(policy.ToolField) != "" && !isValidJSONFieldPath(policy.ToolField, false) {
		return errors.NewValidationError(field, "graphql operation policy toolField must be a valid JSON field path")
	}
	if policy.MaxMessages < 0 {
		return errors.NewValidationError(field, "graphql operation policy maxMessages must be zero or greater")
	}
	if strings.TrimSpace(policy.MessagesField) != "" && !isValidJSONFieldPath(policy.MessagesField, false) {
		return errors.NewValidationError(field, "graphql operation policy messagesField must be a valid JSON field path")
	}
	if policy.MaxToolCalls < 0 {
		return errors.NewValidationError(field, "graphql operation policy maxToolCalls must be zero or greater")
	}
	if strings.TrimSpace(policy.ToolCallsField) != "" && !isValidJSONFieldPath(policy.ToolCallsField, false) {
		return errors.NewValidationError(field, "graphql operation policy toolCallsField must be a valid JSON field path")
	}
	if policy.MaxInputTokens < 0 {
		return errors.NewValidationError(field, "graphql operation policy maxInputTokens must be zero or greater")
	}
	if strings.TrimSpace(policy.InputTokensField) != "" && !isValidJSONFieldPath(policy.InputTokensField, false) {
		return errors.NewValidationError(field, "graphql operation policy inputTokensField must be a valid JSON field path")
	}
	if policy.MaxOutputTokens < 0 {
		return errors.NewValidationError(field, "graphql operation policy maxOutputTokens must be zero or greater")
	}
	if strings.TrimSpace(policy.OutputTokensField) != "" && !isValidJSONFieldPath(policy.OutputTokensField, false) {
		return errors.NewValidationError(field, "graphql operation policy outputTokensField must be a valid JSON field path")
	}
	for _, host := range policy.AllowedUpstreamHosts {
		if strings.TrimSpace(host) == "" {
			return errors.NewValidationError(field, "graphql operation policy allowedUpstreamHosts must not contain empty values")
		}
	}
	return nil
}
