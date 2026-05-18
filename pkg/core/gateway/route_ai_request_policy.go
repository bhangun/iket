package gateway

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/bhangun/iket/pkg/config"
	coreerrors "github.com/bhangun/iket/pkg/core/errors"
)

func enforceAllowedModels(req *http.Request, route config.RouterConfig) error {
	route = graphQLOperationAIRequestRoute(route, req)
	if req == nil || len(route.AllowedModels) == 0 {
		return nil
	}
	payload, err := routeJSONPayload(req, "request model field is missing")
	if err != nil {
		return err
	}
	modelField := strings.TrimSpace(route.ModelField)
	if modelField == "" {
		modelField = "model"
	}
	model, ok := nestedJSONStringValue(payload, modelField)
	if !ok || strings.TrimSpace(model) == "" {
		return coreerrors.NewRequiredFieldError("request model field is missing")
	}
	for _, allowed := range route.AllowedModels {
		if strings.EqualFold(strings.TrimSpace(allowed), strings.TrimSpace(model)) {
			return nil
		}
	}
	return coreerrors.NewCodeError(coreerrors.CodeValidationError, "requested model is not allowed", nil)
}

func enforceAllowedTools(req *http.Request, route config.RouterConfig) error {
	route = graphQLOperationAIRequestRoute(route, req)
	if req == nil || len(route.AllowedToolNames) == 0 {
		return nil
	}
	payload, err := routeJSONPayload(req, "request tool field is missing")
	if err != nil {
		return err
	}
	toolField := strings.TrimSpace(route.ToolField)
	if toolField == "" {
		toolField = "tools[].name"
	}
	toolNames := nestedJSONStringValues(payload, toolField)
	if len(toolNames) == 0 {
		return coreerrors.NewRequiredFieldError("request tool field is missing")
	}

	allowed := make(map[string]struct{}, len(route.AllowedToolNames))
	for _, name := range route.AllowedToolNames {
		normalized := strings.ToLower(strings.TrimSpace(name))
		if normalized != "" {
			allowed[normalized] = struct{}{}
		}
	}
	for _, toolName := range toolNames {
		if _, ok := allowed[strings.ToLower(strings.TrimSpace(toolName))]; !ok {
			return coreerrors.NewCodeError(coreerrors.CodeValidationError, "requested tool is not allowed", nil)
		}
	}
	return nil
}

func enforceTokenBudgets(req *http.Request, route config.RouterConfig) error {
	route = graphQLOperationAIRequestRoute(route, req)
	if req == nil || (route.MaxInputTokens <= 0 && route.MaxOutputTokens <= 0) {
		return nil
	}
	payload, err := routeJSONPayload(req, "request token field is missing")
	if err != nil {
		return err
	}
	if route.MaxInputTokens > 0 {
		field := strings.TrimSpace(route.InputTokensField)
		if field == "" {
			field = "max_prompt_tokens"
		}
		value, ok := nestedJSONIntValue(payload, field)
		if !ok {
			return coreerrors.NewRequiredFieldError("request input token field is missing")
		}
		if value > route.MaxInputTokens {
			return coreerrors.NewCodeError(coreerrors.CodeValidationError, "requested input token budget exceeds allowed maximum", nil)
		}
	}
	if route.MaxOutputTokens > 0 {
		field := strings.TrimSpace(route.OutputTokensField)
		if field == "" {
			field = "max_tokens"
		}
		value, ok := nestedJSONIntValue(payload, field)
		if !ok {
			return coreerrors.NewRequiredFieldError("request output token field is missing")
		}
		if value > route.MaxOutputTokens {
			return coreerrors.NewCodeError(coreerrors.CodeValidationError, "requested output token budget exceeds allowed maximum", nil)
		}
	}
	return nil
}

func enforceConversationBudgets(req *http.Request, route config.RouterConfig) error {
	route = graphQLOperationAIRequestRoute(route, req)
	if req == nil || (route.MaxMessages <= 0 && route.MaxToolCalls <= 0) {
		return nil
	}
	payload, err := routeJSONPayload(req, "request conversation field is missing")
	if err != nil {
		return err
	}
	if route.MaxMessages > 0 {
		field := strings.TrimSpace(route.MessagesField)
		if field == "" {
			field = "messages"
		}
		count, ok := nestedJSONArrayLength(payload, field)
		if !ok {
			return coreerrors.NewRequiredFieldError("request messages field is missing")
		}
		if count > route.MaxMessages {
			return coreerrors.NewCodeError(coreerrors.CodeValidationError, "request message count exceeds allowed maximum", nil)
		}
	}
	if route.MaxToolCalls > 0 {
		field := strings.TrimSpace(route.ToolCallsField)
		if field == "" {
			field = "tools"
		}
		count, ok := nestedJSONArrayLength(payload, field)
		if !ok {
			return coreerrors.NewRequiredFieldError("request tool calls field is missing")
		}
		if count > route.MaxToolCalls {
			return coreerrors.NewCodeError(coreerrors.CodeValidationError, "request tool call count exceeds allowed maximum", nil)
		}
	}
	return nil
}

func routeJSONPayload(req *http.Request, missingMessage string) (map[string]interface{}, error) {
	contentType := strings.ToLower(strings.TrimSpace(req.Header.Get("Content-Type")))
	if contentType != "" && !strings.Contains(contentType, "application/json") && !strings.Contains(contentType, "+json") {
		return nil, coreerrors.NewRequiredFieldError(missingMessage)
	}
	bodyBytes, err := cloneRequestBody(req)
	if err != nil {
		return nil, err
	}
	if len(bytes.TrimSpace(bodyBytes)) == 0 {
		return nil, coreerrors.NewRequiredFieldError(missingMessage)
	}

	var payload map[string]interface{}
	if err := json.Unmarshal(bodyBytes, &payload); err != nil {
		return nil, coreerrors.NewRequiredFieldError(missingMessage)
	}
	return payload, nil
}
