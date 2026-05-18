package gateway

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/bhangun/iket/pkg/config"
	coreerrors "github.com/bhangun/iket/pkg/core/errors"
)

func defaultGraphQLPersistedQueryField(route config.RouterConfig) string {
	if strings.TrimSpace(route.GraphQLPersistedQueryField) != "" {
		return strings.TrimSpace(route.GraphQLPersistedQueryField)
	}
	return "extensions.persistedQuery.sha256Hash"
}

func extractGraphQLRouteMetadata(req *http.Request, route config.RouterConfig) (string, string, string, map[string]interface{}, error) {
	if req == nil {
		return "", "", "", nil, nil
	}
	if req.Method == http.MethodGet {
		queryText := strings.TrimSpace(req.URL.Query().Get("query"))
		persisted, err := extractPersistedQueryIDFromExtensions(req.URL.Query().Get("extensions"), defaultGraphQLPersistedQueryField(route))
		operationName := strings.TrimSpace(req.URL.Query().Get("operationName"))
		variables, variablesErr := extractGraphQLVariablesFromRaw(req.URL.Query().Get("variables"))
		if variablesErr != nil {
			return "", "", "", nil, variablesErr
		}
		return queryText, persisted, operationName, variables, err
	}

	bodyBytes, err := cloneRequestBody(req)
	if err != nil {
		return "", "", "", nil, err
	}
	if len(bytes.TrimSpace(bodyBytes)) == 0 {
		return "", "", "", nil, nil
	}

	contentType := strings.ToLower(strings.TrimSpace(req.Header.Get("Content-Type")))
	if strings.Contains(contentType, "application/graphql") {
		return string(bodyBytes), "", inferGraphQLOperationName(string(bodyBytes)), nil, nil
	}

	var payload map[string]interface{}
	if err := json.Unmarshal(bodyBytes, &payload); err != nil {
		return "", "", "", nil, nil
	}
	queryText, _ := payload["query"].(string)
	persisted := lookupJSONFieldStringValue(payload, defaultGraphQLPersistedQueryField(route))
	operationName, _ := payload["operationName"].(string)
	variables, err := extractGraphQLVariablesFromPayload(payload["variables"])
	if err != nil {
		return "", "", "", nil, err
	}
	return strings.TrimSpace(queryText), strings.TrimSpace(persisted), strings.TrimSpace(operationName), variables, nil
}

func extractPersistedQueryIDFromExtensions(raw string, field string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil
	}
	var payload map[string]interface{}
	if err := json.Unmarshal([]byte(raw), &payload); err != nil {
		return "", coreerrors.NewCodeError(coreerrors.CodeValidationError, "graphql extensions payload is invalid", err)
	}
	return strings.TrimSpace(lookupJSONFieldStringValue(payload, field)), nil
}

func extractGraphQLVariablesFromRaw(raw string) (map[string]interface{}, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	var payload interface{}
	if err := json.Unmarshal([]byte(raw), &payload); err != nil {
		return nil, coreerrors.NewCodeError(coreerrors.CodeValidationError, "graphql variables payload is invalid", err)
	}
	return extractGraphQLVariablesFromPayload(payload)
}

func extractGraphQLVariablesFromPayload(value interface{}) (map[string]interface{}, error) {
	if value == nil {
		return nil, nil
	}
	variables, ok := value.(map[string]interface{})
	if !ok {
		return nil, coreerrors.NewCodeError(coreerrors.CodeValidationError, "graphql variables payload must be a JSON object", nil)
	}
	return variables, nil
}
