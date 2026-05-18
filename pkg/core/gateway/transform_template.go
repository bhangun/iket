package gateway

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/gorilla/mux"
)

var transformTemplateRe = regexp.MustCompile(`\{\{([^}]+)\}\}`)

type responseTemplateContext struct {
	headers    http.Header
	statusCode int
	body       string
}

func resolveJSONTransformValue(r *http.Request, responseCtx *responseTemplateContext, value string) (interface{}, error) {
	resolved := resolveTransformTemplateWithResponseContext(r, responseCtx, value)
	trimmed := strings.TrimSpace(resolved)
	if !strings.HasPrefix(trimmed, "json:") {
		return resolved, nil
	}
	literal := strings.TrimSpace(strings.TrimPrefix(trimmed, "json:"))
	if literal == "" {
		return nil, fmt.Errorf("json: transform values must contain valid JSON")
	}
	var parsed interface{}
	if err := json.Unmarshal([]byte(literal), &parsed); err != nil {
		return nil, fmt.Errorf("json: transform values must contain valid JSON")
	}
	return parsed, nil
}

func resolveTransformTemplate(r *http.Request, value string) string {
	return resolveTransformTemplateWithResponseContext(r, nil, value)
}

func resolveTransformTemplateWithResponseContext(r *http.Request, responseCtx *responseTemplateContext, value string) string {
	if r == nil || !strings.Contains(value, "{{") {
		return value
	}
	return transformTemplateRe.ReplaceAllStringFunc(value, func(match string) string {
		sub := transformTemplateRe.FindStringSubmatch(match)
		if len(sub) < 2 {
			return match
		}
		token := strings.TrimSpace(sub[1])
		switch {
		case token == "realm":
			return GetTenantRealm(r)
		case token == "request_id":
			if requestID := GetRequestID(r); requestID != "" {
				return requestID
			}
			return r.Header.Get("X-Request-Id")
		case strings.HasPrefix(token, "query."):
			return r.URL.Query().Get(strings.TrimSpace(strings.TrimPrefix(token, "query.")))
		case strings.HasPrefix(token, "var."):
			return routeVarValue(r, strings.TrimSpace(strings.TrimPrefix(token, "var.")))
		case strings.HasPrefix(token, "header."):
			return r.Header.Get(strings.TrimSpace(strings.TrimPrefix(token, "header.")))
		case strings.HasPrefix(token, "response_header."):
			if responseCtx == nil || responseCtx.headers == nil {
				return ""
			}
			return responseCtx.headers.Get(strings.TrimSpace(strings.TrimPrefix(token, "response_header.")))
		case token == "response_status":
			if responseCtx == nil || responseCtx.statusCode <= 0 {
				return ""
			}
			return strconv.Itoa(responseCtx.statusCode)
		case token == "response_body":
			if responseCtx == nil {
				return ""
			}
			return responseCtx.body
		default:
			return ""
		}
	})
}

func routeVarValue(r *http.Request, name string) string {
	if name == "" || r == nil {
		return ""
	}
	if vars := GetRouteVars(r); vars != nil {
		return vars[name]
	}
	if vars := mux.Vars(r); vars != nil {
		return vars[name]
	}
	return ""
}
