package gateway

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/bhangun/iket/pkg/config"
)

func replaceResponseWithPolicyError(g *Gateway, route config.RouterConfig, resp *http.Response, statusCode int, code string, message string, reason string) {
	if resp == nil {
		return
	}
	if g != nil && strings.TrimSpace(reason) != "" {
		g.RecordPolicyHit(route, reason)
	}
	payload := map[string]string{
		"error":   code,
		"message": message,
	}
	bodyBytes, _ := json.Marshal(payload)
	resp.StatusCode = statusCode
	resp.Status = fmt.Sprintf("%d %s", statusCode, http.StatusText(statusCode))
	resp.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	resp.ContentLength = int64(len(bodyBytes))
	resp.Header.Set("Content-Length", fmt.Sprintf("%d", len(bodyBytes)))
	resp.Header.Set("Content-Type", "application/json")
	if strings.TrimSpace(reason) != "" {
		resp.Header.Set(policyHitHeader, reason)
	}
}

func writePolicyError(g *Gateway, route config.RouterConfig, w http.ResponseWriter, statusCode int, reason string, message string) {
	if w == nil {
		return
	}
	if g != nil && strings.TrimSpace(reason) != "" {
		g.RecordPolicyHit(route, reason)
	}
	if strings.TrimSpace(reason) != "" {
		w.Header().Set(policyHitHeader, reason)
	}
	http.Error(w, message, statusCode)
}

func policyReasonForRequestError(err error, fallback string) string {
	if err == nil {
		return fallback
	}
	message := strings.ToLower(err.Error())
	switch {
	case strings.Contains(message, "input token"):
		return "input_token_budget"
	case strings.Contains(message, "output token"):
		return "output_token_budget"
	case strings.Contains(message, "message count"):
		return "message_count_budget"
	case strings.Contains(message, "tool call count"):
		return "tool_call_budget"
	case strings.Contains(message, "required content policy marker"):
		return fallback
	case strings.Contains(message, "blocked by content policy"):
		if fallback == "request_content_policy" {
			return "request_content_policy"
		}
		return fallback
	default:
		return fallback
	}
}

func piiPatternsForTypes(types []string) []string {
	patterns := make([]string, 0, len(types))
	for _, value := range types {
		switch strings.ToLower(strings.TrimSpace(value)) {
		case "email":
			patterns = append(patterns, `(?i)\b[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}\b`)
		case "phone":
			patterns = append(patterns, `(?i)\b(?:\+?\d[\d\-\s().]{7,}\d)\b`)
		case "api_key":
			patterns = append(patterns, `(?i)\b(?:sk|pk|rk)_[a-z0-9]{8,}\b`)
		case "card":
			patterns = append(patterns, `\b(?:\d[ -]*?){13,19}\b`)
		}
	}
	return patterns
}

func responseRedactionValue(route config.RouterConfig) string {
	if strings.TrimSpace(route.RedactionValue) != "" {
		return route.RedactionValue
	}
	return "[REDACTED]"
}

func applyResponseHeaderRedactions(headers http.Header, route config.RouterConfig, redactHeaders []string) {
	if headers == nil {
		return
	}
	replacement := responseRedactionValue(route)
	for _, key := range redactHeaders {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		if _, exists := headers[key]; exists {
			headers.Set(key, replacement)
		}
	}
}

func applyRequestHeaderRedactions(headers http.Header, route config.RouterConfig) {
	if headers == nil {
		return
	}
	replacement := responseRedactionValue(route)
	for _, key := range route.RequestRedactHeaders {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		if _, exists := headers[key]; exists {
			headers.Set(key, replacement)
		}
	}
}

func applyResponseJSONRedactions(payload map[string]interface{}, route config.RouterConfig, redactFields []string) {
	if payload == nil {
		return
	}
	replacement := responseRedactionValue(route)
	for _, key := range redactFields {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		redactNestedJSONField(payload, key, replacement)
	}
}

func applyRequestJSONRedactions(payload map[string]interface{}, route config.RouterConfig) {
	if payload == nil {
		return
	}
	replacement := responseRedactionValue(route)
	for _, key := range route.RequestRedactJSONFields {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		redactNestedJSONField(payload, key, replacement)
	}
}
