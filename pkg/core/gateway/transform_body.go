package gateway

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"

	"github.com/bhangun/iket/pkg/config"
)

func applySuccessResponseEnvelope(resp *http.Response, route config.RouterConfig, upstreamHeaders http.Header) (bool, error) {
	if resp == nil || resp.Body == nil || resp.StatusCode < 200 || resp.StatusCode >= 400 {
		return false, nil
	}
	effectiveRoute := graphQLOperationRequestRoute(route, resp.Request)
	fields := effectiveRoute.SuccessResponseFields
	if len(fields) == 0 {
		return false, nil
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return true, err
	}
	if err := resp.Body.Close(); err != nil {
		return true, err
	}

	ctx := &responseTemplateContext{
		headers:    upstreamHeaders,
		statusCode: resp.StatusCode,
		body:       string(bodyBytes),
	}
	payload := make(map[string]interface{})
	for key, value := range fields {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		resolvedValue, err := resolveJSONTransformValue(resp.Request, ctx, value)
		if err != nil {
			return true, err
		}
		setNestedJSONField(payload, key, resolvedValue)
	}
	applyResponseJSONRedactions(payload, effectiveRoute, effectiveRoute.ResponseRedactJSONFields)

	updatedBody, err := json.Marshal(payload)
	if err != nil {
		return true, err
	}
	resp.Body = io.NopCloser(bytes.NewReader(updatedBody))
	resp.ContentLength = int64(len(updatedBody))
	resp.Header.Set("Content-Length", fmt.Sprintf("%d", len(updatedBody)))
	resp.Header.Set("Content-Type", "application/json")
	return true, nil
}

func applyErrorResponseEnvelope(resp *http.Response, route config.RouterConfig, upstreamHeaders http.Header) (bool, error) {
	if resp == nil || resp.Body == nil || resp.StatusCode < http.StatusBadRequest {
		return false, nil
	}
	effectiveRoute := graphQLOperationRequestRoute(route, resp.Request)
	fields := effectiveRoute.ErrorResponseFields
	if len(fields) == 0 {
		return false, nil
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return true, err
	}
	if err := resp.Body.Close(); err != nil {
		return true, err
	}

	ctx := &responseTemplateContext{
		headers:    upstreamHeaders,
		statusCode: resp.StatusCode,
		body:       string(bodyBytes),
	}
	payload := make(map[string]interface{})
	for key, value := range fields {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		resolvedValue, err := resolveJSONTransformValue(resp.Request, ctx, value)
		if err != nil {
			return true, err
		}
		setNestedJSONField(payload, key, resolvedValue)
	}
	applyResponseJSONRedactions(payload, effectiveRoute, effectiveRoute.ResponseRedactJSONFields)

	updatedBody, err := json.Marshal(payload)
	if err != nil {
		return true, err
	}
	resp.Body = io.NopCloser(bytes.NewReader(updatedBody))
	resp.ContentLength = int64(len(updatedBody))
	resp.Header.Set("Content-Length", fmt.Sprintf("%d", len(updatedBody)))
	resp.Header.Set("Content-Type", "application/json")
	return true, nil
}

func applyResponseJSONTransforms(resp *http.Response, route config.RouterConfig, upstreamHeaders http.Header) error {
	if resp == nil || resp.Body == nil {
		return nil
	}
	effectiveRoute := graphQLOperationRequestRoute(route, resp.Request)
	if !responseTransformsEnabled(resp.Request, effectiveRoute, "response_json", resp.StatusCode, upstreamHeaders) {
		return nil
	}
	if len(effectiveRoute.ResponseJSONFields) == 0 && len(effectiveRoute.RemoveResponseJSONFields) == 0 && len(effectiveRoute.ResponseRedactJSONFields) == 0 {
		return nil
	}
	contentType := strings.ToLower(strings.TrimSpace(resp.Header.Get("Content-Type")))
	if contentType != "" && !strings.Contains(contentType, "application/json") && !strings.Contains(contentType, "+json") {
		return nil
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if err := resp.Body.Close(); err != nil {
		return err
	}
	if len(bytes.TrimSpace(bodyBytes)) == 0 {
		resp.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		return nil
	}

	ctx := &responseTemplateContext{
		headers:    upstreamHeaders,
		statusCode: resp.StatusCode,
		body:       string(bodyBytes),
	}

	var payload map[string]interface{}
	if err := json.Unmarshal(bodyBytes, &payload); err != nil {
		resp.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		resp.ContentLength = int64(len(bodyBytes))
		resp.Header.Set("Content-Length", fmt.Sprintf("%d", len(bodyBytes)))
		return nil
	}

	for key, value := range effectiveRoute.ResponseJSONFields {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		resolvedValue, err := resolveJSONTransformValue(resp.Request, ctx, value)
		if err != nil {
			return err
		}
		setNestedJSONField(payload, key, resolvedValue)
	}
	for _, key := range effectiveRoute.RemoveResponseJSONFields {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		deleteNestedJSONField(payload, key)
	}
	applyResponseJSONRedactions(payload, effectiveRoute, effectiveRoute.ResponseRedactJSONFields)

	updatedBody, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	resp.Body = io.NopCloser(bytes.NewReader(updatedBody))
	resp.ContentLength = int64(len(updatedBody))
	resp.Header.Set("Content-Length", fmt.Sprintf("%d", len(updatedBody)))
	return nil
}

func applyResponseBodyPatterns(g *Gateway, resp *http.Response, route config.RouterConfig) (bool, error) {
	if resp == nil || resp.Body == nil {
		return false, nil
	}
	effectiveRoute := graphQLOperationRequestRoute(route, resp.Request)
	blockRegex := effectiveRoute.ResponseBodyBlockRegex
	requireRegex := effectiveRoute.ResponseBodyRequireRegex
	piiBlockTypes := effectiveRoute.ResponsePIIBlockTypes
	if len(blockRegex) == 0 && len(requireRegex) == 0 && len(piiBlockTypes) == 0 {
		return false, nil
	}
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return true, err
	}
	if err := resp.Body.Close(); err != nil {
		return true, err
	}
	body := string(bodyBytes)
	for _, pattern := range append([]string{}, blockRegex...) {
		matched, err := regexp.MatchString(pattern, body)
		if err != nil {
			return true, err
		}
		if matched {
			replaceResponseWithPolicyError(g, route, resp, http.StatusBadGateway, "Blocked Response", "Response body blocked by content policy", "response_content_policy")
			return true, nil
		}
	}
	for _, pattern := range piiPatternsForTypes(piiBlockTypes) {
		matched, err := regexp.MatchString(pattern, body)
		if err != nil {
			return true, err
		}
		if matched {
			replaceResponseWithPolicyError(g, route, resp, http.StatusBadGateway, "Blocked Response", "Response body blocked by content policy", "response_pii_policy")
			return true, nil
		}
	}
	for _, pattern := range requireRegex {
		matched, err := regexp.MatchString(pattern, body)
		if err != nil {
			return true, err
		}
		if !matched {
			replaceResponseWithPolicyError(g, route, resp, http.StatusBadGateway, "Invalid Response", "Response body is missing required content policy marker", "response_content_policy")
			return true, nil
		}
	}
	resp.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	resp.ContentLength = int64(len(bodyBytes))
	resp.Header.Set("Content-Length", fmt.Sprintf("%d", len(bodyBytes)))
	return false, nil
}

func applyRequestJSONTransforms(req *http.Request, route config.RouterConfig) error {
	if req == nil || req.Body == nil {
		return nil
	}
	effectiveRoute := graphQLOperationRequestRoute(route, req)
	if !routeTransformsEnabled(req, effectiveRoute, "request_json") {
		return nil
	}
	if len(effectiveRoute.RequestJSONFields) == 0 && len(effectiveRoute.RemoveRequestJSONFields) == 0 && len(effectiveRoute.RequestRedactJSONFields) == 0 {
		return nil
	}
	contentType := strings.ToLower(strings.TrimSpace(req.Header.Get("Content-Type")))
	if contentType != "" && !strings.Contains(contentType, "application/json") && !strings.Contains(contentType, "+json") {
		return nil
	}

	bodyBytes, err := cloneRequestBody(req)
	if err != nil {
		return err
	}
	if len(bytes.TrimSpace(bodyBytes)) == 0 {
		return nil
	}

	var payload map[string]interface{}
	if err := json.Unmarshal(bodyBytes, &payload); err != nil {
		req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		req.ContentLength = int64(len(bodyBytes))
		req.GetBody = func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(bodyBytes)), nil
		}
		return nil
	}

	for key, value := range effectiveRoute.RequestJSONFields {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		resolvedValue, err := resolveJSONTransformValue(req, nil, value)
		if err != nil {
			return err
		}
		setNestedJSONField(payload, key, resolvedValue)
	}
	for _, key := range effectiveRoute.RemoveRequestJSONFields {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		deleteNestedJSONField(payload, key)
	}
	applyRequestJSONRedactions(payload, effectiveRoute)

	updatedBody, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req.Body = io.NopCloser(bytes.NewReader(updatedBody))
	req.ContentLength = int64(len(updatedBody))
	req.Header.Set("Content-Length", fmt.Sprintf("%d", len(updatedBody)))
	req.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(updatedBody)), nil
	}
	return nil
}
