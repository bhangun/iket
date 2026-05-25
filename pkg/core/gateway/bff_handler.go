package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/bhangun/iket/pkg/config"
	"github.com/bhangun/iket/pkg/logging"
)

const defaultBFFStepTimeout = 5 * time.Second

type bffRequestBodyCacheContextKey struct{}

type bffRequestBodyCache struct {
	bodyOnce sync.Once
	body     []byte
	bodyErr  error

	jsonOnce sync.Once
	jsonBody interface{}
	jsonErr  error
}

type bffStepResult struct {
	name           string
	method         string
	upstreamHost   string
	upstreamPath   string
	attempts       int
	cacheHit       bool
	cacheStale     bool
	coalesced      bool
	fallback       bool
	skipped        bool
	successful     bool
	statusCode     int
	header         http.Header
	body           []byte
	jsonBody       interface{}
	err            error
	durationMillis int64
}

type bffResultsSummary struct {
	partial      bool
	degraded     bool
	totalSteps   int
	completed    []string
	failedSteps  []string
	skippedSteps []string
	errors       map[string]string
}

type bffStepExecution struct {
	step config.BFFStepConfig
	done chan struct{}
}

func (g *Gateway) handleBFFRoute(w http.ResponseWriter, r *http.Request, route config.RouterConfig) {
	if route.BFF == nil || !route.BFF.IsEnabled() {
		http.NotFound(w, r)
		return
	}
	if err := enforceRouteProtocol(r, route); err != nil {
		writePolicyError(g, route, w, http.StatusBadRequest, "protocol", err.Error())
		return
	}
	if err := enforceRequiredRequestHeaders(r, route); err != nil {
		writePolicyError(g, route, w, http.StatusBadRequest, "required_header", err.Error())
		return
	}
	applyQueryTransforms(r, route)
	if err := enforceRequestBodyLimit(r, route); err != nil {
		writePolicyError(g, route, w, http.StatusRequestEntityTooLarge, "request_body_size", err.Error())
		return
	}
	if err := enforceAllowedModels(r, route); err != nil {
		writePolicyError(g, route, w, http.StatusForbidden, "model_allowlist", err.Error())
		return
	}
	if err := enforceAllowedTools(r, route); err != nil {
		writePolicyError(g, route, w, http.StatusForbidden, "tool_allowlist", err.Error())
		return
	}
	if err := enforceTokenBudgets(r, route); err != nil {
		writePolicyError(g, route, w, http.StatusForbidden, "token_budget", err.Error())
		return
	}
	if err := enforceConversationBudgets(r, route); err != nil {
		writePolicyError(g, route, w, http.StatusForbidden, "conversation_budget", err.Error())
		return
	}
	if err := enforceRequestBodyPatterns(r, route); err != nil {
		writePolicyError(g, route, w, http.StatusForbidden, "request_content_policy", err.Error())
		return
	}

	ctx := r.Context()
	if timeout := bffTimeout(route.BFF.Timeout); timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	bffRequest := withBFFRequestBodyCache(r.WithContext(ctx))
	if err := validateBFFRequestJSON(bffRequest, route); err != nil {
		writeBFFError(w, bffRequest, route, http.StatusBadRequest, "BFF request validation failed", err.Error())
		return
	}

	results := g.executeBFFSteps(ctx, bffRequest, route)
	for _, step := range route.BFF.Steps {
		result := results[step.Name]
		if result.err != nil && step.IsRequired() && !route.BFF.AllowPartialResponse {
			g.logger.Warn("BFF required upstream failed",
				logging.String("route_path", route.Path),
				logging.String("step", step.Name),
				logging.Error(result.err),
			)
			writeBFFError(w, r, route, http.StatusBadGateway, "BFF upstream failed", result.err.Error())
			return
		}
		if result.statusCode > 0 && !result.successful && step.IsRequired() && !route.BFF.AllowPartialResponse {
			message := bffStepErrorMessage(step.Name, result)
			writeBFFError(w, r, route, http.StatusBadGateway, "BFF upstream failed", message)
			return
		}
	}

	payload, err := buildBFFResponsePayload(bffRequest, route, results)
	if err != nil {
		g.logger.Warn("Failed to build BFF response", logging.String("route_path", route.Path), logging.Error(err))
		writeBFFError(w, bffRequest, route, http.StatusInternalServerError, "BFF response mapping failed", err.Error())
		return
	}
	body, err := json.Marshal(payload)
	if err != nil {
		writeBFFError(w, bffRequest, route, http.StatusInternalServerError, "BFF response encoding failed", err.Error())
		return
	}
	statusCode, err := bffResponseStatus(bffRequest, route, results)
	if err != nil {
		g.logger.Warn("Failed to resolve BFF response status", logging.String("route_path", route.Path), logging.Error(err))
		writeBFFError(w, bffRequest, route, http.StatusInternalServerError, "BFF response status mapping failed", err.Error())
		return
	}
	if err := applyBFFResponseHeaders(w, bffRequest, route, results); err != nil {
		g.logger.Warn("Failed to resolve BFF response headers", logging.String("route_path", route.Path), logging.Error(err))
		writeBFFError(w, bffRequest, route, http.StatusInternalServerError, "BFF response header mapping failed", err.Error())
		return
	}
	w.WriteHeader(statusCode)
	_, _ = w.Write(body)
}

func (g *Gateway) executeBFFSteps(ctx context.Context, r *http.Request, route config.RouterConfig) map[string]bffStepResult {
	results := make(map[string]bffStepResult, len(route.BFF.Steps))
	if strings.EqualFold(strings.TrimSpace(route.BFF.Mode), "sequential") {
		for _, step := range route.BFF.Steps {
			result := g.executeBFFStep(ctx, r, route, step, results)
			results[step.Name] = result
			if result.err != nil && step.IsRequired() && !route.BFF.AllowPartialResponse {
				break
			}
		}
		return results
	}
	if bffStepsHaveDependencies(route.BFF.Steps) {
		return g.executeBFFStepsWithDependencies(ctx, r, route)
	}

	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, step := range route.BFF.Steps {
		step := step
		wg.Add(1)
		go func() {
			defer wg.Done()
			result := g.executeBFFStep(ctx, r, route, step, nil)
			mu.Lock()
			results[step.Name] = result
			mu.Unlock()
		}()
	}
	wg.Wait()
	return results
}

func bffStepsHaveDependencies(steps []config.BFFStepConfig) bool {
	for _, step := range steps {
		if len(bffStepDependencies(step)) > 0 {
			return true
		}
	}
	return false
}

func bffStepDependencies(step config.BFFStepConfig) []string {
	dependencies, _, _ := bffStepDependencyBreakdown(step)
	return dependencies
}

func bffStepDependencyBreakdown(step config.BFFStepConfig) ([]string, []string, []string) {
	explicitDependencies := make([]string, 0, len(step.DependsOn))
	explicitSeen := make(map[string]struct{}, len(step.DependsOn))
	for _, dependency := range step.DependsOn {
		explicitDependencies = appendBFFDependency(explicitDependencies, explicitSeen, dependency)
	}

	inferredDependencies := make([]string, 0)
	inferredSeen := make(map[string]struct{})
	for _, template := range bffStepLocalTemplateValues(step) {
		for _, dependency := range bffStepTemplateReferences(template) {
			inferredDependencies = appendBFFDependency(inferredDependencies, inferredSeen, dependency)
		}
	}

	dependencies := make([]string, 0, len(explicitDependencies)+len(inferredDependencies))
	seen := make(map[string]struct{}, len(explicitDependencies)+len(inferredDependencies))
	for _, dependency := range explicitDependencies {
		dependencies = appendBFFDependency(dependencies, seen, dependency)
	}
	for _, dependency := range inferredDependencies {
		dependencies = appendBFFDependency(dependencies, seen, dependency)
	}
	return dependencies, explicitDependencies, inferredDependencies
}

func appendBFFDependency(dependencies []string, seen map[string]struct{}, name string) []string {
	name = strings.TrimSpace(name)
	if name == "" {
		return dependencies
	}
	if _, ok := seen[name]; ok {
		return dependencies
	}
	seen[name] = struct{}{}
	return append(dependencies, name)
}

func bffStepLocalTemplateValues(step config.BFFStepConfig) []string {
	values := []string{
		step.URL,
		step.When,
		step.CacheKey,
		step.Body,
	}
	values = appendBFFTemplateMapValues(values, step.Headers)
	values = appendBFFTemplateMapValues(values, step.QueryParams)
	values = appendBFFTemplateMapValues(values, step.WhenHeaders)
	values = appendBFFTemplateMapValues(values, step.WhenQueryParams)
	if step.Fallback != nil {
		values = append(values, step.Fallback.Body)
		values = appendBFFTemplateMapValues(values, step.Fallback.Headers)
	}
	return values
}

func appendBFFTemplateMapValues(values []string, source map[string]string) []string {
	keys := make([]string, 0, len(source))
	for key := range source {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		values = append(values, source[key])
	}
	return values
}

func bffStepTemplateReferences(value string) []string {
	matches := transformTemplateRe.FindAllStringSubmatch(value, -1)
	if len(matches) == 0 {
		return nil
	}
	references := make([]string, 0, len(matches))
	for _, match := range matches {
		if len(match) < 2 {
			continue
		}
		token := strings.TrimSpace(match[1])
		if !strings.HasPrefix(token, "step.") {
			continue
		}
		remainder := strings.TrimPrefix(token, "step.")
		parts := strings.SplitN(remainder, ".", 2)
		if strings.TrimSpace(parts[0]) != "" {
			references = append(references, strings.TrimSpace(parts[0]))
		}
	}
	return references
}

func (g *Gateway) executeBFFStepsWithDependencies(ctx context.Context, r *http.Request, route config.RouterConfig) map[string]bffStepResult {
	results := make(map[string]bffStepResult, len(route.BFF.Steps))
	executions := make(map[string]*bffStepExecution, len(route.BFF.Steps))
	for _, step := range route.BFF.Steps {
		executions[step.Name] = &bffStepExecution{step: step, done: make(chan struct{})}
	}

	var mu sync.Mutex
	storeResult := func(name string, result bffStepResult) {
		mu.Lock()
		results[name] = result
		mu.Unlock()
	}

	var wg sync.WaitGroup
	for _, execution := range executions {
		execution := execution
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer close(execution.done)

			step := execution.step
			if result, ok := g.waitForBFFStepDependencies(ctx, r, route, step, executions, results, &mu); ok {
				storeResult(step.Name, result)
				return
			}
			previous := bffDependencyResults(step, results, &mu)
			storeResult(step.Name, g.executeBFFStep(ctx, r, route, step, previous))
		}()
	}
	wg.Wait()
	return results
}

func (g *Gateway) waitForBFFStepDependencies(ctx context.Context, r *http.Request, route config.RouterConfig, step config.BFFStepConfig, executions map[string]*bffStepExecution, results map[string]bffStepResult, mu *sync.Mutex) (bffStepResult, bool) {
	for _, dependency := range bffStepDependencies(step) {
		dependency = strings.TrimSpace(dependency)
		if dependency == "" {
			continue
		}
		if dependency == strings.TrimSpace(step.Name) {
			return g.syntheticBFFStepResult(r, route, step, func(result bffStepResult) bffStepResult {
				result.err = fmt.Errorf("BFF step cannot depend on itself")
				return result
			}), true
		}
		execution, ok := executions[dependency]
		if !ok {
			return g.syntheticBFFStepResult(r, route, step, func(result bffStepResult) bffStepResult {
				result.err = fmt.Errorf("BFF dependency %s was not found", dependency)
				return result
			}), true
		}
		select {
		case <-execution.done:
		case <-ctx.Done():
			return g.syntheticBFFStepResult(r, route, step, func(result bffStepResult) bffStepResult {
				result.err = ctx.Err()
				return result
			}), true
		}
	}

	for _, dependency := range bffStepDependencies(step) {
		dependency = strings.TrimSpace(dependency)
		if dependency == "" {
			continue
		}
		mu.Lock()
		dependencyResult := results[dependency]
		mu.Unlock()
		if dependencyResult.skipped {
			return g.syntheticBFFStepResult(r, route, step, func(result bffStepResult) bffStepResult {
				result.skipped = true
				return result
			}), true
		}
		if dependencyResult.err != nil || (dependencyResult.statusCode > 0 && !dependencyResult.successful) {
			return g.syntheticBFFStepResult(r, route, step, func(result bffStepResult) bffStepResult {
				result.err = fmt.Errorf("BFF dependency %s failed", dependency)
				return result
			}), true
		}
	}
	return bffStepResult{}, false
}

func bffDependencyResults(step config.BFFStepConfig, results map[string]bffStepResult, mu *sync.Mutex) map[string]bffStepResult {
	dependencies := bffStepDependencies(step)
	if len(dependencies) == 0 {
		return nil
	}
	previous := make(map[string]bffStepResult, len(dependencies))
	mu.Lock()
	defer mu.Unlock()
	for _, dependency := range dependencies {
		dependency = strings.TrimSpace(dependency)
		if dependency == "" {
			continue
		}
		if result, ok := results[dependency]; ok {
			previous[dependency] = result
		}
	}
	return previous
}

func (g *Gateway) executeBFFStep(ctx context.Context, r *http.Request, route config.RouterConfig, step config.BFFStepConfig, previous map[string]bffStepResult) (result bffStepResult) {
	start := time.Now()
	result = newBFFStepResult(step)
	defer func() {
		result = g.completeBFFStepResult(r, route, step, result, start)
	}()

	conditionsMatch, err := bffStepConditionsMatch(r, previous, step)
	if err != nil {
		result.err = err
		return result
	}
	if !conditionsMatch {
		result.skipped = true
		return result
	}

	rawURL, err := resolveBFFTemplateStringValue(r, previous, step.URL)
	if err != nil {
		result.err = err
		return result
	}
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		result.err = err
		return result
	}
	if err := enforceAllowedUpstreamHost(r, parsedURL, route); err != nil {
		result.err = err
		return result
	}
	result.upstreamHost = parsedURL.Host
	result.upstreamPath = parsedURL.EscapedPath()
	query := parsedURL.Query()
	for key, value := range step.QueryParams {
		if strings.TrimSpace(key) == "" {
			continue
		}
		resolved, err := resolveBFFTemplateStringValue(r, previous, value)
		if err != nil {
			result.err = err
			return result
		}
		query.Set(key, resolved)
	}
	parsedURL.RawQuery = query.Encode()
	cacheTTL := bffStepCacheTTL(step)
	staleIfError := bffStepStaleIfError(step)
	cacheKey := ""
	cacheable := cacheTTL > 0 && bffStepCacheAllowedForMethod(step, result.method)
	if cacheable {
		cacheKey, err = bffStepCacheKey(r, previous, route, step, parsedURL)
		if err != nil {
			result.err = err
			return result
		}
		if cached, ok := g.getBFFCacheEntry(cacheKey, time.Now()); ok {
			cached.name = result.name
			cached.method = result.method
			cached.upstreamHost = result.upstreamHost
			cached.upstreamPath = result.upstreamPath
			return cached
		}
	}

	fetch := func() bffStepResult {
		if cacheable {
			if cached, ok := g.getBFFCacheEntry(cacheKey, time.Now()); ok {
				cached.name = result.name
				cached.method = result.method
				cached.upstreamHost = result.upstreamHost
				cached.upstreamPath = result.upstreamPath
				return cached
			}
		}
		return g.fetchBFFStep(ctx, r, route, step, previous, result, parsedURL, cacheTTL, staleIfError, cacheKey, cacheable)
	}
	if cacheable {
		return g.coalesceBFFStep(cacheKey, fetch)
	}
	return fetch()
}

func newBFFStepResult(step config.BFFStepConfig) bffStepResult {
	return bffStepResult{name: step.Name, method: strings.ToUpper(step.EffectiveMethod()), header: make(http.Header)}
}

func (g *Gateway) syntheticBFFStepResult(r *http.Request, route config.RouterConfig, step config.BFFStepConfig, mutate func(bffStepResult) bffStepResult) bffStepResult {
	start := time.Now()
	result := newBFFStepResult(step)
	if mutate != nil {
		result = mutate(result)
	}
	return g.completeBFFStepResult(r, route, step, result, start)
}

func (g *Gateway) completeBFFStepResult(r *http.Request, route config.RouterConfig, step config.BFFStepConfig, result bffStepResult, start time.Time) bffStepResult {
	duration := time.Since(start)
	result.durationMillis = duration.Milliseconds()
	if result.statusCode > 0 {
		result.successful = bffStepStatusSuccessful(step, result.statusCode)
	}
	outcome := bffStepOutcome(result)
	if g.metrics != nil {
		g.metrics.RecordBFFStep(route.Path, step.Name, result.statusCode, step.IsRequired(), outcome, duration.Seconds())
	}
	g.logBFFStepResult(r, route, step, result, outcome, duration)
	return result
}

func bffStepConditionsMatch(r *http.Request, previous map[string]bffStepResult, step config.BFFStepConfig) (bool, error) {
	if strings.TrimSpace(step.When) != "" {
		matches, err := bffConditionExpressionMatches(r, previous, step.When)
		if err != nil {
			return false, err
		}
		if !matches {
			return false, nil
		}
	}
	for key, expected := range step.WhenHeaders {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		resolved, err := resolveBFFTemplateStringValue(r, previous, expected)
		if err != nil {
			return false, err
		}
		if r.Header.Get(key) != resolved {
			return false, nil
		}
	}
	for key, expected := range step.WhenQueryParams {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		resolved, err := resolveBFFTemplateStringValue(r, previous, expected)
		if err != nil {
			return false, err
		}
		if r.URL.Query().Get(key) != resolved {
			return false, nil
		}
	}
	return true, nil
}

func bffConditionExpressionMatches(r *http.Request, previous map[string]bffStepResult, raw string) (bool, error) {
	resolvedValue, err := resolveBFFTemplateStringValue(r, previous, raw)
	if err != nil {
		return false, err
	}
	resolved := strings.TrimSpace(resolvedValue)
	if resolved == "" {
		return false, nil
	}
	if left, right, ok := strings.Cut(resolved, "=="); ok {
		return strings.TrimSpace(left) == strings.TrimSpace(right), nil
	}
	if left, right, ok := strings.Cut(resolved, "!="); ok {
		return strings.TrimSpace(left) != strings.TrimSpace(right), nil
	}
	return bffConditionTruthy(resolved), nil
}

func bffConditionTruthy(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "0", "false", "f", "no", "n", "off", "null", "nil", "none", "empty":
		return false
	default:
		return true
	}
}

func (g *Gateway) fetchBFFStep(ctx context.Context, r *http.Request, route config.RouterConfig, step config.BFFStepConfig, previous map[string]bffStepResult, result bffStepResult, parsedURL *url.URL, cacheTTL time.Duration, staleIfError time.Duration, cacheKey string, cacheable bool) bffStepResult {
	stepCtx := ctx
	if timeout := bffTimeout(step.Timeout); timeout > 0 {
		var cancel context.CancelFunc
		stepCtx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	} else if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		stepCtx, cancel = context.WithTimeout(ctx, defaultBFFStepTimeout)
		defer cancel()
	}

	body, contentType, err := bffStepBody(r, previous, step)
	if err != nil {
		result.err = err
		return result
	}
	req, err := http.NewRequestWithContext(stepCtx, result.method, parsedURL.String(), bytes.NewReader(body))
	if err != nil {
		result.err = err
		return result
	}
	if len(body) > 0 {
		req.ContentLength = int64(len(body))
		if contentType != "" {
			req.Header.Set("Content-Type", contentType)
		}
	}
	applyBFFUpstreamHeaders(r, req, route)
	for key, value := range step.Headers {
		if strings.TrimSpace(key) == "" {
			continue
		}
		resolved, err := resolveBFFTemplateStringValue(r, previous, value)
		if err != nil {
			result.err = err
			return result
		}
		req.Header.Set(key, resolved)
	}

	resp, attempts, err := roundTripBFFStep(req, body, step)
	result.attempts = attempts
	if err != nil {
		result.err = err
		if stale, ok := g.bffStaleFallback(cacheKey, result, time.Now()); ok {
			return stale
		}
		if fallback, ok := buildBFFStepFallback(r, previous, step, result); ok {
			return fallback
		}
		return result
	}
	defer resp.Body.Close()
	result.statusCode = resp.StatusCode
	result.header = resp.Header.Clone()
	result.body, err = readBFFStepResponseBody(resp, route, step)
	if err != nil {
		result.err = err
		if stale, ok := g.bffStaleFallback(cacheKey, result, time.Now()); ok {
			return stale
		}
		if fallback, ok := buildBFFStepFallback(r, previous, step, result); ok {
			return fallback
		}
		return result
	}
	result.jsonBody, err = parseBFFStepJSONBody(result.body, step)
	if err != nil {
		result.err = err
		if stale, ok := g.bffStaleFallback(cacheKey, result, time.Now()); ok {
			return stale
		}
		if fallback, ok := buildBFFStepFallback(r, previous, step, result); ok {
			return fallback
		}
		return result
	}
	if cacheable && result.err == nil && bffStepCacheStatusAllowed(step, result.statusCode) {
		g.setBFFCacheEntry(cacheKey, cacheTTL, staleIfError, result, time.Now())
	}
	if cacheable && staleIfError > 0 && !bffStepStatusSuccessful(step, result.statusCode) {
		if stale, ok := g.bffStaleFallback(cacheKey, result, time.Now()); ok {
			return stale
		}
	}
	if !bffStepStatusSuccessful(step, result.statusCode) {
		if fallback, ok := buildBFFStepFallback(r, previous, step, result); ok {
			return fallback
		}
	}
	return result
}

func parseBFFStepJSONBody(body []byte, step config.BFFStepConfig) (interface{}, error) {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		if step.RequireJSON || len(step.RequiredJSONPaths) > 0 {
			return nil, fmt.Errorf("BFF step response body must contain valid JSON")
		}
		return nil, nil
	}
	var parsed interface{}
	if err := json.Unmarshal(trimmed, &parsed); err != nil {
		if step.RequireJSON || len(step.RequiredJSONPaths) > 0 {
			return nil, fmt.Errorf("BFF step response body must contain valid JSON: %w", err)
		}
		return nil, nil
	}
	for _, path := range step.RequiredJSONPaths {
		if _, ok := bffJSONPathValue(parsed, path); !ok {
			return nil, fmt.Errorf("BFF step response body is missing required JSON path %q", path)
		}
	}
	return parsed, nil
}

func readBFFStepResponseBody(resp *http.Response, route config.RouterConfig, step config.BFFStepConfig) ([]byte, error) {
	if resp == nil || resp.Body == nil {
		return nil, nil
	}
	limit := bffStepMaxResponseBodyBytes(route, step)
	if limit <= 0 {
		return io.ReadAll(resp.Body)
	}
	if resp.ContentLength > limit {
		return nil, fmt.Errorf("BFF step response body exceeds configured limit of %d bytes", limit)
	}
	readLimit := limit + 1
	if readLimit <= 0 {
		readLimit = limit
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, readLimit))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > limit {
		return nil, fmt.Errorf("BFF step response body exceeds configured limit of %d bytes", limit)
	}
	return body, nil
}

func bffStepMaxResponseBodyBytes(route config.RouterConfig, step config.BFFStepConfig) int64 {
	if step.MaxResponseBodyBytes > 0 {
		return step.MaxResponseBodyBytes
	}
	if route.BFF != nil && route.BFF.MaxStepResponseBodyBytes > 0 {
		return route.BFF.MaxStepResponseBodyBytes
	}
	return 0
}

func buildBFFStepFallback(r *http.Request, previous map[string]bffStepResult, step config.BFFStepConfig, failed bffStepResult) (bffStepResult, bool) {
	if step.Fallback == nil {
		return bffStepResult{}, false
	}
	fallback := failed
	fallback.err = nil
	fallback.fallback = true
	fallback.cacheHit = false
	fallback.cacheStale = false
	fallback.coalesced = false
	fallback.statusCode = step.Fallback.Status
	if fallback.statusCode == 0 {
		fallback.statusCode = http.StatusOK
	}
	fallback.header = make(http.Header)
	for key, value := range step.Fallback.Headers {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		resolved, err := resolveBFFTemplateStringValue(r, previous, value)
		if err != nil {
			return bffStepResult{}, false
		}
		fallback.header.Set(key, resolved)
	}

	body, parsed, contentType, err := bffFallbackBody(r, previous, step.Fallback.Body)
	if err != nil {
		return bffStepResult{}, false
	}
	fallback.body = body
	fallback.jsonBody = parsed
	if contentType != "" && fallback.header.Get("Content-Type") == "" {
		fallback.header.Set("Content-Type", contentType)
	}
	return fallback, true
}

func bffFallbackBody(r *http.Request, previous map[string]bffStepResult, raw string) ([]byte, interface{}, string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, nil, "", nil
	}
	contentType := "application/json"
	if strings.HasPrefix(trimmed, "json:") {
		resolvedValue, err := resolveBFFTemplateStringValue(r, previous, raw)
		if err != nil {
			return nil, nil, "", err
		}
		resolved := strings.TrimSpace(strings.TrimPrefix(resolvedValue, "json:"))
		var parsed interface{}
		if err := json.Unmarshal([]byte(resolved), &parsed); err == nil {
			return []byte(resolved), parsed, contentType, nil
		}
		return []byte(resolved), nil, contentType, nil
	}
	resolved, err := resolveBFFTemplateStringValue(r, previous, raw)
	if err != nil {
		return nil, nil, "", err
	}
	var parsed interface{}
	if err := json.Unmarshal([]byte(resolved), &parsed); err == nil {
		return []byte(resolved), parsed, contentType, nil
	}
	return []byte(resolved), nil, "", nil
}

func (g *Gateway) bffStaleFallback(cacheKey string, failed bffStepResult, now time.Time) (bffStepResult, bool) {
	stale, ok := g.getBFFStaleCacheEntry(cacheKey, now)
	if !ok {
		return bffStepResult{}, false
	}
	stale.name = failed.name
	stale.method = failed.method
	stale.upstreamHost = failed.upstreamHost
	stale.upstreamPath = failed.upstreamPath
	stale.attempts = failed.attempts
	return stale, true
}

func roundTripBFFStep(req *http.Request, body []byte, step config.BFFStepConfig) (*http.Response, int, error) {
	base := cloneDefaultTransport()
	attempts := bffStepRetryAttempts(step)
	retryStatuses := bffStepRetryStatusSet(step)
	backoff := bffStepRetryBackoff(step)
	jitter := bffStepRetryJitter(step)

	var lastResp *http.Response
	var lastErr error
	for attempt := 0; attempt < attempts; attempt++ {
		attemptReq := req.Clone(req.Context())
		if len(body) > 0 {
			attemptReq.Body = io.NopCloser(bytes.NewReader(body))
			attemptReq.ContentLength = int64(len(body))
			attemptReq.GetBody = func() (io.ReadCloser, error) {
				return io.NopCloser(bytes.NewReader(body)), nil
			}
		}

		resp, roundTripErr := base.RoundTrip(attemptReq)
		if roundTripErr == nil && !retryStatuses[resp.StatusCode] {
			return resp, attempt + 1, nil
		}
		if !bffStepRetryAllowedForMethod(step, req.Method) {
			if resp != nil {
				return resp, attempt + 1, nil
			}
			return nil, attempt + 1, roundTripErr
		}
		if roundTripErr == nil {
			lastResp = resp
		} else {
			lastErr = roundTripErr
		}
		if attempt == attempts-1 {
			break
		}
		if resp != nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
		}
		delay := backoff + retryJitterOffset(jitter)
		if delay > 0 {
			timer := time.NewTimer(delay)
			select {
			case <-req.Context().Done():
				timer.Stop()
				if lastErr != nil {
					return nil, attempt + 1, lastErr
				}
				if lastResp != nil {
					return lastResp, attempt + 1, nil
				}
				return nil, attempt + 1, req.Context().Err()
			case <-timer.C:
			}
		}
	}

	if lastResp != nil {
		return lastResp, attempts, nil
	}
	return nil, attempts, lastErr
}

func bffStepRetryAttempts(step config.BFFStepConfig) int {
	if step.RetryCount <= 0 {
		return 1
	}
	return step.RetryCount + 1
}

func bffStepRetryBackoff(step config.BFFStepConfig) time.Duration {
	if strings.TrimSpace(step.RetryBackoff) == "" {
		return 0
	}
	backoff, err := time.ParseDuration(strings.TrimSpace(step.RetryBackoff))
	if err != nil || backoff < 0 {
		return 0
	}
	return backoff
}

func bffStepRetryJitter(step config.BFFStepConfig) time.Duration {
	if strings.TrimSpace(step.RetryJitter) == "" {
		return 0
	}
	jitter, err := time.ParseDuration(strings.TrimSpace(step.RetryJitter))
	if err != nil || jitter < 0 {
		return 0
	}
	return jitter
}

func bffStepRetryStatusSet(step config.BFFStepConfig) map[int]bool {
	if len(step.RetryStatuses) == 0 {
		return map[int]bool{
			http.StatusBadGateway:         true,
			http.StatusServiceUnavailable: true,
			http.StatusGatewayTimeout:     true,
			http.StatusTooManyRequests:    true,
		}
	}
	statuses := make(map[int]bool, len(step.RetryStatuses))
	for _, statusCode := range step.RetryStatuses {
		statuses[statusCode] = true
	}
	return statuses
}

func bffStepRetryAllowedForMethod(step config.BFFStepConfig, method string) bool {
	if step.RetryUnsafe {
		return true
	}
	switch strings.ToUpper(strings.TrimSpace(method)) {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace, http.MethodPut, http.MethodDelete:
		return true
	default:
		return false
	}
}

func bffStepStatusSuccessful(step config.BFFStepConfig, statusCode int) bool {
	if statusCode <= 0 {
		return false
	}
	if len(step.SuccessStatuses) == 0 {
		return statusCode >= http.StatusOK && statusCode < http.StatusBadRequest
	}
	for _, candidate := range step.SuccessStatuses {
		if candidate == statusCode {
			return true
		}
	}
	return false
}

func bffStepOutcome(result bffStepResult) string {
	if result.skipped {
		return "skipped"
	}
	if result.cacheStale {
		return "cache_stale"
	}
	if result.cacheHit {
		return "cache_hit"
	}
	if result.fallback {
		return "fallback"
	}
	if result.err != nil {
		return "error"
	}
	if result.statusCode > 0 && !result.successful {
		return "failure"
	}
	if result.coalesced {
		return "coalesced"
	}
	if result.statusCode > 0 {
		return "success"
	}
	return "unknown"
}

func (g *Gateway) logBFFStepResult(r *http.Request, route config.RouterConfig, step config.BFFStepConfig, result bffStepResult, outcome string, duration time.Duration) {
	if result.err != nil {
		g.logger.Warn("BFF upstream step failed",
			logging.String("route_path", route.Path),
			logging.String("service_name", route.ServiceName),
			logging.String("step", step.Name),
			logging.String("method", result.method),
			logging.String("upstream_host", result.upstreamHost),
			logging.String("upstream_path", result.upstreamPath),
			logging.Bool("required", step.IsRequired()),
			logging.String("outcome", outcome),
			logging.Int("attempts", result.attempts),
			logging.Bool("cache_hit", result.cacheHit),
			logging.Bool("cache_stale", result.cacheStale),
			logging.Bool("coalesced", result.coalesced),
			logging.Bool("fallback", result.fallback),
			logging.Bool("skipped", result.skipped),
			logging.Bool("successful", result.successful),
			logging.Int("status_code", result.statusCode),
			logging.Int64("duration_ms", duration.Milliseconds()),
			logging.String("request_id", GetRequestID(r)),
			logging.Error(result.err),
		)
		return
	}
	if result.statusCode > 0 && !result.successful {
		g.logger.Warn("BFF upstream step returned failure status",
			logging.String("route_path", route.Path),
			logging.String("service_name", route.ServiceName),
			logging.String("step", step.Name),
			logging.String("method", result.method),
			logging.String("upstream_host", result.upstreamHost),
			logging.String("upstream_path", result.upstreamPath),
			logging.Bool("required", step.IsRequired()),
			logging.String("outcome", outcome),
			logging.Int("attempts", result.attempts),
			logging.Bool("cache_hit", result.cacheHit),
			logging.Bool("cache_stale", result.cacheStale),
			logging.Bool("coalesced", result.coalesced),
			logging.Bool("fallback", result.fallback),
			logging.Bool("skipped", result.skipped),
			logging.Bool("successful", result.successful),
			logging.Int("status_code", result.statusCode),
			logging.Int64("duration_ms", duration.Milliseconds()),
			logging.String("request_id", GetRequestID(r)),
		)
		return
	}
	g.logger.Info("BFF upstream step completed",
		logging.String("route_path", route.Path),
		logging.String("service_name", route.ServiceName),
		logging.String("step", step.Name),
		logging.String("method", result.method),
		logging.String("upstream_host", result.upstreamHost),
		logging.String("upstream_path", result.upstreamPath),
		logging.Bool("required", step.IsRequired()),
		logging.String("outcome", outcome),
		logging.Int("attempts", result.attempts),
		logging.Bool("cache_hit", result.cacheHit),
		logging.Bool("cache_stale", result.cacheStale),
		logging.Bool("coalesced", result.coalesced),
		logging.Bool("fallback", result.fallback),
		logging.Bool("skipped", result.skipped),
		logging.Bool("successful", result.successful),
		logging.Int("status_code", result.statusCode),
		logging.Int64("duration_ms", duration.Milliseconds()),
		logging.String("request_id", GetRequestID(r)),
	)
}

func applyBFFUpstreamHeaders(original *http.Request, upstream *http.Request, route config.RouterConfig) {
	if original == nil || upstream == nil {
		return
	}
	effectiveRoute := graphQLOperationRequestRoute(route, original)
	normalizeForwardedHeaderMap(original, upstream.Header)
	if realm := GetTenantRealm(original); realm != "" && upstream.Header.Get("X-Realm") == "" {
		upstream.Header.Set("X-Realm", realm)
	}
	if !routeTransformsEnabled(original, effectiveRoute, "request_headers") {
		applyRequestHeaderRedactions(upstream.Header, effectiveRoute)
		return
	}
	for key, value := range effectiveRoute.Headers {
		if strings.TrimSpace(key) == "" {
			continue
		}
		upstream.Header.Set(key, resolveTransformTemplate(original, value))
	}
	for key, value := range effectiveRoute.RequestHeaders {
		if strings.TrimSpace(key) == "" {
			continue
		}
		upstream.Header.Set(key, resolveTransformTemplate(original, value))
	}
	for _, key := range effectiveRoute.RemoveRequestHeaders {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		upstream.Header.Del(key)
	}
	applyRequestHeaderRedactions(upstream.Header, effectiveRoute)
}

func applyBFFResponseHeaders(w http.ResponseWriter, r *http.Request, route config.RouterConfig, results map[string]bffStepResult) error {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Gateway", "Iket")
	w.Header().Set("X-Gateway-Route", route.Path)
	if requestID := GetRequestID(r); requestID != "" {
		w.Header().Set("X-Request-Id", requestID)
	}
	if route.BFF == nil {
		return nil
	}
	for key, value := range route.BFF.ResponseHeaders {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		resolved, err := resolveBFFTemplateStringValue(r, results, value)
		if err != nil {
			return err
		}
		w.Header().Set(key, resolved)
	}
	return nil
}

func bffStepBody(r *http.Request, previous map[string]bffStepResult, step config.BFFStepConfig) ([]byte, string, error) {
	raw := strings.TrimSpace(step.Body)
	if raw == "" {
		return nil, "", nil
	}
	if raw == "{{request_body}}" {
		body, err := bffRequestBodyBytes(r)
		return body, r.Header.Get("Content-Type"), err
	}
	value, err := resolveBFFTemplateValue(r, previous, step.Body)
	if err != nil {
		return nil, "", err
	}
	switch typed := value.(type) {
	case string:
		return []byte(typed), "application/json", nil
	default:
		encoded, err := json.Marshal(typed)
		return encoded, "application/json", err
	}
}

func buildBFFResponsePayload(r *http.Request, route config.RouterConfig, results map[string]bffStepResult) (map[string]interface{}, error) {
	payload := make(map[string]interface{})
	if len(route.BFF.ResponseFields) > 0 {
		for key, template := range route.BFF.ResponseFields {
			key = strings.TrimSpace(key)
			if key == "" {
				continue
			}
			value, err := resolveBFFTemplateValue(r, results, template)
			if err != nil {
				return nil, err
			}
			setNestedJSONField(payload, key, value)
		}
		if route.BFF.IncludeMeta {
			payload["meta"] = bffMetaPayload(route.BFF.Steps, results)
		}
		return payload, nil
	}

	data := make(map[string]interface{}, len(results))
	for _, step := range route.BFF.Steps {
		result := results[step.Name]
		if result.skipped || result.err != nil {
			data[step.Name] = nil
			continue
		}
		if result.jsonBody != nil {
			data[step.Name] = result.jsonBody
		} else {
			data[step.Name] = string(result.body)
		}
	}
	payload["data"] = data
	if route.BFF.IncludeMeta {
		payload["meta"] = bffMetaPayload(route.BFF.Steps, results)
	}
	return payload, nil
}

func bffResponseStatus(r *http.Request, route config.RouterConfig, results map[string]bffStepResult) (int, error) {
	if route.BFF == nil {
		return http.StatusOK, nil
	}
	if route.BFF.PartialResponseStatus > 0 && summarizeBFFResults(route.BFF.Steps, results).partial {
		return route.BFF.PartialResponseStatus, nil
	}
	if strings.TrimSpace(route.BFF.ResponseStatus) == "" {
		return http.StatusOK, nil
	}
	resolvedValue, err := resolveBFFTemplateStringValue(r, results, route.BFF.ResponseStatus)
	if err != nil {
		return 0, err
	}
	resolved := strings.TrimSpace(resolvedValue)
	statusCode, err := strconv.Atoi(resolved)
	if err != nil || statusCode < 200 || statusCode > 599 {
		return 0, fmt.Errorf("bff.responseStatus resolved to invalid HTTP status %q", resolved)
	}
	return statusCode, nil
}

func bffMetaPayload(configuredSteps []config.BFFStepConfig, results map[string]bffStepResult) map[string]interface{} {
	steps := make(map[string]interface{}, len(results))
	summary := summarizeBFFResults(configuredSteps, results)
	for _, configuredStep := range configuredSteps {
		result, ok := results[configuredStep.Name]
		if !ok {
			continue
		}
		dependencies, explicitDependencies, inferredDependencies := bffStepDependencyBreakdown(configuredStep)
		errorMessage := bffStepErrorMessage(configuredStep.Name, result)
		step := map[string]interface{}{
			"status":                result.statusCode,
			"duration_ms":           result.durationMillis,
			"attempts":              result.attempts,
			"cache_hit":             result.cacheHit,
			"cache_stale":           result.cacheStale,
			"coalesced":             result.coalesced,
			"fallback":              result.fallback,
			"skipped":               result.skipped,
			"successful":            result.successful,
			"dependencies":          dependencies,
			"explicit_dependencies": explicitDependencies,
			"inferred_dependencies": inferredDependencies,
		}
		if errorMessage != "" {
			step["error"] = errorMessage
		}
		steps[configuredStep.Name] = step
	}
	return map[string]interface{}{
		"steps":           steps,
		"partial":         summary.partial,
		"degraded":        summary.degraded,
		"total_steps":     summary.totalSteps,
		"completed_steps": summary.completed,
		"completed_count": len(summary.completed),
		"failed_steps":    summary.failedSteps,
		"failed_count":    len(summary.failedSteps),
		"skipped_steps":   summary.skippedSteps,
		"skipped_count":   len(summary.skippedSteps),
		"errors":          summary.errors,
	}
}

func summarizeBFFResults(configuredSteps []config.BFFStepConfig, results map[string]bffStepResult) bffResultsSummary {
	summary := bffResultsSummary{
		completed:    make([]string, 0),
		failedSteps:  make([]string, 0),
		skippedSteps: make([]string, 0),
		errors:       make(map[string]string),
	}
	names := make([]string, 0, len(results))
	if len(configuredSteps) > 0 {
		summary.totalSteps = len(configuredSteps)
		for _, step := range configuredSteps {
			if _, ok := results[step.Name]; ok {
				names = append(names, step.Name)
			}
		}
	} else {
		summary.totalSteps = len(results)
		for name := range results {
			names = append(names, name)
		}
		sort.Strings(names)
	}
	for _, name := range names {
		result := results[name]
		failed := false
		if errorMessage := bffStepErrorMessage(name, result); errorMessage != "" {
			failed = true
			summary.failedSteps = append(summary.failedSteps, name)
			summary.errors[name] = errorMessage
		}
		if result.skipped {
			summary.skippedSteps = append(summary.skippedSteps, name)
			continue
		}
		if !failed {
			summary.completed = append(summary.completed, name)
		}
	}
	summary.partial = len(summary.failedSteps) > 0
	summary.degraded = summary.partial || len(summary.skippedSteps) > 0
	return summary
}

func bffErrorSummary(summary bffResultsSummary) string {
	if len(summary.failedSteps) == 0 {
		return ""
	}
	parts := make([]string, 0, len(summary.failedSteps))
	for _, step := range summary.failedSteps {
		parts = append(parts, step+": "+summary.errors[step])
	}
	return strings.Join(parts, "; ")
}

func bffStepErrorMessage(stepName string, result bffStepResult) string {
	if result.err != nil {
		return result.err.Error()
	}
	if result.statusCode > 0 && !result.successful {
		stepName = strings.TrimSpace(stepName)
		if stepName == "" {
			stepName = strings.TrimSpace(result.name)
		}
		if stepName != "" {
			return fmt.Sprintf("BFF upstream %s returned status %d", stepName, result.statusCode)
		}
		return fmt.Sprintf("BFF upstream returned status %d", result.statusCode)
	}
	return ""
}

func resolveBFFTemplateValue(r *http.Request, results map[string]bffStepResult, value string) (interface{}, error) {
	trimmed := strings.TrimSpace(value)
	if strings.HasPrefix(trimmed, "json:") {
		resolvedValue, err := resolveBFFTemplateStringValue(r, results, value)
		if err != nil {
			return nil, err
		}
		resolved := strings.TrimSpace(strings.TrimPrefix(resolvedValue, "json:"))
		if resolved == "" {
			return nil, fmt.Errorf("json: bff response values must contain valid JSON")
		}
		var parsed interface{}
		if err := json.Unmarshal([]byte(resolved), &parsed); err != nil {
			return nil, fmt.Errorf("json: bff response values must contain valid JSON")
		}
		return parsed, nil
	}
	matches := transformTemplateRe.FindAllStringSubmatch(value, -1)
	if len(matches) == 1 && strings.TrimSpace(matches[0][0]) == trimmed {
		token := strings.TrimSpace(matches[0][1])
		resolved, ok, err := bffTemplateTokenValue(r, results, token)
		if err != nil {
			return nil, err
		}
		if !ok {
			return "", nil
		}
		return resolved, nil
	}
	return resolveBFFTemplateStringValue(r, results, value)
}

func resolveBFFTemplateString(r *http.Request, results map[string]bffStepResult, value string) string {
	resolved, _ := resolveBFFTemplateStringValue(r, results, value)
	return resolved
}

func resolveBFFTemplateStringValue(r *http.Request, results map[string]bffStepResult, value string) (string, error) {
	if !strings.Contains(value, "{{") {
		return value, nil
	}
	var resolveErr error
	resolved := transformTemplateRe.ReplaceAllStringFunc(value, func(match string) string {
		if resolveErr != nil {
			return ""
		}
		sub := transformTemplateRe.FindStringSubmatch(match)
		if len(sub) < 2 {
			return match
		}
		token := strings.TrimSpace(sub[1])
		resolved, ok, err := bffTemplateTokenValue(r, results, token)
		if err != nil {
			resolveErr = err
			return ""
		}
		if !ok || resolved == nil {
			return ""
		}
		return bffTemplateString(resolved)
	})
	if resolveErr != nil {
		return "", resolveErr
	}
	return resolved, nil
}

func bffTemplateTokenValue(r *http.Request, results map[string]bffStepResult, token string) (interface{}, bool, error) {
	lookup, filters := bffTemplateFilters(token)
	resolved, ok := bffTemplateRawTokenValue(r, results, lookup)
	for _, filter := range filters {
		switch filter.name {
		case "default":
			if bffTemplateDefaultApplies(resolved, ok) {
				resolved = parseBFFTemplateDefaultValue(filter.value)
				ok = true
			}
		case "required":
			if bffTemplateRequiredApplies(resolved, ok) {
				return nil, false, bffTemplateRequiredError(filter.value)
			}
		case "join":
			if !ok {
				return resolved, ok, nil
			}
			resolved = bffTemplateJoin(resolved, filter.value)
			ok = true
		case "len", "length":
			if !ok {
				return resolved, ok, nil
			}
			resolved = bffTemplateLength(resolved)
			ok = true
		case "first":
			if !ok {
				return resolved, ok, nil
			}
			resolved = bffTemplateFirst(resolved)
			ok = true
		case "last":
			if !ok {
				return resolved, ok, nil
			}
			resolved = bffTemplateLast(resolved)
			ok = true
		case "compact":
			if !ok {
				return resolved, ok, nil
			}
			resolved = bffTemplateCompact(resolved)
			ok = true
		case "unique":
			if !ok {
				return resolved, ok, nil
			}
			resolved = bffTemplateUnique(resolved)
			ok = true
		case "lower":
			if !ok {
				return resolved, ok, nil
			}
			resolved = bffTemplateStringFilter(resolved, strings.ToLower)
			ok = true
		case "replace":
			if !ok {
				return resolved, ok, nil
			}
			resolved = bffTemplateReplace(resolved, filter.value)
			ok = true
		case "trim":
			if !ok {
				return resolved, ok, nil
			}
			resolved = bffTemplateStringFilter(resolved, strings.TrimSpace)
			ok = true
		case "upper":
			if !ok {
				return resolved, ok, nil
			}
			resolved = bffTemplateStringFilter(resolved, strings.ToUpper)
			ok = true
		case "json":
			if !ok {
				return resolved, ok, nil
			}
			encoded, err := json.Marshal(resolved)
			if err != nil {
				return "", false, err
			}
			resolved = string(encoded)
			ok = true
		case "urlpath":
			if !ok {
				return resolved, ok, nil
			}
			resolved = url.PathEscape(bffTemplateString(resolved))
			ok = true
		case "urlquery":
			if !ok {
				return resolved, ok, nil
			}
			resolved = url.QueryEscape(bffTemplateString(resolved))
			ok = true
		}
	}
	return resolved, ok, nil
}

func bffTemplateRawTokenValue(r *http.Request, results map[string]bffStepResult, token string) (interface{}, bool) {
	switch {
	case token == "request_body":
		body, err := bffRequestBodyBytes(r)
		if err != nil {
			return "", false
		}
		return string(body), true
	case strings.HasPrefix(token, "request.json."):
		return bffRequestJSONPathValue(r, strings.TrimPrefix(token, "request.json."))
	case strings.HasPrefix(token, "bff."):
		return bffSummaryTokenValue(results, strings.TrimPrefix(token, "bff."))
	case strings.HasPrefix(token, "step."):
		return bffStepTokenValue(results, strings.TrimPrefix(token, "step."))
	default:
		return resolveTransformTemplate(r, "{{"+token+"}}"), true
	}
}

type bffTemplateFilter struct {
	name  string
	value string
}

func bffTemplateFilters(token string) (string, []bffTemplateFilter) {
	parts := strings.Split(token, "|")
	if len(parts) == 1 {
		return strings.TrimSpace(token), nil
	}
	lookup := strings.TrimSpace(parts[0])
	filters := make([]bffTemplateFilter, 0, len(parts)-1)
	for _, rawFilter := range parts[1:] {
		rawFilter = strings.TrimSpace(rawFilter)
		name, value, hasValue := strings.Cut(rawFilter, ":")
		name = strings.ToLower(strings.TrimSpace(name))
		switch name {
		case "default":
			if !hasValue {
				continue
			}
			filters = append(filters, bffTemplateFilter{name: name, value: value})
		case "required":
			if hasValue {
				filters = append(filters, bffTemplateFilter{name: name, value: value})
			} else {
				filters = append(filters, bffTemplateFilter{name: name})
			}
		case "join":
			if !hasValue {
				continue
			}
			filters = append(filters, bffTemplateFilter{name: name, value: value})
		case "len", "length":
			filters = append(filters, bffTemplateFilter{name: name})
		case "replace":
			if !hasValue {
				continue
			}
			filters = append(filters, bffTemplateFilter{name: name, value: value})
		case "compact", "first", "json", "last", "lower", "trim", "unique", "upper", "urlpath", "urlquery":
			filters = append(filters, bffTemplateFilter{name: name})
		default:
			continue
		}
	}
	return lookup, filters
}

func bffTemplateRequiredError(message string) error {
	message = strings.TrimSpace(message)
	if message == "" {
		return fmt.Errorf("required BFF template value is missing")
	}
	return fmt.Errorf("required BFF template value is missing: %s", message)
}

func bffTemplateJoin(value interface{}, separator string) string {
	switch typed := value.(type) {
	case []interface{}:
		parts := make([]string, 0, len(typed))
		for _, item := range typed {
			parts = append(parts, bffTemplateString(item))
		}
		return strings.Join(parts, separator)
	case []string:
		return strings.Join(typed, separator)
	default:
		return bffTemplateString(value)
	}
}

func bffTemplateStringFilter(value interface{}, transform func(string) string) interface{} {
	switch typed := value.(type) {
	case []interface{}:
		items := make([]interface{}, 0, len(typed))
		for _, item := range typed {
			items = append(items, transform(bffTemplateString(item)))
		}
		return items
	case []string:
		items := make([]string, 0, len(typed))
		for _, item := range typed {
			items = append(items, transform(item))
		}
		return items
	default:
		return transform(bffTemplateString(value))
	}
}

func bffTemplateReplace(value interface{}, raw string) interface{} {
	oldValue, newValue, ok := strings.Cut(raw, ",")
	if !ok {
		return value
	}
	return bffTemplateStringFilter(value, func(item string) string {
		return strings.ReplaceAll(item, oldValue, newValue)
	})
}

func bffTemplateFirst(value interface{}) interface{} {
	switch typed := value.(type) {
	case []interface{}:
		if len(typed) == 0 {
			return nil
		}
		return typed[0]
	case []string:
		if len(typed) == 0 {
			return nil
		}
		return typed[0]
	default:
		return value
	}
}

func bffTemplateLast(value interface{}) interface{} {
	switch typed := value.(type) {
	case []interface{}:
		if len(typed) == 0 {
			return nil
		}
		return typed[len(typed)-1]
	case []string:
		if len(typed) == 0 {
			return nil
		}
		return typed[len(typed)-1]
	default:
		return value
	}
}

func bffTemplateCompact(value interface{}) interface{} {
	switch typed := value.(type) {
	case []interface{}:
		items := make([]interface{}, 0, len(typed))
		for _, item := range typed {
			if bffTemplateEmptyValue(item) {
				continue
			}
			items = append(items, item)
		}
		return items
	case []string:
		items := make([]string, 0, len(typed))
		for _, item := range typed {
			if strings.TrimSpace(item) == "" {
				continue
			}
			items = append(items, item)
		}
		return items
	default:
		return value
	}
}

func bffTemplateUnique(value interface{}) interface{} {
	switch typed := value.(type) {
	case []interface{}:
		seen := make(map[string]struct{}, len(typed))
		items := make([]interface{}, 0, len(typed))
		for _, item := range typed {
			key := bffTemplateString(item)
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			items = append(items, item)
		}
		return items
	case []string:
		seen := make(map[string]struct{}, len(typed))
		items := make([]string, 0, len(typed))
		for _, item := range typed {
			if _, ok := seen[item]; ok {
				continue
			}
			seen[item] = struct{}{}
			items = append(items, item)
		}
		return items
	default:
		return value
	}
}

func bffTemplateEmptyValue(value interface{}) bool {
	if value == nil {
		return true
	}
	if typed, ok := value.(string); ok {
		return strings.TrimSpace(typed) == ""
	}
	return false
}

func bffTemplateLength(value interface{}) int {
	switch typed := value.(type) {
	case []interface{}:
		return len(typed)
	case []string:
		return len(typed)
	case map[string]interface{}:
		return len(typed)
	case string:
		return len(typed)
	default:
		return 0
	}
}

func parseBFFTemplateDefaultValue(value string) interface{} {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	var parsed interface{}
	if err := json.Unmarshal([]byte(value), &parsed); err == nil {
		return parsed
	}
	return value
}

func bffTemplateDefaultApplies(value interface{}, ok bool) bool {
	if !ok || value == nil {
		return true
	}
	if typed, ok := value.(string); ok {
		return typed == ""
	}
	return false
}

func bffTemplateRequiredApplies(value interface{}, ok bool) bool {
	if bffTemplateDefaultApplies(value, ok) {
		return true
	}
	switch typed := value.(type) {
	case []interface{}:
		return len(typed) == 0
	case []string:
		return len(typed) == 0
	default:
		return false
	}
}

func bffSummaryTokenValue(results map[string]bffStepResult, token string) (interface{}, bool) {
	if results == nil {
		return nil, false
	}
	summary := summarizeBFFResults(nil, results)
	switch strings.TrimSpace(token) {
	case "partial":
		return summary.partial, true
	case "degraded":
		return summary.degraded, true
	case "total_steps":
		return summary.totalSteps, true
	case "completed_steps":
		return summary.completed, true
	case "completed_count":
		return len(summary.completed), true
	case "failed_steps":
		return summary.failedSteps, true
	case "skipped_steps":
		return summary.skippedSteps, true
	case "errors":
		return summary.errors, true
	case "error_summary":
		return bffErrorSummary(summary), true
	case "failed_count":
		return len(summary.failedSteps), true
	case "skipped_count":
		return len(summary.skippedSteps), true
	default:
		return nil, false
	}
}

func bffStepTokenValue(results map[string]bffStepResult, token string) (interface{}, bool) {
	parts := strings.SplitN(token, ".", 2)
	if len(parts) != 2 || results == nil {
		return nil, false
	}
	result, ok := results[parts[0]]
	if !ok {
		return nil, false
	}
	switch {
	case parts[1] == "body":
		return string(result.body), true
	case parts[1] == "status":
		return result.statusCode, true
	case parts[1] == "attempts":
		return result.attempts, true
	case parts[1] == "cache_hit":
		return result.cacheHit, true
	case parts[1] == "cache_stale":
		return result.cacheStale, true
	case parts[1] == "coalesced":
		return result.coalesced, true
	case parts[1] == "fallback":
		return result.fallback, true
	case parts[1] == "skipped":
		return result.skipped, true
	case parts[1] == "ok":
		return !result.skipped && result.err == nil && result.successful, true
	case parts[1] == "error":
		return bffStepErrorMessage(result.name, result), true
	case strings.HasPrefix(parts[1], "header."):
		return result.header.Get(strings.TrimPrefix(parts[1], "header.")), true
	case strings.HasPrefix(parts[1], "json."):
		return bffJSONPathValue(result.jsonBody, strings.TrimPrefix(parts[1], "json."))
	default:
		return nil, false
	}
}

func withBFFRequestBodyCache(r *http.Request) *http.Request {
	if r == nil {
		return nil
	}
	if _, ok := r.Context().Value(bffRequestBodyCacheContextKey{}).(*bffRequestBodyCache); ok {
		return r
	}
	ctx := context.WithValue(r.Context(), bffRequestBodyCacheContextKey{}, &bffRequestBodyCache{})
	return r.WithContext(ctx)
}

func bffRequestBodyBytes(r *http.Request) ([]byte, error) {
	if r == nil {
		return nil, nil
	}
	if cache, ok := r.Context().Value(bffRequestBodyCacheContextKey{}).(*bffRequestBodyCache); ok && cache != nil {
		cache.bodyOnce.Do(func() {
			cache.body, cache.bodyErr = cloneRequestBody(r)
		})
		if cache.bodyErr != nil {
			return nil, cache.bodyErr
		}
		return cache.body, nil
	}
	return cloneRequestBody(r)
}

func bffRequestJSONPathValue(r *http.Request, path string) (interface{}, bool) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, false
	}
	parsed, ok := bffRequestJSONBody(r)
	if !ok {
		return nil, false
	}
	return bffJSONPathValue(parsed, path)
}

func bffRequestJSONBody(r *http.Request) (interface{}, bool) {
	parsed, err := bffRequestJSONBodyValue(r)
	return parsed, err == nil
}

func bffRequestJSONBodyValue(r *http.Request) (interface{}, error) {
	if r == nil {
		return nil, fmt.Errorf("BFF request body must contain valid JSON")
	}
	if cache, ok := r.Context().Value(bffRequestBodyCacheContextKey{}).(*bffRequestBodyCache); ok && cache != nil {
		cache.jsonOnce.Do(func() {
			cache.jsonBody, cache.jsonErr = parseBFFRequestJSONBody(r)
		})
		return cache.jsonBody, cache.jsonErr
	}
	return parseBFFRequestJSONBody(r)
}

func validateBFFRequestJSON(r *http.Request, route config.RouterConfig) error {
	if route.BFF == nil || (!route.BFF.RequireRequestJSON && len(route.BFF.RequiredRequestJSONPaths) == 0) {
		return nil
	}
	parsed, err := bffRequestJSONBodyValue(r)
	if err != nil {
		return err
	}
	for _, path := range route.BFF.RequiredRequestJSONPaths {
		if _, ok := bffJSONPathValue(parsed, path); !ok {
			return fmt.Errorf("BFF request body is missing required JSON path %q", path)
		}
	}
	return nil
}

func parseBFFRequestJSONBody(r *http.Request) (interface{}, error) {
	body, err := bffRequestBodyBytes(r)
	if err != nil {
		return nil, err
	}
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		return nil, fmt.Errorf("BFF request body must contain valid JSON")
	}
	var parsed interface{}
	if err := json.Unmarshal(trimmed, &parsed); err != nil {
		return nil, fmt.Errorf("BFF request body must contain valid JSON: %w", err)
	}
	return parsed, nil
}

func bffJSONPathValue(value interface{}, path string) (interface{}, bool) {
	if value == nil {
		return nil, false
	}
	segments := parseJSONFieldPath(path)
	if len(segments) == 0 {
		return nil, false
	}
	values, ok := bffJSONPathValues(value, segments)
	if !ok {
		return nil, false
	}
	if bffJSONPathHasWildcard(segments) {
		return values, true
	}
	if len(values) == 0 {
		return nil, false
	}
	return values[0], true
}

func bffJSONPathValues(current interface{}, segments []jsonPathSegment) ([]interface{}, bool) {
	if len(segments) == 0 {
		return []interface{}{current}, true
	}
	obj, ok := current.(map[string]interface{})
	if !ok {
		return nil, false
	}
	segment := segments[0]
	next, ok := obj[segment.key]
	if !ok {
		return nil, false
	}
	if !segment.hasArray() {
		return bffJSONPathValues(next, segments[1:])
	}
	array, ok := next.([]interface{})
	if !ok {
		return nil, false
	}
	if !segment.append {
		if segment.index < 0 || segment.index >= len(array) {
			return nil, false
		}
		return bffJSONPathValues(array[segment.index], segments[1:])
	}
	values := make([]interface{}, 0, len(array))
	for _, item := range array {
		childValues, ok := bffJSONPathValues(item, segments[1:])
		if !ok {
			continue
		}
		values = append(values, childValues...)
	}
	return values, true
}

func bffJSONPathHasWildcard(segments []jsonPathSegment) bool {
	for _, segment := range segments {
		if segment.append {
			return true
		}
	}
	return false
}

func bffTemplateString(value interface{}) string {
	switch typed := value.(type) {
	case string:
		return typed
	case nil:
		return ""
	case int:
		return strconv.Itoa(typed)
	case int64:
		return strconv.FormatInt(typed, 10)
	case float64:
		return strconv.FormatFloat(typed, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(typed)
	default:
		encoded, err := json.Marshal(typed)
		if err != nil {
			return fmt.Sprint(typed)
		}
		return string(encoded)
	}
}

func bffTimeout(value string) time.Duration {
	if strings.TrimSpace(value) == "" {
		return 0
	}
	timeout, err := time.ParseDuration(strings.TrimSpace(value))
	if err != nil || timeout <= 0 {
		return 0
	}
	return timeout
}

func writeBFFError(w http.ResponseWriter, r *http.Request, route config.RouterConfig, statusCode int, message, detail string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Gateway", "Iket")
	w.Header().Set("X-Gateway-Route", route.Path)
	if requestID := GetRequestID(r); requestID != "" {
		w.Header().Set("X-Request-Id", requestID)
	}
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"error":   message,
		"message": detail,
	})
}
