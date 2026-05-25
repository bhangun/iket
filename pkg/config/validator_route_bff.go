package config

import (
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

var bffTemplateStepReferenceRe = regexp.MustCompile(`\{\{\s*step\.([^.\s}]+)`)

func validateRouteBFFPolicy(ctx serviceValidationContext) error {
	bff := ctx.route.BFF
	if bff == nil {
		return nil
	}
	if !bff.IsEnabled() {
		return nil
	}
	switch strings.ToLower(strings.TrimSpace(bff.Mode)) {
	case "", "parallel", "sequential":
	default:
		return validationError(ctx.routeField("bff.mode"), "bff.mode must be parallel or sequential")
	}
	if err := validateOptionalPositiveDuration(ctx.routeField("bff.timeout"), bff.Timeout, "bff.timeout must use a positive duration format"); err != nil {
		return err
	}
	if bff.MaxStepResponseBodyBytes < 0 {
		return validationError(ctx.routeField("bff.maxStepResponseBodyBytes"), "bff.maxStepResponseBodyBytes must be zero or greater")
	}
	if err := validateJSONFieldSlice(ctx.routeField("bff.requiredRequestJSONPaths"), bff.RequiredRequestJSONPaths, false, "bff.requiredRequestJSONPaths must contain valid JSON field paths"); err != nil {
		return err
	}
	if len(bff.Steps) == 0 {
		return validationError(ctx.routeField("bff.steps"), "bff.steps must contain at least one upstream step")
	}
	if err := validateJSONTransformMap(ctx.routeField("bff.responseFields"), bff.ResponseFields, true, "bff.responseFields must not contain empty field names"); err != nil {
		return err
	}
	if err := validateMapKeysNonEmpty(ctx.routeField("bff.responseHeaders"), bff.ResponseHeaders, "bff.responseHeaders must not contain empty header names"); err != nil {
		return err
	}
	if err := validateBFFResponseStatus(ctx.routeField("bff.responseStatus"), bff.ResponseStatus); err != nil {
		return err
	}
	if bff.PartialResponseStatus != 0 && (bff.PartialResponseStatus < 200 || bff.PartialResponseStatus > 599) {
		return validationError(ctx.routeField("bff.partialResponseStatus"), "bff.partialResponseStatus must be a 2xx-5xx HTTP status code")
	}

	seenSteps := make(map[string]struct{}, len(bff.Steps))
	for stepIndex, step := range bff.Steps {
		if err := validateBFFStep(ctx, stepIndex, step, seenSteps); err != nil {
			return err
		}
	}
	sequential := strings.EqualFold(strings.TrimSpace(bff.Mode), "sequential")
	if err := validateBFFStepDependencies(ctx, bff.Steps, sequential); err != nil {
		return err
	}
	if err := validateBFFStepTemplateReferences(ctx, bff, sequential); err != nil {
		return err
	}
	return nil
}

func validateBFFResponseStatus(field string, value string) error {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" || strings.Contains(trimmed, "{{") {
		return nil
	}
	statusCode, err := strconv.Atoi(trimmed)
	if err != nil || statusCode < 200 || statusCode > 599 {
		return validationError(field, "bff.responseStatus must be a 2xx-5xx HTTP status code or template")
	}
	return nil
}

func validateBFFStep(ctx serviceValidationContext, stepIndex int, step BFFStepConfig, seenSteps map[string]struct{}) error {
	field := func(name string) string {
		return fmt.Sprintf("%s.steps[%d].%s", ctx.routeField("bff"), stepIndex, name)
	}
	name := strings.TrimSpace(step.Name)
	if name == "" {
		return validationError(field("name"), "bff step name is required")
	}
	if _, ok := seenSteps[name]; ok {
		return validationError(field("name"), "bff step names must be unique")
	}
	seenSteps[name] = struct{}{}

	if !isValidHTTPMethod(step.EffectiveMethod()) {
		return validationError(field("method"), fmt.Sprintf("invalid BFF step HTTP method: %s", step.Method))
	}
	if strings.TrimSpace(step.URL) == "" {
		return validationError(field("url"), "bff step url is required")
	}
	parsed, err := url.Parse(strings.TrimSpace(step.URL))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return validationError(field("url"), "bff step url must be an absolute http or https URL")
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return validationError(field("url"), "bff step url must use http or https")
	}
	if err := validateOptionalPositiveDuration(field("timeout"), step.Timeout, "bff step timeout must use a positive duration format"); err != nil {
		return err
	}
	if err := validateMapKeysNonEmpty(field("whenHeaders"), step.WhenHeaders, "bff step whenHeaders must not contain empty names"); err != nil {
		return err
	}
	if err := validateMapKeysNonEmpty(field("whenQueryParams"), step.WhenQueryParams, "bff step whenQueryParams must not contain empty names"); err != nil {
		return err
	}
	if err := validateJSONFieldSlice(field("requiredJSONPaths"), step.RequiredJSONPaths, false, "bff step requiredJSONPaths must contain valid JSON field paths"); err != nil {
		return err
	}
	if step.RetryCount < 0 {
		return validationError(field("retryCount"), "bff step retryCount must be zero or greater")
	}
	if err := validateOptionalDuration(field("retryBackoff"), step.RetryBackoff, "bff step retryBackoff must use a valid duration format"); err != nil {
		return err
	}
	if err := validateOptionalDuration(field("retryJitter"), step.RetryJitter, "bff step retryJitter must use a valid duration format"); err != nil {
		return err
	}
	for retryStatusIndex, statusCode := range step.RetryStatuses {
		if statusCode < 100 || statusCode > 599 {
			return validationError(fmt.Sprintf("%s[%d]", field("retryStatusCodes"), retryStatusIndex), "bff step retryStatusCodes entries must be valid HTTP status codes")
		}
	}
	for successStatusIndex, statusCode := range step.SuccessStatuses {
		if statusCode < 100 || statusCode > 599 {
			return validationError(fmt.Sprintf("%s[%d]", field("successStatusCodes"), successStatusIndex), "bff step successStatusCodes entries must be valid HTTP status codes")
		}
	}
	if err := validateOptionalPositiveDuration(field("cacheTTL"), step.CacheTTL, "bff step cacheTTL must use a positive duration format"); err != nil {
		return err
	}
	if err := validateOptionalPositiveDuration(field("staleIfError"), step.StaleIfError, "bff step staleIfError must use a positive duration format"); err != nil {
		return err
	}
	if step.MaxResponseBodyBytes < 0 {
		return validationError(field("maxResponseBodyBytes"), "bff step maxResponseBodyBytes must be zero or greater")
	}
	for cacheStatusIndex, statusCode := range step.CacheStatuses {
		if statusCode < 100 || statusCode > 599 {
			return validationError(fmt.Sprintf("%s[%d]", field("cacheStatusCodes"), cacheStatusIndex), "bff step cacheStatusCodes entries must be valid HTTP status codes")
		}
	}
	if step.Fallback != nil {
		if step.Fallback.Status != 0 && (step.Fallback.Status < 100 || step.Fallback.Status > 599) {
			return validationError(field("fallback.status"), "bff step fallback status must be a valid HTTP status code")
		}
		if err := validateMapKeysNonEmpty(field("fallback.headers"), step.Fallback.Headers, "bff step fallback headers must not contain empty names"); err != nil {
			return err
		}
	}
	if err := validateMapKeysNonEmpty(field("headers"), step.Headers, "bff step headers must not contain empty names"); err != nil {
		return err
	}
	return validateMapKeysNonEmpty(field("queryParams"), step.QueryParams, "bff step queryParams must not contain empty names")
}

func validateBFFStepDependencies(ctx serviceValidationContext, steps []BFFStepConfig, sequential bool) error {
	indexByName := make(map[string]int, len(steps))
	stepsByName := make(map[string]BFFStepConfig, len(steps))
	for stepIndex, step := range steps {
		name := strings.TrimSpace(step.Name)
		if name == "" {
			continue
		}
		indexByName[name] = stepIndex
		stepsByName[name] = step
	}

	for stepIndex, step := range steps {
		stepName := strings.TrimSpace(step.Name)
		field := fmt.Sprintf("%s.steps[%d].dependsOn", ctx.routeField("bff"), stepIndex)
		seenDeps := make(map[string]struct{}, len(step.DependsOn))
		for depIndex, dependency := range step.DependsOn {
			dependency = strings.TrimSpace(dependency)
			depField := fmt.Sprintf("%s[%d]", field, depIndex)
			if dependency == "" {
				return validationError(depField, "bff step dependsOn entries must not be empty")
			}
			if dependency == stepName {
				return validationError(depField, "bff step cannot depend on itself")
			}
			dependencyIndex, ok := indexByName[dependency]
			if !ok {
				return validationError(depField, "bff step dependsOn references an unknown step")
			}
			if _, exists := seenDeps[dependency]; exists {
				return validationError(depField, "bff step dependsOn entries must be unique")
			}
			seenDeps[dependency] = struct{}{}
			if sequential && dependencyIndex > stepIndex {
				return validationError(depField, "bff sequential step dependencies must reference earlier steps")
			}
		}
		for _, dependency := range bffStepImplicitTemplateDependencies(step) {
			if dependency == stepName {
				return validationError(fmt.Sprintf("%s.steps[%d]", ctx.routeField("bff"), stepIndex), "bff step templates cannot reference the same step")
			}
			dependencyIndex, ok := indexByName[dependency]
			if !ok {
				continue
			}
			if sequential && dependencyIndex > stepIndex {
				return validationError(fmt.Sprintf("%s.steps[%d]", ctx.routeField("bff"), stepIndex), "bff sequential step templates must reference earlier steps")
			}
		}
	}

	visiting := make(map[string]bool, len(stepsByName))
	visited := make(map[string]bool, len(stepsByName))
	var visit func(string) bool
	visit = func(name string) bool {
		if visiting[name] {
			return true
		}
		if visited[name] {
			return false
		}
		visiting[name] = true
		for _, dependency := range bffStepDependencyNames(stepsByName[name]) {
			dependency = strings.TrimSpace(dependency)
			if dependency == "" {
				continue
			}
			if _, ok := stepsByName[dependency]; !ok {
				continue
			}
			if visit(dependency) {
				return true
			}
		}
		visiting[name] = false
		visited[name] = true
		return false
	}
	for name := range stepsByName {
		if visit(name) {
			return validationError(ctx.routeField("bff.steps"), "bff step dependsOn must not contain cycles")
		}
	}
	return nil
}

func validateBFFStepTemplateReferences(ctx serviceValidationContext, bff *BFFConfig, sequential bool) error {
	stepNames := make(map[string]struct{}, len(bff.Steps))
	stepIndexByName := make(map[string]int, len(bff.Steps))
	for index, step := range bff.Steps {
		name := strings.TrimSpace(step.Name)
		if name == "" {
			continue
		}
		stepNames[name] = struct{}{}
		stepIndexByName[name] = index
	}

	if err := validateBFFTemplateFieldStepReferences(ctx.routeField("bff.responseStatus"), bff.ResponseStatus, stepNames, stepNames); err != nil {
		return err
	}
	for fieldName, template := range bff.ResponseFields {
		field := fmt.Sprintf("%s[%s]", ctx.routeField("bff.responseFields"), fieldName)
		if err := validateBFFTemplateFieldStepReferences(field, template, stepNames, stepNames); err != nil {
			return err
		}
	}
	for headerName, template := range bff.ResponseHeaders {
		field := fmt.Sprintf("%s[%s]", ctx.routeField("bff.responseHeaders"), headerName)
		if err := validateBFFTemplateFieldStepReferences(field, template, stepNames, stepNames); err != nil {
			return err
		}
	}

	for stepIndex, step := range bff.Steps {
		allowedStepRefs := make(map[string]struct{}, len(stepNames))
		if sequential {
			for name, index := range stepIndexByName {
				if index < stepIndex {
					allowedStepRefs[name] = struct{}{}
				}
			}
		} else {
			for name := range stepNames {
				allowedStepRefs[name] = struct{}{}
			}
		}
		field := func(name string) string {
			return fmt.Sprintf("%s.steps[%d].%s", ctx.routeField("bff"), stepIndex, name)
		}
		for _, candidate := range []struct {
			field string
			value string
		}{
			{field: field("url"), value: step.URL},
			{field: field("when"), value: step.When},
			{field: field("cacheKey"), value: step.CacheKey},
			{field: field("body"), value: step.Body},
		} {
			if err := validateBFFTemplateFieldStepReferences(candidate.field, candidate.value, stepNames, allowedStepRefs); err != nil {
				return err
			}
		}
		for key, template := range step.Headers {
			if err := validateBFFTemplateFieldStepReferences(fmt.Sprintf("%s[%s]", field("headers"), key), template, stepNames, allowedStepRefs); err != nil {
				return err
			}
		}
		for key, template := range step.QueryParams {
			if err := validateBFFTemplateFieldStepReferences(fmt.Sprintf("%s[%s]", field("queryParams"), key), template, stepNames, allowedStepRefs); err != nil {
				return err
			}
		}
		for key, template := range step.WhenHeaders {
			if err := validateBFFTemplateFieldStepReferences(fmt.Sprintf("%s[%s]", field("whenHeaders"), key), template, stepNames, allowedStepRefs); err != nil {
				return err
			}
		}
		for key, template := range step.WhenQueryParams {
			if err := validateBFFTemplateFieldStepReferences(fmt.Sprintf("%s[%s]", field("whenQueryParams"), key), template, stepNames, allowedStepRefs); err != nil {
				return err
			}
		}
		if step.Fallback != nil {
			if err := validateBFFTemplateFieldStepReferences(field("fallback.body"), step.Fallback.Body, stepNames, allowedStepRefs); err != nil {
				return err
			}
			for key, template := range step.Fallback.Headers {
				if err := validateBFFTemplateFieldStepReferences(fmt.Sprintf("%s[%s]", field("fallback.headers"), key), template, stepNames, allowedStepRefs); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func validateBFFTemplateFieldStepReferences(field string, value string, knownSteps map[string]struct{}, allowedSteps map[string]struct{}) error {
	for _, match := range bffTemplateStepReferenceRe.FindAllStringSubmatch(value, -1) {
		if len(match) < 2 {
			continue
		}
		stepName := strings.TrimSpace(match[1])
		if _, ok := knownSteps[stepName]; !ok {
			return validationError(field, "bff template references an unknown step")
		}
		if _, ok := allowedSteps[stepName]; !ok {
			return validationError(field, "bff step templates can only reference completed dependency steps")
		}
	}
	return nil
}

func bffStepDependencyNames(step BFFStepConfig) []string {
	seen := make(map[string]struct{}, len(step.DependsOn))
	dependencies := make([]string, 0, len(step.DependsOn))
	add := func(name string) {
		name = strings.TrimSpace(name)
		if name == "" {
			return
		}
		if _, ok := seen[name]; ok {
			return
		}
		seen[name] = struct{}{}
		dependencies = append(dependencies, name)
	}
	for _, dependency := range step.DependsOn {
		add(dependency)
	}
	for _, dependency := range bffStepImplicitTemplateDependencies(step) {
		add(dependency)
	}
	return dependencies
}

func bffStepImplicitTemplateDependencies(step BFFStepConfig) []string {
	seen := make(map[string]struct{})
	dependencies := make([]string, 0)
	for _, template := range bffStepLocalTemplateValues(step) {
		for _, dependency := range bffTemplateStepReferenceNames(template) {
			if dependency == "" {
				continue
			}
			if _, ok := seen[dependency]; ok {
				continue
			}
			seen[dependency] = struct{}{}
			dependencies = append(dependencies, dependency)
		}
	}
	return dependencies
}

func bffStepLocalTemplateValues(step BFFStepConfig) []string {
	values := []string{
		step.URL,
		step.When,
		step.CacheKey,
		step.Body,
	}
	for _, value := range step.Headers {
		values = append(values, value)
	}
	for _, value := range step.QueryParams {
		values = append(values, value)
	}
	for _, value := range step.WhenHeaders {
		values = append(values, value)
	}
	for _, value := range step.WhenQueryParams {
		values = append(values, value)
	}
	if step.Fallback != nil {
		values = append(values, step.Fallback.Body)
		for _, value := range step.Fallback.Headers {
			values = append(values, value)
		}
	}
	return values
}

func bffTemplateStepReferenceNames(value string) []string {
	matches := bffTemplateStepReferenceRe.FindAllStringSubmatch(value, -1)
	if len(matches) == 0 {
		return nil
	}
	references := make([]string, 0, len(matches))
	for _, match := range matches {
		if len(match) < 2 {
			continue
		}
		name := strings.TrimSpace(match[1])
		if name != "" {
			references = append(references, name)
		}
	}
	return references
}

func routeHasEnabledBFF(route RouterConfig) bool {
	return route.BFF != nil && route.BFF.IsEnabled()
}
