package config

import "strings"

func validateRouteAIPresets(ctx serviceValidationContext) error {
	route := ctx.route
	if err := validateAIPolicyPresetMap(ctx.routeField("aiPolicyPresets"), route.AIPolicyPresets); err != nil {
		return err
	}
	if presetName := strings.TrimSpace(route.AIPolicyPreset); presetName != "" {
		if !ctx.hasAIPolicyPreset(presetName) {
			return validationError(ctx.routeField("aiPolicyPreset"), "aiPolicyPreset must reference a defined aiPolicyPresets entry")
		}
	}
	for _, presetName := range route.AIPolicyPresetChain {
		resolvedName := strings.TrimSpace(presetName)
		if resolvedName == "" {
			return validationError(ctx.routeField("aiPolicyPresetChain"), "aiPolicyPresetChain must not contain empty preset names")
		}
		if !ctx.hasAIPolicyPreset(resolvedName) {
			return validationError(ctx.routeField("aiPolicyPresetChain"), "aiPolicyPresetChain must reference defined aiPolicyPresets entries")
		}
	}
	return nil
}

func (ctx serviceValidationContext) hasAIPolicyPreset(name string) bool {
	if _, ok := ctx.route.AIPolicyPresets[name]; ok {
		return true
	}
	if _, ok := ctx.service.AIPolicyPresets[name]; ok {
		return true
	}
	_, ok := ctx.cfg.AIPolicyPresets[name]
	return ok
}

func validateRouteAIRequestPolicy(ctx serviceValidationContext) error {
	route := ctx.route
	checks := []func() error{
		func() error {
			return validateNonEmptyStringSlice(ctx.routeField("allowedModels"), route.AllowedModels, "allowedModels must not contain empty values")
		},
		func() error {
			return validateJSONFieldPathIfSet(ctx.routeField("modelField"), route.ModelField, "modelField must be a valid JSON field path")
		},
		func() error {
			return validateNonEmptyStringSlice(ctx.routeField("allowedToolNames"), route.AllowedToolNames, "allowedToolNames must not contain empty values")
		},
		func() error {
			return validateJSONFieldPathIfSet(ctx.routeField("toolField"), route.ToolField, "toolField must be a valid JSON field path")
		},
		func() error {
			return validateNonNegativeInt(ctx.routeField("maxMessages"), route.MaxMessages, "maxMessages must be zero or greater")
		},
		func() error {
			return validateJSONFieldPathIfSet(ctx.routeField("messagesField"), route.MessagesField, "messagesField must be a valid JSON field path")
		},
		func() error {
			return validateNonNegativeInt(ctx.routeField("maxToolCalls"), route.MaxToolCalls, "maxToolCalls must be zero or greater")
		},
		func() error {
			return validateJSONFieldPathIfSet(ctx.routeField("toolCallsField"), route.ToolCallsField, "toolCallsField must be a valid JSON field path")
		},
		func() error {
			return validateNonNegativeInt(ctx.routeField("maxInputTokens"), route.MaxInputTokens, "maxInputTokens must be zero or greater")
		},
		func() error {
			return validateJSONFieldPathIfSet(ctx.routeField("inputTokensField"), route.InputTokensField, "inputTokensField must be a valid JSON field path")
		},
		func() error {
			return validateNonNegativeInt(ctx.routeField("maxOutputTokens"), route.MaxOutputTokens, "maxOutputTokens must be zero or greater")
		},
		func() error {
			return validateJSONFieldPathIfSet(ctx.routeField("outputTokensField"), route.OutputTokensField, "outputTokensField must be a valid JSON field path")
		},
		func() error {
			return validateNonEmptyStringSlice(ctx.routeField("allowedUpstreamHosts"), route.AllowedUpstreamHosts, "allowedUpstreamHosts must not contain empty values")
		},
	}
	for _, check := range checks {
		if err := check(); err != nil {
			return err
		}
	}
	return nil
}

func validateJSONFieldPathIfSet(field, value, message string) error {
	if strings.TrimSpace(value) != "" && !isValidJSONFieldPath(value, false) {
		return validationError(field, message)
	}
	return nil
}

func validateNonNegativeInt(field string, value int, message string) error {
	if value < 0 {
		return validationError(field, message)
	}
	return nil
}
