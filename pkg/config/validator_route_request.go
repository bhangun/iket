package config

import "fmt"

func validateRouteCORS(ctx serviceValidationContext) error {
	cors := ctx.route.CORS
	if cors == nil {
		return nil
	}
	if len(cors.AllowedOrigins) == 0 {
		return validationError(ctx.routeField("cors.allowedOrigins"), "cors.allowedOrigins must contain at least one origin")
	}
	if err := validateNonEmptyStringSlice(ctx.routeField("cors.allowedOrigins"), cors.AllowedOrigins, "cors.allowedOrigins must not contain empty values"); err != nil {
		return err
	}
	for _, method := range cors.AllowedMethods {
		if !isValidHTTPMethod(method) {
			return validationError(ctx.routeField("cors.allowedMethods"), fmt.Sprintf("invalid CORS HTTP method: %s", method))
		}
	}
	if err := validateNonEmptyStringSlice(ctx.routeField("cors.allowedHeaders"), cors.AllowedHeaders, "cors.allowedHeaders must not contain empty values"); err != nil {
		return err
	}
	if err := validateNonEmptyStringSlice(ctx.routeField("cors.exposedHeaders"), cors.ExposedHeaders, "cors.exposedHeaders must not contain empty values"); err != nil {
		return err
	}
	if cors.MaxAge < 0 {
		return validationError(ctx.routeField("cors.maxAge"), "cors.maxAge must be zero or greater")
	}
	return nil
}

func validateRouteHeaderPolicy(ctx serviceValidationContext) error {
	route := ctx.route
	if err := validateMapKeysNonEmpty(ctx.routeField("requestHeaders"), route.RequestHeaders, "requestHeaders must not contain empty header names"); err != nil {
		return err
	}
	if err := validateMapKeysNonEmpty(ctx.routeField("responseHeaders"), route.ResponseHeaders, "responseHeaders must not contain empty header names"); err != nil {
		return err
	}
	if err := validateNonEmptyStringSlice(ctx.routeField("removeRequestHeaders"), route.RemoveRequestHeaders, "removeRequestHeaders must not contain empty values"); err != nil {
		return err
	}
	if err := validateNonEmptyStringSlice(ctx.routeField("requestRedactHeaders"), route.RequestRedactHeaders, "requestRedactHeaders must not contain empty values"); err != nil {
		return err
	}
	if err := validateNonEmptyStringSlice(ctx.routeField("requiredRequestHeaders"), route.RequiredRequestHeaders, "requiredRequestHeaders must not contain empty values"); err != nil {
		return err
	}
	return validateRegexMap(
		ctx.routeField("requiredRequestHeaderRegex"),
		route.RequiredRequestHeaderRegex,
		"requiredRequestHeaderRegex must not contain empty header names",
		"requiredRequestHeaderRegex must contain valid regex patterns",
	)
}

func validateRouteRequestJSONPolicy(ctx serviceValidationContext) error {
	route := ctx.route
	if err := validateJSONTransformMap(ctx.routeField("requestJSONFields"), route.RequestJSONFields, true, "requestJSONFields must not contain empty field names"); err != nil {
		return err
	}
	if err := validateJSONFieldSlice(ctx.routeField("removeRequestJSONFields"), route.RemoveRequestJSONFields, false, "removeRequestJSONFields must not contain empty values"); err != nil {
		return err
	}
	return validateJSONFieldSlice(ctx.routeField("requestRedactJSONFields"), route.RequestRedactJSONFields, false, "requestRedactJSONFields must not contain empty values")
}

func validateRouteRequestBodyPolicy(ctx serviceValidationContext) error {
	route := ctx.route
	if err := validateRegexSlice(ctx.routeField("requestBodyBlockRegex"), route.RequestBodyBlockRegex, "requestBodyBlockRegex must not contain empty values", "requestBodyBlockRegex must contain valid regex patterns"); err != nil {
		return err
	}
	if err := validateRegexSlice(ctx.routeField("requestBodyRequireRegex"), route.RequestBodyRequireRegex, "requestBodyRequireRegex must not contain empty values", "requestBodyRequireRegex must contain valid regex patterns"); err != nil {
		return err
	}
	return validatePIITypeSlice(ctx.routeField("requestPIIBlockTypes"), route.RequestPIIBlockTypes, "requestPIIBlockTypes must only contain email, phone, api_key, or card")
}
