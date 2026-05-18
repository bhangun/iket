package config

import "strings"

func validateRouteTransformPolicy(ctx serviceValidationContext) error {
	route := ctx.route
	if err := validateMapKeysNonEmpty(ctx.routeField("transformWhenHeaders"), route.TransformWhenHeaders, "transformWhenHeaders must not contain empty header names"); err != nil {
		return err
	}
	if err := validateMapKeysNonEmpty(ctx.routeField("transformWhenQueryParams"), route.TransformWhenQueryParams, "transformWhenQueryParams must not contain empty parameter names"); err != nil {
		return err
	}
	if err := validateRegexMap(ctx.routeField("transformWhenHeaderRegex"), route.TransformWhenHeaderRegex, "transformWhenHeaderRegex must not contain empty header names", "transformWhenHeaderRegex must contain valid regex patterns"); err != nil {
		return err
	}
	if err := validateRegexMap(ctx.routeField("transformWhenQueryRegex"), route.TransformWhenQueryRegex, "transformWhenQueryRegex must not contain empty parameter names", "transformWhenQueryRegex must contain valid regex patterns"); err != nil {
		return err
	}
	if err := validateTransformScopes(ctx); err != nil {
		return err
	}
	if err := validateResponseTransformStatusFilters(ctx); err != nil {
		return err
	}
	if err := validateMapKeysNonEmpty(ctx.routeField("responseTransformWhenHeaders"), route.ResponseTransformWhenHeaders, "responseTransformWhenHeaders must not contain empty header names"); err != nil {
		return err
	}
	if err := validateRegexMap(ctx.routeField("responseTransformHeaderRegex"), route.ResponseTransformHeaderRegex, "responseTransformHeaderRegex must not contain empty header names", "responseTransformHeaderRegex must contain valid regex patterns"); err != nil {
		return err
	}
	if err := validateHTTPMethodSlice(ctx.routeField("transformMethods"), route.TransformMethods, "transformMethods must only contain valid HTTP methods"); err != nil {
		return err
	}
	return validateNonEmptyStringSlice(ctx.routeField("removeQueryParams"), route.RemoveQueryParams, "removeQueryParams must not contain empty values")
}

func validateTransformScopes(ctx serviceValidationContext) error {
	for _, scope := range ctx.route.TransformScopes {
		scope = strings.TrimSpace(scope)
		if _, ok := allowedTransformScopes[scope]; !ok {
			return validationError(ctx.routeField("transformScopes"), "transformScopes must only contain request_headers, query, request_json, response_headers, or response_json")
		}
	}
	return nil
}

func validateResponseTransformStatusFilters(ctx serviceValidationContext) error {
	for _, statusCode := range ctx.route.ResponseTransformStatusCodes {
		if statusCode < 100 || statusCode > 599 {
			return validationError(ctx.routeField("responseTransformStatusCodes"), "responseTransformStatusCodes must only contain valid HTTP status codes")
		}
	}
	for _, statusClass := range ctx.route.ResponseTransformStatusClasses {
		statusClass = strings.ToLower(strings.TrimSpace(statusClass))
		if _, ok := allowedResponseTransformStatusClasses[statusClass]; !ok {
			return validationError(ctx.routeField("responseTransformStatusClasses"), "responseTransformStatusClasses must only contain 1xx, 2xx, 3xx, 4xx, or 5xx")
		}
	}
	return nil
}
