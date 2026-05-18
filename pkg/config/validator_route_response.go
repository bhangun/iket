package config

func validateRouteResponsePolicy(ctx serviceValidationContext) error {
	route := ctx.route
	if err := validateNonEmptyStringSlice(ctx.routeField("removeResponseHeaders"), route.RemoveResponseHeaders, "removeResponseHeaders must not contain empty values"); err != nil {
		return err
	}
	if err := validateNonEmptyStringSlice(ctx.routeField("responseRedactHeaders"), route.ResponseRedactHeaders, "responseRedactHeaders must not contain empty values"); err != nil {
		return err
	}
	if err := validateJSONTransformMap(ctx.routeField("successResponseFields"), route.SuccessResponseFields, true, "successResponseFields must not contain empty field names"); err != nil {
		return err
	}
	if err := validateJSONTransformMap(ctx.routeField("errorResponseFields"), route.ErrorResponseFields, true, "errorResponseFields must not contain empty field names"); err != nil {
		return err
	}
	if err := validateJSONTransformMap(ctx.routeField("responseJSONFields"), route.ResponseJSONFields, true, "responseJSONFields must not contain empty field names"); err != nil {
		return err
	}
	if err := validateJSONFieldSlice(ctx.routeField("removeResponseJSONFields"), route.RemoveResponseJSONFields, false, "removeResponseJSONFields must not contain empty values"); err != nil {
		return err
	}
	if err := validateJSONFieldSlice(ctx.routeField("responseRedactJSONFields"), route.ResponseRedactJSONFields, false, "responseRedactJSONFields must not contain empty values"); err != nil {
		return err
	}
	if err := validateRegexSlice(ctx.routeField("responseBodyBlockRegex"), route.ResponseBodyBlockRegex, "responseBodyBlockRegex must not contain empty values", "responseBodyBlockRegex must contain valid regex patterns"); err != nil {
		return err
	}
	if err := validateRegexSlice(ctx.routeField("responseBodyRequireRegex"), route.ResponseBodyRequireRegex, "responseBodyRequireRegex must not contain empty values", "responseBodyRequireRegex must contain valid regex patterns"); err != nil {
		return err
	}
	if err := validatePIITypeSlice(ctx.routeField("responsePIIBlockTypes"), route.ResponsePIIBlockTypes, "responsePIIBlockTypes must only contain email, phone, api_key, or card"); err != nil {
		return err
	}
	if route.MaxRequestBodyBytes < 0 {
		return validationError(ctx.routeField("maxRequestBodyBytes"), "maxRequestBodyBytes must be zero or greater")
	}
	if route.MaxResponseBodyBytes < 0 {
		return validationError(ctx.routeField("maxResponseBodyBytes"), "maxResponseBodyBytes must be zero or greater")
	}
	return nil
}
