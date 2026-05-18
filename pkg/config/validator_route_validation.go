package config

import (
	"fmt"
	"strings"
)

type routeValidator func(serviceValidationContext) error

var serviceRouteValidators = []routeValidator{
	validateRouteResiliencePolicy,
	validateRouteCORS,
	validateRouteHeaderPolicy,
	validateRouteRequestJSONPolicy,
	validateRouteRequestBodyPolicy,
	validateRouteAIPresets,
	validateRouteRateLimitPolicy,
	validateRouteConcurrencyLimitPolicy,
	validateRouteQueryAndProtocolPolicy,
	validateRouteGraphQLPolicy,
	validateRouteAIRequestPolicy,
	validateRouteTransformPolicy,
	validateRouteResponsePolicy,
	validateRouteBackendPolicy,
}

func validateRoute(ctx serviceValidationContext, seenRoutePaths map[string]bool) error {
	if err := validateRouteIdentity(ctx, seenRoutePaths); err != nil {
		return err
	}
	for _, validate := range serviceRouteValidators {
		if err := validate(ctx); err != nil {
			return err
		}
	}
	return nil
}

func validateRouteIdentity(ctx serviceValidationContext, seenRoutePaths map[string]bool) error {
	route := ctx.route
	if route.Path == "" {
		return validationError(ctx.routeField("path"), "path is required")
	}
	if !strings.HasPrefix(route.Path, "/") {
		return validationError(ctx.routeField("path"), "path must start with /")
	}

	fullPath := ctx.service.BasePath + route.Path
	if seenRoutePaths[fullPath] {
		return validationError(ctx.routeField("path"), "duplicate path found within service")
	}
	seenRoutePaths[fullPath] = true

	if route.Method == "" && len(route.Methods) == 0 {
		return validationError(ctx.routeField(""), "either method or methods is required")
	}
	if route.Method != "" && !isValidRouteMethod(route.Method) {
		return validationError(ctx.routeField("method"), fmt.Sprintf("invalid HTTP method: %s", route.Method))
	}
	if route.Priority < 0 {
		return validationError(ctx.routeField("priority"), "priority must be non-negative")
	}
	return nil
}

func isValidRouteMethod(method string) bool {
	switch strings.ToUpper(method) {
	case "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE":
		return true
	default:
		return false
	}
}
