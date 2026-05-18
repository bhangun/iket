package config

import "fmt"

func validateRouteResiliencePolicy(ctx serviceValidationContext) error {
	route := ctx.route
	if route.RetryCount < 0 {
		return validationError(ctx.routeField("retryCount"), "retryCount must be zero or greater")
	}
	if err := validateOptionalDuration(ctx.routeField("retryBackoff"), route.RetryBackoff, "retryBackoff must use a valid duration format"); err != nil {
		return err
	}
	if err := validateOptionalDuration(ctx.routeField("retryJitter"), route.RetryJitter, "retryJitter must use a valid duration format"); err != nil {
		return err
	}
	if err := validateOptionalDuration(ctx.routeField("hedgeDelay"), route.HedgeDelay, "hedgeDelay must use a valid duration format"); err != nil {
		return err
	}
	if route.ShadowTrafficPercent < 0 || route.ShadowTrafficPercent > 100 {
		return validationError(ctx.routeField("shadowTrafficPercent"), "shadowTrafficPercent must be between 0 and 100")
	}
	if route.ShadowMinRequests < 0 {
		return validationError(ctx.routeField("shadowMinRequests"), "shadowMinRequests must be zero or greater")
	}
	if route.ShadowMaxErrorRate < 0 || route.ShadowMaxErrorRate > 1 {
		return validationError(ctx.routeField("shadowMaxErrorRate"), "shadowMaxErrorRate must be between 0 and 1")
	}
	if err := validateOptionalDuration(ctx.routeField("shadowMaxLatencyDelta"), route.ShadowMaxLatencyDelta, "shadowMaxLatencyDelta must use a valid duration format"); err != nil {
		return err
	}
	for retryStatusIndex, statusCode := range route.RetryStatuses {
		if statusCode < 100 || statusCode > 599 {
			return validationError(fmt.Sprintf("%s[%d]", ctx.routeField("retryStatusCodes"), retryStatusIndex), "retryStatusCodes entries must be valid HTTP status codes")
		}
	}
	return nil
}
