package config

import "strings"

func validateRouteBackendPolicy(ctx serviceValidationContext) error {
	route := ctx.route
	if len(route.Backends) == 0 && !isPluginOrInternalRoute(route.Path) && !routeHasEnabledBFF(route) {
		return validationError(ctx.routeField("backend"), "at least one backend must be configured unless this is a plugin, BFF, or internal route")
	}
	for backendIndex, backend := range route.Backends {
		if err := validateRouteBackend(ctx, backendIndex, backend); err != nil {
			return err
		}
	}
	return nil
}

func validateRouteBackend(ctx serviceValidationContext, backendIndex int, backend Backend) error {
	if backend.URLPattern == "" {
		return validationError(ctx.backendField(backendIndex, "url_pattern"), "url_pattern is required")
	}
	if strings.TrimSpace(backend.Host) != "" {
		if err := validateServiceHost(backend.Host); err != nil {
			return validationError(ctx.backendField(backendIndex, "host"), err.Error())
		}
	}
	if backend.Weight < 0 {
		return validationError(ctx.backendField(backendIndex, "weight"), "weight must be zero or greater")
	}
	if err := validateOptionalDuration(ctx.backendField(backendIndex, "timeout"), backend.Timeout, "timeout must use a valid duration format"); err != nil {
		return err
	}
	if backend.FailureThreshold < 0 {
		return validationError(ctx.backendField(backendIndex, "failureThreshold"), "failureThreshold must be zero or greater")
	}
	if backend.HalfOpenMaxRequests < 0 {
		return validationError(ctx.backendField(backendIndex, "halfOpenMaxRequests"), "halfOpenMaxRequests must be zero or greater")
	}
	if backend.RecoverySuccessThreshold < 0 {
		return validationError(ctx.backendField(backendIndex, "recoverySuccessThreshold"), "recoverySuccessThreshold must be zero or greater")
	}
	if backend.OutlierConsecutiveSlowResponses < 0 {
		return validationError(ctx.backendField(backendIndex, "outlierConsecutiveSlowResponses"), "outlierConsecutiveSlowResponses must be zero or greater")
	}
	if err := validateOptionalDuration(ctx.backendField(backendIndex, "cooldown"), backend.Cooldown, "cooldown must use a valid duration format"); err != nil {
		return err
	}
	if err := validateOptionalDuration(ctx.backendField(backendIndex, "outlierLatencyThreshold"), backend.OutlierLatencyThreshold, "outlierLatencyThreshold must use a valid duration format"); err != nil {
		return err
	}
	if err := validateOptionalDuration(ctx.backendField(backendIndex, "outlierCooldown"), backend.OutlierCooldown, "outlierCooldown must use a valid duration format"); err != nil {
		return err
	}
	if strings.TrimSpace(backend.HealthCheckPath) != "" && !strings.HasPrefix(strings.TrimSpace(backend.HealthCheckPath), "/") {
		return validationError(ctx.backendField(backendIndex, "healthCheckPath"), "healthCheckPath must start with /")
	}
	if err := validateOptionalDuration(ctx.backendField(backendIndex, "healthInterval"), backend.HealthInterval, "healthInterval must use a valid duration format"); err != nil {
		return err
	}
	if err := validateOptionalDuration(ctx.backendField(backendIndex, "healthTimeout"), backend.HealthTimeout, "healthTimeout must use a valid duration format"); err != nil {
		return err
	}
	if err := validateBackendPattern(ctx.route, backend); err != nil {
		return validationError(ctx.backendField(backendIndex, "url_pattern"), err.Error())
	}
	return nil
}
