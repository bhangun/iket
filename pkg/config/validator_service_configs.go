package config

import (
	"fmt"
	"strings"
)

func validateGlobalAIPolicyPresets(cfg *Config) error {
	return validateAIPolicyPresetMap("aiPolicyPresets", cfg.AIPolicyPresets)
}

func validateServiceConfig(cfg *Config, serviceConfigIndex int, serviceConfig ServiceConfig) error {
	if serviceConfig.Version <= 0 {
		return validationError(serviceConfigField(serviceConfigIndex, "version"), "version must be positive")
	}
	if len(serviceConfig.Services) == 0 {
		return validationError(serviceConfigField(serviceConfigIndex, "services"), "at least one service must be configured")
	}
	if err := validateOptionalDuration(serviceConfigField(serviceConfigIndex, "cache_ttl"), serviceConfig.CacheTTL, "invalid duration format"); err != nil {
		return err
	}
	if err := validateOptionalDuration(serviceConfigField(serviceConfigIndex, "timeout"), serviceConfig.Timeout, "invalid duration format"); err != nil {
		return err
	}

	seenServiceNames := make(map[string]bool)
	for serviceIndex, service := range serviceConfig.Services {
		if err := validateService(cfg, serviceConfigIndex, serviceIndex, service, seenServiceNames); err != nil {
			return err
		}
	}
	return nil
}

func validateService(cfg *Config, serviceConfigIndex, serviceIndex int, service Service, seenServiceNames map[string]bool) error {
	if service.Name == "" {
		return validationError(serviceField(serviceConfigIndex, serviceIndex, "name"), "service name is required")
	}
	if seenServiceNames[service.Name] {
		return validationError(serviceField(serviceConfigIndex, serviceIndex, "name"), "duplicate service name found")
	}
	seenServiceNames[service.Name] = true

	if service.Host == "" {
		return validationError(serviceField(serviceConfigIndex, serviceIndex, "host"), "host is required")
	}
	if err := validateServiceHost(service.Host); err != nil {
		return validationError(serviceField(serviceConfigIndex, serviceIndex, "host"), err.Error())
	}
	if service.BasePath != "" && !strings.HasPrefix(service.BasePath, "/") {
		return validationError(serviceField(serviceConfigIndex, serviceIndex, "base_path"), "base path must start with /")
	}
	if err := validateAIPolicyPresetMap(serviceField(serviceConfigIndex, serviceIndex, "aiPolicyPresets"), service.AIPolicyPresets); err != nil {
		return err
	}
	if len(service.Routes) == 0 {
		return validationError(serviceField(serviceConfigIndex, serviceIndex, "routes"), "at least one route must be configured")
	}

	seenRoutePaths := make(map[string]bool)
	for routeIndex, route := range service.Routes {
		ctx := serviceValidationContext{
			cfg:                cfg,
			serviceConfigIndex: serviceConfigIndex,
			serviceIndex:       serviceIndex,
			routeIndex:         routeIndex,
			service:            service,
			route:              route,
		}
		if err := validateRoute(ctx, seenRoutePaths); err != nil {
			return err
		}
	}
	return nil
}

func validateAIPolicyPresetMap(field string, presets map[string]AIPolicyPreset) error {
	for presetName, presetPolicy := range presets {
		trimmedName := strings.TrimSpace(presetName)
		if trimmedName == "" {
			return validationError(field, "aiPolicyPresets must not contain empty preset names")
		}
		if err := validateGraphQLOperationPolicyField(fmt.Sprintf("%s.%s", field, trimmedName), presetPolicy, false); err != nil {
			return err
		}
	}
	return nil
}
