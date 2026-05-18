package config

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/bhangun/iket/pkg/core/errors"
)

// ValidationRule defines a configuration validation rule
type ValidationRule interface {
	Validate(cfg *Config) error
}

// ConfigValidator validates configuration using a set of rules
type ConfigValidator struct {
	rules []ValidationRule
}

// NewConfigValidator creates a new validator with default rules
func NewConfigValidator() *ConfigValidator {
	return &ConfigValidator{
		rules: []ValidationRule{
			&ServerConfigRule{},
			&SecurityConfigRule{},
			&StorageConfigRule{},
			&ServicesConfigRule{},
			&PluginsConfigRule{},
		},
	}
}

// AddRule adds a custom validation rule
func (v *ConfigValidator) AddRule(rule ValidationRule) {
	v.rules = append(v.rules, rule)
}

// Validate validates the configuration using all rules
func (v *ConfigValidator) Validate(cfg *Config) error {
	for _, rule := range v.rules {
		if err := rule.Validate(cfg); err != nil {
			return fmt.Errorf("validation failed: %w", err)
		}
	}
	return nil
}

// ServerConfigRule validates server configuration
type ServerConfigRule struct{}

func (r *ServerConfigRule) Validate(cfg *Config) error {
	if cfg.Server.Port <= 0 || cfg.Server.Port > 65535 {
		return errors.NewValidationError("server.port", "port must be between 1 and 65535")
	}

	if cfg.Server.ReadTimeout != "" {
		if _, err := time.ParseDuration(cfg.Server.ReadTimeout); err != nil {
			return errors.NewValidationError("server.readTimeout", "invalid duration format")
		}
	}

	if cfg.Server.WriteTimeout != "" {
		if _, err := time.ParseDuration(cfg.Server.WriteTimeout); err != nil {
			return errors.NewValidationError("server.writeTimeout", "invalid duration format")
		}
	}

	if cfg.Server.IdleTimeout != "" {
		if _, err := time.ParseDuration(cfg.Server.IdleTimeout); err != nil {
			return errors.NewValidationError("server.idleTimeout", "invalid duration format")
		}
	}

	return nil
}

type StorageConfigRule struct{}

func (r *StorageConfigRule) Validate(cfg *Config) error {
	mode := cfg.Storage.EffectiveMode()
	switch mode {
	case "sqlite", "file", "postgres":
	default:
		return errors.NewValidationError("storage.mode", "storage mode must be sqlite, file, or postgres")
	}
	if mode == "postgres" && strings.TrimSpace(cfg.Storage.PostgresURL) == "" {
		return errors.NewValidationError("storage.postgres_url", "postgres_url is required when storage mode is postgres")
	}
	return nil
}

// SecurityConfigRule validates security configuration
type SecurityConfigRule struct{}

func (r *SecurityConfigRule) Validate(cfg *Config) error {
	if cfg.Security.TLS.Enabled {
		if cfg.Security.TLS.CertFile == "" {
			return errors.NewValidationError("security.tls.certFile", "certificate file is required when TLS is enabled")
		}
		if cfg.Security.TLS.KeyFile == "" {
			return errors.NewValidationError("security.tls.keyFile", "private key file is required when TLS is enabled")
		}
		if cfg.Security.TLS.Port < 0 || cfg.Security.TLS.Port > 65535 {
			return errors.NewValidationError("security.tls.port", "TLS port must be between 0 and 65535")
		}
		if cfg.Security.TLS.HTTP3Port < 0 || cfg.Security.TLS.HTTP3Port > 65535 {
			return errors.NewValidationError("security.tls.http3Port", "HTTP/3 port must be between 0 and 65535")
		}
		if cfg.Security.TLS.EnrollmentPort < 0 || cfg.Security.TLS.EnrollmentPort > 65535 {
			return errors.NewValidationError("security.tls.enrollmentPort", "enrollment TLS port must be between 0 and 65535")
		}
		if cfg.Security.TLS.EnrollmentMaxActive < 0 {
			return errors.NewValidationError("security.tls.enrollmentMaxActive", "enrollment max active must be zero or greater")
		}
	}
	if cfg.Security.TLS.HTTP3Enabled && !cfg.Security.TLS.Enabled {
		return errors.NewValidationError("security.tls.http3Enabled", "HTTP/3 requires TLS to be enabled")
	}

	if cfg.Security.EnableBasicAuth {
		if len(cfg.Security.BasicAuthUsers) == 0 {
			return errors.NewValidationError("security.basicAuthUsers", "at least one user is required when basic auth is enabled")
		}
	}

	// Validate clients map if present
	if cfg.Security.Clients != nil {
		if len(cfg.Security.Clients) == 0 {
			return errors.NewValidationError("security.clients", "at least one client must be configured if clients map is present")
		}
		for k, v := range cfg.Security.Clients {
			if k == "" || v == "" {
				return errors.NewValidationError("security.clients", "client ID and secret must not be empty")
			}
		}
	}

	if cfg.Security.MutationPolicy.RequireNoteForHighImpact && !cfg.Security.MutationPolicy.Enabled {
		return errors.NewValidationError("security.mutationPolicy.enabled", "mutation policy must be enabled before requiring notes for high-impact actions")
	}
	if cfg.Security.MutationPolicy.RequireChangeRefForHighImpact && !cfg.Security.MutationPolicy.Enabled {
		return errors.NewValidationError("security.mutationPolicy.enabled", "mutation policy must be enabled before requiring change references for high-impact actions")
	}
	if cfg.Security.MutationPolicy.RequireDifferentReviewerForProposals && !cfg.Security.MutationPolicy.Enabled {
		return errors.NewValidationError("security.mutationPolicy.enabled", "mutation policy must be enabled before requiring different proposal reviewers")
	}
	if cfg.Security.MutationPolicy.RequireNotBeforeForHighImpactProposals && !cfg.Security.MutationPolicy.Enabled {
		return errors.NewValidationError("security.mutationPolicy.enabled", "mutation policy must be enabled before requiring proposal schedule windows")
	}
	if cfg.Security.MutationPolicy.RequireVerificationForPromotedHighImpactProposals && !cfg.Security.MutationPolicy.Enabled {
		return errors.NewValidationError("security.mutationPolicy.enabled", "mutation policy must be enabled before requiring promoted proposal verification")
	}
	if cfg.Security.MutationPolicy.RequireShadowEvaluationForPromotedHighImpactProposals && !cfg.Security.MutationPolicy.Enabled {
		return errors.NewValidationError("security.mutationPolicy.enabled", "mutation policy must be enabled before requiring promoted proposal shadow evaluation")
	}
	if cfg.Security.MutationPolicy.MinShadowHealthyVerificationsForPromotedHighImpactProposals < 0 {
		return errors.NewValidationError("security.mutationPolicy.minShadowHealthyVerificationsForPromotedHighImpactProposals", "minimum shadow healthy verifications must be zero or greater")
	}
	if cfg.Security.MutationPolicy.MinShadowHealthyVerificationsForPromotedHighImpactProposals > 0 && !cfg.Security.MutationPolicy.Enabled {
		return errors.NewValidationError("security.mutationPolicy.enabled", "mutation policy must be enabled before requiring a shadow verification streak")
	}
	if strings.TrimSpace(cfg.Security.MutationPolicy.MaxProposalAge) != "" && !cfg.Security.MutationPolicy.Enabled {
		return errors.NewValidationError("security.mutationPolicy.enabled", "mutation policy must be enabled before limiting proposal age")
	}
	if strings.TrimSpace(cfg.Security.MutationPolicy.MaxApprovalAge) != "" && !cfg.Security.MutationPolicy.Enabled {
		return errors.NewValidationError("security.mutationPolicy.enabled", "mutation policy must be enabled before limiting approval age")
	}
	if len(cfg.Security.MutationPolicy.BlockedApplyWindows) > 0 && !cfg.Security.MutationPolicy.Enabled {
		return errors.NewValidationError("security.mutationPolicy.enabled", "mutation policy must be enabled before configuring blocked apply windows")
	}
	if cfg.Security.MutationPolicy.MinApproversForHighImpactProposals < 0 {
		return errors.NewValidationError("security.mutationPolicy.minApproversForHighImpactProposals", "minimum approvers must be zero or greater")
	}
	if cfg.Security.MutationPolicy.MinApproversForHighImpactProposals > 0 && !cfg.Security.MutationPolicy.Enabled {
		return errors.NewValidationError("security.mutationPolicy.enabled", "mutation policy must be enabled before requiring proposal approvers")
	}
	if strings.TrimSpace(cfg.Security.MutationPolicy.MaxProposalAge) != "" {
		if _, err := time.ParseDuration(strings.TrimSpace(cfg.Security.MutationPolicy.MaxProposalAge)); err != nil {
			return errors.NewValidationError("security.mutationPolicy.maxProposalAge", "max proposal age must use a valid duration format")
		}
	}
	if strings.TrimSpace(cfg.Security.MutationPolicy.MaxApprovalAge) != "" {
		if _, err := time.ParseDuration(strings.TrimSpace(cfg.Security.MutationPolicy.MaxApprovalAge)); err != nil {
			return errors.NewValidationError("security.mutationPolicy.maxApprovalAge", "max approval age must use a valid duration format")
		}
	}
	for _, scope := range cfg.Security.MutationPolicy.EnforcedScopes {
		switch strings.ToLower(strings.TrimSpace(scope)) {
		case "", "all", "config", "services", "routes", "plugins", "clients", "revisions", "high_impact":
		default:
			return errors.NewValidationError("security.mutationPolicy.enforcedScopes", "mutation policy scope must be one of all, config, services, routes, plugins, clients, revisions, or high_impact")
		}
	}
	for i, window := range cfg.Security.MutationPolicy.BlockedApplyWindows {
		if strings.TrimSpace(window.Start) == "" || strings.TrimSpace(window.End) == "" {
			return errors.NewValidationError(fmt.Sprintf("security.mutationPolicy.blockedApplyWindows[%d]", i), "blocked apply windows require both start and end times")
		}
		if _, err := time.Parse("15:04", strings.TrimSpace(window.Start)); err != nil {
			return errors.NewValidationError(fmt.Sprintf("security.mutationPolicy.blockedApplyWindows[%d].start", i), "start must use HH:MM 24-hour format")
		}
		if _, err := time.Parse("15:04", strings.TrimSpace(window.End)); err != nil {
			return errors.NewValidationError(fmt.Sprintf("security.mutationPolicy.blockedApplyWindows[%d].end", i), "end must use HH:MM 24-hour format")
		}
		if strings.TrimSpace(window.Start) == strings.TrimSpace(window.End) {
			return errors.NewValidationError(fmt.Sprintf("security.mutationPolicy.blockedApplyWindows[%d]", i), "blocked apply window start and end must differ")
		}
		if tz := strings.TrimSpace(window.Timezone); tz != "" {
			if _, err := time.LoadLocation(tz); err != nil {
				return errors.NewValidationError(fmt.Sprintf("security.mutationPolicy.blockedApplyWindows[%d].timezone", i), "timezone must be a valid IANA timezone")
			}
		}
		for _, day := range window.Days {
			if !isKnownPolicyWeekday(day) {
				return errors.NewValidationError(fmt.Sprintf("security.mutationPolicy.blockedApplyWindows[%d].days", i), "days must use weekday names such as mon, tue, wed, thu, fri, sat, or sun")
			}
		}
		for _, scope := range window.Scopes {
			switch strings.ToLower(strings.TrimSpace(scope)) {
			case "", "all", "config", "services", "routes", "plugins", "clients", "revisions", "high_impact":
			default:
				return errors.NewValidationError(fmt.Sprintf("security.mutationPolicy.blockedApplyWindows[%d].scopes", i), "blocked apply window scope must be one of all, config, services, routes, plugins, clients, revisions, or high_impact")
			}
		}
	}
	if err := validateProposalQueueUrgencyThresholds("security.mutationPolicy.proposalQueue.defaultUrgency", cfg.Security.MutationPolicy.ProposalQueue.DefaultUrgency); err != nil {
		return err
	}
	for environment, thresholds := range cfg.Security.MutationPolicy.ProposalQueue.EnvironmentUrgency {
		envName := strings.TrimSpace(environment)
		if envName == "" {
			return errors.NewValidationError("security.mutationPolicy.proposalQueue.environmentUrgency", "environment urgency overrides require a non-empty environment key")
		}
		if err := validateProposalQueueUrgencyThresholds(fmt.Sprintf("security.mutationPolicy.proposalQueue.environmentUrgency.%s", envName), thresholds); err != nil {
			return err
		}
	}
	if err := validateProposalQueueNotificationPolicy("security.mutationPolicy.proposalQueue.notifications", cfg.Security.MutationPolicy.ProposalQueue.Notifications); err != nil {
		return err
	}
	if err := validatePolicyAlertNotificationPolicy("security.mutationPolicy.policyAlertNotifications", cfg.Security.MutationPolicy.PolicyAlertNotifications); err != nil {
		return err
	}
	for i, webhook := range cfg.Security.NotificationWebhooks {
		if strings.TrimSpace(webhook.URL) == "" {
			return errors.NewValidationError(fmt.Sprintf("security.notificationWebhooks[%d].url", i), "notification webhook url is required")
		}
		parsed, err := url.Parse(strings.TrimSpace(webhook.URL))
		if err != nil || parsed.Scheme == "" || parsed.Host == "" {
			return errors.NewValidationError(fmt.Sprintf("security.notificationWebhooks[%d].url", i), "notification webhook url must be a valid absolute http or https URL")
		}
		scheme := strings.ToLower(strings.TrimSpace(parsed.Scheme))
		if scheme != "http" && scheme != "https" {
			return errors.NewValidationError(fmt.Sprintf("security.notificationWebhooks[%d].url", i), "notification webhook url must use http or https")
		}
		switch strings.ToLower(strings.TrimSpace(webhook.Format)) {
		case "", "generic", "slack", "teams":
		default:
			return errors.NewValidationError(fmt.Sprintf("security.notificationWebhooks[%d].format", i), "notification webhook format must be generic, slack, or teams")
		}
		if strings.TrimSpace(webhook.Timeout) != "" {
			if _, err := time.ParseDuration(strings.TrimSpace(webhook.Timeout)); err != nil {
				return errors.NewValidationError(fmt.Sprintf("security.notificationWebhooks[%d].timeout", i), "notification webhook timeout must use a valid duration format")
			}
		}
		if webhook.RetryCount < 0 {
			return errors.NewValidationError(fmt.Sprintf("security.notificationWebhooks[%d].retryCount", i), "notification webhook retryCount must be zero or greater")
		}
		if webhook.MinSLABreachCount < 0 {
			return errors.NewValidationError(fmt.Sprintf("security.notificationWebhooks[%d].minSLABreachCount", i), "notification webhook minSLABreachCount must be zero or greater")
		}
		if webhook.MinConsecutiveSLABreaches < 0 {
			return errors.NewValidationError(fmt.Sprintf("security.notificationWebhooks[%d].minConsecutiveSLABreaches", i), "notification webhook minConsecutiveSLABreaches must be zero or greater")
		}
		for _, environment := range webhook.Environments {
			if strings.TrimSpace(environment) == "" {
				return errors.NewValidationError(fmt.Sprintf("security.notificationWebhooks[%d].environments", i), "notification webhook environments must not contain empty values")
			}
		}
		if strings.TrimSpace(webhook.MinSLABreachDuration) != "" {
			if _, err := time.ParseDuration(strings.TrimSpace(webhook.MinSLABreachDuration)); err != nil {
				return errors.NewValidationError(fmt.Sprintf("security.notificationWebhooks[%d].minSLABreachDuration", i), "notification webhook minSLABreachDuration must use a valid duration format")
			}
		}
		switch strings.ToLower(strings.TrimSpace(webhook.MinSLABreachTier)) {
		case "", "warning", "elevated", "critical":
		default:
			return errors.NewValidationError(fmt.Sprintf("security.notificationWebhooks[%d].minSLABreachTier", i), "notification webhook minSLABreachTier must be warning, elevated, or critical")
		}
		if strings.TrimSpace(webhook.SLABreachCooldown) != "" {
			if _, err := time.ParseDuration(strings.TrimSpace(webhook.SLABreachCooldown)); err != nil {
				return errors.NewValidationError(fmt.Sprintf("security.notificationWebhooks[%d].slaBreachCooldown", i), "notification webhook slaBreachCooldown must use a valid duration format")
			}
		}
		if strings.TrimSpace(webhook.RetryBackoff) != "" {
			if _, err := time.ParseDuration(strings.TrimSpace(webhook.RetryBackoff)); err != nil {
				return errors.NewValidationError(fmt.Sprintf("security.notificationWebhooks[%d].retryBackoff", i), "notification webhook retryBackoff must use a valid duration format")
			}
		}
		if strings.TrimSpace(webhook.SignatureHeader) != "" && strings.TrimSpace(webhook.SigningSecret) == "" {
			return errors.NewValidationError(fmt.Sprintf("security.notificationWebhooks[%d].signingSecret", i), "signingSecret is required when signatureHeader is configured")
		}
		if strings.TrimSpace(webhook.TimestampHeader) != "" && strings.TrimSpace(webhook.SigningSecret) == "" {
			return errors.NewValidationError(fmt.Sprintf("security.notificationWebhooks[%d].signingSecret", i), "signingSecret is required when timestampHeader is configured")
		}
		for _, event := range webhook.Events {
			if strings.TrimSpace(event) == "" {
				return errors.NewValidationError(fmt.Sprintf("security.notificationWebhooks[%d].events", i), "notification webhook events must not be empty")
			}
		}
	}

	return nil
}

func validateProposalQueueUrgencyThresholds(field string, thresholds ProposalQueueUrgencyThresholds) error {
	readyAging, err := validateOptionalQueueThresholdDuration(field+".readyAgingAfter", thresholds.ReadyAgingAfter)
	if err != nil {
		return err
	}
	readyOverdue, err := validateOptionalQueueThresholdDuration(field+".readyOverdueAfter", thresholds.ReadyOverdueAfter)
	if err != nil {
		return err
	}
	blockedAging, err := validateOptionalQueueThresholdDuration(field+".blockedAgingAfter", thresholds.BlockedAgingAfter)
	if err != nil {
		return err
	}
	blockedOverdue, err := validateOptionalQueueThresholdDuration(field+".blockedOverdueAfter", thresholds.BlockedOverdueAfter)
	if err != nil {
		return err
	}
	if readyAging > 0 && readyOverdue > 0 && readyOverdue <= readyAging {
		return errors.NewValidationError(field, "readyOverdueAfter must be greater than readyAgingAfter")
	}
	if blockedAging > 0 && blockedOverdue > 0 && blockedOverdue <= blockedAging {
		return errors.NewValidationError(field, "blockedOverdueAfter must be greater than blockedAgingAfter")
	}
	return nil
}

func validateOptionalQueueThresholdDuration(field, value string) (time.Duration, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return 0, nil
	}
	parsed, err := time.ParseDuration(trimmed)
	if err != nil {
		return 0, errors.NewValidationError(field, "must use a valid duration format")
	}
	if parsed <= 0 {
		return 0, errors.NewValidationError(field, "must be greater than zero")
	}
	return parsed, nil
}

func validateProposalQueueNotificationPolicy(field string, policy ProposalQueueNotificationPolicy) error {
	if strings.TrimSpace(policy.Interval) != "" {
		if _, err := validateOptionalQueueThresholdDuration(field+".interval", policy.Interval); err != nil {
			return err
		}
	}
	if strings.TrimSpace(policy.MinNotificationInterval) != "" {
		if _, err := validateOptionalQueueThresholdDuration(field+".minNotificationInterval", policy.MinNotificationInterval); err != nil {
			return err
		}
	}
	for _, environment := range policy.Environments {
		if strings.TrimSpace(environment) == "" {
			return errors.NewValidationError(field+".environments", "queue notification environments must not contain empty values")
		}
	}
	return nil
}

func validatePolicyAlertNotificationPolicy(field string, policy PolicyAlertNotificationPolicy) error {
	if strings.TrimSpace(policy.Interval) != "" {
		if _, err := time.ParseDuration(strings.TrimSpace(policy.Interval)); err != nil {
			return errors.NewValidationError(field+".interval", "policy alert notification interval must use a valid duration format")
		}
	}
	if strings.TrimSpace(policy.MinNotificationInterval) != "" {
		if _, err := time.ParseDuration(strings.TrimSpace(policy.MinNotificationInterval)); err != nil {
			return errors.NewValidationError(field+".minNotificationInterval", "policy alert notification minNotificationInterval must use a valid duration format")
		}
	}
	if strings.TrimSpace(policy.Window) != "" {
		if _, err := time.ParseDuration(strings.TrimSpace(policy.Window)); err != nil {
			return errors.NewValidationError(field+".window", "policy alert notification window must use a valid duration format")
		}
	}
	if policy.MinCount < 0 {
		return errors.NewValidationError(field+".minCount", "policy alert notification minCount must be zero or greater")
	}
	switch strings.ToLower(strings.TrimSpace(policy.MinSeverity)) {
	case "", "warning", "elevated", "critical":
	default:
		return errors.NewValidationError(field+".minSeverity", "policy alert notification minSeverity must be warning, elevated, or critical")
	}
	return nil
}

func isKnownPolicyWeekday(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "sun", "sunday", "mon", "monday", "tue", "tues", "tuesday", "wed", "wednesday", "thu", "thur", "thurs", "thursday", "fri", "friday", "sat", "saturday":
		return true
	default:
		return false
	}
}

func isValidHTTPMethod(method string) bool {
	switch strings.ToUpper(strings.TrimSpace(method)) {
	case "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE":
		return true
	default:
		return false
	}
}

// ServicesConfigRule validates service-based configuration
type ServicesConfigRule struct{}

var routeTemplateVarPattern = regexp.MustCompile(`\{([A-Za-z0-9_]+)(:[^}]*)?\}`)
var allowedTransformScopes = map[string]struct{}{
	"request_headers":  {},
	"query":            {},
	"request_json":     {},
	"response_headers": {},
	"response_json":    {},
}
var allowedResponseTransformStatusClasses = map[string]struct{}{
	"1xx": {},
	"2xx": {},
	"3xx": {},
	"4xx": {},
	"5xx": {},
}

func (r *ServicesConfigRule) Validate(cfg *Config) error {
	if len(cfg.Services) == 0 {
		// Services are optional, so no error if not present
		return nil
	}

	for i, serviceConfig := range cfg.Services {
		// Validate service config version
		if serviceConfig.Version <= 0 {
			return errors.NewValidationError(fmt.Sprintf("services[%d].version", i), "version must be positive")
		}

		// Validate services array
		if len(serviceConfig.Services) == 0 {
			return errors.NewValidationError(fmt.Sprintf("services[%d].services", i), "at least one service must be configured")
		}

		// Validate cache TTL if specified
		if serviceConfig.CacheTTL != "" {
			if _, err := time.ParseDuration(serviceConfig.CacheTTL); err != nil {
				return errors.NewValidationError(fmt.Sprintf("services[%d].cache_ttl", i), "invalid duration format")
			}
		}

		// Validate timeout if specified
		if serviceConfig.Timeout != "" {
			if _, err := time.ParseDuration(serviceConfig.Timeout); err != nil {
				return errors.NewValidationError(fmt.Sprintf("services[%d].timeout", i), "invalid duration format")
			}
		}

		// Validate each service
		seenServiceNames := make(map[string]bool)
		for j, service := range serviceConfig.Services {
			// Validate service name
			if service.Name == "" {
				return errors.NewValidationError(fmt.Sprintf("services[%d].services[%d].name", i, j), "service name is required")
			}

			// Check for duplicate service names
			if seenServiceNames[service.Name] {
				return errors.NewValidationError(fmt.Sprintf("services[%d].services[%d].name", i, j), "duplicate service name found")
			}
			seenServiceNames[service.Name] = true

			// Validate host
			if service.Host == "" {
				return errors.NewValidationError(fmt.Sprintf("services[%d].services[%d].host", i, j), "host is required")
			}

			// Validate host URL
			if err := validateServiceHost(service.Host); err != nil {
				return errors.NewValidationError(fmt.Sprintf("services[%d].services[%d].host", i, j), err.Error())
			}

			// Validate base path if specified
			if service.BasePath != "" && !strings.HasPrefix(service.BasePath, "/") {
				return errors.NewValidationError(fmt.Sprintf("services[%d].services[%d].base_path", i, j), "base path must start with /")
			}

			// Validate routes
			if len(service.Routes) == 0 {
				return errors.NewValidationError(fmt.Sprintf("services[%d].services[%d].routes", i, j), "at least one route must be configured")
			}

			// Validate each route in the service
			seenRoutePaths := make(map[string]bool)
			for k, route := range service.Routes {
				// Validate path
				if route.Path == "" {
					return errors.NewValidationError(fmt.Sprintf("services[%d].services[%d].routes[%d].path", i, j, k), "path is required")
				}

				if !strings.HasPrefix(route.Path, "/") {
					return errors.NewValidationError(fmt.Sprintf("services[%d].services[%d].routes[%d].path", i, j, k), "path must start with /")
				}

				// Check for duplicate paths within the service
				fullPath := service.BasePath + route.Path
				if seenRoutePaths[fullPath] {
					return errors.NewValidationError(fmt.Sprintf("services[%d].services[%d].routes[%d].path", i, j, k), "duplicate path found within service")
				}
				seenRoutePaths[fullPath] = true

				// Validate method (new format) or methods (old format)
				if route.Method == "" && len(route.Methods) == 0 {
					return errors.NewValidationError(fmt.Sprintf("services[%d].services[%d].routes[%d]", i, j, k), "either method or methods is required")
				}

				// Validate method if specified
				if route.Method != "" {
					validMethods := map[string]bool{
						"GET": true, "POST": true, "PUT": true, "DELETE": true,
						"PATCH": true, "HEAD": true, "OPTIONS": true, "TRACE": true,
					}
					if !validMethods[strings.ToUpper(route.Method)] {
						return errors.NewValidationError(fmt.Sprintf("services[%d].services[%d].routes[%d].method", i, j, k), fmt.Sprintf("invalid HTTP method: %s", route.Method))
					}
				}

				// Validate priority if specified
				if route.Priority < 0 {
					return errors.NewValidationError(fmt.Sprintf("services[%d].services[%d].routes[%d].priority", i, j, k), "priority must be non-negative")
				}
				if route.RetryCount < 0 {
					return errors.NewValidationError(fmt.Sprintf("services[%d].services[%d].routes[%d].retryCount", i, j, k), "retryCount must be zero or greater")
				}
				if strings.TrimSpace(route.RetryBackoff) != "" {
					if _, err := time.ParseDuration(strings.TrimSpace(route.RetryBackoff)); err != nil {
						return errors.NewValidationError(fmt.Sprintf("services[%d].services[%d].routes[%d].retryBackoff", i, j, k), "retryBackoff must use a valid duration format")
					}
				}
				if strings.TrimSpace(route.RetryJitter) != "" {
					if _, err := time.ParseDuration(strings.TrimSpace(route.RetryJitter)); err != nil {
						return errors.NewValidationError(fmt.Sprintf("services[%d].services[%d].routes[%d].retryJitter", i, j, k), "retryJitter must use a valid duration format")
					}
				}
				if strings.TrimSpace(route.HedgeDelay) != "" {
					if _, err := time.ParseDuration(strings.TrimSpace(route.HedgeDelay)); err != nil {
						return errors.NewValidationError(fmt.Sprintf("services[%d].services[%d].routes[%d].hedgeDelay", i, j, k), "hedgeDelay must use a valid duration format")
					}
				}
				if route.ShadowTrafficPercent < 0 || route.ShadowTrafficPercent > 100 {
					return errors.NewValidationError(fmt.Sprintf("services[%d].services[%d].routes[%d].shadowTrafficPercent", i, j, k), "shadowTrafficPercent must be between 0 and 100")
				}
				if route.ShadowMinRequests < 0 {
					return errors.NewValidationError(fmt.Sprintf("services[%d].services[%d].routes[%d].shadowMinRequests", i, j, k), "shadowMinRequests must be zero or greater")
				}
				if route.CORS != nil {
					if len(route.CORS.AllowedOrigins) == 0 {
						return errors.NewValidationError(fmt.Sprintf("services[%d].services[%d].routes[%d].cors.allowedOrigins", i, j, k), "cors.allowedOrigins must contain at least one origin")
					}
					for _, origin := range route.CORS.AllowedOrigins {
						if strings.TrimSpace(origin) == "" {
							return errors.NewValidationError(fmt.Sprintf("services[%d].services[%d].routes[%d].cors.allowedOrigins", i, j, k), "cors.allowedOrigins must not contain empty values")
						}
					}
					for _, method := range route.CORS.AllowedMethods {
						if !isValidHTTPMethod(method) {
							return errors.NewValidationError(fmt.Sprintf("services[%d].services[%d].routes[%d].cors.allowedMethods", i, j, k), fmt.Sprintf("invalid CORS HTTP method: %s", method))
						}
					}
					for _, header := range route.CORS.AllowedHeaders {
						if strings.TrimSpace(header) == "" {
							return errors.NewValidationError(fmt.Sprintf("services[%d].services[%d].routes[%d].cors.allowedHeaders", i, j, k), "cors.allowedHeaders must not contain empty values")
						}
					}
					for _, header := range route.CORS.ExposedHeaders {
						if strings.TrimSpace(header) == "" {
							return errors.NewValidationError(fmt.Sprintf("services[%d].services[%d].routes[%d].cors.exposedHeaders", i, j, k), "cors.exposedHeaders must not contain empty values")
						}
					}
					if route.CORS.MaxAge < 0 {
						return errors.NewValidationError(fmt.Sprintf("services[%d].services[%d].routes[%d].cors.maxAge", i, j, k), "cors.maxAge must be zero or greater")
					}
				}
				for key := range route.RequestHeaders {
					if strings.TrimSpace(key) == "" {
						return errors.NewValidationError(fmt.Sprintf("services[%d].services[%d].routes[%d].requestHeaders", i, j, k), "requestHeaders must not contain empty header names")
					}
				}
				for key := range route.ResponseHeaders {
					if strings.TrimSpace(key) == "" {
						return errors.NewValidationError(fmt.Sprintf("services[%d].services[%d].routes[%d].responseHeaders", i, j, k), "responseHeaders must not contain empty header names")
					}
				}
				for _, header := range route.RemoveRequestHeaders {
					if strings.TrimSpace(header) == "" {
						return errors.NewValidationError(fmt.Sprintf("services[%d].services[%d].routes[%d].removeRequestHeaders", i, j, k), "removeRequestHeaders must not contain empty values")
					}
				}
				for _, header := range route.RequestRedactHeaders {
					if strings.TrimSpace(header) == "" {
						return errors.NewValidationError(fmt.Sprintf("services[%d].services[%d].routes[%d].requestRedactHeaders", i, j, k), "requestRedactHeaders must not contain empty values")
					}
				}
				for _, header := range route.RequiredRequestHeaders {
					if strings.TrimSpace(header) == "" {
						return errors.NewValidationError(fmt.Sprintf("services[%d].services[%d].routes[%d].requiredRequestHeaders", i, j, k), "requiredRequestHeaders must not contain empty values")
					}
				}
				for key, pattern := range route.RequiredRequestHeaderRegex {
					if strings.TrimSpace(key) == "" {
						return errors.NewValidationError(fmt.Sprintf("services[%d].services[%d].routes[%d].requiredRequestHeaderRegex", i, j, k), "requiredRequestHeaderRegex must not contain empty header names")
					}
					if _, err := regexp.Compile(pattern); err != nil {
						return errors.NewValidationError(fmt.Sprintf("services[%d].services[%d].routes[%d].requiredRequestHeaderRegex", i, j, k), "requiredRequestHeaderRegex must contain valid regex patterns")
					}
				}
				for key := range route.RequestJSONFields {
					if !isValidJSONFieldPath(key, true) {
						return errors.NewValidationError(fmt.Sprintf("services[%d].services[%d].routes[%d].requestJSONFields", i, j, k), "requestJSONFields must not contain empty field names")
					}
				}
				for _, value := range route.RequestJSONFields {
					if err := validateJSONTransformLiteral(value); err != nil {
						return errors.NewValidationError(fmt.Sprintf("services[%d].services[%d].routes[%d].requestJSONFields", i, j, k), err.Error())
					}
				}
				for _, field := range route.RemoveRequestJSONFields {
					if !isValidJSONFieldPath(field, false) {
						return errors.NewValidationError(fmt.Sprintf("services[%d].services[%d].routes[%d].removeRequestJSONFields", i, j, k), "removeRequestJSONFields must not contain empty values")
					}
				}
				for _, field := range route.RequestRedactJSONFields {
					if !isValidJSONFieldPath(field, false) {
						return errors.NewValidationError(fmt.Sprintf("services[%d].services[%d].routes[%d].requestRedactJSONFields", i, j, k), "requestRedactJSONFields must not contain empty values")
					}
				}
				for _, pattern := range route.RequestBodyBlockRegex {
					if strings.TrimSpace(pattern) == "" {
						return errors.NewValidationError(fmt.Sprintf("services[%d].services[%d].routes[%d].requestBodyBlockRegex", i, j, k), "requestBodyBlockRegex must not contain empty values")
					}
					if _, err := regexp.Compile(pattern); err != nil {
						return errors.NewValidationError(fmt.Sprintf("services[%d].services[%d].routes[%d].requestBodyBlockRegex", i, j, k), "requestBodyBlockRegex must contain valid regex patterns")
					}
				}
				for _, pattern := range route.RequestBodyRequireRegex {
					if strings.TrimSpace(pattern) == "" {
						return errors.NewValidationError(fmt.Sprintf("services[%d].services[%d].routes[%d].requestBodyRequireRegex", i, j, k), "requestBodyRequireRegex must not contain empty values")
					}
					if _, err := regexp.Compile(pattern); err != nil {
						return errors.NewValidationError(fmt.Sprintf("services[%d].services[%d].routes[%d].requestBodyRequireRegex", i, j, k), "requestBodyRequireRegex must contain valid regex patterns")
					}
				}
				for _, piiType := range route.RequestPIIBlockTypes {
					if !isAllowedPIIType(piiType) {
						return errors.NewValidationError(fmt.Sprintf("services[%d].services[%d].routes[%d].requestPIIBlockTypes", i, j, k), "requestPIIBlockTypes must only contain email, phone, api_key, or card")
					}
				}
				for key := range route.QueryParams {
					if strings.TrimSpace(key) == "" {
						return errors.NewValidationError(fmt.Sprintf("services[%d].services[%d].routes[%d].queryParams", i, j, k), "queryParams must not contain empty parameter names")
					}
				}
				if strings.TrimSpace(route.Protocol) != "" {
					switch strings.ToLower(strings.TrimSpace(route.Protocol)) {
					case "http", "graphql", "grpc", "grpc-web", "websocket", "sse":
					default:
						return errors.NewValidationError(fmt.Sprintf("services[%d].services[%d].routes[%d].protocol", i, j, k), "protocol must be one of http, graphql, grpc, grpc-web, websocket, or sse")
					}
				}
				if strings.EqualFold(strings.TrimSpace(route.Protocol), "sse") {
					if len(route.ResponseJSONFields) > 0 || len(route.RemoveResponseJSONFields) > 0 {
						return errors.NewValidationError(fmt.Sprintf("services[%d].services[%d].routes[%d].responseJSONFields", i, j, k), "sse routes do not support response JSON body transforms")
					}
					if len(route.SuccessResponseFields) > 0 || len(route.ErrorResponseFields) > 0 {
						return errors.NewValidationError(fmt.Sprintf("services[%d].services[%d].routes[%d].successResponseFields", i, j, k), "sse routes do not support response body envelopes")
					}
					if len(route.ResponseBodyBlockRegex) > 0 || len(route.ResponseBodyRequireRegex) > 0 || len(route.ResponsePIIBlockTypes) > 0 {
						return errors.NewValidationError(fmt.Sprintf("services[%d].services[%d].routes[%d].responseBodyBlockRegex", i, j, k), "sse routes do not support buffered response body inspection policies")
					}
					if route.MaxResponseBodyBytes > 0 {
						return errors.NewValidationError(fmt.Sprintf("services[%d].services[%d].routes[%d].maxResponseBodyBytes", i, j, k), "sse routes do not support maxResponseBodyBytes because responses are streamed")
					}
				}
				if strings.EqualFold(strings.TrimSpace(route.Protocol), "graphql") {
					if strings.TrimSpace(route.GraphQLPersistedQueryField) != "" && !isValidJSONFieldPath(route.GraphQLPersistedQueryField, false) {
						return errors.NewValidationError(fmt.Sprintf("services[%d].services[%d].routes[%d].graphqlPersistedQueryField", i, j, k), "graphqlPersistedQueryField must be a valid JSON field path")
					}
					for _, op := range route.GraphQLAllowedOperations {
						if strings.TrimSpace(op) == "" {
							return errors.NewValidationError(fmt.Sprintf("services[%d].services[%d].routes[%d].graphqlAllowedOperations", i, j, k), "graphqlAllowedOperations must not contain empty values")
						}
					}
				}
				for _, model := range route.AllowedModels {
					if strings.TrimSpace(model) == "" {
						return errors.NewValidationError(fmt.Sprintf("services[%d].services[%d].routes[%d].allowedModels", i, j, k), "allowedModels must not contain empty values")
					}
				}
				if strings.TrimSpace(route.ModelField) != "" && !isValidJSONFieldPath(route.ModelField, false) {
					return errors.NewValidationError(fmt.Sprintf("services[%d].services[%d].routes[%d].modelField", i, j, k), "modelField must be a valid JSON field path")
				}
				for _, tool := range route.AllowedToolNames {
					if strings.TrimSpace(tool) == "" {
						return errors.NewValidationError(fmt.Sprintf("services[%d].services[%d].routes[%d].allowedToolNames", i, j, k), "allowedToolNames must not contain empty values")
					}
				}
				if strings.TrimSpace(route.ToolField) != "" && !isValidJSONFieldPath(route.ToolField, false) {
					return errors.NewValidationError(fmt.Sprintf("services[%d].services[%d].routes[%d].toolField", i, j, k), "toolField must be a valid JSON field path")
				}
				if route.MaxMessages < 0 {
					return errors.NewValidationError(fmt.Sprintf("services[%d].services[%d].routes[%d].maxMessages", i, j, k), "maxMessages must be zero or greater")
				}
				if strings.TrimSpace(route.MessagesField) != "" && !isValidJSONFieldPath(route.MessagesField, false) {
					return errors.NewValidationError(fmt.Sprintf("services[%d].services[%d].routes[%d].messagesField", i, j, k), "messagesField must be a valid JSON field path")
				}
				if route.MaxToolCalls < 0 {
					return errors.NewValidationError(fmt.Sprintf("services[%d].services[%d].routes[%d].maxToolCalls", i, j, k), "maxToolCalls must be zero or greater")
				}
				if strings.TrimSpace(route.ToolCallsField) != "" && !isValidJSONFieldPath(route.ToolCallsField, false) {
					return errors.NewValidationError(fmt.Sprintf("services[%d].services[%d].routes[%d].toolCallsField", i, j, k), "toolCallsField must be a valid JSON field path")
				}
				if route.MaxInputTokens < 0 {
					return errors.NewValidationError(fmt.Sprintf("services[%d].services[%d].routes[%d].maxInputTokens", i, j, k), "maxInputTokens must be zero or greater")
				}
				if strings.TrimSpace(route.InputTokensField) != "" && !isValidJSONFieldPath(route.InputTokensField, false) {
					return errors.NewValidationError(fmt.Sprintf("services[%d].services[%d].routes[%d].inputTokensField", i, j, k), "inputTokensField must be a valid JSON field path")
				}
				if route.MaxOutputTokens < 0 {
					return errors.NewValidationError(fmt.Sprintf("services[%d].services[%d].routes[%d].maxOutputTokens", i, j, k), "maxOutputTokens must be zero or greater")
				}
				if strings.TrimSpace(route.OutputTokensField) != "" && !isValidJSONFieldPath(route.OutputTokensField, false) {
					return errors.NewValidationError(fmt.Sprintf("services[%d].services[%d].routes[%d].outputTokensField", i, j, k), "outputTokensField must be a valid JSON field path")
				}
				for _, host := range route.AllowedUpstreamHosts {
					if strings.TrimSpace(host) == "" {
						return errors.NewValidationError(fmt.Sprintf("services[%d].services[%d].routes[%d].allowedUpstreamHosts", i, j, k), "allowedUpstreamHosts must not contain empty values")
					}
				}
				for key := range route.TransformWhenHeaders {
					if strings.TrimSpace(key) == "" {
						return errors.NewValidationError(fmt.Sprintf("services[%d].services[%d].routes[%d].transformWhenHeaders", i, j, k), "transformWhenHeaders must not contain empty header names")
					}
				}
				for key := range route.TransformWhenQueryParams {
					if strings.TrimSpace(key) == "" {
						return errors.NewValidationError(fmt.Sprintf("services[%d].services[%d].routes[%d].transformWhenQueryParams", i, j, k), "transformWhenQueryParams must not contain empty parameter names")
					}
				}
				for key, pattern := range route.TransformWhenHeaderRegex {
					if strings.TrimSpace(key) == "" {
						return errors.NewValidationError(fmt.Sprintf("services[%d].services[%d].routes[%d].transformWhenHeaderRegex", i, j, k), "transformWhenHeaderRegex must not contain empty header names")
					}
					if _, err := regexp.Compile(pattern); err != nil {
						return errors.NewValidationError(fmt.Sprintf("services[%d].services[%d].routes[%d].transformWhenHeaderRegex", i, j, k), "transformWhenHeaderRegex must contain valid regex patterns")
					}
				}
				for key, pattern := range route.TransformWhenQueryRegex {
					if strings.TrimSpace(key) == "" {
						return errors.NewValidationError(fmt.Sprintf("services[%d].services[%d].routes[%d].transformWhenQueryRegex", i, j, k), "transformWhenQueryRegex must not contain empty parameter names")
					}
					if _, err := regexp.Compile(pattern); err != nil {
						return errors.NewValidationError(fmt.Sprintf("services[%d].services[%d].routes[%d].transformWhenQueryRegex", i, j, k), "transformWhenQueryRegex must contain valid regex patterns")
					}
				}
				for _, scope := range route.TransformScopes {
					scope = strings.TrimSpace(scope)
					if _, ok := allowedTransformScopes[scope]; !ok {
						return errors.NewValidationError(fmt.Sprintf("services[%d].services[%d].routes[%d].transformScopes", i, j, k), "transformScopes must only contain request_headers, query, request_json, response_headers, or response_json")
					}
				}
				for _, statusCode := range route.ResponseTransformStatusCodes {
					if statusCode < 100 || statusCode > 599 {
						return errors.NewValidationError(fmt.Sprintf("services[%d].services[%d].routes[%d].responseTransformStatusCodes", i, j, k), "responseTransformStatusCodes must only contain valid HTTP status codes")
					}
				}
				for _, statusClass := range route.ResponseTransformStatusClasses {
					statusClass = strings.ToLower(strings.TrimSpace(statusClass))
					if _, ok := allowedResponseTransformStatusClasses[statusClass]; !ok {
						return errors.NewValidationError(fmt.Sprintf("services[%d].services[%d].routes[%d].responseTransformStatusClasses", i, j, k), "responseTransformStatusClasses must only contain 1xx, 2xx, 3xx, 4xx, or 5xx")
					}
				}
				for key := range route.ResponseTransformWhenHeaders {
					if strings.TrimSpace(key) == "" {
						return errors.NewValidationError(fmt.Sprintf("services[%d].services[%d].routes[%d].responseTransformWhenHeaders", i, j, k), "responseTransformWhenHeaders must not contain empty header names")
					}
				}
				for key, pattern := range route.ResponseTransformHeaderRegex {
					if strings.TrimSpace(key) == "" {
						return errors.NewValidationError(fmt.Sprintf("services[%d].services[%d].routes[%d].responseTransformHeaderRegex", i, j, k), "responseTransformHeaderRegex must not contain empty header names")
					}
					if _, err := regexp.Compile(pattern); err != nil {
						return errors.NewValidationError(fmt.Sprintf("services[%d].services[%d].routes[%d].responseTransformHeaderRegex", i, j, k), "responseTransformHeaderRegex must contain valid regex patterns")
					}
				}
				for _, method := range route.TransformMethods {
					if !isValidHTTPMethod(method) {
						return errors.NewValidationError(fmt.Sprintf("services[%d].services[%d].routes[%d].transformMethods", i, j, k), "transformMethods must only contain valid HTTP methods")
					}
				}
				for _, key := range route.RemoveQueryParams {
					if strings.TrimSpace(key) == "" {
						return errors.NewValidationError(fmt.Sprintf("services[%d].services[%d].routes[%d].removeQueryParams", i, j, k), "removeQueryParams must not contain empty values")
					}
				}
				for _, header := range route.RemoveResponseHeaders {
					if strings.TrimSpace(header) == "" {
						return errors.NewValidationError(fmt.Sprintf("services[%d].services[%d].routes[%d].removeResponseHeaders", i, j, k), "removeResponseHeaders must not contain empty values")
					}
				}
				for _, header := range route.ResponseRedactHeaders {
					if strings.TrimSpace(header) == "" {
						return errors.NewValidationError(fmt.Sprintf("services[%d].services[%d].routes[%d].responseRedactHeaders", i, j, k), "responseRedactHeaders must not contain empty values")
					}
				}
				for key := range route.SuccessResponseFields {
					if !isValidJSONFieldPath(key, true) {
						return errors.NewValidationError(fmt.Sprintf("services[%d].services[%d].routes[%d].successResponseFields", i, j, k), "successResponseFields must not contain empty field names")
					}
				}
				for _, value := range route.SuccessResponseFields {
					if err := validateJSONTransformLiteral(value); err != nil {
						return errors.NewValidationError(fmt.Sprintf("services[%d].services[%d].routes[%d].successResponseFields", i, j, k), err.Error())
					}
				}
				for key := range route.ErrorResponseFields {
					if !isValidJSONFieldPath(key, true) {
						return errors.NewValidationError(fmt.Sprintf("services[%d].services[%d].routes[%d].errorResponseFields", i, j, k), "errorResponseFields must not contain empty field names")
					}
				}
				for _, value := range route.ErrorResponseFields {
					if err := validateJSONTransformLiteral(value); err != nil {
						return errors.NewValidationError(fmt.Sprintf("services[%d].services[%d].routes[%d].errorResponseFields", i, j, k), err.Error())
					}
				}
				for key := range route.ResponseJSONFields {
					if !isValidJSONFieldPath(key, true) {
						return errors.NewValidationError(fmt.Sprintf("services[%d].services[%d].routes[%d].responseJSONFields", i, j, k), "responseJSONFields must not contain empty field names")
					}
				}
				for _, value := range route.ResponseJSONFields {
					if err := validateJSONTransformLiteral(value); err != nil {
						return errors.NewValidationError(fmt.Sprintf("services[%d].services[%d].routes[%d].responseJSONFields", i, j, k), err.Error())
					}
				}
				for _, field := range route.RemoveResponseJSONFields {
					if !isValidJSONFieldPath(field, false) {
						return errors.NewValidationError(fmt.Sprintf("services[%d].services[%d].routes[%d].removeResponseJSONFields", i, j, k), "removeResponseJSONFields must not contain empty values")
					}
				}
				for _, field := range route.ResponseRedactJSONFields {
					if !isValidJSONFieldPath(field, false) {
						return errors.NewValidationError(fmt.Sprintf("services[%d].services[%d].routes[%d].responseRedactJSONFields", i, j, k), "responseRedactJSONFields must not contain empty values")
					}
				}
				for _, pattern := range route.ResponseBodyBlockRegex {
					if strings.TrimSpace(pattern) == "" {
						return errors.NewValidationError(fmt.Sprintf("services[%d].services[%d].routes[%d].responseBodyBlockRegex", i, j, k), "responseBodyBlockRegex must not contain empty values")
					}
					if _, err := regexp.Compile(pattern); err != nil {
						return errors.NewValidationError(fmt.Sprintf("services[%d].services[%d].routes[%d].responseBodyBlockRegex", i, j, k), "responseBodyBlockRegex must contain valid regex patterns")
					}
				}
				for _, pattern := range route.ResponseBodyRequireRegex {
					if strings.TrimSpace(pattern) == "" {
						return errors.NewValidationError(fmt.Sprintf("services[%d].services[%d].routes[%d].responseBodyRequireRegex", i, j, k), "responseBodyRequireRegex must not contain empty values")
					}
					if _, err := regexp.Compile(pattern); err != nil {
						return errors.NewValidationError(fmt.Sprintf("services[%d].services[%d].routes[%d].responseBodyRequireRegex", i, j, k), "responseBodyRequireRegex must contain valid regex patterns")
					}
				}
				for _, piiType := range route.ResponsePIIBlockTypes {
					if !isAllowedPIIType(piiType) {
						return errors.NewValidationError(fmt.Sprintf("services[%d].services[%d].routes[%d].responsePIIBlockTypes", i, j, k), "responsePIIBlockTypes must only contain email, phone, api_key, or card")
					}
				}
				if route.MaxRequestBodyBytes < 0 {
					return errors.NewValidationError(fmt.Sprintf("services[%d].services[%d].routes[%d].maxRequestBodyBytes", i, j, k), "maxRequestBodyBytes must be zero or greater")
				}
				if route.MaxResponseBodyBytes < 0 {
					return errors.NewValidationError(fmt.Sprintf("services[%d].services[%d].routes[%d].maxResponseBodyBytes", i, j, k), "maxResponseBodyBytes must be zero or greater")
				}
				if route.ShadowMaxErrorRate < 0 || route.ShadowMaxErrorRate > 1 {
					return errors.NewValidationError(fmt.Sprintf("services[%d].services[%d].routes[%d].shadowMaxErrorRate", i, j, k), "shadowMaxErrorRate must be between 0 and 1")
				}
				if strings.TrimSpace(route.ShadowMaxLatencyDelta) != "" {
					if _, err := time.ParseDuration(strings.TrimSpace(route.ShadowMaxLatencyDelta)); err != nil {
						return errors.NewValidationError(fmt.Sprintf("services[%d].services[%d].routes[%d].shadowMaxLatencyDelta", i, j, k), "shadowMaxLatencyDelta must use a valid duration format")
					}
				}
				for l, statusCode := range route.RetryStatuses {
					if statusCode < 100 || statusCode > 599 {
						return errors.NewValidationError(fmt.Sprintf("services[%d].services[%d].routes[%d].retryStatusCodes[%d]", i, j, k, l), "retryStatusCodes entries must be valid HTTP status codes")
					}
				}

				// Validate backends
				if len(route.Backends) == 0 && !isPluginOrInternalRoute(route.Path) {
					return errors.NewValidationError(fmt.Sprintf("services[%d].services[%d].routes[%d].backend", i, j, k), "at least one backend must be configured unless this is a plugin or internal route")
				}

				for l, backend := range route.Backends {
					if backend.URLPattern == "" {
						return errors.NewValidationError(fmt.Sprintf("services[%d].services[%d].routes[%d].backend[%d].url_pattern", i, j, k, l), "url_pattern is required")
					}
					if strings.TrimSpace(backend.Host) != "" {
						if err := validateServiceHost(backend.Host); err != nil {
							return errors.NewValidationError(fmt.Sprintf("services[%d].services[%d].routes[%d].backend[%d].host", i, j, k, l), err.Error())
						}
					}
					if backend.Weight < 0 {
						return errors.NewValidationError(fmt.Sprintf("services[%d].services[%d].routes[%d].backend[%d].weight", i, j, k, l), "weight must be zero or greater")
					}
					if strings.TrimSpace(backend.Timeout) != "" {
						if _, err := time.ParseDuration(strings.TrimSpace(backend.Timeout)); err != nil {
							return errors.NewValidationError(fmt.Sprintf("services[%d].services[%d].routes[%d].backend[%d].timeout", i, j, k, l), "timeout must use a valid duration format")
						}
					}
					if backend.FailureThreshold < 0 {
						return errors.NewValidationError(fmt.Sprintf("services[%d].services[%d].routes[%d].backend[%d].failureThreshold", i, j, k, l), "failureThreshold must be zero or greater")
					}
					if backend.HalfOpenMaxRequests < 0 {
						return errors.NewValidationError(fmt.Sprintf("services[%d].services[%d].routes[%d].backend[%d].halfOpenMaxRequests", i, j, k, l), "halfOpenMaxRequests must be zero or greater")
					}
					if backend.RecoverySuccessThreshold < 0 {
						return errors.NewValidationError(fmt.Sprintf("services[%d].services[%d].routes[%d].backend[%d].recoverySuccessThreshold", i, j, k, l), "recoverySuccessThreshold must be zero or greater")
					}
					if backend.OutlierConsecutiveSlowResponses < 0 {
						return errors.NewValidationError(fmt.Sprintf("services[%d].services[%d].routes[%d].backend[%d].outlierConsecutiveSlowResponses", i, j, k, l), "outlierConsecutiveSlowResponses must be zero or greater")
					}
					if strings.TrimSpace(backend.Cooldown) != "" {
						if _, err := time.ParseDuration(strings.TrimSpace(backend.Cooldown)); err != nil {
							return errors.NewValidationError(fmt.Sprintf("services[%d].services[%d].routes[%d].backend[%d].cooldown", i, j, k, l), "cooldown must use a valid duration format")
						}
					}
					if strings.TrimSpace(backend.OutlierLatencyThreshold) != "" {
						if _, err := time.ParseDuration(strings.TrimSpace(backend.OutlierLatencyThreshold)); err != nil {
							return errors.NewValidationError(fmt.Sprintf("services[%d].services[%d].routes[%d].backend[%d].outlierLatencyThreshold", i, j, k, l), "outlierLatencyThreshold must use a valid duration format")
						}
					}
					if strings.TrimSpace(backend.OutlierCooldown) != "" {
						if _, err := time.ParseDuration(strings.TrimSpace(backend.OutlierCooldown)); err != nil {
							return errors.NewValidationError(fmt.Sprintf("services[%d].services[%d].routes[%d].backend[%d].outlierCooldown", i, j, k, l), "outlierCooldown must use a valid duration format")
						}
					}
					if strings.TrimSpace(backend.HealthCheckPath) != "" && !strings.HasPrefix(strings.TrimSpace(backend.HealthCheckPath), "/") {
						return errors.NewValidationError(fmt.Sprintf("services[%d].services[%d].routes[%d].backend[%d].healthCheckPath", i, j, k, l), "healthCheckPath must start with /")
					}
					if strings.TrimSpace(backend.HealthInterval) != "" {
						if _, err := time.ParseDuration(strings.TrimSpace(backend.HealthInterval)); err != nil {
							return errors.NewValidationError(fmt.Sprintf("services[%d].services[%d].routes[%d].backend[%d].healthInterval", i, j, k, l), "healthInterval must use a valid duration format")
						}
					}
					if strings.TrimSpace(backend.HealthTimeout) != "" {
						if _, err := time.ParseDuration(strings.TrimSpace(backend.HealthTimeout)); err != nil {
							return errors.NewValidationError(fmt.Sprintf("services[%d].services[%d].routes[%d].backend[%d].healthTimeout", i, j, k, l), "healthTimeout must use a valid duration format")
						}
					}
					if err := validateBackendPattern(route, backend); err != nil {
						return errors.NewValidationError(fmt.Sprintf("services[%d].services[%d].routes[%d].backend[%d].url_pattern", i, j, k, l), err.Error())
					}
				}
			}
		}
	}

	return nil
}

// PluginsConfigRule validates plugins configuration
type PluginsConfigRule struct{}

func (r *PluginsConfigRule) Validate(cfg *Config) error {
	for pluginName, pluginConfig := range cfg.Plugins {
		if pluginName == "" {
			return errors.NewValidationError("plugins", "plugin name cannot be empty")
		}

		// Validate plugin configuration structure
		if pluginConfig == nil {
			return errors.NewValidationError(fmt.Sprintf("plugins.%s", pluginName), "plugin configuration cannot be nil")
		}

		// Add plugin-specific validation here
		switch pluginName {
		case "auth":
			if err := r.validateAuthPlugin(pluginConfig); err != nil {
				return err
			}
		case "rate":
			if err := r.validateRatePlugin(pluginConfig); err != nil {
				return err
			}
		case "cors":
			if err := r.validateCorsPlugin(pluginConfig); err != nil {
				return err
			}
		}
	}

	return nil
}

func (r *PluginsConfigRule) validateAuthPlugin(config map[string]interface{}) error {
	// Validate auth plugin specific configuration
	if provider, ok := config["provider"].(string); ok {
		validProviders := map[string]bool{
			"keycloak": true,
			"saml":     true,
			"basic":    true,
		}
		if !validProviders[provider] {
			return errors.NewValidationError("plugins.auth.provider", fmt.Sprintf("unsupported auth provider: %s", provider))
		}
	}

	return nil
}

func (r *PluginsConfigRule) validateRatePlugin(config map[string]interface{}) error {
	// Validate rate limiting plugin configuration
	if limit, ok := config["limit"].(float64); ok {
		if limit <= 0 {
			return errors.NewValidationError("plugins.rate.limit", "rate limit must be positive")
		}
	}

	if window, ok := config["window"].(string); ok {
		if _, err := time.ParseDuration(window); err != nil {
			return errors.NewValidationError("plugins.rate.window", "invalid duration format")
		}
	}

	return nil
}

func (r *PluginsConfigRule) validateCorsPlugin(config map[string]interface{}) error {
	// Validate CORS plugin configuration
	if origins, ok := config["origins"].([]interface{}); ok {
		for i, origin := range origins {
			if originStr, ok := origin.(string); ok {
				if originStr != "*" {
					if _, err := url.Parse(originStr); err != nil {
						return errors.NewValidationError(fmt.Sprintf("plugins.cors.origins[%d]", i), "invalid origin URL")
					}
				}
			}
		}
	}

	return nil
}

// Add helper function to check if a route is plugin/static/internal
func isPluginOrInternalRoute(path string) bool {
	pluginPaths := []string{"/openapi", "/swagger-ui", "/docs", "/docs/", "/docs/{rest:.*}"}
	for _, p := range pluginPaths {
		if strings.HasPrefix(path, p) {
			return true
		}
	}
	return false
}

func validateServiceHost(raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid host URL")
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return fmt.Errorf("host must use http or https")
	}
	if parsed.Host == "" || parsed.Hostname() == "" {
		return fmt.Errorf("host must include a hostname")
	}
	hostname := parsed.Hostname()
	if strings.Contains(hostname, ":") && net.ParseIP(hostname) == nil {
		return fmt.Errorf("host contains an invalid hostname")
	}
	if port := parsed.Port(); port != "" {
		if _, err := net.LookupPort("tcp", port); err != nil {
			return fmt.Errorf("host contains an invalid port")
		}
	}
	return nil
}

func validateBackendPattern(route RouterConfig, backend Backend) error {
	routeVars := extractTemplateVars(route.Path)
	patternVars := extractTemplateVars(backend.URLPattern)
	_, routeHasRest := routeVars["rest"]
	_, patternHasRest := patternVars["rest"]

	if route.StripPath && patternHasRest && !routeHasRest {
		return fmt.Errorf("stripPath=true with url_pattern {rest} requires route path to define {rest:.*}")
	}
	if patternHasRest && !routeHasRest {
		return fmt.Errorf("url_pattern contains {rest} but route path does not define it")
	}

	for name := range patternVars {
		if _, ok := routeVars[name]; !ok {
			return fmt.Errorf("url_pattern contains {%s} but route path does not define it", name)
		}
	}

	return nil
}

func extractTemplateVars(path string) map[string]struct{} {
	matches := routeTemplateVarPattern.FindAllStringSubmatch(path, -1)
	vars := make(map[string]struct{}, len(matches))
	for _, match := range matches {
		if len(match) > 1 {
			vars[match[1]] = struct{}{}
		}
	}
	return vars
}

func isValidJSONFieldPath(path string, allowAppend bool) bool {
	path = strings.TrimSpace(path)
	if path == "" {
		return false
	}
	parts := strings.Split(path, ".")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			return false
		}
		if strings.HasSuffix(part, "[]") {
			if !allowAppend {
				return false
			}
			part = strings.TrimSuffix(part, "[]")
			if strings.TrimSpace(part) == "" {
				return false
			}
			continue
		}
		if open := strings.Index(part, "["); open >= 0 {
			if !strings.HasSuffix(part, "]") {
				return false
			}
			if open == 0 {
				return false
			}
			index := part[open+1 : len(part)-1]
			if index == "" {
				return false
			}
			for _, ch := range index {
				if ch < '0' || ch > '9' {
					return false
				}
			}
			part = part[:open]
			if strings.TrimSpace(part) == "" {
				return false
			}
		}
	}
	return true
}

func validateJSONTransformLiteral(value string) error {
	value = strings.TrimSpace(value)
	if !strings.HasPrefix(value, "json:") {
		return nil
	}
	literal := strings.TrimSpace(strings.TrimPrefix(value, "json:"))
	if literal == "" {
		return fmt.Errorf("json: transform values must contain valid JSON")
	}
	if strings.Contains(literal, "{{") {
		return nil
	}
	var parsed interface{}
	if err := json.Unmarshal([]byte(literal), &parsed); err != nil {
		return fmt.Errorf("json: transform values must contain valid JSON")
	}
	return nil
}

func isAllowedPIIType(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "email", "phone", "api_key", "card":
		return true
	default:
		return false
	}
}
