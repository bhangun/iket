package app

import (
	"errors"
	"fmt"
	"strings"
)

const (
	CapabilityGatewayRuntime     = "gateway.runtime"
	CapabilityConfigProviders    = "config.providers"
	CapabilityCommunityPlugins   = "plugins.community"
	CapabilityLocalManagement    = "management.local"
	CapabilityBasicObservability = "observability.basic"
	CapabilityBaselineSecurity   = "security.baseline"

	CapabilityTenantWorkspaces   = "tenant.workspaces"
	CapabilityEnterpriseRBAC     = "security.enterprise_rbac"
	CapabilityAuditTrails        = "governance.audit_trails"
	CapabilityBillingIntegration = "commercial.billing"
	CapabilityHighAvailability   = "gateway.high_availability"
	CapabilityAdvancedAnalytics  = "observability.advanced"
)

// CapabilityCheck is the stable response shape for feature-gate checks.
type CapabilityCheck struct {
	Key         string `json:"key"`
	Supported   bool   `json:"supported"`
	Edition     string `json:"edition"`
	DisplayName string `json:"display_name"`
	Message     string `json:"message,omitempty"`
}

// CapabilitySetCheck is the stable response shape for multi-capability gates.
type CapabilitySetCheck struct {
	Supported               bool              `json:"supported"`
	Edition                 string            `json:"edition"`
	DisplayName             string            `json:"display_name"`
	Capabilities            []CapabilityCheck `json:"capabilities"`
	UnsupportedCapabilities []CapabilityCheck `json:"unsupported_capabilities,omitempty"`
	Message                 string            `json:"message,omitempty"`
}

type CapabilityUnavailableError struct {
	Status CapabilityCheck
}

type CapabilitiesUnavailableError struct {
	Status CapabilitySetCheck
}

func (e CapabilityUnavailableError) Error() string {
	if e.Status.Message != "" {
		return e.Status.Message
	}
	return fmt.Sprintf("capability %q is not available", e.Status.Key)
}

func (e CapabilitiesUnavailableError) Error() string {
	if e.Status.Message != "" {
		return e.Status.Message
	}
	return "required capabilities are not available"
}

func CheckCapability(key string) CapabilityCheck {
	return capabilityCheckFor(CurrentEdition(), key)
}

func CheckCapabilities(keys ...string) CapabilitySetCheck {
	info := CurrentEdition()
	normalizedKeys := normalizeCapabilityKeys(keys)
	check := CapabilitySetCheck{
		Supported:   false,
		Edition:     info.Edition,
		DisplayName: info.DisplayName,
	}
	if len(normalizedKeys) == 0 {
		check.Message = "at least one capability is required"
		return check
	}

	check.Capabilities = make([]CapabilityCheck, 0, len(normalizedKeys))
	for _, key := range normalizedKeys {
		capabilityCheck := capabilityCheckFor(info, key)
		check.Capabilities = append(check.Capabilities, capabilityCheck)
		if !capabilityCheck.Supported {
			check.UnsupportedCapabilities = append(check.UnsupportedCapabilities, capabilityCheck)
		}
	}
	check.Supported = len(check.UnsupportedCapabilities) == 0
	if !check.Supported {
		check.Message = capabilitySetMessage(check.UnsupportedCapabilities, info.DisplayName)
	}
	return check
}

func capabilityCheckFor(info EditionInfo, key string) CapabilityCheck {
	key = normalizeCapabilityKey(key)
	check := CapabilityCheck{
		Key:         key,
		Supported:   false,
		Edition:     info.Edition,
		DisplayName: info.DisplayName,
	}
	if key == "" {
		check.Message = "capability key is required"
		return check
	}
	if _, ok := FindCapability(info, key); ok {
		check.Supported = true
		return check
	}
	check.Message = fmt.Sprintf("capability %q is not available in %s", key, info.DisplayName)
	return check
}

func RequireCapability(key string) error {
	check := CheckCapability(key)
	if check.Supported {
		return nil
	}
	return CapabilityUnavailableError{Status: check}
}

func RequireCapabilities(keys ...string) error {
	check := CheckCapabilities(keys...)
	if check.Supported {
		return nil
	}
	return CapabilitiesUnavailableError{Status: check}
}

func IsCapabilityUnavailable(err error) bool {
	var capabilityErr CapabilityUnavailableError
	if errors.As(err, &capabilityErr) {
		return true
	}
	var capabilitiesErr CapabilitiesUnavailableError
	return errors.As(err, &capabilitiesErr)
}

func normalizeCapabilityKeys(keys []string) []string {
	out := make([]string, 0, len(keys))
	seen := make(map[string]struct{}, len(keys))
	for _, key := range keys {
		key = normalizeCapabilityKey(key)
		if _, exists := seen[key]; exists {
			continue
		}
		out = append(out, key)
		seen[key] = struct{}{}
	}
	return out
}

func capabilitySetMessage(missing []CapabilityCheck, displayName string) string {
	if len(missing) == 0 {
		return ""
	}
	if len(missing) == 1 {
		return missing[0].Message
	}
	keys := make([]string, 0, len(missing))
	for _, check := range missing {
		keys = append(keys, check.Key)
	}
	return fmt.Sprintf("capabilities %q are not available in %s", strings.Join(keys, ", "), displayName)
}

func normalizeCapabilityKey(key string) string {
	return strings.ToLower(strings.TrimSpace(key))
}
