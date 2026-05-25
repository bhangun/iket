package plugin

import (
	"strconv"
	"strings"
)

// WithNormalizedDimensions returns an event copy populated with stable,
// redacted dimensions suitable for billing, quotas, and analytics labels.
func (event ClientUsageEvent) WithNormalizedDimensions() ClientUsageEvent {
	event.Dimensions = event.NormalizedDimensions()
	return event
}

// NormalizedDimensions derives canonical string labels from redacted event
// fields. Existing custom dimensions are preserved unless a canonical field
// uses the same key.
func (event ClientUsageEvent) NormalizedDimensions() map[string]string {
	dimensions := copyClientUsageDimensions(event.Dimensions)
	if dimensions == nil {
		dimensions = make(map[string]string)
	}
	addClientUsageDimension(dimensions, ClientUsageDimensionSchemaVersion, event.NormalizedSchemaVersion())
	addClientUsageDimension(dimensions, ClientUsageDimensionEventID, event.EventID)
	if event.Quantity > 0 {
		addClientUsageDimension(dimensions, ClientUsageDimensionQuantity, strconv.FormatInt(event.Quantity, 10))
	}
	addClientUsageDimension(dimensions, ClientUsageDimensionProvider, event.Provider)
	addClientUsageDimension(dimensions, ClientUsageDimensionClientID, event.ClientID)
	addClientUsageDimension(dimensions, ClientUsageDimensionClientName, event.Name)
	addClientUsageDimension(dimensions, ClientUsageDimensionClientGroup, event.Group)
	addClientUsageDimension(dimensions, ClientUsageDimensionClientScopes, strings.Join(normalizedClientUsageList(event.Scopes), ","))
	addClientUsageDimension(dimensions, ClientUsageDimensionClientTags, strings.Join(normalizedClientUsageList(event.Tags), ","))
	addClientUsageDimension(dimensions, ClientUsageDimensionKeyFingerprint, event.KeyFingerprint)
	if event.Identity != nil {
		addClientUsageDimension(dimensions, ClientUsageDimensionIdentityKind, event.Identity.Kind)
		addClientUsageDimension(dimensions, ClientUsageDimensionIdentitySource, event.Identity.Source)
		if event.Identity.Sensitive {
			addClientUsageDimension(dimensions, ClientUsageDimensionIdentitySecret, "true")
		} else {
			addClientUsageDimension(dimensions, ClientUsageDimensionIdentityValue, event.Identity.Value)
		}
	}
	addClientUsageDimension(dimensions, ClientUsageDimensionRequestID, event.RequestID)
	addClientUsageDimension(dimensions, ClientUsageDimensionRequestMethod, event.RequestMethod)
	addClientUsageDimension(dimensions, ClientUsageDimensionRequestPath, event.RequestPath)
	addClientUsageDimension(dimensions, ClientUsageDimensionRequestHost, event.RequestHost)
	addClientUsageDimension(dimensions, ClientUsageDimensionRequestScheme, event.RequestScheme)
	if event.ResponseStatus > 0 {
		addClientUsageDimension(dimensions, ClientUsageDimensionResponseStatus, strconv.Itoa(event.ResponseStatus))
		addClientUsageDimension(dimensions, ClientUsageDimensionResponseClass, strconv.Itoa(event.ResponseStatus/100)+"xx")
	}
	if event.ResponseBytes > 0 {
		addClientUsageDimension(dimensions, ClientUsageDimensionResponseBytes, strconv.FormatInt(event.ResponseBytes, 10))
	}
	if event.DurationMillis > 0 {
		addClientUsageDimension(dimensions, ClientUsageDimensionRequestLatency, strconv.FormatInt(event.DurationMillis, 10))
	}
	addClientUsageDimension(dimensions, ClientUsageDimensionTenantRealm, event.TenantRealm)
	addClientUsageDimension(dimensions, ClientUsageDimensionServiceName, event.ServiceName)
	addClientUsageDimension(dimensions, ClientUsageDimensionRouteName, event.RouteName)
	addClientUsageDimension(dimensions, ClientUsageDimensionRoutePath, event.RoutePath)
	if len(dimensions) == 0 {
		return nil
	}
	return dimensions
}

func copyClientUsageDimensions(dimensions map[string]string) map[string]string {
	if len(dimensions) == 0 {
		return nil
	}
	copied := make(map[string]string, len(dimensions))
	for key, value := range dimensions {
		addClientUsageDimension(copied, key, value)
	}
	if len(copied) == 0 {
		return nil
	}
	return copied
}

func addClientUsageDimension(dimensions map[string]string, key, value string) {
	key = strings.TrimSpace(key)
	value = strings.TrimSpace(value)
	if key == "" || value == "" {
		return
	}
	dimensions[key] = value
}

func normalizedClientUsageList(values []string) []string {
	normalized := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			normalized = append(normalized, value)
		}
	}
	return normalized
}
