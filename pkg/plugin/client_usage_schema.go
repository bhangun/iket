package plugin

import "strings"

const (
	ClientUsageEventSchemaVersion = "iket.client_usage.v1"

	ClientUsageDimensionSchemaVersion  = "usage.schema_version"
	ClientUsageDimensionEventID        = "usage.event_id"
	ClientUsageDimensionQuantity       = "usage.quantity"
	ClientUsageDimensionProvider       = "provider"
	ClientUsageDimensionClientID       = "client.id"
	ClientUsageDimensionClientName     = "client.name"
	ClientUsageDimensionClientGroup    = "client.group"
	ClientUsageDimensionClientScopes   = "client.scopes"
	ClientUsageDimensionClientTags     = "client.tags"
	ClientUsageDimensionKeyFingerprint = "client.key_fingerprint"
	ClientUsageDimensionIdentityKind   = "identity.kind"
	ClientUsageDimensionIdentitySource = "identity.source"
	ClientUsageDimensionIdentityValue  = "identity.value"
	ClientUsageDimensionIdentitySecret = "identity.sensitive"
	ClientUsageDimensionRequestID      = "request.id"
	ClientUsageDimensionRequestMethod  = "request.method"
	ClientUsageDimensionRequestPath    = "request.path"
	ClientUsageDimensionRequestHost    = "request.host"
	ClientUsageDimensionRequestScheme  = "request.scheme"
	ClientUsageDimensionRequestLatency = "request.duration_ms"
	ClientUsageDimensionResponseStatus = "response.status"
	ClientUsageDimensionResponseClass  = "response.status_class"
	ClientUsageDimensionResponseBytes  = "response.bytes"
	ClientUsageDimensionTenantRealm    = "tenant.realm"
	ClientUsageDimensionServiceName    = "service.name"
	ClientUsageDimensionRouteName      = "route.name"
	ClientUsageDimensionRoutePath      = "route.path"
)

func (event ClientUsageEvent) NormalizedSchemaVersion() string {
	if schemaVersion := strings.TrimSpace(event.SchemaVersion); schemaVersion != "" {
		return schemaVersion
	}
	return ClientUsageEventSchemaVersion
}
