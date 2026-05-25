package plugin

import (
	"context"
	"time"

	"github.com/bhangun/iket/pkg/core/authcontext"
)

// ClientUsageEvent is the redacted metering event emitted by auth plugins after
// a credential is successfully accepted. It intentionally excludes raw secrets.
type ClientUsageEvent struct {
	SchemaVersion  string                         `json:"schema_version,omitempty"`
	EventID        string                         `json:"event_id,omitempty"`
	Provider       string                         `json:"provider"`
	ClientID       string                         `json:"client_id,omitempty"`
	Name           string                         `json:"name,omitempty"`
	Identity       *authcontext.PrincipalIdentity `json:"identity,omitempty"`
	Group          string                         `json:"group,omitempty"`
	Scopes         []string                       `json:"scopes,omitempty"`
	Tags           []string                       `json:"tags,omitempty"`
	KeyFingerprint string                         `json:"key_fingerprint,omitempty"`
	Quantity       int64                          `json:"quantity,omitempty"`
	RequestCount   int64                          `json:"request_count,omitempty"`
	OccurredAt     time.Time                      `json:"occurred_at"`
	RequestID      string                         `json:"request_id,omitempty"`
	RequestMethod  string                         `json:"request_method,omitempty"`
	RequestPath    string                         `json:"request_path,omitempty"`
	RequestHost    string                         `json:"request_host,omitempty"`
	RequestScheme  string                         `json:"request_scheme,omitempty"`
	ResponseStatus int                            `json:"response_status,omitempty"`
	ResponseBytes  int64                          `json:"response_bytes,omitempty"`
	DurationMillis int64                          `json:"duration_ms,omitempty"`
	TenantRealm    string                         `json:"tenant_realm,omitempty"`
	ServiceName    string                         `json:"service_name,omitempty"`
	RouteName      string                         `json:"route_name,omitempty"`
	RoutePath      string                         `json:"route_path,omitempty"`
	Dimensions     map[string]string              `json:"dimensions,omitempty"`
}

// Clone returns an observer-safe copy of the event. Slice fields and nested
// identity pointers are copied so one observer cannot mutate another's view.
func (event ClientUsageEvent) Clone() ClientUsageEvent {
	cloned := event
	if event.Identity != nil {
		identity := *event.Identity
		cloned.Identity = &identity
	}
	cloned.Scopes = append([]string(nil), event.Scopes...)
	cloned.Tags = append([]string(nil), event.Tags...)
	cloned.Dimensions = copyClientUsageDimensions(event.Dimensions)
	return cloned
}

// ClientUsageObserver is an optional enterprise/community plugin capability for
// billing, quota sync, audit trails, or analytics systems that need auth usage.
type ClientUsageObserver interface {
	Plugin
	ObserveClientUsage(context.Context, ClientUsageEvent)
}

// ClientUsageObserverRegistrar is implemented by auth plugins that can publish
// usage events to observer plugins without taking a hard dependency on them.
type ClientUsageObserverRegistrar interface {
	Plugin
	RegisterClientUsageObserver(ClientUsageObserver)
}
