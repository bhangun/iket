package plugin

import (
	"net/http"
	"reflect"
	"testing"
	"time"

	"github.com/bhangun/iket/pkg/core/authcontext"
)

func TestClientUsageEventCloneCopiesMutableFields(t *testing.T) {
	event := ClientUsageEvent{
		Identity: &authcontext.PrincipalIdentity{
			Kind:   authcontext.PrincipalIdentityClient,
			Source: "apikey",
			Value:  "client-a",
		},
		Scopes:     []string{"read", "write"},
		Tags:       []string{"gold"},
		Dimensions: map[string]string{ClientUsageDimensionTenantRealm: "tenant-a"},
	}

	cloned := event.Clone()
	cloned.Identity.Value = "client-b"
	cloned.Scopes[0] = "admin"
	cloned.Tags[0] = "platinum"
	cloned.Dimensions[ClientUsageDimensionTenantRealm] = "tenant-b"

	if event.Identity.Value != "client-a" {
		t.Fatalf("expected cloned identity pointer to be independent, got %+v", event.Identity)
	}
	if !reflect.DeepEqual(event.Scopes, []string{"read", "write"}) {
		t.Fatalf("expected cloned scopes to be independent, got %+v", event.Scopes)
	}
	if !reflect.DeepEqual(event.Tags, []string{"gold"}) {
		t.Fatalf("expected cloned tags to be independent, got %+v", event.Tags)
	}
	if !reflect.DeepEqual(event.Dimensions, map[string]string{ClientUsageDimensionTenantRealm: "tenant-a"}) {
		t.Fatalf("expected cloned dimensions to be independent, got %+v", event.Dimensions)
	}
}

func TestClientUsageEventNormalizedDimensions(t *testing.T) {
	event := ClientUsageEvent{
		EventID:  "usage_custom",
		Provider: "apikey",
		ClientID: "client-a",
		Name:     "Client A",
		Identity: &authcontext.PrincipalIdentity{
			Kind:   authcontext.PrincipalIdentityClient,
			Source: "apikey",
			Value:  "client-a",
		},
		Group:          "billing",
		Scopes:         []string{"read", " ", "write"},
		Tags:           []string{"gold"},
		KeyFingerprint: "fp_123",
		Quantity:       3,
		RequestID:      "req-1",
		RequestMethod:  "GET",
		RequestPath:    "/v1/orders",
		RequestHost:    "api.example.test",
		RequestScheme:  "https",
		ResponseStatus: http.StatusAccepted,
		ResponseBytes:  2048,
		DurationMillis: 37,
		TenantRealm:    "tenant-a",
		ServiceName:    "orders",
		RouteName:      "list-orders",
		RoutePath:      "/v1/orders",
		Dimensions: map[string]string{
			"custom.plan": "enterprise",
			" provider ":  "custom-provider",
			"empty":       " ",
		},
	}

	dimensions := event.NormalizedDimensions()

	expected := map[string]string{
		ClientUsageDimensionSchemaVersion:  ClientUsageEventSchemaVersion,
		ClientUsageDimensionProvider:       "apikey",
		ClientUsageDimensionEventID:        "usage_custom",
		ClientUsageDimensionQuantity:       "3",
		ClientUsageDimensionClientID:       "client-a",
		ClientUsageDimensionClientName:     "Client A",
		ClientUsageDimensionClientGroup:    "billing",
		ClientUsageDimensionClientScopes:   "read,write",
		ClientUsageDimensionClientTags:     "gold",
		ClientUsageDimensionKeyFingerprint: "fp_123",
		ClientUsageDimensionIdentityKind:   authcontext.PrincipalIdentityClient,
		ClientUsageDimensionIdentitySource: "apikey",
		ClientUsageDimensionIdentityValue:  "client-a",
		ClientUsageDimensionRequestID:      "req-1",
		ClientUsageDimensionRequestMethod:  "GET",
		ClientUsageDimensionRequestPath:    "/v1/orders",
		ClientUsageDimensionRequestHost:    "api.example.test",
		ClientUsageDimensionRequestScheme:  "https",
		ClientUsageDimensionResponseStatus: "202",
		ClientUsageDimensionResponseClass:  "2xx",
		ClientUsageDimensionResponseBytes:  "2048",
		ClientUsageDimensionRequestLatency: "37",
		ClientUsageDimensionTenantRealm:    "tenant-a",
		ClientUsageDimensionServiceName:    "orders",
		ClientUsageDimensionRouteName:      "list-orders",
		ClientUsageDimensionRoutePath:      "/v1/orders",
		"custom.plan":                      "enterprise",
	}
	if !reflect.DeepEqual(dimensions, expected) {
		t.Fatalf("unexpected normalized dimensions:\nwant %+v\ngot  %+v", expected, dimensions)
	}
}

func TestClientUsageEventWithNormalizedMeteringAddsIdempotencyAndQuantity(t *testing.T) {
	event := ClientUsageEvent{
		Provider:       "apikey",
		ClientID:       "client-a",
		KeyFingerprint: "fp_123",
		RequestID:      "req-1",
		RequestMethod:  "GET",
		RequestPath:    "/v1/orders",
		RequestCount:   7,
		OccurredAt:     time.Date(2026, 5, 20, 1, 2, 3, 4, time.UTC),
	}

	metered := event.WithNormalizedMetering()
	again := event.WithNormalizedMetering()
	changed := event
	changed.RequestID = "req-2"

	if metered.Quantity != 1 {
		t.Fatalf("expected default billing quantity 1, got %+v", metered)
	}
	if metered.SchemaVersion != ClientUsageEventSchemaVersion {
		t.Fatalf("expected default schema version %q, got %+v", ClientUsageEventSchemaVersion, metered)
	}
	if metered.EventID == "" || metered.EventID != again.EventID {
		t.Fatalf("expected stable non-empty idempotency key, got %q and %q", metered.EventID, again.EventID)
	}
	if metered.EventID == changed.WithNormalizedMetering().EventID {
		t.Fatalf("expected idempotency key to change when request identity changes")
	}
	if metered.Dimensions[ClientUsageDimensionSchemaVersion] != ClientUsageEventSchemaVersion ||
		metered.Dimensions[ClientUsageDimensionEventID] != metered.EventID ||
		metered.Dimensions[ClientUsageDimensionQuantity] != "1" {
		t.Fatalf("expected normalized metering dimensions, got %+v", metered.Dimensions)
	}
	if err := metered.Validate(); err != nil {
		t.Fatalf("expected normalized metering event to validate: %v", err)
	}
}

func TestClientUsageEventCustomSchemaVersionParticipatesInIdempotency(t *testing.T) {
	event := ClientUsageEvent{
		SchemaVersion: "iket.client_usage.v2",
		Provider:      "apikey",
		ClientID:      "client-a",
		RequestID:     "req-1",
		OccurredAt:    time.Date(2026, 5, 20, 1, 2, 3, 4, time.UTC),
	}
	defaulted := event
	defaulted.SchemaVersion = ""

	metered := event.WithNormalizedMetering()
	defaultMetered := defaulted.WithNormalizedMetering()

	if metered.SchemaVersion != "iket.client_usage.v2" {
		t.Fatalf("expected custom schema version to be preserved, got %+v", metered)
	}
	if metered.EventID == defaultMetered.EventID {
		t.Fatalf("expected schema version to participate in idempotency key")
	}
	if metered.Dimensions[ClientUsageDimensionSchemaVersion] != "iket.client_usage.v2" {
		t.Fatalf("expected custom schema dimension, got %+v", metered.Dimensions)
	}
}

func TestClientUsageEventNormalizedDimensionsOmitSensitiveIdentityValue(t *testing.T) {
	event := ClientUsageEvent{
		Provider: "jwt",
		Identity: &authcontext.PrincipalIdentity{
			Kind:      authcontext.PrincipalIdentityEmail,
			Source:    "jwt",
			Value:     "person@example.test",
			Sensitive: true,
		},
	}

	dimensions := event.NormalizedDimensions()

	if dimensions[ClientUsageDimensionIdentityValue] != "" {
		t.Fatalf("expected sensitive identity value to be omitted, got %+v", dimensions)
	}
	if dimensions[ClientUsageDimensionIdentityKind] != authcontext.PrincipalIdentityEmail ||
		dimensions[ClientUsageDimensionIdentitySource] != "jwt" ||
		dimensions[ClientUsageDimensionIdentitySecret] != "true" {
		t.Fatalf("expected non-secret sensitive identity labels, got %+v", dimensions)
	}
}

func TestClientUsageEventValidateRejectsMalformedEvents(t *testing.T) {
	valid := ClientUsageEvent{
		Provider:       "apikey",
		ClientID:       "client-a",
		KeyFingerprint: "fp_123",
		RequestID:      "req-1",
		OccurredAt:     time.Date(2026, 5, 20, 1, 2, 3, 4, time.UTC),
	}.WithNormalizedMetering()

	tests := []struct {
		name  string
		event ClientUsageEvent
		field string
	}{
		{
			name: "missing schema",
			event: func() ClientUsageEvent {
				event := valid
				event.SchemaVersion = ""
				return event
			}(),
			field: "schema_version",
		},
		{
			name: "missing event id",
			event: func() ClientUsageEvent {
				event := valid
				event.EventID = ""
				return event
			}(),
			field: "event_id",
		},
		{
			name: "missing provider",
			event: func() ClientUsageEvent {
				event := valid
				event.Provider = ""
				return event
			}(),
			field: "provider",
		},
		{
			name: "invalid quantity",
			event: func() ClientUsageEvent {
				event := valid
				event.Quantity = 0
				return event
			}(),
			field: "quantity",
		},
		{
			name: "missing occurred at",
			event: func() ClientUsageEvent {
				event := valid
				event.OccurredAt = time.Time{}
				return event
			}(),
			field: "occurred_at",
		},
		{
			name: "invalid response status",
			event: func() ClientUsageEvent {
				event := valid
				event.ResponseStatus = 99
				return event
			}(),
			field: "response_status",
		},
		{
			name: "missing dimensions",
			event: func() ClientUsageEvent {
				event := valid
				event.Dimensions = nil
				return event
			}(),
			field: "dimensions",
		},
		{
			name: "mismatched event dimension",
			event: func() ClientUsageEvent {
				event := valid
				event.Dimensions = event.Clone().Dimensions
				event.Dimensions[ClientUsageDimensionEventID] = "usage_other"
				return event
			}(),
			field: "dimensions." + ClientUsageDimensionEventID,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.event.Validate()
			if err == nil {
				t.Fatalf("expected validation error")
			}
			validationErr, ok := err.(ClientUsageValidationError)
			if !ok {
				t.Fatalf("expected ClientUsageValidationError, got %T: %v", err, err)
			}
			if validationErr.Field != tc.field {
				t.Fatalf("expected field %q, got %+v", tc.field, validationErr)
			}
		})
	}
}

func TestClientUsageEventValidateRejectsSensitiveIdentityDimensionValue(t *testing.T) {
	event := ClientUsageEvent{
		Provider: "jwt",
		Identity: &authcontext.PrincipalIdentity{
			Kind:      authcontext.PrincipalIdentityEmail,
			Source:    "jwt",
			Value:     "person@example.test",
			Sensitive: true,
		},
		OccurredAt: time.Date(2026, 5, 20, 1, 2, 3, 4, time.UTC),
	}.WithNormalizedMetering()
	event.Dimensions[ClientUsageDimensionIdentityValue] = "person@example.test"

	err := event.Validate()
	if err == nil {
		t.Fatalf("expected sensitive identity validation error")
	}
	validationErr, ok := err.(ClientUsageValidationError)
	if !ok {
		t.Fatalf("expected ClientUsageValidationError, got %T: %v", err, err)
	}
	if validationErr.Field != "dimensions."+ClientUsageDimensionIdentityValue {
		t.Fatalf("expected identity dimension error, got %+v", validationErr)
	}
}
