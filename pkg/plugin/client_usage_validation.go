package plugin

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

type ClientUsageValidationError struct {
	Field  string
	Reason string
}

func (err ClientUsageValidationError) Error() string {
	if strings.TrimSpace(err.Field) == "" {
		return "client usage event is invalid: " + err.Reason
	}
	return fmt.Sprintf("client usage event %s is invalid: %s", err.Field, err.Reason)
}

// Validate checks that the usage event is normalized and safe to export to
// billing, quota, audit, or analytics observers.
func (event ClientUsageEvent) Validate() error {
	if strings.TrimSpace(event.SchemaVersion) == "" {
		return clientUsageValidationError("schema_version", "required")
	}
	if strings.TrimSpace(event.EventID) == "" {
		return clientUsageValidationError("event_id", "required")
	}
	if strings.TrimSpace(event.Provider) == "" {
		return clientUsageValidationError("provider", "required")
	}
	if event.Quantity <= 0 {
		return clientUsageValidationError("quantity", "must be greater than zero")
	}
	if event.OccurredAt.IsZero() {
		return clientUsageValidationError("occurred_at", "required")
	}
	if event.RequestCount < 0 {
		return clientUsageValidationError("request_count", "must not be negative")
	}
	if event.ResponseStatus != 0 && (event.ResponseStatus < http.StatusContinue || event.ResponseStatus > 599) {
		return clientUsageValidationError("response_status", "must be between 100 and 599")
	}
	if event.ResponseBytes < 0 {
		return clientUsageValidationError("response_bytes", "must not be negative")
	}
	if event.DurationMillis < 0 {
		return clientUsageValidationError("duration_ms", "must not be negative")
	}
	if err := event.validateClientUsageDimensions(); err != nil {
		return err
	}
	return nil
}

func (event ClientUsageEvent) validateClientUsageDimensions() error {
	if len(event.Dimensions) == 0 {
		return clientUsageValidationError("dimensions", "required")
	}
	if err := requireClientUsageDimension(event.Dimensions, ClientUsageDimensionSchemaVersion, event.SchemaVersion); err != nil {
		return err
	}
	if err := requireClientUsageDimension(event.Dimensions, ClientUsageDimensionEventID, event.EventID); err != nil {
		return err
	}
	if err := requireClientUsageDimension(event.Dimensions, ClientUsageDimensionQuantity, strconv.FormatInt(event.Quantity, 10)); err != nil {
		return err
	}
	if err := requireClientUsageDimension(event.Dimensions, ClientUsageDimensionProvider, event.Provider); err != nil {
		return err
	}
	if event.Identity != nil && event.Identity.Sensitive {
		if strings.TrimSpace(event.Dimensions[ClientUsageDimensionIdentityValue]) != "" {
			return clientUsageValidationError("dimensions."+ClientUsageDimensionIdentityValue, "must be omitted for sensitive identities")
		}
	}
	return nil
}

func requireClientUsageDimension(dimensions map[string]string, key, expected string) error {
	actual := strings.TrimSpace(dimensions[key])
	expected = strings.TrimSpace(expected)
	if actual == "" {
		return clientUsageValidationError("dimensions."+key, "required")
	}
	if actual != expected {
		return clientUsageValidationError("dimensions."+key, fmt.Sprintf("expected %q", expected))
	}
	return nil
}

func clientUsageValidationError(field, reason string) error {
	return ClientUsageValidationError{Field: field, Reason: reason}
}
