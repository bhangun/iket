package plugin

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
	"time"
)

// WithNormalizedMetering returns an event copy with a stable idempotency key,
// default unit quantity, and canonical redacted dimensions.
func (event ClientUsageEvent) WithNormalizedMetering() ClientUsageEvent {
	event.SchemaVersion = event.NormalizedSchemaVersion()
	if event.Quantity <= 0 {
		event.Quantity = 1
	}
	event.EventID = strings.TrimSpace(event.EventID)
	if event.EventID == "" {
		event.EventID = event.IdempotencyKey()
	}
	return event.WithNormalizedDimensions()
}

func (event ClientUsageEvent) IdempotencyKey() string {
	parts := []string{
		event.NormalizedSchemaVersion(),
		event.Provider,
		event.ClientID,
		event.KeyFingerprint,
		event.RequestID,
		event.RequestMethod,
		event.RequestHost,
		event.RequestPath,
		event.TenantRealm,
		event.ServiceName,
		event.RouteName,
		event.RoutePath,
		strconv.FormatInt(event.RequestCount, 10),
		event.OccurredAt.UTC().Format(time.RFC3339Nano),
	}
	if event.Identity != nil {
		parts = append(parts, event.Identity.Kind, event.Identity.Source)
		if !event.Identity.Sensitive {
			parts = append(parts, event.Identity.Value)
		}
	}
	normalized := make([]string, 0, len(parts))
	for _, part := range parts {
		normalized = append(normalized, strings.TrimSpace(part))
	}
	sum := sha256.Sum256([]byte(strings.Join(normalized, "\x1f")))
	return "usage_" + hex.EncodeToString(sum[:])
}
