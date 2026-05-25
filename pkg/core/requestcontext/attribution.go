package requestcontext

import (
	"context"
	"strings"
)

type attributionContextKey struct{}

// Attribution contains stable, non-secret request dimensions that downstream
// observers can use for metering, audit, and analytics.
type Attribution struct {
	RequestID   string
	TenantRealm string
	ServiceName string
	RouteName   string
	RoutePath   string
}

func WithAttribution(ctx context.Context, attribution Attribution) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	current, _ := AttributionFromContext(ctx)
	return context.WithValue(ctx, attributionContextKey{}, current.Merge(attribution))
}

func AttributionFromContext(ctx context.Context) (Attribution, bool) {
	if ctx == nil {
		return Attribution{}, false
	}
	attribution, ok := ctx.Value(attributionContextKey{}).(Attribution)
	return attribution, ok
}

func (attribution Attribution) Merge(next Attribution) Attribution {
	merged := attribution
	if value := strings.TrimSpace(next.RequestID); value != "" {
		merged.RequestID = value
	}
	if value := strings.TrimSpace(next.TenantRealm); value != "" {
		merged.TenantRealm = value
	}
	if value := strings.TrimSpace(next.ServiceName); value != "" {
		merged.ServiceName = value
	}
	if value := strings.TrimSpace(next.RouteName); value != "" {
		merged.RouteName = value
	}
	if value := strings.TrimSpace(next.RoutePath); value != "" {
		merged.RoutePath = value
	}
	return merged
}
