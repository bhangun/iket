package requestcontext

import (
	"context"
	"testing"
)

func TestWithAttributionMergesNonEmptyFields(t *testing.T) {
	ctx := WithAttribution(context.Background(), Attribution{
		TenantRealm: "tenant-a",
		ServiceName: "orders",
		RoutePath:   "/v1/orders/{id}",
	})

	ctx = WithAttribution(ctx, Attribution{
		RequestID:   "req-1",
		ServiceName: " ",
		RouteName:   "get-order",
	})

	attribution, ok := AttributionFromContext(ctx)
	if !ok {
		t.Fatalf("expected attribution in context")
	}
	if attribution.RequestID != "req-1" ||
		attribution.TenantRealm != "tenant-a" ||
		attribution.ServiceName != "orders" ||
		attribution.RouteName != "get-order" ||
		attribution.RoutePath != "/v1/orders/{id}" {
		t.Fatalf("unexpected merged attribution: %+v", attribution)
	}
}

func TestAttributionFromNilContextIsEmpty(t *testing.T) {
	if attribution, ok := AttributionFromContext(nil); ok || attribution != (Attribution{}) {
		t.Fatalf("expected nil context to have no attribution, got %+v", attribution)
	}
}
