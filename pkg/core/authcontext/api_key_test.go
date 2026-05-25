package authcontext

import (
	"context"
	"reflect"
	"testing"
)

func TestWithAPIKeyClientStoresTypedAndLegacyValues(t *testing.T) {
	ctx := WithAPIKeyClient(context.Background(), APIKeyClient{
		ID:     "client-a",
		Group:  "billing",
		Scopes: []string{"read", "write"},
	})

	id, ok := APIKeyClientID(ctx)
	if !ok || id != "client-a" {
		t.Fatalf("expected typed client id, got %q ok=%v", id, ok)
	}
	group, ok := APIKeyGroup(ctx)
	if !ok || group != "billing" {
		t.Fatalf("expected typed client group, got %q ok=%v", group, ok)
	}
	scopes, ok := APIKeyScopes(ctx)
	if !ok || !reflect.DeepEqual(scopes, []string{"read", "write"}) {
		t.Fatalf("expected typed client scopes, got %+v ok=%v", scopes, ok)
	}
	if got := ctx.Value(legacyAPIKeyClientIDKey); got != "client-a" {
		t.Fatalf("expected legacy client id, got %v", got)
	}
	if got := ctx.Value(legacyAPIKeyGroupKey); got != "billing" {
		t.Fatalf("expected legacy client group, got %v", got)
	}
	if got := ctx.Value(legacyAPIKeyScopesKey); !reflect.DeepEqual(got, []string{"read", "write"}) {
		t.Fatalf("expected legacy client scopes, got %+v", got)
	}
}

func TestAPIKeyClientFromContextFallsBackToLegacyValues(t *testing.T) {
	ctx := context.WithValue(context.Background(), legacyAPIKeyClientIDKey, "client-a")
	ctx = context.WithValue(ctx, legacyAPIKeyGroupKey, "ops")
	ctx = context.WithValue(ctx, legacyAPIKeyScopesKey, []string{"read"})

	client, ok := APIKeyClientFromContext(ctx)
	if !ok {
		t.Fatalf("expected legacy context values to be recognized")
	}
	if client.ID != "client-a" || client.Group != "ops" || !reflect.DeepEqual(client.Scopes, []string{"read"}) {
		t.Fatalf("unexpected legacy client context: %+v", client)
	}
}

func TestAPIKeyClientFromContextReturnsScopeCopy(t *testing.T) {
	ctx := WithAPIKeyClient(context.Background(), APIKeyClient{Scopes: []string{"read"}})
	scopes, ok := APIKeyScopes(ctx)
	if !ok {
		t.Fatalf("expected scopes")
	}
	scopes[0] = "mutated"

	again, ok := APIKeyScopes(ctx)
	if !ok || !reflect.DeepEqual(again, []string{"read"}) {
		t.Fatalf("expected context scopes to be immutable from callers, got %+v ok=%v", again, ok)
	}
}
