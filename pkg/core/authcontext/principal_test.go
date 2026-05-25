package authcontext

import (
	"context"
	"reflect"
	"testing"
	"time"
)

func TestWithPrincipalStoresTypedPrincipalAndRoles(t *testing.T) {
	expiresAt := time.Unix(1000, 0).UTC()
	issuedAt := time.Unix(500, 0).UTC()
	ctx := WithPrincipal(context.Background(), Principal{
		Source:    "jwt",
		Subject:   "subject-a",
		UserID:    "user-a",
		Username:  "alice",
		Email:     "alice@example.test",
		Roles:     []string{"admin", "reader"},
		Groups:    []string{"payments"},
		Scopes:    []string{"gateway:read"},
		ClientID:  "client-a",
		Issuer:    "issuer-a",
		Audience:  []string{"audience-a"},
		ExpiresAt: &expiresAt,
		IssuedAt:  &issuedAt,
		Custom:    map[string]string{"tenant": "tenant-a"},
	})

	principal, ok := PrincipalFromContext(ctx)
	if !ok {
		t.Fatalf("expected typed principal")
	}
	if principal.Source != "jwt" || principal.Subject != "subject-a" || principal.UserID != "user-a" {
		t.Fatalf("unexpected principal identity: %+v", principal)
	}
	if !reflect.DeepEqual(principal.Roles, []string{"admin", "reader"}) {
		t.Fatalf("expected principal roles, got %+v", principal.Roles)
	}
	if !reflect.DeepEqual(principal.Groups, []string{"payments"}) {
		t.Fatalf("expected principal groups, got %+v", principal.Groups)
	}
	if !reflect.DeepEqual(principal.Scopes, []string{"gateway:read"}) {
		t.Fatalf("expected principal scopes, got %+v", principal.Scopes)
	}
	if principal.ExpiresAt == nil || !principal.ExpiresAt.Equal(expiresAt) {
		t.Fatalf("expected principal expiration, got %+v", principal.ExpiresAt)
	}
	if principal.IssuedAt == nil || !principal.IssuedAt.Equal(issuedAt) {
		t.Fatalf("expected principal issued-at, got %+v", principal.IssuedAt)
	}
	if !reflect.DeepEqual(principal.Custom, map[string]string{"tenant": "tenant-a"}) {
		t.Fatalf("expected principal custom claims, got %+v", principal.Custom)
	}

	roles, ok := Roles(ctx)
	if !ok || !reflect.DeepEqual(roles, []string{"admin", "reader"}) {
		t.Fatalf("expected principal roles to also populate role context, got %+v ok=%v", roles, ok)
	}
	scopes, ok := Scopes(ctx)
	if !ok || !reflect.DeepEqual(scopes, []string{"gateway:read"}) {
		t.Fatalf("expected principal scopes through generic accessor, got %+v ok=%v", scopes, ok)
	}
	groups, ok := Groups(ctx)
	if !ok || !reflect.DeepEqual(groups, []string{"payments"}) {
		t.Fatalf("expected principal groups through generic accessor, got %+v ok=%v", groups, ok)
	}
}

func TestPrincipalAccessorsFallbackToAPIKeyClient(t *testing.T) {
	ctx := WithAPIKeyClient(context.Background(), APIKeyClient{
		Group:  "billing",
		Scopes: []string{"read", "write"},
	})

	scopes, ok := Scopes(ctx)
	if !ok || !reflect.DeepEqual(scopes, []string{"read", "write"}) {
		t.Fatalf("expected API-key scopes fallback, got %+v ok=%v", scopes, ok)
	}
	groups, ok := Groups(ctx)
	if !ok || !reflect.DeepEqual(groups, []string{"billing"}) {
		t.Fatalf("expected API-key group fallback, got %+v ok=%v", groups, ok)
	}
}

func TestPrincipalAccessorsPreferPrincipalValues(t *testing.T) {
	ctx := WithAPIKeyClient(context.Background(), APIKeyClient{
		Group:  "legacy",
		Scopes: []string{"legacy:read"},
	})
	ctx = WithPrincipal(ctx, Principal{
		Groups: []string{"principal"},
		Scopes: []string{"principal:read"},
	})

	scopes, ok := Scopes(ctx)
	if !ok || !reflect.DeepEqual(scopes, []string{"principal:read"}) {
		t.Fatalf("expected principal scopes to win, got %+v ok=%v", scopes, ok)
	}
	groups, ok := Groups(ctx)
	if !ok || !reflect.DeepEqual(groups, []string{"principal"}) {
		t.Fatalf("expected principal groups to win, got %+v ok=%v", groups, ok)
	}
}

func TestPrincipalAccessorsDoNotFallbackWhenPrincipalHasNoScopesOrGroups(t *testing.T) {
	ctx := WithAPIKeyClient(context.Background(), APIKeyClient{
		Group:  "legacy",
		Scopes: []string{"legacy:read"},
	})
	ctx = WithPrincipal(ctx, Principal{
		Source: "mtls",
		UserID: "client-a",
	})

	scopes, ok := Scopes(ctx)
	if !ok || len(scopes) != 0 {
		t.Fatalf("expected empty principal scopes to be authoritative, got %+v ok=%v", scopes, ok)
	}
	groups, ok := Groups(ctx)
	if !ok || len(groups) != 0 {
		t.Fatalf("expected empty principal groups to be authoritative, got %+v ok=%v", groups, ok)
	}
}

func TestWithPrincipalWithoutRolesDoesNotOverwriteExistingRoles(t *testing.T) {
	ctx := WithRoles(context.Background(), []string{"admin"})
	ctx = WithPrincipal(ctx, Principal{
		Source: "apikey",
		UserID: "client-a",
	})

	roles, ok := Roles(ctx)
	if !ok || !reflect.DeepEqual(roles, []string{"admin"}) {
		t.Fatalf("expected existing roles to be preserved, got %+v ok=%v", roles, ok)
	}
}

func TestWithPrincipalWithoutRolesDoesNotInventRoleContext(t *testing.T) {
	ctx := WithPrincipal(context.Background(), Principal{
		Source: "mtls",
		UserID: "client-a",
	})

	if roles, ok := Roles(ctx); ok {
		t.Fatalf("expected no role context for role-less principal, got %+v", roles)
	}
}

func TestPrincipalFromContextReturnsDeepCopy(t *testing.T) {
	expiresAt := time.Unix(1000, 0).UTC()
	ctx := WithPrincipal(context.Background(), Principal{
		Roles:     []string{"reader"},
		Groups:    []string{"payments"},
		Scopes:    []string{"gateway:read"},
		Audience:  []string{"audience-a"},
		ExpiresAt: &expiresAt,
		Custom:    map[string]string{"tenant": "tenant-a"},
	})

	principal, ok := PrincipalFromContext(ctx)
	if !ok {
		t.Fatalf("expected typed principal")
	}
	principal.Roles[0] = "mutated"
	principal.Groups[0] = "mutated"
	principal.Scopes[0] = "mutated"
	principal.Audience[0] = "mutated"
	principal.ExpiresAt = nil
	principal.Custom["tenant"] = "mutated"

	again, ok := PrincipalFromContext(ctx)
	if !ok {
		t.Fatalf("expected typed principal")
	}
	if !reflect.DeepEqual(again.Roles, []string{"reader"}) {
		t.Fatalf("expected roles to be immutable from callers, got %+v", again.Roles)
	}
	if !reflect.DeepEqual(again.Groups, []string{"payments"}) {
		t.Fatalf("expected groups to be immutable from callers, got %+v", again.Groups)
	}
	if !reflect.DeepEqual(again.Scopes, []string{"gateway:read"}) {
		t.Fatalf("expected scopes to be immutable from callers, got %+v", again.Scopes)
	}
	if !reflect.DeepEqual(again.Audience, []string{"audience-a"}) {
		t.Fatalf("expected audience to be immutable from callers, got %+v", again.Audience)
	}
	if again.ExpiresAt == nil || !again.ExpiresAt.Equal(expiresAt) {
		t.Fatalf("expected expiration to be immutable from callers, got %+v", again.ExpiresAt)
	}
	if !reflect.DeepEqual(again.Custom, map[string]string{"tenant": "tenant-a"}) {
		t.Fatalf("expected custom claims to be immutable from callers, got %+v", again.Custom)
	}
}

func TestPrincipalFromContextReturnsFalseWhenMissing(t *testing.T) {
	if principal, ok := PrincipalFromContext(context.Background()); ok {
		t.Fatalf("expected no principal, got %+v", principal)
	}
	if principal, ok := PrincipalFromContext(nil); ok {
		t.Fatalf("expected no principal for nil context, got %+v", principal)
	}
}
