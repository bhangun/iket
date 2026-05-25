package authcontext

import (
	"context"
	"testing"
)

func TestHasAnyRoleMatchesPrincipalRoles(t *testing.T) {
	ctx := WithPrincipal(context.Background(), Principal{
		Roles: []string{"admin", "reader"},
	})

	matched, present := HasAnyRole(ctx, []string{"operator", "reader"})
	if !present || !matched {
		t.Fatalf("expected role match, matched=%v present=%v", matched, present)
	}
}

func TestHasAnyRoleReportsMissingAndInsufficient(t *testing.T) {
	matched, present := HasAnyRole(context.Background(), []string{"admin"})
	if present || matched {
		t.Fatalf("expected missing roles, matched=%v present=%v", matched, present)
	}

	ctx := WithRoles(context.Background(), []string{"reader"})
	matched, present = HasAnyRole(ctx, []string{"admin"})
	if !present || matched {
		t.Fatalf("expected insufficient roles, matched=%v present=%v", matched, present)
	}
}

func TestHasAnyScopeMatchesPrincipalScopes(t *testing.T) {
	ctx := WithPrincipal(context.Background(), Principal{
		Scopes: []string{"orders:read", "orders:write"},
	})

	matched, present := HasAnyScope(ctx, []string{"orders:delete", "orders:write"})
	if !present || !matched {
		t.Fatalf("expected scope match, matched=%v present=%v", matched, present)
	}
}

func TestHasAnyScopeFallsBackToAPIKeyScopes(t *testing.T) {
	ctx := WithAPIKeyClient(context.Background(), APIKeyClient{
		Scopes: []string{"orders:read"},
	})

	matched, present := HasAnyScope(ctx, []string{"orders:read"})
	if !present || !matched {
		t.Fatalf("expected API-key scope fallback match, matched=%v present=%v", matched, present)
	}
}

func TestHasAnyScopeDoesNotFallbackWhenPrincipalHasNoScopes(t *testing.T) {
	ctx := WithAPIKeyClient(context.Background(), APIKeyClient{
		Scopes: []string{"orders:read"},
	})
	ctx = WithPrincipal(ctx, Principal{
		Source: "mtls",
		UserID: "client-a",
	})

	matched, present := HasAnyScope(ctx, []string{"orders:read"})
	if present || matched {
		t.Fatalf("expected principal without scopes to block API-key fallback, matched=%v present=%v", matched, present)
	}
}

func TestHasAnyScopeReportsMissingAndInsufficient(t *testing.T) {
	matched, present := HasAnyScope(context.Background(), []string{"orders:read"})
	if present || matched {
		t.Fatalf("expected missing scopes, matched=%v present=%v", matched, present)
	}

	ctx := WithPrincipal(context.Background(), Principal{
		Scopes: []string{"orders:read"},
	})
	matched, present = HasAnyScope(ctx, []string{"orders:write"})
	if !present || matched {
		t.Fatalf("expected insufficient scopes, matched=%v present=%v", matched, present)
	}
}

func TestHasGroupMatchesPrincipalGroups(t *testing.T) {
	ctx := WithPrincipal(context.Background(), Principal{
		Groups: []string{"billing", "ops"},
	})

	matched, present := HasGroup(ctx, "ops")
	if !present || !matched {
		t.Fatalf("expected group match, matched=%v present=%v", matched, present)
	}
}

func TestHasGroupFallsBackToAPIKeyGroup(t *testing.T) {
	ctx := WithAPIKeyClient(context.Background(), APIKeyClient{
		Group: "billing",
	})

	matched, present := HasGroup(ctx, "billing")
	if !present || !matched {
		t.Fatalf("expected API-key group fallback match, matched=%v present=%v", matched, present)
	}
}

func TestHasGroupDoesNotFallbackWhenPrincipalHasNoGroups(t *testing.T) {
	ctx := WithAPIKeyClient(context.Background(), APIKeyClient{
		Group: "billing",
	})
	ctx = WithPrincipal(ctx, Principal{
		Source: "jwt",
		UserID: "user-a",
	})

	matched, present := HasGroup(ctx, "billing")
	if present || matched {
		t.Fatalf("expected principal without groups to block API-key fallback, matched=%v present=%v", matched, present)
	}
}

func TestHasGroupReportsMissingAndInsufficient(t *testing.T) {
	matched, present := HasGroup(context.Background(), "billing")
	if present || matched {
		t.Fatalf("expected missing groups, matched=%v present=%v", matched, present)
	}

	ctx := WithPrincipal(context.Background(), Principal{
		Groups: []string{"ops"},
	})
	matched, present = HasGroup(ctx, "billing")
	if !present || matched {
		t.Fatalf("expected group mismatch, matched=%v present=%v", matched, present)
	}
}
