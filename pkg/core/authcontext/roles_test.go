package authcontext

import (
	"context"
	"reflect"
	"testing"
)

func TestWithRolesStoresTypedAndLegacyValues(t *testing.T) {
	ctx := WithRoles(context.Background(), []string{"admin", "reader"})

	roles, ok := Roles(ctx)
	if !ok || !reflect.DeepEqual(roles, []string{"admin", "reader"}) {
		t.Fatalf("expected typed roles, got %+v ok=%v", roles, ok)
	}
	if got := ctx.Value(legacyRolesKey); !reflect.DeepEqual(got, []string{"admin", "reader"}) {
		t.Fatalf("expected legacy roles, got %+v", got)
	}
}

func TestRolesFallsBackToLegacyValues(t *testing.T) {
	ctx := context.WithValue(context.Background(), legacyRolesKey, []string{"operator"})

	roles, ok := Roles(ctx)
	if !ok || !reflect.DeepEqual(roles, []string{"operator"}) {
		t.Fatalf("expected legacy roles fallback, got %+v ok=%v", roles, ok)
	}
}

func TestRolesReturnsCopy(t *testing.T) {
	ctx := WithRoles(context.Background(), []string{"reader"})

	roles, ok := Roles(ctx)
	if !ok {
		t.Fatalf("expected roles")
	}
	roles[0] = "mutated"

	again, ok := Roles(ctx)
	if !ok || !reflect.DeepEqual(again, []string{"reader"}) {
		t.Fatalf("expected roles to be immutable from callers, got %+v ok=%v", again, ok)
	}
}
