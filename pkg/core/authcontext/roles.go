package authcontext

import "context"

const legacyRolesKey = "roles"

type rolesContextKey struct{}

// WithRoles stores authenticated role metadata with a typed key. It also
// writes the legacy "roles" key so existing middleware/plugins keep working.
func WithRoles(ctx context.Context, roles []string) context.Context {
	roles = append([]string(nil), roles...)
	ctx = context.WithValue(ctx, rolesContextKey{}, roles)
	ctx = context.WithValue(ctx, legacyRolesKey, append([]string(nil), roles...))
	return ctx
}

func Roles(ctx context.Context) ([]string, bool) {
	if ctx == nil {
		return nil, false
	}
	if roles, ok := ctx.Value(rolesContextKey{}).([]string); ok {
		return append([]string(nil), roles...), true
	}
	if roles, ok := ctx.Value(legacyRolesKey).([]string); ok {
		return append([]string(nil), roles...), true
	}
	return nil, false
}
