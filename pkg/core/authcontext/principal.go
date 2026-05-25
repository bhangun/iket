package authcontext

import (
	"context"
	"time"
)

type principalContextKey struct{}

// Principal is the normalized authenticated identity exposed by auth plugins.
// Plugin-specific claims may still be available through plugin-local accessors.
type Principal struct {
	Source    string
	Subject   string
	UserID    string
	Username  string
	Email     string
	Roles     []string
	Groups    []string
	Scopes    []string
	ClientID  string
	Issuer    string
	Audience  []string
	ExpiresAt *time.Time
	IssuedAt  *time.Time
	Custom    map[string]string
}

func WithPrincipal(ctx context.Context, principal Principal) context.Context {
	principal = clonePrincipal(principal)
	ctx = context.WithValue(ctx, principalContextKey{}, principal)
	if len(principal.Roles) == 0 {
		return ctx
	}
	return WithRoles(ctx, principal.Roles)
}

func PrincipalFromContext(ctx context.Context) (Principal, bool) {
	if ctx == nil {
		return Principal{}, false
	}
	principal, ok := ctx.Value(principalContextKey{}).(Principal)
	if !ok {
		return Principal{}, false
	}
	return clonePrincipal(principal), true
}

func Scopes(ctx context.Context) ([]string, bool) {
	principal, hasPrincipal := PrincipalFromContext(ctx)
	if hasPrincipal {
		return principal.Scopes, true
	}
	if scopes, ok := APIKeyScopes(ctx); ok {
		return scopes, true
	}
	return nil, false
}

func Groups(ctx context.Context) ([]string, bool) {
	principal, hasPrincipal := PrincipalFromContext(ctx)
	if hasPrincipal {
		return principal.Groups, true
	}
	if group, ok := APIKeyGroup(ctx); ok {
		if group == "" {
			return []string{}, true
		}
		return []string{group}, true
	}
	return nil, false
}

func clonePrincipal(principal Principal) Principal {
	principal.Roles = append([]string(nil), principal.Roles...)
	principal.Groups = append([]string(nil), principal.Groups...)
	principal.Scopes = append([]string(nil), principal.Scopes...)
	principal.Audience = append([]string(nil), principal.Audience...)
	principal.ExpiresAt = cloneTime(principal.ExpiresAt)
	principal.IssuedAt = cloneTime(principal.IssuedAt)
	if principal.Custom != nil {
		principal.Custom = cloneStringMap(principal.Custom)
	}
	return principal
}

func cloneTime(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	copied := *value
	return &copied
}

func cloneStringMap(value map[string]string) map[string]string {
	copied := make(map[string]string, len(value))
	for key, item := range value {
		copied[key] = item
	}
	return copied
}
