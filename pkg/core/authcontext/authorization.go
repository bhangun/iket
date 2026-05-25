package authcontext

import "context"

func HasAnyRole(ctx context.Context, requiredRoles []string) (bool, bool) {
	roles, ok := Roles(ctx)
	if !ok || len(roles) == 0 {
		return false, false
	}
	if len(requiredRoles) == 0 {
		return true, true
	}
	return containsAny(roles, requiredRoles), true
}

func HasAnyScope(ctx context.Context, requiredScopes []string) (bool, bool) {
	scopes, ok := Scopes(ctx)
	if !ok || len(scopes) == 0 {
		return false, false
	}
	if len(requiredScopes) == 0 {
		return true, true
	}
	return containsAny(scopes, requiredScopes), true
}

func HasGroup(ctx context.Context, requiredGroup string) (bool, bool) {
	groups, ok := Groups(ctx)
	if !ok || len(groups) == 0 {
		return false, false
	}
	if requiredGroup == "" {
		return true, true
	}
	return contains(groups, requiredGroup), true
}

func containsAny(actual []string, required []string) bool {
	for _, requiredValue := range required {
		if contains(actual, requiredValue) {
			return true
		}
	}
	return false
}

func contains(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}
