package gateway

import (
	"fmt"
	"strings"
	"time"

	"github.com/bhangun/iket/pkg/core/authcontext"
	"github.com/golang-jwt/jwt/v4"
)

func principalFromMapClaims(claims jwt.MapClaims) authcontext.Principal {
	subject := stringClaim(claims, "sub")
	userID := firstNonEmpty(stringClaim(claims, "user_id"), subject)
	return authcontext.Principal{
		Source:    "jwt",
		Subject:   subject,
		UserID:    userID,
		Username:  firstNonEmpty(stringClaim(claims, "username"), stringClaim(claims, "preferred_username"), stringClaim(claims, "name")),
		Email:     stringClaim(claims, "email"),
		Roles:     stringListClaim(claims, "roles", "role"),
		Groups:    stringListClaim(claims, "groups", "group"),
		Scopes:    scopesFromMapClaims(claims),
		ClientID:  firstNonEmpty(stringClaim(claims, "client_id"), stringClaim(claims, "azp")),
		Issuer:    stringClaim(claims, "iss"),
		Audience:  stringListClaim(claims, "aud"),
		ExpiresAt: unixClaimTime(claims, "exp"),
		IssuedAt:  unixClaimTime(claims, "iat"),
	}
}

func scopesFromMapClaims(claims jwt.MapClaims) []string {
	scopes := stringListClaim(claims, "scopes")
	if len(scopes) > 0 {
		return scopes
	}
	return strings.Fields(stringClaim(claims, "scope"))
}

func stringClaim(claims jwt.MapClaims, key string) string {
	value, ok := claims[key]
	if !ok || value == nil {
		return ""
	}
	switch typed := value.(type) {
	case string:
		return strings.TrimSpace(typed)
	case fmt.Stringer:
		return strings.TrimSpace(typed.String())
	default:
		rendered := strings.TrimSpace(fmt.Sprintf("%v", typed))
		if rendered == "<nil>" {
			return ""
		}
		return rendered
	}
}

func stringListClaim(claims jwt.MapClaims, keys ...string) []string {
	for _, key := range keys {
		if values := stringListValue(claims[key]); len(values) > 0 {
			return values
		}
	}
	return nil
}

func stringListValue(value interface{}) []string {
	switch typed := value.(type) {
	case nil:
		return nil
	case string:
		return strings.Fields(typed)
	case []string:
		return trimmedStrings(typed)
	case []interface{}:
		values := make([]string, 0, len(typed))
		for _, item := range typed {
			if value := strings.TrimSpace(fmt.Sprintf("%v", item)); value != "" && value != "<nil>" {
				values = append(values, value)
			}
		}
		return values
	default:
		if value := strings.TrimSpace(fmt.Sprintf("%v", typed)); value != "" && value != "<nil>" {
			return []string{value}
		}
		return nil
	}
}

func trimmedStrings(values []string) []string {
	trimmed := make([]string, 0, len(values))
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			trimmed = append(trimmed, value)
		}
	}
	return trimmed
}

func unixClaimTime(claims jwt.MapClaims, key string) *time.Time {
	seconds, ok := numericClaim(claims[key])
	if !ok || seconds <= 0 {
		return nil
	}
	value := time.Unix(int64(seconds), 0).UTC()
	return &value
}

func numericClaim(value interface{}) (float64, bool) {
	switch typed := value.(type) {
	case float64:
		return typed, true
	case float32:
		return float64(typed), true
	case int:
		return float64(typed), true
	case int64:
		return float64(typed), true
	case jsonNumber:
		parsed, err := typed.Float64()
		return parsed, err == nil
	default:
		return 0, false
	}
}

type jsonNumber interface {
	Float64() (float64, error)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
