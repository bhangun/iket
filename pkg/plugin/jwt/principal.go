package jwt

import (
	"time"

	"github.com/bhangun/iket/pkg/core/authcontext"
	jwtlib "github.com/golang-jwt/jwt/v4"
)

func principalFromClaims(claims *Claims) authcontext.Principal {
	if claims == nil {
		return authcontext.Principal{Source: "jwt"}
	}
	subject := claims.Subject
	if subject == "" {
		subject = claims.UserID
	}
	return authcontext.Principal{
		Source:    "jwt",
		Subject:   subject,
		UserID:    claims.UserID,
		Username:  claims.Username,
		Email:     claims.Email,
		Roles:     claims.Roles,
		Issuer:    claims.Issuer,
		Audience:  []string(claims.Audience),
		ExpiresAt: timeFromNumericDate(claims.ExpiresAt),
		IssuedAt:  timeFromNumericDate(claims.IssuedAt),
		Custom:    claims.Custom,
	}
}

func timeFromNumericDate(value *jwtlib.NumericDate) *time.Time {
	if value == nil {
		return nil
	}
	copied := value.Time
	return &copied
}
