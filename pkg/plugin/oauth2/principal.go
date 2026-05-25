package oauth2

import (
	"strings"
	"time"

	"github.com/bhangun/iket/pkg/core/authcontext"
)

func principalFromClaims(claims *Claims) authcontext.Principal {
	if claims == nil {
		return authcontext.Principal{Source: "oauth2"}
	}
	return authcontext.Principal{
		Source:    "oauth2",
		Subject:   claims.UserID,
		UserID:    claims.UserID,
		Username:  claims.Username,
		Email:     claims.Email,
		Roles:     claims.Roles,
		Scopes:    strings.Fields(claims.Scope),
		ClientID:  claims.ClientID,
		Issuer:    claims.Issuer,
		Audience:  claims.Audience,
		ExpiresAt: unixTime(claims.Expires),
		IssuedAt:  unixTime(claims.IssuedAt),
		Custom:    claims.Custom,
	}
}

func unixTime(seconds int64) *time.Time {
	if seconds <= 0 {
		return nil
	}
	value := time.Unix(seconds, 0).UTC()
	return &value
}
