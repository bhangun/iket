package authcontext

import (
	"context"
	"strings"
)

const (
	PrincipalIdentityClient   = "client"
	PrincipalIdentitySubject  = "subject"
	PrincipalIdentityUser     = "user"
	PrincipalIdentityUsername = "username"
	PrincipalIdentityEmail    = "email"
)

// PrincipalIdentity is the stable identity selected from an authenticated
// principal for attribution, billing, and limiter buckets.
type PrincipalIdentity struct {
	Kind      string `json:"kind,omitempty"`
	Source    string `json:"source,omitempty"`
	Value     string `json:"value,omitempty"`
	Sensitive bool   `json:"sensitive,omitempty"`
}

func PrincipalIdentityFromContext(ctx context.Context) (PrincipalIdentity, bool) {
	if principal, ok := PrincipalFromContext(ctx); ok {
		if identity, ok := PrincipalIdentityFromPrincipal(principal); ok {
			return identity, true
		}
	}
	if client, ok := APIKeyClientFromContext(ctx); ok {
		if id := strings.TrimSpace(client.ID); id != "" {
			return PrincipalIdentity{Kind: PrincipalIdentityClient, Value: id}, true
		}
	}
	return PrincipalIdentity{}, false
}

func PrincipalIdentityFromPrincipal(principal Principal) (PrincipalIdentity, bool) {
	source := strings.ToLower(strings.TrimSpace(principal.Source))
	if clientID := strings.TrimSpace(principal.ClientID); clientID != "" {
		return PrincipalIdentity{Kind: PrincipalIdentityClient, Source: source, Value: clientID}, true
	}
	if subject := strings.TrimSpace(principal.Subject); subject != "" {
		return PrincipalIdentity{Kind: PrincipalIdentitySubject, Source: source, Value: subject}, true
	}
	if userID := strings.TrimSpace(principal.UserID); userID != "" {
		return PrincipalIdentity{Kind: PrincipalIdentityUser, Source: source, Value: userID}, true
	}
	if username := strings.TrimSpace(principal.Username); username != "" {
		return PrincipalIdentity{Kind: PrincipalIdentityUsername, Source: source, Value: username}, true
	}
	if email := strings.ToLower(strings.TrimSpace(principal.Email)); email != "" {
		return PrincipalIdentity{Kind: PrincipalIdentityEmail, Source: source, Value: email, Sensitive: true}, true
	}
	return PrincipalIdentity{}, false
}
