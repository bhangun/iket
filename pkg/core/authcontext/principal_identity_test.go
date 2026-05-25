package authcontext

import (
	"context"
	"reflect"
	"testing"
)

func TestPrincipalIdentityFromPrincipalPrefersClientID(t *testing.T) {
	identity, ok := PrincipalIdentityFromPrincipal(Principal{
		Source:   "oauth2",
		ClientID: "client-a",
		Subject:  "subject-a",
		UserID:   "user-a",
	})
	if !ok {
		t.Fatalf("expected principal identity")
	}
	expected := PrincipalIdentity{
		Kind:   PrincipalIdentityClient,
		Source: "oauth2",
		Value:  "client-a",
	}
	if !reflect.DeepEqual(identity, expected) {
		t.Fatalf("expected client identity, got %+v", identity)
	}
}

func TestPrincipalIdentityFromPrincipalUsesQualifiedSubject(t *testing.T) {
	identity, ok := PrincipalIdentityFromPrincipal(Principal{
		Source:  "jwt",
		Subject: "subject-a",
	})
	if !ok {
		t.Fatalf("expected principal identity")
	}
	expected := PrincipalIdentity{
		Kind:   PrincipalIdentitySubject,
		Source: "jwt",
		Value:  "subject-a",
	}
	if !reflect.DeepEqual(identity, expected) {
		t.Fatalf("expected subject identity, got %+v", identity)
	}
}

func TestPrincipalIdentityFromPrincipalMarksEmailSensitive(t *testing.T) {
	identity, ok := PrincipalIdentityFromPrincipal(Principal{
		Source: "jwt",
		Email:  "User@Example.COM",
	})
	if !ok {
		t.Fatalf("expected principal identity")
	}
	expected := PrincipalIdentity{
		Kind:      PrincipalIdentityEmail,
		Source:    "jwt",
		Value:     "user@example.com",
		Sensitive: true,
	}
	if !reflect.DeepEqual(identity, expected) {
		t.Fatalf("expected sensitive email identity, got %+v", identity)
	}
}

func TestPrincipalIdentityFromContextFallsBackToAPIKeyClient(t *testing.T) {
	ctx := WithAPIKeyClient(context.Background(), APIKeyClient{ID: "client-a"})

	identity, ok := PrincipalIdentityFromContext(ctx)
	if !ok {
		t.Fatalf("expected API-key client fallback identity")
	}
	expected := PrincipalIdentity{
		Kind:  PrincipalIdentityClient,
		Value: "client-a",
	}
	if !reflect.DeepEqual(identity, expected) {
		t.Fatalf("expected API-key client identity, got %+v", identity)
	}
}

func TestPrincipalIdentityFromContextFallsBackWhenPrincipalHasNoIdentity(t *testing.T) {
	ctx := WithAPIKeyClient(context.Background(), APIKeyClient{ID: "client-a"})
	ctx = WithPrincipal(ctx, Principal{Source: "jwt"})

	identity, ok := PrincipalIdentityFromContext(ctx)
	if !ok {
		t.Fatalf("expected API-key client fallback identity")
	}
	if identity.Kind != PrincipalIdentityClient || identity.Value != "client-a" {
		t.Fatalf("expected API-key client identity fallback, got %+v", identity)
	}
}

func TestPrincipalIdentityFromContextReturnsFalseWhenMissing(t *testing.T) {
	if identity, ok := PrincipalIdentityFromContext(context.Background()); ok {
		t.Fatalf("expected no identity, got %+v", identity)
	}
	if identity, ok := PrincipalIdentityFromContext(nil); ok {
		t.Fatalf("expected no identity for nil context, got %+v", identity)
	}
}
