package gateway

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bhangun/iket/pkg/config"
	"github.com/bhangun/iket/pkg/core/authcontext"
	"github.com/bhangun/iket/pkg/core/credentials"
	"github.com/golang-jwt/jwt/v4"
)

func TestResolveRouteRateLimitKeyUsesAPIKeyPrincipalIdentity(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-API-Key", "raw-secret")
	req = req.WithContext(authcontext.WithPrincipal(req.Context(), authcontext.Principal{
		Source:   "apikey",
		ClientID: "client-a",
		Custom:   map[string]string{"key_fingerprint": "fp-secret"},
	}))

	keyType, bucketKey := resolveRouteRateLimitKey(req, &config.RateLimitPolicyConfig{KeyBy: "api_key"})
	if keyType != "api_key" || bucketKey != "apikey:client-a" {
		t.Fatalf("expected API-key principal bucket, got %s %s", keyType, bucketKey)
	}
}

func TestResolveRouteRateLimitKeyUsesAPIKeyFingerprintWhenIdentityMissing(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req = req.WithContext(authcontext.WithPrincipal(req.Context(), authcontext.Principal{
		Source: "apikey",
		Custom: map[string]string{"key_fingerprint": "fp-secret"},
	}))

	keyType, bucketKey := resolveRouteRateLimitKey(req, &config.RateLimitPolicyConfig{KeyBy: "api_key"})
	if keyType != "api_key" || bucketKey != "apikey_fingerprint:fp-secret" {
		t.Fatalf("expected API-key fingerprint bucket, got %s %s", keyType, bucketKey)
	}
}

func TestResolveRouteRateLimitKeyUsesClientCredentialPrincipalIdentity(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.SetBasicAuth("client-a", "secret")
	req = req.WithContext(authcontext.WithPrincipal(req.Context(), authcontext.Principal{
		Source:   "client_credentials",
		ClientID: "client-a",
	}))

	keyType, bucketKey := resolveRouteRateLimitKey(req, &config.RateLimitPolicyConfig{KeyBy: "api_key"})
	if keyType != "api_key" || bucketKey != "basic:client-a" {
		t.Fatalf("expected client credentials principal bucket, got %s %s", keyType, bucketKey)
	}
}

func TestResolveRouteRateLimitKeyFallsBackToRawAPIKeyInputs(t *testing.T) {
	t.Run("basic", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.SetBasicAuth("client-a", "secret")

		keyType, bucketKey := resolveRouteRateLimitKey(req, &config.RateLimitPolicyConfig{KeyBy: "api_key"})
		if keyType != "api_key" || bucketKey != "basic:client-a" {
			t.Fatalf("expected basic fallback bucket, got %s %s", keyType, bucketKey)
		}
	})

	t.Run("header", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("X-API-Key", "raw-secret")

		keyType, bucketKey := resolveRouteRateLimitKey(req, &config.RateLimitPolicyConfig{KeyBy: "api_key"})
		expected := "apikey_fingerprint:" + credentials.APIKeyFingerprint("raw-secret")
		if keyType != "api_key" || bucketKey != expected {
			t.Fatalf("expected header fallback bucket, got %s %s", keyType, bucketKey)
		}
		if strings.Contains(bucketKey, "raw-secret") {
			t.Fatalf("expected header fallback bucket to avoid raw secret, got %s", bucketKey)
		}
	})
}

func TestResolveRouteRateLimitKeyKeepsNonSensitiveHeaderBucketReadable(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Tenant", "tenant-a")

	keyType, bucketKey := resolveRouteRateLimitKey(req, &config.RateLimitPolicyConfig{
		KeyBy:     "header",
		KeyHeader: "X-Tenant",
	})
	if keyType != "header" || bucketKey != "x-tenant:tenant-a" {
		t.Fatalf("expected readable header bucket, got %s %s", keyType, bucketKey)
	}
}

func TestResolveRouteRateLimitKeyFingerprintsSensitiveHeaderBucket(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer raw-secret")

	keyType, bucketKey := resolveRouteRateLimitKey(req, &config.RateLimitPolicyConfig{
		KeyBy:     "header",
		KeyHeader: "Authorization",
	})
	expected := "authorization:fingerprint:" + credentials.APIKeyFingerprint("Bearer raw-secret")
	if keyType != "header" || bucketKey != expected {
		t.Fatalf("expected fingerprinted sensitive header bucket, got %s %s", keyType, bucketKey)
	}
	if strings.Contains(bucketKey, "raw-secret") || strings.Contains(bucketKey, "Bearer") {
		t.Fatalf("expected sensitive header bucket to avoid raw credential, got %s", bucketKey)
	}
}

func TestResolveRouteConcurrencyKeyUsesSharedSensitiveHeaderBucket(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-API-Key", "raw-secret")

	keyType, bucketKey := resolveRouteConcurrencyKey(req, &config.ConcurrencyLimitPolicyConfig{
		KeyBy:     "header",
		KeyHeader: "X-API-Key",
	})
	expected := "x-api-key:fingerprint:" + credentials.APIKeyFingerprint("raw-secret")
	if keyType != "header" || bucketKey != expected {
		t.Fatalf("expected shared sensitive header bucket, got %s %s", keyType, bucketKey)
	}
}

func TestResolveRouteRateLimitKeyUsesPrincipalClientIdentity(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req = req.WithContext(authcontext.WithPrincipal(req.Context(), authcontext.Principal{
		Source:   "oauth2",
		ClientID: "client-a",
		Subject:  "user-a",
	}))

	keyType, bucketKey := resolveRouteRateLimitKey(req, &config.RateLimitPolicyConfig{KeyBy: "principal"})
	if keyType != "principal" || bucketKey != "client:client-a" {
		t.Fatalf("expected principal client bucket, got %s %s", keyType, bucketKey)
	}
}

func TestResolveRouteConcurrencyKeyUsesPrincipalSubjectIdentity(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req = req.WithContext(authcontext.WithPrincipal(req.Context(), authcontext.Principal{
		Source:  "jwt",
		Subject: "subject-a",
	}))

	keyType, bucketKey := resolveRouteConcurrencyKey(req, &config.ConcurrencyLimitPolicyConfig{KeyBy: "principal"})
	if keyType != "principal" || bucketKey != "subject:jwt:subject-a" {
		t.Fatalf("expected principal subject bucket, got %s %s", keyType, bucketKey)
	}
}

func TestResolveRouteRateLimitKeyFingerprintsPrincipalEmailIdentity(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req = req.WithContext(authcontext.WithPrincipal(req.Context(), authcontext.Principal{
		Source: "jwt",
		Email:  "User@Example.COM",
	}))

	keyType, bucketKey := resolveRouteRateLimitKey(req, &config.RateLimitPolicyConfig{KeyBy: "principal"})
	expected := "email_fingerprint:" + credentials.APIKeyFingerprint("user@example.com")
	if keyType != "principal" || bucketKey != expected {
		t.Fatalf("expected principal email fingerprint bucket, got %s %s", keyType, bucketKey)
	}
	if strings.Contains(bucketKey, "User") || strings.Contains(bucketKey, "example.com") {
		t.Fatalf("expected principal email bucket to avoid raw email, got %s", bucketKey)
	}
}

func TestResolveRouteRateLimitKeyUsesLegacyAPIKeyClientForPrincipalIdentity(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req = req.WithContext(authcontext.WithAPIKeyClient(req.Context(), authcontext.APIKeyClient{
		ID: "client-a",
	}))

	keyType, bucketKey := resolveRouteRateLimitKey(req, &config.RateLimitPolicyConfig{KeyBy: "principal"})
	if keyType != "principal" || bucketKey != "client:client-a" {
		t.Fatalf("expected legacy API-key client principal bucket, got %s %s", keyType, bucketKey)
	}
}

func TestResolveRouteRateLimitKeyMarksMissingPrincipalIdentity(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	keyType, bucketKey := resolveRouteRateLimitKey(req, &config.RateLimitPolicyConfig{KeyBy: "principal"})
	if keyType != "principal" || bucketKey != "__missing__" {
		t.Fatalf("expected missing principal bucket, got %s %s", keyType, bucketKey)
	}
}

func TestResolveRouteConcurrencyKeyUsesAPIKeyPrincipalIdentity(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-API-Key", "raw-secret")
	req = req.WithContext(authcontext.WithPrincipal(req.Context(), authcontext.Principal{
		Source:   "apikey",
		ClientID: "client-a",
	}))

	keyType, bucketKey := resolveRouteConcurrencyKey(req, &config.ConcurrencyLimitPolicyConfig{KeyBy: "api_key"})
	if keyType != "api_key" || bucketKey != "apikey:client-a" {
		t.Fatalf("expected API-key principal concurrency bucket, got %s %s", keyType, bucketKey)
	}
}

func TestResolveRouteRateLimitKeyUsesJWTPrincipalSubject(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req = req.WithContext(authcontext.WithPrincipal(req.Context(), authcontext.Principal{
		Source:  "jwt",
		Subject: "subject-a",
	}))

	keyType, bucketKey := resolveRouteRateLimitKey(req, &config.RateLimitPolicyConfig{KeyBy: "jwt_sub"})
	if keyType != "jwt_sub" || bucketKey != "subject-a" {
		t.Fatalf("expected JWT principal subject bucket, got %s %s", keyType, bucketKey)
	}
}

func TestResolveRouteRateLimitKeyUsesOAuth2PrincipalSubject(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req = req.WithContext(authcontext.WithPrincipal(req.Context(), authcontext.Principal{
		Source:  "oauth2",
		Subject: "user-a",
	}))

	keyType, bucketKey := resolveRouteRateLimitKey(req, &config.RateLimitPolicyConfig{KeyBy: "jwt_sub"})
	if keyType != "jwt_sub" || bucketKey != "user-a" {
		t.Fatalf("expected OAuth2 principal subject bucket, got %s %s", keyType, bucketKey)
	}
}

func TestResolveRouteRateLimitKeyFallsBackToRawJWTClaims(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	ctx := context.WithValue(req.Context(), jwtClaimsKey, jwt.MapClaims{"sub": "legacy-subject"})
	req = req.WithContext(ctx)

	keyType, bucketKey := resolveRouteRateLimitKey(req, &config.RateLimitPolicyConfig{KeyBy: "jwt_sub"})
	if keyType != "jwt_sub" || bucketKey != "legacy-subject" {
		t.Fatalf("expected raw JWT claims bucket, got %s %s", keyType, bucketKey)
	}
}

func TestResolveRouteRateLimitKeyDoesNotUseNonJWTPrincipals(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req = req.WithContext(authcontext.WithPrincipal(req.Context(), authcontext.Principal{
		Source:  "apikey",
		Subject: "client-a",
	}))

	keyType, bucketKey := resolveRouteRateLimitKey(req, &config.RateLimitPolicyConfig{KeyBy: "jwt_sub"})
	if keyType != "jwt_sub" || bucketKey != "__missing__" {
		t.Fatalf("expected non-JWT principal to be ignored, got %s %s", keyType, bucketKey)
	}
}

func TestResolveRouteConcurrencyKeyUsesJWTPrincipalSubject(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req = req.WithContext(authcontext.WithPrincipal(req.Context(), authcontext.Principal{
		Source:  "jwt",
		Subject: "subject-a",
	}))

	keyType, bucketKey := resolveRouteConcurrencyKey(req, &config.ConcurrencyLimitPolicyConfig{KeyBy: "jwt_sub"})
	if keyType != "jwt_sub" || bucketKey != "subject-a" {
		t.Fatalf("expected JWT principal subject concurrency bucket, got %s %s", keyType, bucketKey)
	}
}
