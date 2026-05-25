package gateway

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/bhangun/iket/pkg/config"
	"github.com/bhangun/iket/pkg/core/authcontext"
	"github.com/bhangun/iket/pkg/logging"
	"github.com/golang-jwt/jwt/v4"
)

func TestPrincipalFromMapClaimsNormalizesCommonClaims(t *testing.T) {
	expiresAt := time.Now().Add(time.Hour).Unix()
	issuedAt := time.Now().Add(-time.Minute).Unix()
	principal := principalFromMapClaims(jwt.MapClaims{
		"sub":       "subject-a",
		"user_id":   "user-a",
		"username":  "alice",
		"email":     "alice@example.test",
		"roles":     []interface{}{"admin", "reader"},
		"groups":    []interface{}{"billing", "ops"},
		"scope":     "orders:read orders:write",
		"client_id": "client-a",
		"iss":       "issuer-a",
		"aud":       []interface{}{"audience-a"},
		"exp":       float64(expiresAt),
		"iat":       float64(issuedAt),
	})

	if principal.Source != "jwt" || principal.Subject != "subject-a" || principal.UserID != "user-a" {
		t.Fatalf("unexpected principal identity: %+v", principal)
	}
	if principal.Username != "alice" || principal.Email != "alice@example.test" || principal.ClientID != "client-a" {
		t.Fatalf("unexpected principal profile: %+v", principal)
	}
	if !reflect.DeepEqual(principal.Roles, []string{"admin", "reader"}) {
		t.Fatalf("expected roles, got %+v", principal.Roles)
	}
	if !reflect.DeepEqual(principal.Groups, []string{"billing", "ops"}) {
		t.Fatalf("expected groups, got %+v", principal.Groups)
	}
	if !reflect.DeepEqual(principal.Scopes, []string{"orders:read", "orders:write"}) {
		t.Fatalf("expected scopes, got %+v", principal.Scopes)
	}
	if principal.Issuer != "issuer-a" || !reflect.DeepEqual(principal.Audience, []string{"audience-a"}) {
		t.Fatalf("unexpected issuer/audience: %+v", principal)
	}
	if principal.ExpiresAt == nil || !principal.ExpiresAt.Equal(time.Unix(expiresAt, 0).UTC()) {
		t.Fatalf("expected expiration, got %+v", principal.ExpiresAt)
	}
	if principal.IssuedAt == nil || !principal.IssuedAt.Equal(time.Unix(issuedAt, 0).UTC()) {
		t.Fatalf("expected issued-at, got %+v", principal.IssuedAt)
	}
}

func TestJWTAuthMiddlewarePublishesPrincipalAndKeepsRawClaims(t *testing.T) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub":    "subject-a",
		"name":   "Alice Example",
		"roles":  []string{"admin", "reader"},
		"scopes": []string{"orders:read"},
		"groups": []string{"ops"},
		"exp":    time.Now().Add(time.Hour).Unix(),
	})
	tokenString, err := token.SignedString([]byte("secret"))
	if err != nil {
		t.Fatalf("failed to sign JWT: %v", err)
	}

	gateway := &Gateway{
		config: &config.Config{},
		logger: logging.NewLogger(false),
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+tokenString)
	resp := httptest.NewRecorder()

	gateway.jwtAuthMiddleware(config.JWTConfig{
		Enabled: true,
		Secret:  "secret",
	})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := r.Context().Value(jwtClaimsKey).(jwt.MapClaims); !ok {
			t.Fatalf("expected raw JWT claims to remain available")
		}
		principal, ok := authcontext.PrincipalFromContext(r.Context())
		if !ok {
			t.Fatalf("expected typed principal")
		}
		if principal.Source != "jwt" || principal.Subject != "subject-a" || principal.Username != "Alice Example" {
			t.Fatalf("unexpected typed principal: %+v", principal)
		}
		roles, ok := authcontext.Roles(r.Context())
		if !ok || !reflect.DeepEqual(roles, []string{"admin", "reader"}) {
			t.Fatalf("expected roles from built-in JWT principal, got %+v ok=%v", roles, ok)
		}
		scopes, ok := authcontext.Scopes(r.Context())
		if !ok || !reflect.DeepEqual(scopes, []string{"orders:read"}) {
			t.Fatalf("expected scopes from built-in JWT principal, got %+v ok=%v", scopes, ok)
		}
		groups, ok := authcontext.Groups(r.Context())
		if !ok || !reflect.DeepEqual(groups, []string{"ops"}) {
			t.Fatalf("expected groups from built-in JWT principal, got %+v ok=%v", groups, ok)
		}
		w.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(resp, req)

	if resp.Code != http.StatusNoContent {
		t.Fatalf("expected request to pass, got %d: %s", resp.Code, resp.Body.String())
	}
}
