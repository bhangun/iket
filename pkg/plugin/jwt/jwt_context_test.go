package jwt

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/bhangun/iket/pkg/core/authcontext"
	jwtlib "github.com/golang-jwt/jwt/v4"
)

func TestJWTPluginPublishesTypedRolesContext(t *testing.T) {
	plugin := &JWTPlugin{}
	if err := plugin.Initialize(map[string]interface{}{
		"enabled": true,
		"secret":  "secret",
	}); err != nil {
		t.Fatalf("failed to initialize jwt plugin: %v", err)
	}
	token := jwtlib.NewWithClaims(jwtlib.SigningMethodHS256, Claims{
		UserID:   "user-a",
		Username: "alice",
		Email:    "alice@example.test",
		Roles:    []string{"admin", "reader"},
		Custom:   map[string]string{"tenant": "tenant-a"},
		RegisteredClaims: jwtlib.RegisteredClaims{
			Issuer:    "issuer-a",
			Subject:   "subject-a",
			Audience:  jwtlib.ClaimStrings{"audience-a"},
			ExpiresAt: jwtlib.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  jwtlib.NewNumericDate(time.Now().Add(-time.Minute)),
		},
	})
	tokenString, err := token.SignedString([]byte("secret"))
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+tokenString)
	resp := httptest.NewRecorder()
	plugin.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		roles, ok := authcontext.Roles(r.Context())
		if !ok || !reflect.DeepEqual(roles, []string{"admin", "reader"}) {
			t.Fatalf("expected typed roles, got %+v ok=%v", roles, ok)
		}
		if got := r.Context().Value("roles"); !reflect.DeepEqual(got, []string{"admin", "reader"}) {
			t.Fatalf("expected legacy roles, got %+v", got)
		}
		principal, ok := authcontext.PrincipalFromContext(r.Context())
		if !ok {
			t.Fatalf("expected typed principal")
		}
		if principal.Source != "jwt" || principal.Subject != "subject-a" || principal.UserID != "user-a" {
			t.Fatalf("unexpected typed principal identity: %+v", principal)
		}
		if principal.Username != "alice" || principal.Email != "alice@example.test" {
			t.Fatalf("unexpected typed principal profile: %+v", principal)
		}
		if principal.Issuer != "issuer-a" || !reflect.DeepEqual(principal.Audience, []string{"audience-a"}) {
			t.Fatalf("unexpected typed principal issuer/audience: %+v", principal)
		}
		if principal.ExpiresAt == nil || principal.IssuedAt == nil {
			t.Fatalf("expected typed principal token timestamps, got %+v", principal)
		}
		if !reflect.DeepEqual(principal.Custom, map[string]string{"tenant": "tenant-a"}) {
			t.Fatalf("unexpected typed principal custom claims: %+v", principal.Custom)
		}
		claims, ok := plugin.GetClaimsFromContext(r.Context())
		if !ok || claims.UserID != "user-a" {
			t.Fatalf("expected jwt claims to remain available, got %+v ok=%v", claims, ok)
		}
		w.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(resp, req)

	if resp.Code != http.StatusNoContent {
		t.Fatalf("expected request to pass, got %d: %s", resp.Code, resp.Body.String())
	}
}
