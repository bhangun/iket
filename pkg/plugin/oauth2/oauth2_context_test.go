package oauth2

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/bhangun/iket/pkg/core/authcontext"
)

func TestOAuth2PluginPublishesTypedRolesContext(t *testing.T) {
	introspectionServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.Form.Get("token") != "token-a" {
			t.Fatalf("expected introspection token token-a, got %q", r.Form.Get("token"))
		}
		expectedAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("client:secret"))
		if r.Header.Get("Authorization") != expectedAuth {
			t.Fatalf("expected encoded introspection auth %q, got %q", expectedAuth, r.Header.Get("Authorization"))
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(IntrospectionResponse{
			Active:   true,
			Scope:    "admin  reader",
			ClientID: "client-a",
			Username: "alice",
			Sub:      "user-a",
			Aud:      []string{"audience-a"},
			Iss:      "issuer-a",
			Exp:      1000,
			Iat:      500,
		}); err != nil {
			t.Fatalf("failed to encode introspection response: %v", err)
		}
	}))
	defer introspectionServer.Close()

	plugin := &OAuth2Plugin{}
	if err := plugin.Initialize(map[string]interface{}{
		"enabled":        true,
		"introspect_url": introspectionServer.URL,
		"client_id":      "client",
		"client_secret":  "secret",
	}); err != nil {
		t.Fatalf("failed to initialize oauth2 plugin: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer token-a")
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
		if principal.Source != "oauth2" || principal.Subject != "user-a" || principal.UserID != "user-a" {
			t.Fatalf("unexpected typed principal identity: %+v", principal)
		}
		if principal.Username != "alice" || principal.ClientID != "client-a" {
			t.Fatalf("unexpected typed principal client/profile: %+v", principal)
		}
		if !reflect.DeepEqual(principal.Scopes, []string{"admin", "reader"}) {
			t.Fatalf("expected normalized scopes, got %+v", principal.Scopes)
		}
		if principal.Issuer != "issuer-a" || !reflect.DeepEqual(principal.Audience, []string{"audience-a"}) {
			t.Fatalf("unexpected typed principal issuer/audience: %+v", principal)
		}
		if principal.ExpiresAt == nil || !principal.ExpiresAt.Equal(time.Unix(1000, 0).UTC()) {
			t.Fatalf("expected typed principal expiration, got %+v", principal.ExpiresAt)
		}
		if principal.IssuedAt == nil || !principal.IssuedAt.Equal(time.Unix(500, 0).UTC()) {
			t.Fatalf("expected typed principal issued-at, got %+v", principal.IssuedAt)
		}
		claims, ok := plugin.GetClaimsFromContext(r.Context())
		if !ok || claims.UserID != "user-a" || claims.ClientID != "client-a" || claims.Issuer != "issuer-a" {
			t.Fatalf("expected oauth2 claims to remain available, got %+v ok=%v", claims, ok)
		}
		w.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(resp, req)

	if resp.Code != http.StatusNoContent {
		t.Fatalf("expected request to pass, got %d: %s", resp.Code, resp.Body.String())
	}
}
