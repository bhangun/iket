package gateway

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/bhangun/iket/pkg/config"
	"github.com/bhangun/iket/pkg/core/authcontext"
	"github.com/bhangun/iket/pkg/logging"
)

func TestClientCredentialAuthMiddlewarePublishesLowPrivilegePrincipal(t *testing.T) {
	gateway := &Gateway{
		config: &config.Config{
			Security: config.SecurityConfig{
				Clients: map[string]string{"client-a": "secret"},
			},
		},
		logger: logging.NewLogger(false),
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.SetBasicAuth("client-a", "secret")
	resp := httptest.NewRecorder()

	gateway.clientCredentialAuthMiddleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assertBasicPrincipal(t, r, "client_credentials", "client-a")
		w.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(resp, req)

	if resp.Code != http.StatusNoContent {
		t.Fatalf("expected request to pass, got %d: %s", resp.Code, resp.Body.String())
	}
}

func TestGlobalBasicAuthMiddlewarePublishesLowPrivilegePrincipal(t *testing.T) {
	gateway := &Gateway{
		config: &config.Config{
			Security: config.SecurityConfig{
				EnableBasicAuth: true,
				BasicAuthUsers:  map[string]string{"alice": "secret"},
			},
		},
		logger: logging.NewLogger(false),
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.SetBasicAuth("alice", "secret")
	resp := httptest.NewRecorder()

	gateway.authMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assertBasicPrincipal(t, r, "basic_auth", "alice")
		w.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(resp, req)

	if resp.Code != http.StatusNoContent {
		t.Fatalf("expected request to pass, got %d: %s", resp.Code, resp.Body.String())
	}
}

func TestAdminAuthMiddlewarePublishesLowPrivilegePrincipal(t *testing.T) {
	gateway := &Gateway{
		config: &config.Config{
			Security: config.SecurityConfig{
				BasicAuthUsers: map[string]string{"admin": "secret"},
			},
		},
		logger: logging.NewLogger(false),
	}
	req := httptest.NewRequest(http.MethodGet, "/admin/config", nil)
	req.SetBasicAuth("admin", "secret")
	resp := httptest.NewRecorder()

	gateway.adminAuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assertBasicPrincipal(t, r, "admin_basic_auth", "admin")
		w.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(resp, req)

	if resp.Code != http.StatusNoContent {
		t.Fatalf("expected request to pass, got %d: %s", resp.Code, resp.Body.String())
	}
}

func assertBasicPrincipal(t *testing.T, r *http.Request, source, username string) {
	t.Helper()
	principal, ok := authcontext.PrincipalFromContext(r.Context())
	if !ok {
		t.Fatalf("expected typed principal")
	}
	if principal.Source != source || principal.Subject != username || principal.UserID != username || principal.Username != username || principal.ClientID != username {
		t.Fatalf("unexpected basic principal: %+v", principal)
	}
	if matched, present := authcontext.HasAnyRole(r.Context(), []string{"admin"}); matched || present {
		t.Fatalf("basic principal should not grant roles, matched=%v present=%v", matched, present)
	}
	if matched, present := authcontext.HasAnyScope(r.Context(), []string{"orders:read"}); matched || present {
		t.Fatalf("basic principal should not grant scopes, matched=%v present=%v", matched, present)
	}
	if matched, present := authcontext.HasGroup(r.Context(), "billing"); matched || present {
		t.Fatalf("basic principal should not grant groups, matched=%v present=%v", matched, present)
	}
}
