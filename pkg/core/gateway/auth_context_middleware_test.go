package gateway

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bhangun/iket/pkg/core/authcontext"
)

func TestRequireRolesMiddlewareAcceptsTypedRolesContext(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req = req.WithContext(authcontext.WithRoles(req.Context(), []string{"admin"}))
	resp := httptest.NewRecorder()

	requireRolesMiddleware([]string{"admin"})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(resp, req)

	if resp.Code != http.StatusNoContent {
		t.Fatalf("expected request to pass, got %d: %s", resp.Code, resp.Body.String())
	}
}

func TestRequireRolesMiddlewareAcceptsLegacyRolesContext(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req = req.WithContext(context.WithValue(req.Context(), "roles", []string{"admin"}))
	resp := httptest.NewRecorder()

	requireRolesMiddleware([]string{"admin"})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(resp, req)

	if resp.Code != http.StatusNoContent {
		t.Fatalf("expected legacy roles request to pass, got %d: %s", resp.Code, resp.Body.String())
	}
}

func TestRequireRolesMiddlewareKeepsForbiddenResponses(t *testing.T) {
	t.Run("missing", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		resp := httptest.NewRecorder()

		requireRolesMiddleware([]string{"admin"})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Fatalf("request without roles should not reach next handler")
		})).ServeHTTP(resp, req)

		if resp.Code != http.StatusForbidden || !strings.Contains(resp.Body.String(), "No roles found") {
			t.Fatalf("expected missing roles forbidden response, got %d: %s", resp.Code, resp.Body.String())
		}
	})

	t.Run("insufficient", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req = req.WithContext(authcontext.WithRoles(req.Context(), []string{"reader"}))
		resp := httptest.NewRecorder()

		requireRolesMiddleware([]string{"admin"})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Fatalf("request with insufficient roles should not reach next handler")
		})).ServeHTTP(resp, req)

		if resp.Code != http.StatusForbidden || !strings.Contains(resp.Body.String(), "Insufficient roles") {
			t.Fatalf("expected insufficient roles forbidden response, got %d: %s", resp.Code, resp.Body.String())
		}
	})
}

func TestRequireScopesMiddlewareAcceptsPrincipalScopesContext(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req = req.WithContext(authcontext.WithPrincipal(req.Context(), authcontext.Principal{
		Scopes: []string{"orders:read"},
	}))
	resp := httptest.NewRecorder()

	requireScopesMiddleware([]string{"orders:read"})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(resp, req)

	if resp.Code != http.StatusNoContent {
		t.Fatalf("expected principal scopes request to pass, got %d: %s", resp.Code, resp.Body.String())
	}
}

func TestRequireScopesMiddlewareAcceptsAPIKeyScopesFallback(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req = req.WithContext(authcontext.WithAPIKeyClient(req.Context(), authcontext.APIKeyClient{
		Scopes: []string{"orders:read"},
	}))
	resp := httptest.NewRecorder()

	requireScopesMiddleware([]string{"orders:read"})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(resp, req)

	if resp.Code != http.StatusNoContent {
		t.Fatalf("expected API-key scopes fallback request to pass, got %d: %s", resp.Code, resp.Body.String())
	}
}

func TestRequireScopesMiddlewareKeepsForbiddenResponses(t *testing.T) {
	t.Run("missing", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		resp := httptest.NewRecorder()

		requireScopesMiddleware([]string{"orders:read"})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Fatalf("request without scopes should not reach next handler")
		})).ServeHTTP(resp, req)

		if resp.Code != http.StatusForbidden || !strings.Contains(resp.Body.String(), "No scopes found") {
			t.Fatalf("expected missing scopes forbidden response, got %d: %s", resp.Code, resp.Body.String())
		}
	})

	t.Run("insufficient", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req = req.WithContext(authcontext.WithPrincipal(req.Context(), authcontext.Principal{
			Scopes: []string{"orders:read"},
		}))
		resp := httptest.NewRecorder()

		requireScopesMiddleware([]string{"orders:write"})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Fatalf("request with insufficient scopes should not reach next handler")
		})).ServeHTTP(resp, req)

		if resp.Code != http.StatusForbidden || !strings.Contains(resp.Body.String(), "Insufficient scopes") {
			t.Fatalf("expected insufficient scopes forbidden response, got %d: %s", resp.Code, resp.Body.String())
		}
	})
}

func TestRequireGroupMiddlewareAcceptsPrincipalGroupsContext(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req = req.WithContext(authcontext.WithPrincipal(req.Context(), authcontext.Principal{
		Groups: []string{"billing", "ops"},
	}))
	resp := httptest.NewRecorder()

	requireGroupMiddleware("ops")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(resp, req)

	if resp.Code != http.StatusNoContent {
		t.Fatalf("expected principal groups request to pass, got %d: %s", resp.Code, resp.Body.String())
	}
}

func TestRequireGroupMiddlewareAcceptsAPIKeyGroupFallback(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req = req.WithContext(authcontext.WithAPIKeyClient(req.Context(), authcontext.APIKeyClient{
		Group: "billing",
	}))
	resp := httptest.NewRecorder()

	requireGroupMiddleware("billing")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(resp, req)

	if resp.Code != http.StatusNoContent {
		t.Fatalf("expected API-key group fallback request to pass, got %d: %s", resp.Code, resp.Body.String())
	}
}

func TestRequireGroupMiddlewareKeepsForbiddenResponse(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req = req.WithContext(authcontext.WithPrincipal(req.Context(), authcontext.Principal{
		Groups: []string{"ops"},
	}))
	resp := httptest.NewRecorder()

	requireGroupMiddleware("billing")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("request with mismatched group should not reach next handler")
	})).ServeHTTP(resp, req)

	if resp.Code != http.StatusForbidden || !strings.Contains(resp.Body.String(), "Principal group mismatch") {
		t.Fatalf("expected group mismatch forbidden response, got %d: %s", resp.Code, resp.Body.String())
	}
}
