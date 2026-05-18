package gateway

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestServePluginRouteDelegatesToNextHandler(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://gateway.local/openapi", nil)
	req = req.WithContext(context.WithValue(req.Context(), "next", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte("plugin"))
	})))
	rec := httptest.NewRecorder()

	if !servePluginRouteIfMatched(rec, req) {
		t.Fatalf("expected plugin route to be handled")
	}
	if rec.Code != http.StatusAccepted {
		t.Fatalf("expected next handler status, got %d", rec.Code)
	}
	if rec.Body.String() != "plugin" {
		t.Fatalf("expected next handler body, got %q", rec.Body.String())
	}
}

func TestServePluginRouteIgnoresNonPluginPaths(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://gateway.local/api/users", nil)
	rec := httptest.NewRecorder()

	if servePluginRouteIfMatched(rec, req) {
		t.Fatalf("expected non-plugin path to be ignored")
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("expected recorder to remain untouched, got %d", rec.Code)
	}
}
