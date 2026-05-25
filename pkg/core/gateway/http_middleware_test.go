package gateway

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/bhangun/iket/pkg/config"
	"github.com/bhangun/iket/pkg/core/requestcontext"
	"github.com/bhangun/iket/pkg/logging"
)

type http3TransportStub struct {
	setHeaders func(http.Header) error
}

func (s *http3TransportStub) ListenAndServe() error { return nil }

func (s *http3TransportStub) Shutdown(context.Context) error { return nil }

func (s *http3TransportStub) SetQUICHeaders(h http.Header) error {
	if s.setHeaders != nil {
		return s.setHeaders(h)
	}
	return nil
}

func TestWrapHandlerWithHTTP3AdvertisementOnlyAddsAltSvcForTLSRequests(t *testing.T) {
	wrapped := wrapHandlerWithHTTP3Advertisement(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}), &http3TransportStub{
		setHeaders: func(h http.Header) error {
			h.Set("Alt-Svc", `h3=":8443"; ma=2592000`)
			return nil
		},
	})

	tlsReq := httptest.NewRequest(http.MethodGet, "https://gateway.local/auth", nil)
	tlsReq.TLS = &tls.ConnectionState{}
	tlsRec := httptest.NewRecorder()
	wrapped.ServeHTTP(tlsRec, tlsReq)
	if got := tlsRec.Header().Get("Alt-Svc"); got == "" {
		t.Fatalf("expected Alt-Svc header on TLS request")
	}

	plainReq := httptest.NewRequest(http.MethodGet, "http://gateway.local/auth", nil)
	plainRec := httptest.NewRecorder()
	wrapped.ServeHTTP(plainRec, plainReq)
	if got := plainRec.Header().Get("Alt-Svc"); got != "" {
		t.Fatalf("expected no Alt-Svc header on plain HTTP request, got %q", got)
	}
}

func TestRouteContextMiddlewarePublishesRequestAttribution(t *testing.T) {
	gateway := &Gateway{
		config: &config.Config{
			Services: []config.ServiceConfig{{
				Services: []config.Service{{
					Name: "orders",
					Host: "http://orders.internal",
					Routes: []config.RouterConfig{{
						Name:    "get-order",
						Path:    "/tenants/{realm}/orders/{id}",
						Methods: []string{http.MethodGet},
					}},
				}},
			}},
		},
		logger: logging.NewLogger(false),
	}

	var attribution requestcontext.Attribution
	var ok bool
	handler := gateway.routeContextMiddleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attribution, ok = requestcontext.AttributionFromContext(r.Context())
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodGet, "/tenants/acme/orders/ord-1", nil)
	resp := httptest.NewRecorder()
	handler.ServeHTTP(resp, req)

	if resp.Code != http.StatusNoContent {
		t.Fatalf("expected request to pass, got %d", resp.Code)
	}
	if !ok {
		t.Fatalf("expected request attribution in context")
	}
	if attribution.TenantRealm != "acme" ||
		attribution.ServiceName != "orders" ||
		attribution.RouteName != "get-order" ||
		attribution.RoutePath != "/tenants/{realm}/orders/{id}" {
		t.Fatalf("unexpected request attribution: %+v", attribution)
	}
}
