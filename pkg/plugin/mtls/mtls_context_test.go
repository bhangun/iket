package mtls

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/bhangun/iket/pkg/core/authcontext"
)

func TestMTLSPluginPublishesTypedPrincipalContext(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	clientCert, caPool := testClientCertificate(t, now)
	plugin := &MTLSPlugin{
		enabled: true,
		caPool:  caPool,
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{clientCert},
	}
	resp := httptest.NewRecorder()
	plugin.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		principal, ok := authcontext.PrincipalFromContext(r.Context())
		if !ok {
			t.Fatalf("expected typed principal")
		}
		if principal.Source != "mtls" || principal.UserID != "client-a" || principal.ClientID != "client-a" {
			t.Fatalf("unexpected typed principal identity: %+v", principal)
		}
		if principal.Subject == "" || principal.Issuer == "" {
			t.Fatalf("expected certificate subject and issuer, got %+v", principal)
		}
		if !reflect.DeepEqual(principal.Groups, []string{"payments"}) {
			t.Fatalf("expected certificate OU as principal groups, got %+v", principal.Groups)
		}
		if roles, ok := authcontext.Roles(r.Context()); ok {
			t.Fatalf("expected mTLS not to grant authorization roles, got %+v ok=%v", roles, ok)
		}
		if principal.IssuedAt == nil || !principal.IssuedAt.Equal(now.Add(-time.Hour)) {
			t.Fatalf("expected certificate not-before as issued-at, got %+v", principal.IssuedAt)
		}
		if principal.ExpiresAt == nil || !principal.ExpiresAt.Equal(now.Add(time.Hour)) {
			t.Fatalf("expected certificate not-after as expiration, got %+v", principal.ExpiresAt)
		}
		if principal.Custom["serial"] == "" || principal.Custom["organization"] != "Iket" {
			t.Fatalf("unexpected certificate custom principal fields: %+v", principal.Custom)
		}
		certInfo, ok := plugin.GetClientCertFromContext(r.Context())
		if !ok || certInfo.CN != "client-a" {
			t.Fatalf("expected mTLS certificate info to remain available, got %+v ok=%v", certInfo, ok)
		}
		w.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(resp, req)

	if resp.Code != http.StatusNoContent {
		t.Fatalf("expected request to pass, got %d: %s", resp.Code, resp.Body.String())
	}
}

func testClientCertificate(t *testing.T, now time.Time) (*x509.Certificate, *x509.CertPool) {
	t.Helper()

	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate CA key: %v", err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             now.Add(-2 * time.Hour),
		NotAfter:              now.Add(2 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("failed to create CA certificate: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("failed to parse CA certificate: %v", err)
	}

	clientKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate client key: %v", err)
	}
	clientTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName:         "client-a",
			OrganizationalUnit: []string{"payments"},
			Organization:       []string{"Iket"},
		},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	clientDER, err := x509.CreateCertificate(rand.Reader, clientTemplate, caCert, &clientKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("failed to create client certificate: %v", err)
	}
	clientCert, err := x509.ParseCertificate(clientDER)
	if err != nil {
		t.Fatalf("failed to parse client certificate: %v", err)
	}

	caPool := x509.NewCertPool()
	caPool.AddCert(caCert)
	return clientCert, caPool
}
