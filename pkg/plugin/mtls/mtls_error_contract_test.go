package mtls

import (
	"crypto/tls"
	"net/http/httptest"
	"testing"

	coreerrors "github.com/bhangun/iket/pkg/core/errors"
	"github.com/bhangun/iket/pkg/core/errors/errortest"
)

func TestMTLSPluginHelpersReturnTypedCodes(t *testing.T) {
	t.Run("missing ca file", func(t *testing.T) {
		p := &MTLSPlugin{}
		err := p.loadCACertPool()
		errortest.AssertBadRequest(t, err, coreerrors.CodeRequiredFieldMissing)
	})

	t.Run("missing tls connection", func(t *testing.T) {
		p := &MTLSPlugin{}
		_, err := p.validateClientCert(httptest.NewRequest("GET", "/", nil))
		errortest.AssertCodeAndStatus(t, err, coreerrors.CodeUnauthorized, 401)
	})

	t.Run("missing client certificate", func(t *testing.T) {
		p := &MTLSPlugin{}
		req := httptest.NewRequest("GET", "/", nil)
		req.TLS = &tls.ConnectionState{}
		_, err := p.validateClientCert(req)
		errortest.AssertCodeAndStatus(t, err, coreerrors.CodeUnauthorized, 401)
	})

	t.Run("health disabled", func(t *testing.T) {
		p := &MTLSPlugin{}
		err := p.Health()
		errortest.AssertCodeAndStatus(t, err, coreerrors.CodePluginUnsupported, 501)
	})
}
