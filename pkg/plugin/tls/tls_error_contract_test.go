package tls

import (
	"testing"

	coreerrors "github.com/bhangun/iket/pkg/core/errors"
	"github.com/bhangun/iket/pkg/core/errors/errortest"
)

func TestTLSPluginHelpersReturnTypedCodes(t *testing.T) {
	t.Run("initialize missing cert and key", func(t *testing.T) {
		p := &TLSPlugin{}
		err := p.Initialize(map[string]interface{}{
			"enabled": true,
		})
		errortest.AssertBadRequest(t, err, coreerrors.CodeRequiredFieldMissing)
	})

	t.Run("health disabled", func(t *testing.T) {
		p := &TLSPlugin{}
		err := p.Health()
		errortest.AssertCodeAndStatus(t, err, coreerrors.CodePluginUnsupported, 501)
	})

	t.Run("health missing certificate file", func(t *testing.T) {
		p := &TLSPlugin{
			enabled:  true,
			certFile: "/definitely/missing/cert.pem",
			keyFile:  "/definitely/missing/key.pem",
		}
		err := p.Health()
		errortest.AssertCodeAndStatus(t, err, coreerrors.CodeCertificateNotFound, 404)
	})
}
