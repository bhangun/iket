package websocket

import (
	"net/http/httptest"
	"testing"

	coreerrors "github.com/bhangun/iket/pkg/core/errors"
	"github.com/bhangun/iket/pkg/core/errors/errortest"
)

func TestWebSocketPluginHelpersReturnTypedCodes(t *testing.T) {
	t.Run("initialize missing upstream url", func(t *testing.T) {
		p := &WebSocketPlugin{}
		err := p.Initialize(map[string]interface{}{
			"enabled": true,
		})
		errortest.AssertBadRequest(t, err, coreerrors.CodeRequiredFieldMissing)
	})

	t.Run("initialize invalid protocol", func(t *testing.T) {
		p := &WebSocketPlugin{}
		err := p.Initialize(map[string]interface{}{
			"enabled":      true,
			"upstream_url": "http://example.com",
		})
		errortest.AssertBadRequest(t, err, coreerrors.CodeValidationError)
	})

	t.Run("build upstream url invalid config", func(t *testing.T) {
		p := &WebSocketPlugin{upstreamURL: "://bad-url"}
		_, err := p.buildUpstreamURL(httptest.NewRequest("GET", "/chat?room=1", nil))
		errortest.AssertCodeAndStatus(t, err, coreerrors.CodeConfigError, 500)
	})

	t.Run("health disabled", func(t *testing.T) {
		p := &WebSocketPlugin{}
		err := p.Health()
		errortest.AssertCodeAndStatus(t, err, coreerrors.CodePluginUnsupported, 501)
	})
}
