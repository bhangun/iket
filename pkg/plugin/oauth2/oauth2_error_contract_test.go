package oauth2

import (
	"net/http/httptest"
	"testing"

	coreerrors "github.com/bhangun/iket/pkg/core/errors"
	"github.com/bhangun/iket/pkg/core/errors/errortest"
)

func TestOAuth2PluginHelpersReturnTypedCodes(t *testing.T) {
	t.Run("initialize missing introspect url", func(t *testing.T) {
		p := &OAuth2Plugin{}
		err := p.Initialize(map[string]interface{}{
			"enabled":       true,
			"client_id":     "client",
			"client_secret": "secret",
		})
		errortest.AssertBadRequest(t, err, coreerrors.CodeRequiredFieldMissing)
	})

	t.Run("missing auth header", func(t *testing.T) {
		p := &OAuth2Plugin{enabled: true}
		_, err := p.validateToken(httptest.NewRequest("GET", "/", nil))
		errortest.AssertCodeAndStatus(t, err, coreerrors.CodeAuthenticationRequired, 401)
	})

	t.Run("health disabled", func(t *testing.T) {
		p := &OAuth2Plugin{}
		err := p.Health()
		errortest.AssertCodeAndStatus(t, err, coreerrors.CodePluginUnsupported, 501)
	})
}
