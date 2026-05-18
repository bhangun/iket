package jwt

import (
	"net/http/httptest"
	"testing"

	coreerrors "github.com/bhangun/iket/pkg/core/errors"
	"github.com/bhangun/iket/pkg/core/errors/errortest"
	"github.com/golang-jwt/jwt/v4"
)

func TestJWTPluginHelpersReturnTypedCodes(t *testing.T) {
	t.Run("load public key invalid pem", func(t *testing.T) {
		p := &JWTPlugin{}
		err := p.loadPublicKey("testdata/not-pem.pem")
		errortest.AssertBadRequest(t, err, coreerrors.CodeCertificatePEMInvalid)
	})

	t.Run("missing auth header", func(t *testing.T) {
		p := &JWTPlugin{enabled: true, secret: "secret", algorithms: []string{"HS256"}}
		_, err := p.validateToken(httptest.NewRequest("GET", "/", nil))
		errortest.AssertCodeAndStatus(t, err, coreerrors.CodeAuthenticationRequired, 401)
	})

	t.Run("missing rsa public key", func(t *testing.T) {
		p := &JWTPlugin{algorithms: []string{"RS256"}}
		token := jwt.New(jwt.SigningMethodRS256)
		_, err := p.getKeyFunc()(token)
		errortest.AssertBadRequest(t, err, coreerrors.CodeRequiredFieldMissing)
	})

	t.Run("health missing credentials", func(t *testing.T) {
		p := &JWTPlugin{enabled: true}
		err := p.Health()
		errortest.AssertBadRequest(t, err, coreerrors.CodeRequiredFieldMissing)
	})
}
