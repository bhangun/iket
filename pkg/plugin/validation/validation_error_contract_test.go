package validation

import (
	"errors"
	"io"
	"net/http/httptest"
	"strings"
	"testing"

	coreerrors "github.com/bhangun/iket/pkg/core/errors"
	"github.com/bhangun/iket/pkg/core/errors/errortest"
)

type failingReadCloser struct{}

func (failingReadCloser) Read([]byte) (int, error) {
	return 0, errors.New("read failed")
}

func (failingReadCloser) Close() error {
	return nil
}

func TestValidationPluginHelpersReturnTypedCodes(t *testing.T) {
	t.Run("request body read failure", func(t *testing.T) {
		p := &ValidationPlugin{enabled: true}
		req := httptest.NewRequest("POST", "/", nil)
		req.Body = failingReadCloser{}

		err := p.validateRequestBody(req)
		errortest.AssertBadRequest(t, err, coreerrors.CodeValidationFailed)
	})

	t.Run("invalid json body", func(t *testing.T) {
		p := &ValidationPlugin{enabled: true}
		req := httptest.NewRequest("POST", "/", io.NopCloser(strings.NewReader("{bad json")))

		err := p.validateRequestBody(req)
		errortest.AssertBadRequest(t, err, coreerrors.CodeValidationError)
	})

	t.Run("validate request wraps body validation", func(t *testing.T) {
		p := &ValidationPlugin{enabled: true}
		req := httptest.NewRequest("POST", "/", io.NopCloser(strings.NewReader("{bad json")))
		req.Header.Set("Content-Type", "application/json")

		err := p.validateRequest(req)
		errortest.AssertCodeAndStatus(t, err, coreerrors.CodeConfigError, 500)
	})

	t.Run("health disabled", func(t *testing.T) {
		p := &ValidationPlugin{}
		err := p.Health()
		errortest.AssertCodeAndStatus(t, err, coreerrors.CodePluginUnsupported, 501)
	})
}
