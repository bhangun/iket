package plugin

import (
	"testing"

	coreerrors "github.com/bhangun/iket/pkg/core/errors"
	"github.com/bhangun/iket/pkg/core/errors/errortest"
)

func TestIPWhitelistPluginHelpersReturnTypedCodes(t *testing.T) {
	t.Run("missing list", func(t *testing.T) {
		p := &IPWhitelistPlugin{}
		err := p.Initialize(map[string]interface{}{})
		errortest.AssertBadRequest(t, err, coreerrors.CodeRequiredFieldMissing)
	})

	t.Run("invalid list type", func(t *testing.T) {
		p := &IPWhitelistPlugin{}
		err := p.Initialize(map[string]interface{}{
			"list": true,
		})
		errortest.AssertBadRequest(t, err, coreerrors.CodeValidationError)
	})

	t.Run("invalid cidr", func(t *testing.T) {
		p := &IPWhitelistPlugin{}
		err := p.Initialize(map[string]interface{}{
			"list": []interface{}{"not-an-ip"},
		})
		errortest.AssertBadRequest(t, err, coreerrors.CodeValidationError)
	})
}
