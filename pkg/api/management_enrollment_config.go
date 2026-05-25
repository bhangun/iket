package api

import (
	"github.com/bhangun/iket/pkg/config"
	coreerrors "github.com/bhangun/iket/pkg/core/errors"
)

func (api *ManagementAPI) enrollmentTLSConfig() (config.TLSConfig, error) {
	cfg := api.gateway.GetConfig()
	if cfg == nil {
		return config.TLSConfig{}, coreerrors.New(coreerrors.CodeConfigNotAvailable, "Configuration not available")
	}
	return cfg.Security.TLS, nil
}
