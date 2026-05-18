package config

import (
	"github.com/bhangun/iket/pkg/core/errors"
	"time"
)

// ServerConfigRule validates server configuration
type ServerConfigRule struct{}

func (r *ServerConfigRule) Validate(cfg *Config) error {
	if cfg.Server.Port <= 0 || cfg.Server.Port > 65535 {
		return errors.NewValidationError("server.port", "port must be between 1 and 65535")
	}

	if cfg.Server.ReadTimeout != "" {
		if _, err := time.ParseDuration(cfg.Server.ReadTimeout); err != nil {
			return errors.NewValidationError("server.readTimeout", "invalid duration format")
		}
	}

	if cfg.Server.WriteTimeout != "" {
		if _, err := time.ParseDuration(cfg.Server.WriteTimeout); err != nil {
			return errors.NewValidationError("server.writeTimeout", "invalid duration format")
		}
	}

	if cfg.Server.IdleTimeout != "" {
		if _, err := time.ParseDuration(cfg.Server.IdleTimeout); err != nil {
			return errors.NewValidationError("server.idleTimeout", "invalid duration format")
		}
	}

	return nil
}
