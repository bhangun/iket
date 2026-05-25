package gateway

import (
	"github.com/bhangun/iket/pkg/config"
	"github.com/bhangun/iket/pkg/core/errors"

	"github.com/gorilla/mux"
)

// GetConfig returns the current configuration.
func (g *Gateway) GetConfig() *config.Config {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.config
}

// GetRouter returns the router for external route registration.
func (g *Gateway) GetRouter() *mux.Router {
	return g.router
}

func (g *Gateway) ReloadConfig() error {
	if g.configProvider == nil {
		return errors.NewCodeError(errors.CodeConfigNotAvailable, "config provider not available", nil)
	}

	cfg, err := g.configProvider.Load()
	if err != nil {
		return errors.NewConfigError("failed to reload configuration", err)
	}
	if err := cfg.Validate(); err != nil {
		return errors.NewConfigError("invalid reloaded configuration", err)
	}

	g.mu.Lock()
	defer g.mu.Unlock()
	g.config = cfg
	g.clearBFFCache()
	if err := g.setupRoutes(); err != nil {
		return errors.NewConfigError("failed to rebuild routes", err)
	}
	g.logger.Info("Configuration reloaded from provider")
	return nil
}

// UpdateConfig updates the gateway configuration.
func (g *Gateway) UpdateConfig(cfg *config.Config) error {
	g.mu.Lock()
	defer g.mu.Unlock()

	if err := cfg.Validate(); err != nil {
		return errors.NewConfigError("invalid configuration", err)
	}

	if g.configProvider != nil {
		if err := g.configProvider.Save(cfg); err != nil {
			g.logger.Error("Failed to persist configuration changes", err)
			return errors.NewConfigError("failed to persist configuration", err)
		}
	}

	g.config = cfg
	g.clearBFFCache()

	if err := g.setupRoutes(); err != nil {
		return errors.NewConfigError("failed to rebuild routes", err)
	}

	g.logger.Info("Configuration updated successfully")
	return nil
}
