package gateway

import (
	"os"
	"path/filepath"

	"github.com/bhangun/iket/pkg/logging"
	"github.com/bhangun/iket/pkg/plugin"
	_ "github.com/bhangun/iket/pkg/plugin/apikey"
	_ "github.com/bhangun/iket/pkg/plugin/jwt"

	pluginlib "plugin"
)

// loadPlugins loads built-in and external plugins.
func (g *Gateway) loadPlugins() error {
	pluginsDir := g.config.Server.PluginsDir
	if pluginsDir == "" {
		return nil
	}
	files, err := os.ReadDir(pluginsDir)
	if err != nil {
		return err
	}
	for _, file := range files {
		if filepath.Ext(file.Name()) != ".so" {
			continue
		}
		plug, err := pluginlib.Open(filepath.Join(pluginsDir, file.Name()))
		if err != nil {
			g.logger.Warn("Failed to open plugin", logging.String("file", file.Name()), logging.Error(err))
			continue
		}
		sym, err := plug.Lookup("Plugin")
		if err != nil {
			g.logger.Warn("Plugin missing 'Plugin' symbol", logging.String("file", file.Name()), logging.Error(err))
			continue
		}
		p, ok := sym.(plugin.Plugin)
		if !ok {
			g.logger.Warn("Plugin symbol does not implement Plugin interface", logging.String("file", file.Name()))
			continue
		}
		if err := g.pluginRegistry.Register(p); err != nil {
			g.logger.Warn("Failed to register plugin", logging.String("name", p.Name()), logging.Error(err))
			continue
		}
		g.logger.Info("Dynamically loaded plugin", logging.String("name", p.Name()), logging.String("file", file.Name()))
	}
	return nil
}
