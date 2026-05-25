package api

import (
	"encoding/json"

	"github.com/bhangun/iket/pkg/config"
	"github.com/bhangun/iket/pkg/logging"
	"github.com/bhangun/iket/pkg/plugin"
)

func clonePluginConfigMap(pluginCfg map[string]interface{}) (map[string]interface{}, error) {
	if pluginCfg == nil {
		return map[string]interface{}{}, nil
	}
	data, err := json.Marshal(pluginCfg)
	if err != nil {
		return nil, err
	}
	cloned := make(map[string]interface{})
	if err := json.Unmarshal(data, &cloned); err != nil {
		return nil, err
	}
	return cloned, nil
}

func (api *ManagementAPI) applyPluginRuntimeConfigChange(p plugin.Plugin, action string, cfg *config.Config, nextPluginCfg, previousPluginCfg map[string]interface{}, label, note, changeRef string, summary map[string]interface{}) error {
	if err := api.enforceMutationPolicy(action, label, note, changeRef); err != nil {
		return err
	}
	return api.applyPluginRuntimeConfigChangeAfterPolicy(p, action, cfg, nextPluginCfg, previousPluginCfg, label, note, changeRef, summary)
}

func (api *ManagementAPI) applyPluginRuntimeConfigChangeAfterPolicy(p plugin.Plugin, action string, cfg *config.Config, nextPluginCfg, previousPluginCfg map[string]interface{}, label, note, changeRef string, summary map[string]interface{}) error {
	runtimePluginCfg, err := clonePluginConfigMap(nextPluginCfg)
	if err != nil {
		return err
	}
	if err := p.Initialize(runtimePluginCfg); err != nil {
		return err
	}
	if err := api.applyManagedConfigChangeAfterPolicy(cfg, action, label, note, changeRef, summary); err != nil {
		api.rollbackPluginRuntimeConfig(p, previousPluginCfg, action)
		return err
	}
	return nil
}

func (api *ManagementAPI) rollbackPluginRuntimeConfig(p plugin.Plugin, previousPluginCfg map[string]interface{}, action string) {
	if err := p.Initialize(previousPluginCfg); err != nil {
		api.logger.Warn("Failed to roll back plugin runtime configuration",
			logging.String("plugin", p.Name()),
			logging.String("action", action),
			logging.Error(err),
		)
	}
}
