package api

import (
	"encoding/json"
	"net/http"

	coreerrors "github.com/bhangun/iket/pkg/core/errors"
)

// ListPlugins returns the list of registered plugin names.
func (m *ManagementAPI) ListPlugins() []string {
	return m.registry.List()
}

func (api *ManagementAPI) listPlugins(w http.ResponseWriter, r *http.Request) {
	filter, err := pluginListFilterFromRequest(r)
	if err != nil {
		api.writeManagedError(w, err, http.StatusBadRequest)
		return
	}
	plugins := api.registry.List()
	allPluginInfos := make([]PluginInfo, 0, len(plugins))
	pluginInfos := make([]PluginInfo, 0, len(plugins))

	for _, name := range plugins {
		plugin, err := api.registry.Get(name)
		if err != nil {
			continue
		}

		info := api.pluginInventorySnapshot(name, plugin).Info

		allPluginInfos = append(allPluginInfos, info)
		if !pluginInfoMatchesFilter(info, filter) {
			continue
		}
		pluginInfos = append(pluginInfos, info)
	}

	response := map[string]interface{}{
		"plugins": pluginInfos,
		"total":   len(pluginInfos),
		"summary": pluginListSummaryFromInfos(allPluginInfos, len(pluginInfos)),
	}
	if pluginListFilterActive(filter) {
		response["filters"] = pluginListFilterResponse(filter)
	}
	api.writeJSON(w, response)
}

func (api *ManagementAPI) getPluginDetails(w http.ResponseWriter, r *http.Request) {
	pluginName, plugin, ok := api.registeredPluginFromRequest(w, r)
	if !ok {
		return
	}

	snapshot := api.pluginInventorySnapshot(pluginName, plugin)
	api.writeJSON(w, pluginDetailsResponse(snapshot))
}

func (api *ManagementAPI) updatePluginConfig(w http.ResponseWriter, r *http.Request) {
	pluginName := pluginNameFromRequest(r)
	dryRun := r.URL.Query().Get("dry_run") == "true"

	var config map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&config); err != nil {
		api.writeManagedError(w, managedValidationError("Invalid configuration format", err), http.StatusBadRequest)
		return
	}

	plugin, err := api.registry.Get(pluginName)
	if err != nil {
		api.writeManagedError(w, managedError(coreerrors.CodePluginNotFound, "Plugin not found", err), http.StatusNotFound)
		return
	}

	cfg := api.gateway.GetConfig()
	if cfg == nil {
		api.writeManagedError(w, managedError(coreerrors.CodeConfigNotAvailable, "Configuration not available", nil), http.StatusInternalServerError)
		return
	}
	simCfg, err := cloneConfig(cfg)
	if err != nil {
		api.writeManagedError(w, managedConfigError("Failed to prepare configuration update", err), http.StatusInternalServerError)
		return
	}
	currentPluginCfg := cfg.Plugins[pluginName]
	previousPluginCfg, err := clonePluginConfigMap(currentPluginCfg)
	if err != nil {
		api.writeManagedError(w, managedConfigError("Failed to snapshot plugin configuration", err), http.StatusInternalServerError)
		return
	}
	simCfg.SetPluginConfig(pluginName, config)
	summary := map[string]interface{}{
		"plugin": pluginName,
		"summary": map[string]interface{}{
			"changed_fields": collectChangedPaths("", currentPluginCfg, config),
		},
	}

	if dryRun {
		api.writeJSON(w, map[string]interface{}{
			"success": true,
			"dry_run": true,
			"message": "[DRY RUN] Plugin configuration is valid and ready to apply",
			"data":    summary,
		})
		return
	}

	label, note, changeRef := revisionMetadataFromRequest(r)
	if err := api.applyPluginRuntimeConfigChange(plugin, "plugin_config_update", simCfg, config, previousPluginCfg, label, note, changeRef, summary); err != nil {
		if code := coreerrors.CodeOf(err); code != "" {
			api.writeManagedError(w, managedError(code, err.Error(), err), coreerrors.HTTPStatusForCode(code))
			return
		}
		api.writeManagedError(w, managedConfigError("Failed to update plugin configuration", err), http.StatusInternalServerError)
		return
	}

	response := APIResponse{
		Success: true,
		Message: "Plugin configuration updated",
		Data:    summary,
	}
	api.writeJSON(w, response)
}

func (api *ManagementAPI) enablePlugin(w http.ResponseWriter, r *http.Request) {
	pluginName := pluginNameFromRequest(r)
	if err := api.setPluginEnabled(r, pluginName, true); err != nil {
		api.writeManagedError(w, err, http.StatusBadRequest)
		return
	}

	response := APIResponse{
		Success: true,
		Message: "Plugin enabled successfully",
	}
	api.writeJSON(w, response)
}

func (api *ManagementAPI) disablePlugin(w http.ResponseWriter, r *http.Request) {
	pluginName := pluginNameFromRequest(r)
	if err := api.setPluginEnabled(r, pluginName, false); err != nil {
		api.writeManagedError(w, err, http.StatusBadRequest)
		return
	}

	response := APIResponse{
		Success: true,
		Message: "Plugin disabled successfully",
	}
	api.writeJSON(w, response)
}

func (api *ManagementAPI) getPluginHealth(w http.ResponseWriter, r *http.Request) {
	_, plugin, ok := api.registeredPluginFromRequest(w, r)
	if !ok {
		return
	}

	health, ok := pluginHealthResponse(plugin)
	if !ok {
		api.writeManagedError(w, managedError(coreerrors.CodePluginUnsupported, "Plugin does not support health checks", nil), http.StatusNotImplemented)
		return
	}

	api.writeJSON(w, health)
}

func (api *ManagementAPI) getPluginStatus(w http.ResponseWriter, r *http.Request) {
	pluginName, plugin, ok := api.registeredPluginFromRequest(w, r)
	if !ok {
		return
	}

	status, ok := pluginStatusResponse(plugin, api.pluginEnabled(pluginName))
	if !ok {
		api.writeManagedError(w, managedError(coreerrors.CodePluginUnsupported, "Plugin does not support status reporting", nil), http.StatusNotImplemented)
		return
	}

	api.writeJSON(w, status)
}

func (api *ManagementAPI) pluginEnabled(name string) bool {
	cfg := api.gateway.GetConfig()
	if cfg == nil {
		return false
	}
	pluginCfg, ok := cfg.GetPluginConfig(name)
	if !ok {
		return false
	}
	if enabled, ok := pluginCfg["enabled"].(bool); ok {
		return enabled
	}
	return true
}

func (api *ManagementAPI) setPluginEnabled(r *http.Request, name string, enabled bool) error {
	p, err := api.registry.Get(name)
	if err != nil {
		return coreerrors.New(coreerrors.CodePluginNotFound, "Plugin not found")
	}
	cfg := api.gateway.GetConfig()
	if cfg == nil {
		return coreerrors.New(coreerrors.CodeConfigNotAvailable, "Configuration not available")
	}
	simCfg, err := cloneConfig(cfg)
	if err != nil {
		return err
	}
	pluginCfg, _ := simCfg.GetPluginConfig(name)
	if pluginCfg == nil {
		pluginCfg = map[string]interface{}{}
	}
	previousPluginCfg, err := clonePluginConfigMap(pluginCfg)
	if err != nil {
		return err
	}
	pluginCfg["enabled"] = enabled
	simCfg.SetPluginConfig(name, pluginCfg)
	label, note, changeRef := revisionMetadataFromRequest(r)
	return api.applyPluginRuntimeConfigChange(p, "plugin_set_enabled", simCfg, pluginCfg, previousPluginCfg, label, note, changeRef, map[string]interface{}{
		"plugin":  name,
		"enabled": enabled,
	})
}
