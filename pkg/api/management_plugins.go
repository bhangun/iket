package api

import (
	"encoding/json"
	coreerrors "github.com/bhangun/iket/pkg/core/errors"
	"github.com/gorilla/mux"
	"net/http"
	"time"
)

// Plugin Response
type PluginInfo struct {
	Name    string            `json:"name"`
	Type    string            `json:"type"`
	Enabled bool              `json:"enabled"`
	Status  string            `json:"status"`
	Tags    map[string]string `json:"tags"`
}

// ListPlugins returns the list of registered plugin names.
func (m *ManagementAPI) ListPlugins() []string {
	return m.registry.List() // assuming Registry has a List() method
}

func (api *ManagementAPI) listPlugins(w http.ResponseWriter, r *http.Request) {
	plugins := api.registry.List()
	pluginInfos := make([]PluginInfo, 0, len(plugins))

	for _, name := range plugins {
		plugin, err := api.registry.Get(name)
		if err != nil {
			continue
		}

		info := PluginInfo{
			Name:    name,
			Type:    "unknown",
			Enabled: api.pluginEnabled(name),
			Status:  "healthy",
			Tags:    make(map[string]string),
		}

		// Get plugin type if available
		if typedPlugin, ok := plugin.(interface{ Type() string }); ok {
			info.Type = typedPlugin.Type()
		}

		// Get plugin tags if available
		if taggedPlugin, ok := plugin.(interface{ Tags() map[string]string }); ok {
			info.Tags = taggedPlugin.Tags()
		}

		// Check health if available
		if healthChecker, ok := plugin.(interface{ Health() error }); ok {
			if err := healthChecker.Health(); err != nil {
				info.Status = "unhealthy"
			}
		}

		pluginInfos = append(pluginInfos, info)
	}

	response := map[string]interface{}{
		"plugins": pluginInfos,
	}
	api.writeJSON(w, response)
}

func (api *ManagementAPI) getPluginDetails(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	pluginName := vars["name"]

	plugin, err := api.registry.Get(pluginName)
	if err != nil {
		api.writeManagedError(w, managedError(coreerrors.CodePluginNotFound, "Plugin not found", err), http.StatusNotFound)
		return
	}

	details := map[string]interface{}{
		"name":    pluginName,
		"type":    "unknown",
		"enabled": api.pluginEnabled(pluginName),
		"status":  "healthy",
	}

	// Get plugin type
	if typedPlugin, ok := plugin.(interface{ Type() string }); ok {
		details["type"] = typedPlugin.Type()
	}

	// Get plugin tags
	if taggedPlugin, ok := plugin.(interface{ Tags() map[string]string }); ok {
		details["tags"] = taggedPlugin.Tags()
	}

	// Get health status
	if healthChecker, ok := plugin.(interface{ Health() error }); ok {
		if err := healthChecker.Health(); err != nil {
			details["status"] = "unhealthy"
			details["health"] = map[string]interface{}{
				"status":  "unhealthy",
				"message": err.Error(),
			}
		} else {
			details["health"] = map[string]interface{}{
				"status":  "healthy",
				"message": "Plugin is functioning normally",
			}
		}
	}

	// Get status
	if statusReporter, ok := plugin.(interface{ Status() string }); ok {
		details["status_message"] = statusReporter.Status()
	}

	api.writeJSON(w, details)
}

func (api *ManagementAPI) updatePluginConfig(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	pluginName := vars["name"]
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
	currentPluginCfg := simCfg.Plugins[pluginName]
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

	// Reload plugin with new configuration
	if err := plugin.Initialize(config); err != nil {
		api.writeManagedError(w, managedConfigError("Failed to update plugin configuration", err), http.StatusInternalServerError)
		return
	}
	label, note, changeRef := revisionMetadataFromRequest(r)
	if err := api.applyManagedConfigChange(simCfg, "plugin_config_update", label, note, changeRef, summary); err != nil {
		api.writeManagedError(w, managedConfigError("Failed to persist plugin configuration", err), http.StatusInternalServerError)
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
	pluginName := mux.Vars(r)["name"]
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
	pluginName := mux.Vars(r)["name"]
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
	vars := mux.Vars(r)
	pluginName := vars["name"]

	plugin, err := api.registry.Get(pluginName)
	if err != nil {
		api.writeManagedError(w, managedError(coreerrors.CodePluginNotFound, "Plugin not found", err), http.StatusNotFound)
		return
	}

	healthChecker, ok := plugin.(interface{ Health() error })
	if !ok {
		api.writeManagedError(w, managedError(coreerrors.CodePluginUnsupported, "Plugin does not support health checks", nil), http.StatusNotImplemented)
		return
	}

	err = healthChecker.Health()
	health := map[string]interface{}{
		"status":     "healthy",
		"last_check": time.Now(),
		"message":    "Plugin is functioning normally",
	}

	if err != nil {
		health["status"] = "unhealthy"
		health["message"] = err.Error()
	}

	api.writeJSON(w, health)
}

func (api *ManagementAPI) getPluginStatus(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	pluginName := vars["name"]

	plugin, err := api.registry.Get(pluginName)
	if err != nil {
		api.writeManagedError(w, managedError(coreerrors.CodePluginNotFound, "Plugin not found", err), http.StatusNotFound)
		return
	}

	statusReporter, ok := plugin.(interface{ Status() string })
	if !ok {
		api.writeManagedError(w, managedError(coreerrors.CodePluginUnsupported, "Plugin does not support status reporting", nil), http.StatusNotImplemented)
		return
	}

	status := map[string]interface{}{
		"status":      statusReporter.Status(),
		"enabled":     api.pluginEnabled(pluginName),
		"last_update": time.Now(),
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
	pluginCfg["enabled"] = enabled
	simCfg.SetPluginConfig(name, pluginCfg)
	if err := p.Initialize(pluginCfg); err != nil {
		return err
	}
	label, note, changeRef := revisionMetadataFromRequest(r)
	return api.applyManagedConfigChange(simCfg, "plugin_set_enabled", label, note, changeRef, map[string]interface{}{
		"plugin":  name,
		"enabled": enabled,
	})
}
