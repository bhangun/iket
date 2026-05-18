package api

import (
	"encoding/json"
	coreerrors "github.com/bhangun/iket/pkg/core/errors"
	"github.com/gorilla/mux"
	"net/http"
	"reflect"
)

func (api *ManagementAPI) listClients(w http.ResponseWriter, r *http.Request) {
	p, err := api.registry.Get("apikey")
	if err != nil {
		api.writeJSON(w, map[string]interface{}{"clients": []interface{}{}})
		return
	}

	// Use reflection to call ListClients if it exists
	val := reflect.ValueOf(p)
	method := val.MethodByName("ListClients")
	if !method.IsValid() {
		api.writeManagedError(w, managedError(coreerrors.CodePluginUnsupported, "Plugin does not support client listing", nil), http.StatusNotImplemented)
		return
	}

	results := method.Call(nil)
	api.writeJSON(w, map[string]interface{}{"clients": results[0].Interface()})
}

func (api *ManagementAPI) addClient(w http.ResponseWriter, r *http.Request) {
	var client struct {
		ID     string   `json:"id"`
		Name   string   `json:"name"`
		Key    string   `json:"key"`
		Group  string   `json:"group"`
		Scopes []string `json:"scopes"`
		Tags   []string `json:"tags"`
	}

	if err := json.NewDecoder(r.Body).Decode(&client); err != nil {
		api.writeManagedError(w, managedError(coreerrors.CodeClientInvalid, "Invalid client data", err), http.StatusBadRequest)
		return
	}

	p, err := api.registry.Get("apikey")
	if err != nil {
		api.writeManagedError(w, managedError(coreerrors.CodePluginNotFound, "API Key plugin not found or not enabled", err), http.StatusNotFound)
		return
	}

	// Actually, easier if we just update config and re-initialize plugin
	cfg := api.gateway.GetConfig()
	pluginCfg, ok := cfg.GetPluginConfig("apikey")
	if !ok {
		pluginCfg = make(map[string]interface{})
	}

	clients, _ := pluginCfg["clients"].([]interface{})
	// Check if key already exists
	for _, c := range clients {
		if m, ok := c.(map[string]interface{}); ok {
			if m["key"] == client.Key {
				api.writeManagedError(w, managedError(coreerrors.CodeClientAlreadyExists, "Client with this key already exists", nil), http.StatusConflict)
				return
			}
		}
	}

	clients = append(clients, map[string]interface{}{
		"id":     client.ID,
		"name":   client.Name,
		"key":    client.Key,
		"group":  client.Group,
		"scopes": client.Scopes,
		"tags":   client.Tags,
	})
	pluginCfg["clients"] = clients
	cfg.SetPluginConfig("apikey", pluginCfg)

	clientAddSummary := map[string]interface{}{
		"client_id": client.ID,
		"group":     client.Group,
	}
	label, note, changeRef := revisionMetadataFromRequest(r)
	if err := api.applyManagedConfigChange(cfg, "client_add", label, note, changeRef, clientAddSummary); err != nil {
		api.writeManagedError(w, managedConfigError("Failed to save configuration", err), http.StatusInternalServerError)
		return
	}

	// Re-initialize plugin
	if err := p.Initialize(pluginCfg); err != nil {
		api.writeManagedError(w, managedError(coreerrors.CodePluginError, "Failed to re-initialize plugin", err), http.StatusInternalServerError)
		return
	}

	api.writeJSON(w, APIResponse{Success: true, Message: "Client added successfully"})
}

func (api *ManagementAPI) removeClient(w http.ResponseWriter, r *http.Request) {
	key := mux.Vars(r)["key"]

	p, err := api.registry.Get("apikey")
	if err != nil {
		api.writeManagedError(w, managedError(coreerrors.CodePluginNotFound, "API Key plugin not found", err), http.StatusNotFound)
		return
	}

	cfg := api.gateway.GetConfig()
	pluginCfg, ok := cfg.GetPluginConfig("apikey")
	if !ok {
		api.writeManagedError(w, managedError(coreerrors.CodePluginConfigNotFound, "Plugin configuration not found", nil), http.StatusNotFound)
		return
	}

	clients, ok := pluginCfg["clients"].([]interface{})
	if !ok {
		api.writeManagedError(w, managedError(coreerrors.CodeClientNotFound, "No clients configured", nil), http.StatusNotFound)
		return
	}

	newClients := []interface{}{}
	found := false
	for _, c := range clients {
		if m, ok := c.(map[string]interface{}); ok {
			if m["key"] == key {
				found = true
				continue
			}
		}
		newClients = append(newClients, c)
	}

	if !found {
		api.writeManagedError(w, managedError(coreerrors.CodeClientNotFound, "Client not found", nil), http.StatusNotFound)
		return
	}

	pluginCfg["clients"] = newClients
	cfg.SetPluginConfig("apikey", pluginCfg)

	clientRemoveSummary := map[string]interface{}{
		"client_key": key,
	}
	label, note, changeRef := revisionMetadataFromRequest(r)
	if err := api.applyManagedConfigChange(cfg, "client_remove", label, note, changeRef, clientRemoveSummary); err != nil {
		api.writeManagedError(w, managedConfigError("Failed to save configuration", err), http.StatusInternalServerError)
		return
	}

	// Re-initialize plugin
	if err := p.Initialize(pluginCfg); err != nil {
		api.writeManagedError(w, managedError(coreerrors.CodePluginError, "Failed to re-initialize plugin", err), http.StatusInternalServerError)
		return
	}

	api.writeJSON(w, APIResponse{Success: true, Message: "Client removed successfully"})
}
