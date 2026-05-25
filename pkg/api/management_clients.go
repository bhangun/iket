package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	coreerrors "github.com/bhangun/iket/pkg/core/errors"
	"github.com/bhangun/iket/pkg/plugin"
	"github.com/gorilla/mux"
)

func (api *ManagementAPI) listClients(w http.ResponseWriter, r *http.Request) {
	p, err := api.registry.Get("apikey")
	if err != nil {
		api.writeJSON(w, map[string]interface{}{"clients": []interface{}{}})
		return
	}

	inventory, ok := p.(plugin.ClientInventoryProvider)
	if !ok {
		api.writeManagedError(w, managedError(coreerrors.CodePluginUnsupported, "Plugin does not support client listing", nil), http.StatusNotImplemented)
		return
	}

	api.writeJSON(w, map[string]interface{}{"clients": inventory.ListClientInventory()})
}

func (api *ManagementAPI) getClient(w http.ResponseWriter, r *http.Request) {
	p, err := api.registry.Get("apikey")
	if err != nil {
		api.writeManagedError(w, managedError(coreerrors.CodePluginNotFound, "API Key plugin not found", err), http.StatusNotFound)
		return
	}

	inventory, ok := p.(plugin.ClientInventoryProvider)
	if !ok {
		api.writeManagedError(w, managedError(coreerrors.CodePluginUnsupported, "Plugin does not support client lookup", nil), http.StatusNotImplemented)
		return
	}

	client, found := inventory.FindClientInventory(mux.Vars(r)["key"])
	if !found {
		api.writeManagedError(w, managedError(coreerrors.CodeClientNotFound, "Client not found", nil), http.StatusNotFound)
		return
	}

	api.writeJSON(w, APIResponse{Success: true, Data: client})
}

func (api *ManagementAPI) addClient(w http.ResponseWriter, r *http.Request) {
	var client managementClientRequest
	if err := json.NewDecoder(r.Body).Decode(&client); err != nil {
		api.writeManagedError(w, managedError(coreerrors.CodeClientInvalid, "Invalid client data", err), http.StatusBadRequest)
		return
	}

	p, err := api.registry.Get("apikey")
	if err != nil {
		api.writeManagedError(w, managedError(coreerrors.CodePluginNotFound, "API Key plugin not found or not enabled", err), http.StatusNotFound)
		return
	}
	generatedKey, err := api.prepareClientAPIKey(&client)
	if err != nil {
		api.writeManagedError(w, err, http.StatusBadRequest)
		return
	}

	cfg := api.gateway.GetConfig()
	if cfg == nil {
		api.writeManagedError(w, managedError(coreerrors.CodeConfigNotAvailable, "Configuration not available", nil), http.StatusInternalServerError)
		return
	}
	simCfg, pluginCfg, previousPluginCfg, clientAddSummary, err := buildAddClientConfig(cfg, client)
	if err != nil {
		status := http.StatusBadRequest
		if coreerrors.CodeOf(err) == coreerrors.CodeClientAlreadyExists {
			status = http.StatusConflict
		}
		api.writeManagedError(w, managedError(coreerrors.CodeOf(err), err.Error(), err), status)
		return
	}

	label, note, changeRef := revisionMetadataFromRequest(r)
	if err := api.enforceMutationPolicy("client_add", label, note, changeRef); err != nil {
		if code := coreerrors.CodeOf(err); code != "" {
			api.writeManagedError(w, managedError(code, err.Error(), err), coreerrors.HTTPStatusForCode(code))
			return
		}
		api.writeManagedError(w, managedError(coreerrors.CodeValidationError, "Client mutation policy rejected the request", err), http.StatusBadRequest)
		return
	}
	clientLifecycleEvent := clientAddLifecycleEvent(client, generatedKey != "", label, note, changeRef)
	if err := api.beforeClientAdd(r.Context(), clientLifecycleEvent); err != nil {
		api.writeManagedError(w, err, gatewayErrorStatus(err, http.StatusServiceUnavailable))
		return
	}
	if err := api.applyPluginRuntimeConfigChangeAfterPolicy(p, "client_add", simCfg, pluginCfg, previousPluginCfg, label, note, changeRef, clientAddSummary); err != nil {
		if code := coreerrors.CodeOf(err); code != "" {
			api.writeManagedError(w, managedError(code, err.Error(), err), coreerrors.HTTPStatusForCode(code))
			return
		}
		api.writeManagedError(w, managedError(coreerrors.CodePluginError, "Failed to apply client plugin runtime configuration", err), http.StatusInternalServerError)
		return
	}
	api.afterClientAdd(r.Context(), clientLifecycleEvent)

	data := map[string]interface{}{
		"client_id":       clientAddSummary["client_id"],
		"generated_key":   generatedKey != "",
		"key_fingerprint": clientLifecycleEvent.KeyFingerprint,
	}
	if generatedKey != "" {
		data["api_key"] = generatedKey
		data["one_time_secret"] = true
	}
	api.writeJSON(w, APIResponse{Success: true, Message: "Client added successfully", Data: data})
}

func (api *ManagementAPI) updateClient(w http.ResponseWriter, r *http.Request) {
	lookupCredential := mux.Vars(r)["key"]

	var updateReq managementClientUpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&updateReq); err != nil {
		message := "Invalid client update payload"
		if errors.Is(err, io.EOF) {
			message = "Client update payload is required"
		}
		api.writeManagedError(w, managedError(coreerrors.CodeClientInvalid, message, err), http.StatusBadRequest)
		return
	}

	p, err := api.registry.Get("apikey")
	if err != nil {
		api.writeManagedError(w, managedError(coreerrors.CodePluginNotFound, "API Key plugin not found", err), http.StatusNotFound)
		return
	}

	cfg := api.gateway.GetConfig()
	if cfg == nil {
		api.writeManagedError(w, managedError(coreerrors.CodeConfigNotAvailable, "Configuration not available", nil), http.StatusInternalServerError)
		return
	}
	simCfg, pluginCfg, previousPluginCfg, clientUpdateSummary, err := buildUpdateClientProfileConfig(cfg, lookupCredential, updateReq)
	if err != nil {
		status := http.StatusBadRequest
		switch coreerrors.CodeOf(err) {
		case coreerrors.CodeClientNotFound, coreerrors.CodePluginConfigNotFound:
			status = http.StatusNotFound
		}
		api.writeManagedError(w, managedError(coreerrors.CodeOf(err), err.Error(), err), status)
		return
	}

	label, note, changeRef := revisionMetadataFromRequest(r)
	if err := api.enforceMutationPolicy(ClientLifecycleOperationUpdate, label, note, changeRef); err != nil {
		if code := coreerrors.CodeOf(err); code != "" {
			api.writeManagedError(w, managedError(code, err.Error(), err), coreerrors.HTTPStatusForCode(code))
			return
		}
		api.writeManagedError(w, managedError(coreerrors.CodeValidationError, "Client mutation policy rejected the request", err), http.StatusBadRequest)
		return
	}
	clientLifecycleEvent := clientUpdateLifecycleEvent(clientUpdateSummary, label, note, changeRef)
	if err := api.beforeClientUpdate(r.Context(), clientLifecycleEvent); err != nil {
		api.writeManagedError(w, err, gatewayErrorStatus(err, http.StatusServiceUnavailable))
		return
	}
	if err := api.applyPluginRuntimeConfigChangeAfterPolicy(p, ClientLifecycleOperationUpdate, simCfg, pluginCfg, previousPluginCfg, label, note, changeRef, clientUpdateSummary); err != nil {
		if code := coreerrors.CodeOf(err); code != "" {
			api.writeManagedError(w, managedError(code, err.Error(), err), coreerrors.HTTPStatusForCode(code))
			return
		}
		api.writeManagedError(w, managedError(coreerrors.CodePluginError, "Failed to apply client plugin runtime configuration", err), http.StatusInternalServerError)
		return
	}
	api.afterClientUpdate(r.Context(), clientLifecycleEvent)

	api.writeJSON(w, APIResponse{Success: true, Message: "Client updated successfully", Data: map[string]interface{}{
		"client_id":       clientLifecycleEvent.ClientID,
		"key_fingerprint": clientLifecycleEvent.KeyFingerprint,
		"name":            clientLifecycleEvent.Name,
		"group":           clientLifecycleEvent.Group,
		"scopes":          clientLifecycleEvent.Scopes,
		"tags":            clientLifecycleEvent.Tags,
		"enabled":         clientLifecycleEvent.Enabled,
	}})
}

func (api *ManagementAPI) removeClient(w http.ResponseWriter, r *http.Request) {
	key := mux.Vars(r)["key"]

	p, err := api.registry.Get("apikey")
	if err != nil {
		api.writeManagedError(w, managedError(coreerrors.CodePluginNotFound, "API Key plugin not found", err), http.StatusNotFound)
		return
	}

	cfg := api.gateway.GetConfig()
	if cfg == nil {
		api.writeManagedError(w, managedError(coreerrors.CodeConfigNotAvailable, "Configuration not available", nil), http.StatusInternalServerError)
		return
	}
	simCfg, pluginCfg, previousPluginCfg, clientRemoveSummary, err := buildRemoveClientConfig(cfg, key)
	if err != nil {
		status := http.StatusBadRequest
		switch coreerrors.CodeOf(err) {
		case coreerrors.CodeClientNotFound, coreerrors.CodePluginConfigNotFound:
			status = http.StatusNotFound
		}
		api.writeManagedError(w, managedError(coreerrors.CodeOf(err), err.Error(), err), status)
		return
	}

	label, note, changeRef := revisionMetadataFromRequest(r)
	if err := api.enforceMutationPolicy("client_remove", label, note, changeRef); err != nil {
		if code := coreerrors.CodeOf(err); code != "" {
			api.writeManagedError(w, managedError(code, err.Error(), err), coreerrors.HTTPStatusForCode(code))
			return
		}
		api.writeManagedError(w, managedError(coreerrors.CodeValidationError, "Client mutation policy rejected the request", err), http.StatusBadRequest)
		return
	}
	clientLifecycleEvent := clientRemoveLifecycleEvent(clientRemoveSummary, label, note, changeRef)
	if err := api.beforeClientRemove(r.Context(), clientLifecycleEvent); err != nil {
		api.writeManagedError(w, err, gatewayErrorStatus(err, http.StatusServiceUnavailable))
		return
	}
	if err := api.applyPluginRuntimeConfigChangeAfterPolicy(p, "client_remove", simCfg, pluginCfg, previousPluginCfg, label, note, changeRef, clientRemoveSummary); err != nil {
		if code := coreerrors.CodeOf(err); code != "" {
			api.writeManagedError(w, managedError(code, err.Error(), err), coreerrors.HTTPStatusForCode(code))
			return
		}
		api.writeManagedError(w, managedError(coreerrors.CodePluginError, "Failed to apply client plugin runtime configuration", err), http.StatusInternalServerError)
		return
	}
	api.afterClientRemove(r.Context(), clientLifecycleEvent)

	api.writeJSON(w, APIResponse{Success: true, Message: "Client removed successfully", Data: map[string]interface{}{
		"client_id":       clientLifecycleEvent.ClientID,
		"key_fingerprint": clientLifecycleEvent.KeyFingerprint,
	}})
}

func (api *ManagementAPI) rotateClient(w http.ResponseWriter, r *http.Request) {
	lookupCredential := mux.Vars(r)["key"]

	var rotateReq managementClientRotateRequest
	if err := json.NewDecoder(r.Body).Decode(&rotateReq); err != nil && !errors.Is(err, io.EOF) {
		api.writeManagedError(w, managedError(coreerrors.CodeClientInvalid, "Invalid client rotation payload", err), http.StatusBadRequest)
		return
	}

	p, err := api.registry.Get("apikey")
	if err != nil {
		api.writeManagedError(w, managedError(coreerrors.CodePluginNotFound, "API Key plugin not found", err), http.StatusNotFound)
		return
	}

	rotatedKey, generatedKey, err := api.prepareRotatedClientAPIKey(rotateReq)
	if err != nil {
		api.writeManagedError(w, err, http.StatusBadRequest)
		return
	}

	cfg := api.gateway.GetConfig()
	if cfg == nil {
		api.writeManagedError(w, managedError(coreerrors.CodeConfigNotAvailable, "Configuration not available", nil), http.StatusInternalServerError)
		return
	}
	simCfg, pluginCfg, previousPluginCfg, clientRotateSummary, err := buildRotateClientConfig(cfg, lookupCredential, rotatedKey)
	if err != nil {
		status := http.StatusBadRequest
		switch coreerrors.CodeOf(err) {
		case coreerrors.CodeClientNotFound, coreerrors.CodePluginConfigNotFound:
			status = http.StatusNotFound
		case coreerrors.CodeClientAlreadyExists:
			status = http.StatusConflict
		}
		api.writeManagedError(w, managedError(coreerrors.CodeOf(err), err.Error(), err), status)
		return
	}

	label, note, changeRef := revisionMetadataFromRequest(r)
	if err := api.enforceMutationPolicy("client_rotate", label, note, changeRef); err != nil {
		if code := coreerrors.CodeOf(err); code != "" {
			api.writeManagedError(w, managedError(code, err.Error(), err), coreerrors.HTTPStatusForCode(code))
			return
		}
		api.writeManagedError(w, managedError(coreerrors.CodeValidationError, "Client mutation policy rejected the request", err), http.StatusBadRequest)
		return
	}
	clientLifecycleEvent := clientRotateLifecycleEvent(clientRotateSummary, generatedKey, label, note, changeRef)
	if err := api.beforeClientRotate(r.Context(), clientLifecycleEvent); err != nil {
		api.writeManagedError(w, err, gatewayErrorStatus(err, http.StatusServiceUnavailable))
		return
	}
	if err := api.applyPluginRuntimeConfigChangeAfterPolicy(p, "client_rotate", simCfg, pluginCfg, previousPluginCfg, label, note, changeRef, clientRotateSummary); err != nil {
		if code := coreerrors.CodeOf(err); code != "" {
			api.writeManagedError(w, managedError(code, err.Error(), err), coreerrors.HTTPStatusForCode(code))
			return
		}
		api.writeManagedError(w, managedError(coreerrors.CodePluginError, "Failed to apply client plugin runtime configuration", err), http.StatusInternalServerError)
		return
	}
	api.afterClientRotate(r.Context(), clientLifecycleEvent)

	data := map[string]interface{}{
		"client_id":           clientLifecycleEvent.ClientID,
		"old_key_fingerprint": clientLifecycleEvent.OldKeyFingerprint,
		"key_fingerprint":     clientLifecycleEvent.KeyFingerprint,
		"generated_key":       generatedKey,
	}
	if generatedKey {
		data["api_key"] = rotatedKey
		data["one_time_secret"] = true
	}
	api.writeJSON(w, APIResponse{Success: true, Message: "Client API key rotated successfully", Data: data})
}

func (api *ManagementAPI) enableClient(w http.ResponseWriter, r *http.Request) {
	api.setClientEnabled(w, r, true)
}

func (api *ManagementAPI) disableClient(w http.ResponseWriter, r *http.Request) {
	api.setClientEnabled(w, r, false)
}

func (api *ManagementAPI) setClientEnabled(w http.ResponseWriter, r *http.Request, enabled bool) {
	lookupCredential := mux.Vars(r)["key"]
	action := ClientLifecycleOperationDisable
	message := "Client disabled successfully"
	if enabled {
		action = ClientLifecycleOperationEnable
		message = "Client enabled successfully"
	}

	p, err := api.registry.Get("apikey")
	if err != nil {
		api.writeManagedError(w, managedError(coreerrors.CodePluginNotFound, "API Key plugin not found", err), http.StatusNotFound)
		return
	}

	cfg := api.gateway.GetConfig()
	if cfg == nil {
		api.writeManagedError(w, managedError(coreerrors.CodeConfigNotAvailable, "Configuration not available", nil), http.StatusInternalServerError)
		return
	}
	simCfg, pluginCfg, previousPluginCfg, clientStatusSummary, err := buildSetClientEnabledConfig(cfg, lookupCredential, enabled)
	if err != nil {
		status := http.StatusBadRequest
		switch coreerrors.CodeOf(err) {
		case coreerrors.CodeClientNotFound, coreerrors.CodePluginConfigNotFound:
			status = http.StatusNotFound
		}
		api.writeManagedError(w, managedError(coreerrors.CodeOf(err), err.Error(), err), status)
		return
	}

	label, note, changeRef := revisionMetadataFromRequest(r)
	if err := api.enforceMutationPolicy(action, label, note, changeRef); err != nil {
		if code := coreerrors.CodeOf(err); code != "" {
			api.writeManagedError(w, managedError(code, err.Error(), err), coreerrors.HTTPStatusForCode(code))
			return
		}
		api.writeManagedError(w, managedError(coreerrors.CodeValidationError, "Client mutation policy rejected the request", err), http.StatusBadRequest)
		return
	}
	clientLifecycleEvent := clientStatusLifecycleEvent(clientStatusSummary, label, note, changeRef)
	if err := api.beforeClientStatusChange(r.Context(), clientLifecycleEvent); err != nil {
		api.writeManagedError(w, err, gatewayErrorStatus(err, http.StatusServiceUnavailable))
		return
	}
	if err := api.applyPluginRuntimeConfigChangeAfterPolicy(p, action, simCfg, pluginCfg, previousPluginCfg, label, note, changeRef, clientStatusSummary); err != nil {
		if code := coreerrors.CodeOf(err); code != "" {
			api.writeManagedError(w, managedError(code, err.Error(), err), coreerrors.HTTPStatusForCode(code))
			return
		}
		api.writeManagedError(w, managedError(coreerrors.CodePluginError, "Failed to apply client plugin runtime configuration", err), http.StatusInternalServerError)
		return
	}
	api.afterClientStatusChange(r.Context(), clientLifecycleEvent)

	api.writeJSON(w, APIResponse{Success: true, Message: message, Data: map[string]interface{}{
		"client_id":        clientLifecycleEvent.ClientID,
		"key_fingerprint":  clientLifecycleEvent.KeyFingerprint,
		"enabled":          clientLifecycleEvent.Enabled,
		"previous_enabled": clientLifecycleEvent.PreviousEnabled,
	}})
}

func (api *ManagementAPI) prepareClientAPIKey(client *managementClientRequest) (string, error) {
	if client == nil {
		return "", coreerrors.New(coreerrors.CodeClientInvalid, "Invalid client data")
	}
	if strings.TrimSpace(client.Key) != "" && client.GenerateKey {
		return "", coreerrors.New(coreerrors.CodeClientInvalid, "key cannot be provided when generate_key is true")
	}
	if strings.TrimSpace(client.Key) != "" {
		client.Key = strings.TrimSpace(client.Key)
		return "", nil
	}

	key, err := api.clientAPIKeyGenerator().GenerateAPIKey()
	if err != nil {
		return "", coreerrors.New(coreerrors.CodePluginError, "Failed to generate API key").WithError(err)
	}
	key = strings.TrimSpace(key)
	if key == "" {
		return "", coreerrors.New(coreerrors.CodePluginError, "API key generator returned an empty key")
	}
	client.Key = key
	client.GenerateKey = true
	return key, nil
}

func (api *ManagementAPI) prepareRotatedClientAPIKey(req managementClientRotateRequest) (string, bool, error) {
	if strings.TrimSpace(req.Key) != "" && req.GenerateKey {
		return "", false, coreerrors.New(coreerrors.CodeClientInvalid, "key cannot be provided when generate_key is true")
	}
	if strings.TrimSpace(req.Key) != "" {
		return strings.TrimSpace(req.Key), false, nil
	}
	key, err := api.clientAPIKeyGenerator().GenerateAPIKey()
	if err != nil {
		return "", false, coreerrors.New(coreerrors.CodePluginError, "Failed to generate API key").WithError(err)
	}
	key = strings.TrimSpace(key)
	if key == "" {
		return "", false, coreerrors.New(coreerrors.CodePluginError, "API key generator returned an empty key")
	}
	return key, true, nil
}
