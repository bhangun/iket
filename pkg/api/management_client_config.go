package api

import (
	"fmt"
	"strings"

	"github.com/bhangun/iket/pkg/config"
	"github.com/bhangun/iket/pkg/core/credentials"
	coreerrors "github.com/bhangun/iket/pkg/core/errors"
)

type managementClientRequest struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Key         string   `json:"key"`
	GenerateKey bool     `json:"generate_key"`
	Enabled     *bool    `json:"enabled"`
	Group       string   `json:"group"`
	Scopes      []string `json:"scopes"`
	Tags        []string `json:"tags"`
}

type managementClientRotateRequest struct {
	Key         string `json:"key"`
	GenerateKey bool   `json:"generate_key"`
}

type managementClientUpdateRequest struct {
	Name   *string   `json:"name"`
	Group  *string   `json:"group"`
	Scopes *[]string `json:"scopes"`
	Tags   *[]string `json:"tags"`
}

func (req managementClientUpdateRequest) hasChanges() bool {
	return req.Name != nil || req.Group != nil || req.Scopes != nil || req.Tags != nil
}

func buildAddClientConfig(current *config.Config, client managementClientRequest) (*config.Config, map[string]interface{}, map[string]interface{}, map[string]interface{}, error) {
	trimmedKey := strings.TrimSpace(client.Key)
	if trimmedKey == "" {
		return nil, nil, nil, nil, coreerrors.New(coreerrors.CodeClientInvalid, "Client key is required")
	}

	previousPluginCfg, err := clonePluginConfigMap(apikeyPluginConfig(current))
	if err != nil {
		return nil, nil, nil, nil, err
	}

	simCfg, err := cloneConfig(current)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	pluginCfg := apikeyPluginConfig(simCfg)
	clients, err := apikeyClientEntries(pluginCfg["clients"])
	if err != nil {
		return nil, nil, nil, nil, err
	}

	for _, entry := range clients {
		if apikeyClientEntryMatchesCredential(entry, trimmedKey) {
			return nil, nil, nil, nil, coreerrors.New(coreerrors.CodeClientAlreadyExists, "Client with this key already exists")
		}
	}

	newClient := apikeyClientEntry(client)
	clients = append(clients, newClient)
	pluginCfg["clients"] = clients
	simCfg.SetPluginConfig("apikey", pluginCfg)

	summary := apikeyClientEntrySummary(newClient)
	summary["generated_key"] = client.GenerateKey
	return simCfg, pluginCfg, previousPluginCfg, summary, nil
}

func buildUpdateClientProfileConfig(current *config.Config, lookupCredential string, update managementClientUpdateRequest) (*config.Config, map[string]interface{}, map[string]interface{}, map[string]interface{}, error) {
	lookupCredential = strings.TrimSpace(lookupCredential)
	if lookupCredential == "" {
		return nil, nil, nil, nil, coreerrors.New(coreerrors.CodeClientInvalid, "Client key or fingerprint is required")
	}
	if !update.hasChanges() {
		return nil, nil, nil, nil, coreerrors.New(coreerrors.CodeClientInvalid, "Client update payload must include at least one profile field")
	}

	currentPluginCfg, ok := current.GetPluginConfig("apikey")
	if !ok {
		return nil, nil, nil, nil, coreerrors.New(coreerrors.CodePluginConfigNotFound, "Plugin configuration not found")
	}
	previousPluginCfg, err := clonePluginConfigMap(currentPluginCfg)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	simCfg, err := cloneConfig(current)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	pluginCfg, ok := simCfg.GetPluginConfig("apikey")
	if !ok {
		return nil, nil, nil, nil, coreerrors.New(coreerrors.CodePluginConfigNotFound, "Plugin configuration not found")
	}
	clients, err := apikeyClientEntries(pluginCfg["clients"])
	if err != nil {
		return nil, nil, nil, nil, err
	}

	for index, entry := range clients {
		if !apikeyClientEntryMatchesCredential(entry, lookupCredential) {
			continue
		}
		client, ok := entry.(map[string]interface{})
		if !ok {
			return nil, nil, nil, nil, coreerrors.New(coreerrors.CodeClientInvalid, "API key plugin client must be an object")
		}

		previousSummary := apikeyClientEntrySummary(client)
		updatedClient := cloneClientEntry(client)
		if update.Name != nil {
			updatedClient["name"] = strings.TrimSpace(*update.Name)
		}
		if update.Group != nil {
			updatedClient["group"] = strings.TrimSpace(*update.Group)
		}
		if update.Scopes != nil {
			updatedClient["scopes"] = stringSliceToInterfaceSlice(*update.Scopes)
		}
		if update.Tags != nil {
			updatedClient["tags"] = stringSliceToInterfaceSlice(*update.Tags)
		}

		clients[index] = updatedClient
		pluginCfg["clients"] = clients
		simCfg.SetPluginConfig("apikey", pluginCfg)

		summary := apikeyClientEntrySummary(updatedClient)
		summary["previous_name"] = previousSummary["name"]
		summary["previous_group"] = previousSummary["group"]
		summary["previous_scopes"] = previousSummary["scopes"]
		summary["previous_tags"] = previousSummary["tags"]
		return simCfg, pluginCfg, previousPluginCfg, summary, nil
	}

	return nil, nil, nil, nil, coreerrors.New(coreerrors.CodeClientNotFound, "Client not found")
}

func buildRotateClientConfig(current *config.Config, lookupCredential, nextKey string) (*config.Config, map[string]interface{}, map[string]interface{}, map[string]interface{}, error) {
	lookupCredential = strings.TrimSpace(lookupCredential)
	nextKey = strings.TrimSpace(nextKey)
	if lookupCredential == "" {
		return nil, nil, nil, nil, coreerrors.New(coreerrors.CodeClientInvalid, "Client key or fingerprint is required")
	}
	if nextKey == "" {
		return nil, nil, nil, nil, coreerrors.New(coreerrors.CodeClientInvalid, "New client key is required")
	}

	currentPluginCfg, ok := current.GetPluginConfig("apikey")
	if !ok {
		return nil, nil, nil, nil, coreerrors.New(coreerrors.CodePluginConfigNotFound, "Plugin configuration not found")
	}
	previousPluginCfg, err := clonePluginConfigMap(currentPluginCfg)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	simCfg, err := cloneConfig(current)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	pluginCfg, ok := simCfg.GetPluginConfig("apikey")
	if !ok {
		return nil, nil, nil, nil, coreerrors.New(coreerrors.CodePluginConfigNotFound, "Plugin configuration not found")
	}
	clients, err := apikeyClientEntries(pluginCfg["clients"])
	if err != nil {
		return nil, nil, nil, nil, err
	}

	matchedIndex := -1
	var matchedClient map[string]interface{}
	for index, entry := range clients {
		if apikeyClientEntryMatchesCredential(entry, lookupCredential) {
			matchedIndex = index
			matchedClient, _ = entry.(map[string]interface{})
			break
		}
	}
	if matchedIndex < 0 || matchedClient == nil {
		return nil, nil, nil, nil, coreerrors.New(coreerrors.CodeClientNotFound, "Client not found")
	}

	newFingerprint := credentials.APIKeyFingerprint(nextKey)
	oldFingerprint := apikeyClientEntryFingerprint(matchedClient)
	if oldFingerprint != "" && oldFingerprint == newFingerprint {
		return nil, nil, nil, nil, coreerrors.New(coreerrors.CodeClientInvalid, "New client key must be different from the current key")
	}
	for index, entry := range clients {
		if index == matchedIndex {
			continue
		}
		if apikeyClientEntryMatchesCredential(entry, nextKey) {
			return nil, nil, nil, nil, coreerrors.New(coreerrors.CodeClientAlreadyExists, "Client with this key already exists")
		}
	}

	rotatedClient := cloneClientEntry(matchedClient)
	delete(rotatedClient, "key")
	rotatedClient["key_hash"] = credentials.APIKeyHash(nextKey)
	rotatedClient["key_fingerprint"] = newFingerprint
	clients[matchedIndex] = rotatedClient
	pluginCfg["clients"] = clients
	simCfg.SetPluginConfig("apikey", pluginCfg)

	summary := apikeyClientEntrySummary(rotatedClient)
	summary["old_key_fingerprint"] = oldFingerprint
	summary["rotated_key"] = true
	return simCfg, pluginCfg, previousPluginCfg, summary, nil
}

func buildSetClientEnabledConfig(current *config.Config, lookupCredential string, enabled bool) (*config.Config, map[string]interface{}, map[string]interface{}, map[string]interface{}, error) {
	lookupCredential = strings.TrimSpace(lookupCredential)
	if lookupCredential == "" {
		return nil, nil, nil, nil, coreerrors.New(coreerrors.CodeClientInvalid, "Client key or fingerprint is required")
	}

	currentPluginCfg, ok := current.GetPluginConfig("apikey")
	if !ok {
		return nil, nil, nil, nil, coreerrors.New(coreerrors.CodePluginConfigNotFound, "Plugin configuration not found")
	}
	previousPluginCfg, err := clonePluginConfigMap(currentPluginCfg)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	simCfg, err := cloneConfig(current)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	pluginCfg, ok := simCfg.GetPluginConfig("apikey")
	if !ok {
		return nil, nil, nil, nil, coreerrors.New(coreerrors.CodePluginConfigNotFound, "Plugin configuration not found")
	}
	clients, err := apikeyClientEntries(pluginCfg["clients"])
	if err != nil {
		return nil, nil, nil, nil, err
	}

	for index, entry := range clients {
		if !apikeyClientEntryMatchesCredential(entry, lookupCredential) {
			continue
		}
		client, ok := entry.(map[string]interface{})
		if !ok {
			return nil, nil, nil, nil, coreerrors.New(coreerrors.CodeClientInvalid, "API key plugin client must be an object")
		}
		previousEnabled := apikeyClientEntryEnabled(client)
		updatedClient := cloneClientEntry(client)
		updatedClient["enabled"] = enabled
		clients[index] = updatedClient
		pluginCfg["clients"] = clients
		simCfg.SetPluginConfig("apikey", pluginCfg)

		summary := apikeyClientEntrySummary(updatedClient)
		summary["enabled"] = enabled
		summary["previous_enabled"] = previousEnabled
		return simCfg, pluginCfg, previousPluginCfg, summary, nil
	}

	return nil, nil, nil, nil, coreerrors.New(coreerrors.CodeClientNotFound, "Client not found")
}

func buildRemoveClientConfig(current *config.Config, key string) (*config.Config, map[string]interface{}, map[string]interface{}, map[string]interface{}, error) {
	trimmedKey := strings.TrimSpace(key)
	if trimmedKey == "" {
		return nil, nil, nil, nil, coreerrors.New(coreerrors.CodeClientInvalid, "Client key is required")
	}

	currentPluginCfg, ok := current.GetPluginConfig("apikey")
	if !ok {
		return nil, nil, nil, nil, coreerrors.New(coreerrors.CodePluginConfigNotFound, "Plugin configuration not found")
	}
	previousPluginCfg, err := clonePluginConfigMap(currentPluginCfg)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	simCfg, err := cloneConfig(current)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	pluginCfg, ok := simCfg.GetPluginConfig("apikey")
	if !ok {
		return nil, nil, nil, nil, coreerrors.New(coreerrors.CodePluginConfigNotFound, "Plugin configuration not found")
	}
	clients, err := apikeyClientEntries(pluginCfg["clients"])
	if err != nil {
		return nil, nil, nil, nil, err
	}

	nextClients := make([]interface{}, 0, len(clients))
	found := false
	var removedSummary map[string]interface{}
	for _, entry := range clients {
		if apikeyClientEntryMatchesCredential(entry, trimmedKey) {
			found = true
			removedSummary = apikeyClientEntrySummary(entry)
			continue
		}
		nextClients = append(nextClients, entry)
	}

	if !found {
		return nil, nil, nil, nil, coreerrors.New(coreerrors.CodeClientNotFound, "Client not found")
	}

	pluginCfg["clients"] = nextClients
	simCfg.SetPluginConfig("apikey", pluginCfg)

	return simCfg, pluginCfg, previousPluginCfg, removedSummary, nil
}

func apikeyPluginConfig(cfg *config.Config) map[string]interface{} {
	pluginCfg, ok := cfg.GetPluginConfig("apikey")
	if !ok || pluginCfg == nil {
		pluginCfg = make(map[string]interface{})
	}
	return pluginCfg
}

func apikeyClientEntries(value interface{}) ([]interface{}, error) {
	switch clients := value.(type) {
	case nil:
		return nil, nil
	case []interface{}:
		return clients, nil
	case []map[string]interface{}:
		out := make([]interface{}, 0, len(clients))
		for _, client := range clients {
			out = append(out, client)
		}
		return out, nil
	default:
		return nil, coreerrors.New(coreerrors.CodeClientInvalid, "API key plugin clients must be an array").WithError(fmt.Errorf("got %T", value))
	}
}

func apikeyClientEntryMatchesCredential(entry interface{}, credential string) bool {
	credential = strings.TrimSpace(credential)
	if credential == "" {
		return false
	}
	client, ok := entry.(map[string]interface{})
	if !ok {
		return false
	}
	if key := stringValue(client["key"]); key != "" && key == credential {
		return true
	}
	if fingerprint := apikeyClientEntryFingerprint(client); fingerprint != "" && fingerprint == credential {
		return true
	}
	return credentials.VerifyAPIKey(credential, stringValue(client["key_hash"]))
}

func apikeyClientEntry(client managementClientRequest) map[string]interface{} {
	enabled := true
	if client.Enabled != nil {
		enabled = *client.Enabled
	}
	return map[string]interface{}{
		"id":              strings.TrimSpace(client.ID),
		"name":            strings.TrimSpace(client.Name),
		"key_hash":        credentials.APIKeyHash(client.Key),
		"key_fingerprint": credentials.APIKeyFingerprint(client.Key),
		"enabled":         enabled,
		"group":           strings.TrimSpace(client.Group),
		"scopes":          stringSliceToInterfaceSlice(client.Scopes),
		"tags":            stringSliceToInterfaceSlice(client.Tags),
	}
}

func apikeyClientEntrySummary(entry interface{}) map[string]interface{} {
	client, ok := entry.(map[string]interface{})
	if !ok {
		return map[string]interface{}{}
	}
	return map[string]interface{}{
		"client_id":       stringValue(client["id"]),
		"name":            stringValue(client["name"]),
		"group":           stringValue(client["group"]),
		"scopes":          stringSliceValue(client["scopes"]),
		"tags":            stringSliceValue(client["tags"]),
		"key_fingerprint": apikeyClientEntryFingerprint(client),
		"enabled":         apikeyClientEntryEnabled(client),
	}
}

func apikeyClientEntryFingerprint(client map[string]interface{}) string {
	if fingerprint := stringValue(client["key_fingerprint"]); fingerprint != "" {
		return fingerprint
	}
	if hashFingerprint := credentials.APIKeyFingerprintFromHash(stringValue(client["key_hash"])); hashFingerprint != "" {
		return hashFingerprint
	}
	return credentials.APIKeyFingerprint(stringValue(client["key"]))
}

func apikeyClientEntryEnabled(client map[string]interface{}) bool {
	enabled, ok := client["enabled"].(bool)
	if !ok {
		return true
	}
	return enabled
}

func cloneClientEntry(client map[string]interface{}) map[string]interface{} {
	out := make(map[string]interface{}, len(client))
	for key, value := range client {
		out[key] = value
	}
	return out
}

func stringSliceToInterfaceSlice(values []string) []interface{} {
	if len(values) == 0 {
		return nil
	}
	out := make([]interface{}, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			out = append(out, value)
		}
	}
	return out
}
