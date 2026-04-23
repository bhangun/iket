package apikey

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"

	"github.com/bhangun/iket/pkg/plugin"
)

type ClientApp struct {
	ID     string   `json:"id"`
	Name   string   `json:"name"`
	Key    string   `json:"key"`
	Group  string   `json:"group,omitempty"`
	Scopes []string `json:"scopes,omitempty"`
	Tags   []string `json:"tags,omitempty"`
}

type APIKeyPlugin struct {
	enabled    bool
	headerName string
	queryParam string
	clients    map[string]ClientApp // Key -> ClientApp
	mu         sync.RWMutex
}

func (p *APIKeyPlugin) Name() string {
	return "apikey"
}

func (p *APIKeyPlugin) Type() plugin.PluginType {
	return plugin.AuthPlugin
}

func (p *APIKeyPlugin) Initialize(config map[string]interface{}) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.enabled = false
	p.headerName = "X-API-Key"
	p.queryParam = "api_key"
	p.clients = make(map[string]ClientApp)

	if enabled, ok := config["enabled"].(bool); ok {
		p.enabled = enabled
	}

	if hn, ok := config["header_name"].(string); ok && hn != "" {
		p.headerName = hn
	}

	if qp, ok := config["query_param"].(string); ok && qp != "" {
		p.queryParam = qp
	}

	if clients, ok := config["clients"].([]interface{}); ok {
		for _, c := range clients {
			if clientMap, ok := c.(map[string]interface{}); ok {
				client := ClientApp{
					ID:   clientMap["id"].(string),
					Name: clientMap["name"].(string),
					Key:  clientMap["key"].(string),
				}
				if group, ok := clientMap["group"].(string); ok {
					client.Group = group
				}
				if scopes, ok := clientMap["scopes"].([]interface{}); ok {
					for _, s := range scopes {
						if scopeStr, ok := s.(string); ok {
							client.Scopes = append(client.Scopes, scopeStr)
						}
					}
				}
				if tags, ok := clientMap["tags"].([]interface{}); ok {
					for _, t := range tags {
						if tagStr, ok := t.(string); ok {
							client.Tags = append(client.Tags, tagStr)
						}
					}
				}
				p.clients[client.Key] = client
			}
		}
	}

	return nil
}

func (p *APIKeyPlugin) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !p.enabled {
			next.ServeHTTP(w, r)
			return
		}

		key := p.extractKey(r)
		if key == "" {
			p.writeError(w, "API key required", http.StatusUnauthorized)
			return
		}

		p.mu.RLock()
		client, exists := p.clients[key]
		p.mu.RUnlock()

		if !exists {
			p.writeError(w, "Invalid API key", http.StatusUnauthorized)
			return
		}

		// Success: inject client info into context
		ctx := context.WithValue(r.Context(), "apikey_client_id", client.ID)
		ctx = context.WithValue(ctx, "apikey_scopes", client.Scopes)
		ctx = context.WithValue(ctx, "apikey_group", client.Group)
		
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (p *APIKeyPlugin) extractKey(r *http.Request) string {
	// 1. Try Header
	key := r.Header.Get(p.headerName)
	if key != "" {
		return key
	}

	// 2. Try Query Param
	return r.URL.Query().Get(p.queryParam)
}

func (p *APIKeyPlugin) writeError(w http.ResponseWriter, message string, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	response := map[string]interface{}{
		"error":   "API Key Error",
		"message": message,
	}
	json.NewEncoder(w).Encode(response)
}

func (p *APIKeyPlugin) Tags() map[string]string {
	return map[string]string{
		"category":   "auth",
		"middleware": "true",
	}
}

func (p *APIKeyPlugin) Health() error {
	return nil
}

func (p *APIKeyPlugin) Status() string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if !p.enabled {
		return "API Key Plugin: Disabled"
	}
	return fmt.Sprintf("API Key Plugin: Enabled (%d clients configured)", len(p.clients))
}

// AddClient adds a new client app dynamically
func (p *APIKeyPlugin) AddClient(client ClientApp) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.clients[client.Key] = client
}

// RemoveClient removes a client app by key
func (p *APIKeyPlugin) RemoveClient(key string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.clients, key)
}

// ListClients returns all configured clients
func (p *APIKeyPlugin) ListClients() []ClientApp {
	p.mu.RLock()
	defer p.mu.RUnlock()
	clients := make([]ClientApp, 0, len(p.clients))
	for _, c := range p.clients {
		clients = append(clients, c)
	}
	return clients
}

func init() {
	plugin.RegisterFactory("apikey", func(config map[string]interface{}) (plugin.Plugin, error) {
		p := &APIKeyPlugin{}
		if config != nil {
			if err := p.Initialize(config); err != nil {
				return nil, err
			}
		}
		return p, nil
	})
}
