package apikey

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bhangun/iket/pkg/core/authcontext"
	"github.com/bhangun/iket/pkg/core/credentials"
	"github.com/bhangun/iket/pkg/plugin"
)

type ClientApp struct {
	ID             string     `json:"id"`
	Name           string     `json:"name"`
	Key            string     `json:"key,omitempty"`
	KeyHash        string     `json:"key_hash,omitempty"`
	KeyFingerprint string     `json:"key_fingerprint,omitempty"`
	Enabled        bool       `json:"enabled"`
	Group          string     `json:"group,omitempty"`
	Scopes         []string   `json:"scopes,omitempty"`
	Tags           []string   `json:"tags,omitempty"`
	RequestCount   int64      `json:"request_count,omitempty"`
	LastUsedAt     *time.Time `json:"last_used_at,omitempty"`
}

type APIKeyPlugin struct {
	enabled                       bool
	headerName                    string
	queryParam                    string
	clients                       map[string]ClientApp // credential lookup key -> ClientApp
	usageObservers                []plugin.ClientUsageObserver
	usageObserverTimeout          time.Duration
	usageObserverAsync            bool
	usageObserverAsyncMaxInFlight int
	usageObserverAsyncLimiter     chan struct{}
	usageObserverAsyncDropped     atomic.Int64
	mu                            sync.RWMutex
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

	usage := captureClientUsage(p.clients)
	p.enabled = false
	p.headerName = "X-API-Key"
	p.queryParam = "api_key"
	p.usageObserverTimeout = defaultClientUsageObserverTimeout
	p.usageObserverAsync = false
	p.usageObserverAsyncMaxInFlight = defaultClientUsageObserverAsyncMaxInFlight
	p.usageObserverAsyncLimiter = make(chan struct{}, p.usageObserverAsyncMaxInFlight)
	p.usageObserverAsyncDropped.Store(0)
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
	if timeout, ok, err := clientUsageObserverTimeoutFromConfig(config); err != nil {
		return err
	} else if ok {
		p.usageObserverTimeout = timeout
	}
	if async, ok, err := clientUsageObserverAsyncFromConfig(config); err != nil {
		return err
	} else if ok {
		p.usageObserverAsync = async
	}
	if maxInFlight, ok, err := clientUsageObserverAsyncMaxInFlightFromConfig(config); err != nil {
		return err
	} else if ok {
		p.usageObserverAsyncMaxInFlight = maxInFlight
		p.usageObserverAsyncLimiter = make(chan struct{}, maxInFlight)
	}

	if clients, ok := config["clients"].([]interface{}); ok {
		for _, c := range clients {
			if clientMap, ok := c.(map[string]interface{}); ok {
				client := clientAppFromConfig(clientMap)
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
				if lookupKey := clientLookupKey(client); lookupKey != "" {
					restoreClientUsage(&client, lookupKey, usage)
					p.clients[lookupKey] = client
				}
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

		client, exists, enabled := p.authenticateClient(key, time.Now().UTC())

		if !exists {
			p.writeError(w, "Invalid API key", http.StatusUnauthorized)
			return
		}
		if !enabled {
			p.writeError(w, "API key client disabled", http.StatusForbidden)
			return
		}

		ctx := authcontext.WithAPIKeyClient(r.Context(), authcontext.APIKeyClient{
			ID:     client.ID,
			Group:  client.Group,
			Scopes: client.Scopes,
		})
		ctx = authcontext.WithPrincipal(ctx, principalFromClient(client))

		startedAt := time.Now()
		responseWriter := newClientUsageResponseWriter(w)
		notifiedUsage := false
		notifyUsage := func(outcome clientUsageOutcome) {
			if notifiedUsage {
				return
			}
			notifiedUsage = true
			p.notifyClientUsage(ctx, clientUsageEventFromRequest(client, r, outcome))
		}
		defer func() {
			if recovered := recover(); recovered != nil {
				outcome := responseWriter.clientUsageOutcome(time.Since(startedAt))
				outcome.statusCode = http.StatusInternalServerError
				notifyUsage(outcome)
				panic(recovered)
			}
		}()
		next.ServeHTTP(responseWriter, r.WithContext(ctx))
		notifyUsage(responseWriter.clientUsageOutcome(time.Since(startedAt)))
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

func (p *APIKeyPlugin) authenticateClient(key string, at time.Time) (ClientApp, bool, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()

	client, lookupKey, exists := p.lookupClientLocked(key)
	if !exists {
		return ClientApp{}, false, false
	}
	if !client.Enabled {
		return client, true, false
	}
	lastUsedAt := at.UTC()
	client.RequestCount++
	client.LastUsedAt = &lastUsedAt
	p.clients[lookupKey] = client
	return client, true, true
}

func (p *APIKeyPlugin) lookupClientLocked(key string) (ClientApp, string, bool) {
	hash := credentials.APIKeyHash(key)
	if client, exists := p.clients[hash]; exists {
		return client, hash, true
	}
	if client, exists := p.clients[key]; exists {
		return client, key, true
	}
	fingerprint := credentials.APIKeyFingerprint(key)
	for lookupKey, client := range p.clients {
		if credentialMatchesClient(client, key, fingerprint) {
			return client, lookupKey, true
		}
	}
	return ClientApp{}, "", false
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

// AddClient adds a new client app dynamically
func (p *APIKeyPlugin) AddClient(client ClientApp) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if lookupKey := clientLookupKey(client); lookupKey != "" {
		p.clients[lookupKey] = client
	}
}

// RemoveClient removes a client app by key
func (p *APIKeyPlugin) RemoveClient(key string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, exists := p.clients[credentials.APIKeyHash(key)]; exists {
		delete(p.clients, credentials.APIKeyHash(key))
		return
	}
	if _, exists := p.clients[key]; exists {
		delete(p.clients, key)
		return
	}
	fingerprint := credentials.APIKeyFingerprint(key)
	for lookupKey, client := range p.clients {
		if credentialMatchesClient(client, key, fingerprint) {
			delete(p.clients, lookupKey)
			return
		}
	}
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

func clientAppFromConfig(clientMap map[string]interface{}) ClientApp {
	client := ClientApp{
		ID:             stringConfigValue(clientMap["id"]),
		Name:           stringConfigValue(clientMap["name"]),
		Key:            stringConfigValue(clientMap["key"]),
		KeyHash:        credentials.NormalizeAPIKeyHash(stringConfigValue(clientMap["key_hash"])),
		KeyFingerprint: stringConfigValue(clientMap["key_fingerprint"]),
		Enabled:        true,
	}
	if enabled, ok := clientMap["enabled"].(bool); ok {
		client.Enabled = enabled
	}
	if client.KeyFingerprint == "" {
		if hashFingerprint := credentials.APIKeyFingerprintFromHash(client.KeyHash); hashFingerprint != "" {
			client.KeyFingerprint = hashFingerprint
		} else {
			client.KeyFingerprint = credentials.APIKeyFingerprint(client.Key)
		}
	}
	return client
}

func clientLookupKey(client ClientApp) string {
	if hash := credentials.NormalizeAPIKeyHash(client.KeyHash); hash != "" && credentials.APIKeyFingerprintFromHash(hash) != "" {
		return hash
	}
	return client.Key
}

func credentialMatchesClient(client ClientApp, key, fingerprint string) bool {
	if client.Key != "" && client.Key == key {
		return true
	}
	if client.KeyHash != "" && credentials.VerifyAPIKey(key, client.KeyHash) {
		return true
	}
	return fingerprint != "" && client.KeyFingerprint == fingerprint
}

func stringConfigValue(value interface{}) string {
	text, _ := value.(string)
	return text
}

func clientUsageObserverTimeoutFromConfig(config map[string]interface{}) (time.Duration, bool, error) {
	for _, key := range []string{"usage_observer_timeout", "usageObserverTimeout"} {
		value, ok := config[key]
		if !ok {
			continue
		}
		timeoutText, ok := value.(string)
		if !ok {
			return 0, false, fmt.Errorf("%s must be a duration string", key)
		}
		timeout, err := time.ParseDuration(strings.TrimSpace(timeoutText))
		if err != nil || timeout <= 0 {
			return 0, false, fmt.Errorf("%s must be a positive duration", key)
		}
		return timeout, true, nil
	}
	return 0, false, nil
}

func clientUsageObserverAsyncFromConfig(config map[string]interface{}) (bool, bool, error) {
	for _, key := range []string{"usage_observer_async", "usageObserverAsync"} {
		value, ok := config[key]
		if !ok {
			continue
		}
		async, ok := value.(bool)
		if !ok {
			return false, false, fmt.Errorf("%s must be a boolean", key)
		}
		return async, true, nil
	}
	return false, false, nil
}

func clientUsageObserverAsyncMaxInFlightFromConfig(config map[string]interface{}) (int, bool, error) {
	for _, key := range []string{"usage_observer_async_max_in_flight", "usageObserverAsyncMaxInFlight"} {
		value, ok := config[key]
		if !ok {
			continue
		}
		maxInFlight, ok := positiveIntConfigValue(value)
		if !ok {
			return 0, false, fmt.Errorf("%s must be a positive integer", key)
		}
		return maxInFlight, true, nil
	}
	return 0, false, nil
}

func positiveIntConfigValue(value interface{}) (int, bool) {
	maxInt := int64(^uint(0) >> 1)
	switch typed := value.(type) {
	case int:
		return typed, typed > 0
	case int64:
		if typed <= 0 || typed > maxInt {
			return 0, false
		}
		return int(typed), typed > 0
	case float64:
		if typed <= 0 || typed > float64(maxInt) {
			return 0, false
		}
		converted := int64(typed)
		if float64(converted) != typed {
			return 0, false
		}
		return int(converted), true
	default:
		return 0, false
	}
}
