package apikey

import (
	"sort"
	"strings"

	"github.com/bhangun/iket/pkg/core/authcontext"
	"github.com/bhangun/iket/pkg/core/credentials"
	"github.com/bhangun/iket/pkg/plugin"
)

var _ plugin.ClientInventoryProvider = (*APIKeyPlugin)(nil)

// ListClients returns redacted configured clients.
//
// Deprecated: use ListClientInventory for the stable management capability.
func (p *APIKeyPlugin) ListClients() []ClientApp {
	p.mu.RLock()
	defer p.mu.RUnlock()
	clients := make([]ClientApp, 0, len(p.clients))
	for _, c := range p.clients {
		clients = append(clients, redactedClientApp(c))
	}
	sort.Slice(clients, func(i, j int) bool {
		if clients[i].ID != clients[j].ID {
			return clients[i].ID < clients[j].ID
		}
		if clients[i].KeyFingerprint != clients[j].KeyFingerprint {
			return clients[i].KeyFingerprint < clients[j].KeyFingerprint
		}
		return clients[i].Name < clients[j].Name
	})
	return clients
}

// ListClientInventory returns redacted client metadata for management APIs.
func (p *APIKeyPlugin) ListClientInventory() []plugin.ClientInventoryRecord {
	p.mu.RLock()
	defer p.mu.RUnlock()
	clients := make([]plugin.ClientInventoryRecord, 0, len(p.clients))
	for _, c := range p.clients {
		clients = append(clients, clientInventoryRecord(c))
	}
	sort.Slice(clients, func(i, j int) bool {
		if clients[i].ID != clients[j].ID {
			return clients[i].ID < clients[j].ID
		}
		if clients[i].KeyFingerprint != clients[j].KeyFingerprint {
			return clients[i].KeyFingerprint < clients[j].KeyFingerprint
		}
		return clients[i].Name < clients[j].Name
	})
	return clients
}

// FindClientInventory returns one redacted client record by raw key or key
// fingerprint. Raw keys are accepted for operator convenience but never echoed.
func (p *APIKeyPlugin) FindClientInventory(credential string) (plugin.ClientInventoryRecord, bool) {
	credential = strings.TrimSpace(credential)
	if credential == "" {
		return plugin.ClientInventoryRecord{}, false
	}

	p.mu.RLock()
	defer p.mu.RUnlock()
	for _, c := range p.clients {
		if clientMatchesInventoryLookup(c, credential) {
			return clientInventoryRecord(c), true
		}
	}
	return plugin.ClientInventoryRecord{}, false
}

func clientInventoryRecord(client ClientApp) plugin.ClientInventoryRecord {
	fingerprint := clientInventoryFingerprint(client)
	lastUsedAt := clonedTime(client.LastUsedAt)
	return plugin.ClientInventoryRecord{
		ID:             client.ID,
		Name:           client.Name,
		Identity:       clientInventoryIdentity(client),
		KeyFingerprint: fingerprint,
		KeyRedacted:    fingerprint != "" || client.Key != "" || client.KeyHash != "",
		Enabled:        client.Enabled,
		Group:          client.Group,
		Scopes:         append([]string(nil), client.Scopes...),
		Tags:           append([]string(nil), client.Tags...),
		RequestCount:   client.RequestCount,
		LastUsedAt:     lastUsedAt,
	}
}

func clientInventoryIdentity(client ClientApp) *authcontext.PrincipalIdentity {
	identity, ok := authcontext.PrincipalIdentityFromPrincipal(principalFromClient(client))
	if !ok {
		return nil
	}
	return &identity
}

func redactedClientApp(client ClientApp) ClientApp {
	client.KeyFingerprint = clientInventoryFingerprint(client)
	client.Key = ""
	client.KeyHash = ""
	client.Scopes = append([]string(nil), client.Scopes...)
	client.Tags = append([]string(nil), client.Tags...)
	client.LastUsedAt = clonedTime(client.LastUsedAt)
	return client
}

func clientMatchesInventoryLookup(client ClientApp, credential string) bool {
	if clientInventoryFingerprint(client) == credential {
		return true
	}
	return credentialMatchesClient(client, credential, credentials.APIKeyFingerprint(credential))
}

func clientInventoryFingerprint(client ClientApp) string {
	if client.KeyFingerprint != "" {
		return client.KeyFingerprint
	}
	if hashFingerprint := credentials.APIKeyFingerprintFromHash(client.KeyHash); hashFingerprint != "" {
		return hashFingerprint
	}
	return credentials.APIKeyFingerprint(client.Key)
}
