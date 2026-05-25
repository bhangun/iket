package apikey

import "time"

type clientUsageSnapshot struct {
	RequestCount int64
	LastUsedAt   *time.Time
}

type clientUsageIndex struct {
	byLookupKey   map[string]clientUsageSnapshot
	byID          map[string]clientUsageSnapshot
	byFingerprint map[string]clientUsageSnapshot
}

func captureClientUsage(clients map[string]ClientApp) clientUsageIndex {
	index := clientUsageIndex{
		byLookupKey:   make(map[string]clientUsageSnapshot),
		byID:          make(map[string]clientUsageSnapshot),
		byFingerprint: make(map[string]clientUsageSnapshot),
	}
	for lookupKey, client := range clients {
		snapshot, ok := clientUsageFromClient(client)
		if !ok {
			continue
		}
		index.byLookupKey[lookupKey] = snapshot
		if client.ID != "" {
			index.byID[client.ID] = snapshot
		}
		if fingerprint := clientInventoryFingerprint(client); fingerprint != "" {
			index.byFingerprint[fingerprint] = snapshot
		}
	}
	return index
}

func restoreClientUsage(client *ClientApp, lookupKey string, index clientUsageIndex) {
	if client == nil {
		return
	}
	if snapshot, ok := index.byLookupKey[lookupKey]; ok {
		applyClientUsage(client, snapshot)
		return
	}
	if client.ID != "" {
		if snapshot, ok := index.byID[client.ID]; ok {
			applyClientUsage(client, snapshot)
			return
		}
	}
	if fingerprint := clientInventoryFingerprint(*client); fingerprint != "" {
		if snapshot, ok := index.byFingerprint[fingerprint]; ok {
			applyClientUsage(client, snapshot)
		}
	}
}

func clientUsageFromClient(client ClientApp) (clientUsageSnapshot, bool) {
	if client.RequestCount == 0 && client.LastUsedAt == nil {
		return clientUsageSnapshot{}, false
	}
	return clientUsageSnapshot{
		RequestCount: client.RequestCount,
		LastUsedAt:   clonedTime(client.LastUsedAt),
	}, true
}

func applyClientUsage(client *ClientApp, usage clientUsageSnapshot) {
	client.RequestCount = usage.RequestCount
	client.LastUsedAt = clonedTime(usage.LastUsedAt)
}

func clonedTime(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	cloned := value.UTC()
	return &cloned
}
