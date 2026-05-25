package gateway

import (
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/bhangun/iket/pkg/config"
)

type bffCacheEntry struct {
	expiresAt  time.Time
	staleUntil time.Time
	result     bffStepResult
}

type bffCoalescedCall struct {
	done   chan struct{}
	result bffStepResult
}

func (g *Gateway) getBFFCacheEntry(key string, now time.Time) (bffStepResult, bool) {
	if strings.TrimSpace(key) == "" {
		return bffStepResult{}, false
	}
	g.bffCacheMu.RLock()
	entry, ok := g.bffCache[key]
	g.bffCacheMu.RUnlock()
	if !ok {
		return bffStepResult{}, false
	}
	if !entry.expiresAt.After(now) {
		if entry.staleUntil.After(now) {
			return bffStepResult{}, false
		}
		g.bffCacheMu.Lock()
		if current, exists := g.bffCache[key]; exists && !current.expiresAt.After(now) && !current.staleUntil.After(now) {
			delete(g.bffCache, key)
		}
		g.bffCacheMu.Unlock()
		return bffStepResult{}, false
	}
	result := cloneBFFStepResult(entry.result)
	result.attempts = 0
	result.cacheHit = true
	return result, true
}

func (g *Gateway) getBFFStaleCacheEntry(key string, now time.Time) (bffStepResult, bool) {
	if strings.TrimSpace(key) == "" {
		return bffStepResult{}, false
	}
	g.bffCacheMu.RLock()
	entry, ok := g.bffCache[key]
	g.bffCacheMu.RUnlock()
	if !ok {
		return bffStepResult{}, false
	}
	if entry.expiresAt.After(now) || !entry.staleUntil.After(now) {
		if !entry.expiresAt.After(now) && !entry.staleUntil.After(now) {
			g.bffCacheMu.Lock()
			if current, exists := g.bffCache[key]; exists && !current.expiresAt.After(now) && !current.staleUntil.After(now) {
				delete(g.bffCache, key)
			}
			g.bffCacheMu.Unlock()
		}
		return bffStepResult{}, false
	}
	result := cloneBFFStepResult(entry.result)
	result.cacheHit = true
	result.cacheStale = true
	return result, true
}

func (g *Gateway) setBFFCacheEntry(key string, ttl time.Duration, staleIfError time.Duration, result bffStepResult, now time.Time) {
	if strings.TrimSpace(key) == "" || ttl <= 0 {
		return
	}
	cached := cloneBFFStepResult(result)
	cached.cacheHit = false
	cached.cacheStale = false
	expiresAt := now.Add(ttl)
	staleUntil := expiresAt
	if staleIfError > 0 {
		staleUntil = staleUntil.Add(staleIfError)
	}
	g.bffCacheMu.Lock()
	g.bffCache[key] = bffCacheEntry{
		expiresAt:  expiresAt,
		staleUntil: staleUntil,
		result:     cached,
	}
	g.bffCacheMu.Unlock()
}

func (g *Gateway) clearBFFCache() {
	g.bffCacheMu.Lock()
	g.bffCache = make(map[string]bffCacheEntry)
	g.bffCacheMu.Unlock()
}

func (g *Gateway) coalesceBFFStep(key string, fn func() bffStepResult) bffStepResult {
	if strings.TrimSpace(key) == "" {
		return fn()
	}

	g.bffCoalesceMu.Lock()
	if call, ok := g.bffCoalesce[key]; ok {
		g.bffCoalesceMu.Unlock()
		<-call.done
		result := cloneBFFStepResult(call.result)
		result.coalesced = true
		return result
	}

	call := &bffCoalescedCall{done: make(chan struct{})}
	g.bffCoalesce[key] = call
	g.bffCoalesceMu.Unlock()

	result := fn()
	call.result = cloneBFFStepResult(result)
	close(call.done)

	g.bffCoalesceMu.Lock()
	delete(g.bffCoalesce, key)
	g.bffCoalesceMu.Unlock()

	return result
}

func cloneBFFStepResult(result bffStepResult) bffStepResult {
	cloned := result
	if result.header != nil {
		cloned.header = result.header.Clone()
	}
	if result.body != nil {
		cloned.body = append([]byte(nil), result.body...)
	}
	return cloned
}

func bffStepCacheTTL(step config.BFFStepConfig) time.Duration {
	if strings.TrimSpace(step.CacheTTL) == "" {
		return 0
	}
	ttl, err := time.ParseDuration(strings.TrimSpace(step.CacheTTL))
	if err != nil || ttl <= 0 {
		return 0
	}
	return ttl
}

func bffStepStaleIfError(step config.BFFStepConfig) time.Duration {
	if strings.TrimSpace(step.StaleIfError) == "" {
		return 0
	}
	ttl, err := time.ParseDuration(strings.TrimSpace(step.StaleIfError))
	if err != nil || ttl <= 0 {
		return 0
	}
	return ttl
}

func bffStepCacheAllowedForMethod(step config.BFFStepConfig, method string) bool {
	if step.CacheUnsafe {
		return true
	}
	switch strings.ToUpper(strings.TrimSpace(method)) {
	case http.MethodGet, http.MethodHead:
		return true
	default:
		return false
	}
}

func bffStepCacheStatusAllowed(step config.BFFStepConfig, statusCode int) bool {
	if len(step.CacheStatuses) == 0 {
		return statusCode >= http.StatusOK && statusCode < http.StatusMultipleChoices
	}
	for _, candidate := range step.CacheStatuses {
		if candidate == statusCode {
			return true
		}
	}
	return false
}

func bffStepCacheKey(r *http.Request, previous map[string]bffStepResult, route config.RouterConfig, step config.BFFStepConfig, parsedURL *url.URL) (string, error) {
	if strings.TrimSpace(step.CacheKey) != "" {
		resolved, err := resolveBFFTemplateStringValue(r, previous, step.CacheKey)
		if err != nil {
			return "", err
		}
		return strings.Join([]string{
			route.Path,
			step.Name,
			strings.ToUpper(step.EffectiveMethod()),
			resolved,
		}, "|"), nil
	}
	resolvedURL := ""
	if parsedURL != nil {
		resolvedURL = parsedURL.String()
	}
	return strings.Join([]string{
		route.Path,
		step.Name,
		strings.ToUpper(step.EffectiveMethod()),
		resolvedURL,
	}, "|"), nil
}
