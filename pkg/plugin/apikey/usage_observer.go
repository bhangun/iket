package apikey

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/bhangun/iket/pkg/core/requestcontext"
	"github.com/bhangun/iket/pkg/plugin"
)

var _ plugin.ClientUsageObserverRegistrar = (*APIKeyPlugin)(nil)

const clientUsageObserverTimeout = 100 * time.Millisecond

const defaultClientUsageObserverTimeout = clientUsageObserverTimeout
const defaultClientUsageObserverAsyncMaxInFlight = 1024

func (p *APIKeyPlugin) RegisterClientUsageObserver(observer plugin.ClientUsageObserver) {
	if observer == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()

	observerName := strings.TrimSpace(observer.Name())
	for _, existing := range p.usageObservers {
		if observerName != "" && strings.EqualFold(strings.TrimSpace(existing.Name()), observerName) {
			return
		}
	}
	p.usageObservers = append(p.usageObservers, observer)
}

func (p *APIKeyPlugin) notifyClientUsage(ctx context.Context, event plugin.ClientUsageEvent) {
	observers := p.clientUsageObserversSnapshot()
	if len(observers) == 0 {
		return
	}
	timeout := p.clientUsageObserverTimeout()
	if p.clientUsageObserverAsync() {
		limiter, acquired := p.tryAcquireClientUsageObserverAsyncSlot()
		if !acquired {
			p.usageObserverAsyncDropped.Add(1)
			return
		}
		go func() {
			defer releaseClientUsageObserverAsyncSlot(limiter)
			observeClientUsage(detachedClientUsageContext(ctx), observers, event.Clone(), timeout)
		}()
		return
	}
	observeClientUsage(ctx, observers, event, timeout)
}

func observeClientUsage(ctx context.Context, observers []plugin.ClientUsageObserver, event plugin.ClientUsageEvent, timeout time.Duration) {
	var wg sync.WaitGroup
	wg.Add(len(observers))
	for _, observer := range observers {
		go func(observer plugin.ClientUsageObserver, event plugin.ClientUsageEvent) {
			defer wg.Done()
			safelyObserveClientUsage(ctx, observer, event, timeout)
		}(observer, event.Clone())
	}
	wg.Wait()
}

func (p *APIKeyPlugin) clientUsageObserversSnapshot() []plugin.ClientUsageObserver {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return append([]plugin.ClientUsageObserver(nil), p.usageObservers...)
}

func safelyObserveClientUsage(ctx context.Context, observer plugin.ClientUsageObserver, event plugin.ClientUsageEvent, timeout time.Duration) {
	if observer == nil {
		return
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if timeout <= 0 {
		timeout = defaultClientUsageObserverTimeout
	}
	observerCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	done := make(chan struct{})
	go func() {
		defer close(done)
		defer func() {
			_ = recover()
		}()
		observer.ObserveClientUsage(observerCtx, event)
	}()

	select {
	case <-done:
	case <-observerCtx.Done():
	}
}

func (p *APIKeyPlugin) clientUsageObserverTimeout() time.Duration {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.usageObserverTimeout <= 0 {
		return defaultClientUsageObserverTimeout
	}
	return p.usageObserverTimeout
}

func (p *APIKeyPlugin) clientUsageObserverAsync() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.usageObserverAsync
}

func (p *APIKeyPlugin) clientUsageObserverAsyncMaxInFlight() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.usageObserverAsyncMaxInFlight <= 0 {
		return defaultClientUsageObserverAsyncMaxInFlight
	}
	return p.usageObserverAsyncMaxInFlight
}

func (p *APIKeyPlugin) tryAcquireClientUsageObserverAsyncSlot() (chan struct{}, bool) {
	p.mu.RLock()
	limiter := p.usageObserverAsyncLimiter
	p.mu.RUnlock()
	if limiter == nil {
		return nil, true
	}
	select {
	case limiter <- struct{}{}:
		return limiter, true
	default:
		return limiter, false
	}
}

func releaseClientUsageObserverAsyncSlot(limiter chan struct{}) {
	if limiter == nil {
		return
	}
	select {
	case <-limiter:
	default:
	}
}

func detachedClientUsageContext(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return context.WithoutCancel(ctx)
}

func clientUsageEventFromRequest(client ClientApp, r *http.Request, outcome clientUsageOutcome) plugin.ClientUsageEvent {
	occurredAt := time.Now().UTC()
	if client.LastUsedAt != nil {
		occurredAt = client.LastUsedAt.UTC()
	}
	attribution, _ := requestcontext.AttributionFromContext(requestContextForClientUsage(r))
	event := plugin.ClientUsageEvent{
		Provider:       "apikey",
		ClientID:       strings.TrimSpace(client.ID),
		Name:           strings.TrimSpace(client.Name),
		Identity:       clientInventoryIdentity(client),
		Group:          strings.TrimSpace(client.Group),
		Scopes:         append([]string(nil), client.Scopes...),
		Tags:           append([]string(nil), client.Tags...),
		KeyFingerprint: clientInventoryFingerprint(client),
		RequestCount:   client.RequestCount,
		OccurredAt:     occurredAt,
		RequestID:      strings.TrimSpace(attribution.RequestID),
		RequestMethod:  requestMethodForClientUsage(r),
		RequestPath:    requestPathForClientUsage(r),
		RequestHost:    requestHostForClientUsage(r),
		RequestScheme:  requestSchemeForClientUsage(r),
		ResponseStatus: outcome.statusCode,
		ResponseBytes:  outcome.bytesWritten,
		DurationMillis: outcome.durationMillis,
		TenantRealm:    strings.TrimSpace(attribution.TenantRealm),
		ServiceName:    strings.TrimSpace(attribution.ServiceName),
		RouteName:      strings.TrimSpace(attribution.RouteName),
		RoutePath:      strings.TrimSpace(attribution.RoutePath),
	}
	return event.WithNormalizedMetering()
}

func requestContextForClientUsage(r *http.Request) context.Context {
	if r == nil {
		return nil
	}
	return r.Context()
}

func requestMethodForClientUsage(r *http.Request) string {
	if r == nil {
		return ""
	}
	return strings.TrimSpace(r.Method)
}

func requestPathForClientUsage(r *http.Request) string {
	if r == nil || r.URL == nil {
		return ""
	}
	return strings.TrimSpace(r.URL.EscapedPath())
}

func requestHostForClientUsage(r *http.Request) string {
	if r == nil {
		return ""
	}
	return strings.TrimSpace(r.Host)
}

func requestSchemeForClientUsage(r *http.Request) string {
	if r == nil {
		return ""
	}
	if r.URL != nil && strings.TrimSpace(r.URL.Scheme) != "" {
		return strings.TrimSpace(r.URL.Scheme)
	}
	if r.TLS != nil {
		return "https"
	}
	return "http"
}
