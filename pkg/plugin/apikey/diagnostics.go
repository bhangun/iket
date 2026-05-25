package apikey

import (
	"fmt"
	"strings"

	"github.com/bhangun/iket/pkg/plugin"
)

type apiKeyDiagnosticsSnapshot struct {
	enabled                  bool
	clientCount              int
	observerCount            int
	observerNamedCount       int
	observerUnnamedCount     int
	observerNames            []string
	observerTimeout          string
	observerAsync            bool
	observerAsyncMaxInFlight int
	observerAsyncInFlight    int
	observerAsyncDropped     int64
}

func (p *APIKeyPlugin) Status() string {
	snapshot := p.diagnosticsSnapshot()
	if !snapshot.enabled {
		return "API Key Plugin: Disabled"
	}
	mode := "sync"
	if snapshot.observerAsync {
		mode = fmt.Sprintf(
			"async, max in-flight: %d, in-flight: %d, dropped: %d",
			snapshot.observerAsyncMaxInFlight,
			snapshot.observerAsyncInFlight,
			snapshot.observerAsyncDropped,
		)
	}
	return fmt.Sprintf(
		"API Key Plugin: Enabled (%d clients configured, %d usage observers, observer mode: %s, observer timeout: %s)",
		snapshot.clientCount,
		snapshot.observerCount,
		mode,
		snapshot.observerTimeout,
	)
}

func (p *APIKeyPlugin) Diagnostics() map[string]interface{} {
	snapshot := p.diagnosticsSnapshot()
	observerMode := "sync"
	if snapshot.observerAsync {
		observerMode = "async"
	}
	status, warningCodes := usageObserverDiagnosticsStatus(snapshot)
	return map[string]interface{}{
		"enabled":       snapshot.enabled,
		"status":        status,
		"warning_codes": append([]string{}, warningCodes...),
		"clients": map[string]interface{}{
			"configured": snapshot.clientCount,
		},
		"usage_observers": map[string]interface{}{
			"registered":          snapshot.observerCount,
			"named":               snapshot.observerNamedCount,
			"unnamed":             snapshot.observerUnnamedCount,
			"names":               append([]string{}, snapshot.observerNames...),
			"status":              status,
			"warning_codes":       append([]string{}, warningCodes...),
			"delivery_mode":       observerMode,
			"timeout":             snapshot.observerTimeout,
			"async_max_in_flight": snapshot.observerAsyncMaxInFlight,
			"async_in_flight":     snapshot.observerAsyncInFlight,
			"async_dropped":       snapshot.observerAsyncDropped,
		},
	}
}

func (p *APIKeyPlugin) diagnosticsSnapshot() apiKeyDiagnosticsSnapshot {
	p.mu.RLock()
	observers := append([]plugin.ClientUsageObserver(nil), p.usageObservers...)
	snapshot := apiKeyDiagnosticsSnapshot{
		enabled:                  p.enabled,
		clientCount:              len(p.clients),
		observerCount:            len(p.usageObservers),
		observerTimeout:          p.usageObserverTimeout.String(),
		observerAsync:            p.usageObserverAsync,
		observerAsyncMaxInFlight: p.usageObserverAsyncMaxInFlight,
	}
	if p.usageObserverAsyncLimiter != nil {
		snapshot.observerAsyncInFlight = len(p.usageObserverAsyncLimiter)
	}
	p.mu.RUnlock()
	snapshot.observerNames, snapshot.observerUnnamedCount = usageObserverNameStats(observers)
	snapshot.observerNamedCount = len(snapshot.observerNames)
	snapshot.observerAsyncDropped = p.usageObserverAsyncDropped.Load()
	return snapshot
}

func usageObserverDiagnosticsStatus(snapshot apiKeyDiagnosticsSnapshot) (string, []string) {
	if !snapshot.enabled {
		return "disabled", []string{}
	}
	status := "ok"
	warnings := []string{}
	if snapshot.observerUnnamedCount > 0 {
		status = "warning"
		warnings = append(warnings, "unnamed_observers_registered")
	}
	if snapshot.observerAsyncDropped > 0 {
		status = "degraded"
		warnings = append(warnings, "async_deliveries_dropped")
	}
	return status, warnings
}

func usageObserverNameStats(observers []plugin.ClientUsageObserver) ([]string, int) {
	names := make([]string, 0, len(observers))
	unnamed := 0
	for _, observer := range observers {
		if observer == nil {
			continue
		}
		if name := strings.TrimSpace(observer.Name()); name != "" {
			names = append(names, name)
		} else {
			unnamed++
		}
	}
	return names, unnamed
}
