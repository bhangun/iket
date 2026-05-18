package gateway

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/bhangun/iket/pkg/config"
)

const (
	defaultBackendHealthInterval = 15 * time.Second
	defaultBackendHealthTimeout  = 2 * time.Second
)

func (g *Gateway) activeBackendProbeLoop() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-g.shutdown:
			return
		case <-ticker.C:
			g.probeConfiguredBackends(time.Now().UTC())
		}
	}
}

func (g *Gateway) probeConfiguredBackends(now time.Time) {
	g.mu.RLock()
	cfg := g.config
	g.mu.RUnlock()
	if cfg == nil {
		return
	}
	for _, route := range cfg.GetAllRoutesFromServices(g.logger) {
		for _, backend := range route.Backends {
			if strings.TrimSpace(backend.HealthCheckPath) == "" {
				continue
			}
			destination := strings.TrimSpace(backend.Host)
			if destination == "" {
				destination = strings.TrimSpace(route.ServiceHost)
			}
			if destination == "" || !g.backendProbeDue(route, backend, destination, now) {
				continue
			}
			g.probeBackend(route, backend, destination, now)
		}
	}
}

func (g *Gateway) backendProbeDue(route config.RouterConfig, backend config.Backend, destination string, now time.Time) bool {
	key := g.backendStateKey(route, backend, destination)
	g.backendStateMu.RLock()
	state := g.backendState[key]
	g.backendStateMu.RUnlock()
	if state.LastChecked.IsZero() {
		return true
	}
	return now.Sub(state.LastChecked) >= backendHealthInterval(backend)
}

func (g *Gateway) probeBackend(route config.RouterConfig, backend config.Backend, destination string, now time.Time) {
	target, err := urlJoinPath(destination, backend.HealthCheckPath)
	if err != nil {
		g.recordBackendFailureWithStatus(route, backend, destination, 0, fmt.Errorf("failed to build backend health check url: %w", err), now)
		return
	}
	client := &http.Client{Timeout: backendHealthTimeout(backend)}
	req, err := http.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		g.recordBackendFailureWithStatus(route, backend, destination, 0, err, now)
		return
	}
	resp, err := client.Do(req)
	if err != nil {
		g.recordBackendFailureWithStatus(route, backend, destination, 0, err, now)
		return
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode >= 200 && resp.StatusCode < 400 {
		g.recordBackendSuccessWithStatus(route, backend, destination, resp.StatusCode, 0, now)
		return
	}
	g.recordBackendFailureWithStatus(route, backend, destination, resp.StatusCode, fmt.Errorf("health check responded with status %d", resp.StatusCode), now)
}

func urlJoinPath(rawBase, probePath string) (string, error) {
	base, err := url.Parse(strings.TrimSpace(rawBase))
	if err != nil {
		return "", err
	}
	base.Path = joinURLPath(base.Path, probePath)
	return base.String(), nil
}

func backendHealthInterval(backend config.Backend) time.Duration {
	if raw := strings.TrimSpace(backend.HealthInterval); raw != "" {
		if parsed, err := time.ParseDuration(raw); err == nil && parsed > 0 {
			return parsed
		}
	}
	return defaultBackendHealthInterval
}

func backendHealthTimeout(backend config.Backend) time.Duration {
	if raw := strings.TrimSpace(backend.HealthTimeout); raw != "" {
		if parsed, err := time.ParseDuration(raw); err == nil && parsed > 0 {
			return parsed
		}
	}
	return defaultBackendHealthTimeout
}
