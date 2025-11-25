package plugins

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"iket/pkg/plugin"
	
	"golang.org/x/time/rate"
)

// RateLimiterPlugin implements a rate limiting plugin
type RateLimiterPlugin struct {
	*plugin.BasePlugin
	windowSize        time.Duration
	maxRequestsPerIP  int
	cleanupInterval   time.Duration
	ipRequestCounters map[string]*ipCounter
	mu                sync.RWMutex
	stopCleanup       chan struct{}
}

type ipCounter struct {
	count       int
	lastRequest time.Time
}

// NewRateLimiterPlugin creates a new rate limiter plugin
func NewRateLimiterPlugin() *RateLimiterPlugin {
	p := &RateLimiterPlugin{
		BasePlugin: plugin.NewBasePlugin("rate-limiter", "1.0.0", "Rate limiting plugin for API gateway"),
	}
	return p
}

// Type returns the plugin type
func (p *RateLimiterPlugin) Type() plugin.PluginType {
	return plugin.MiddlewarePlugin
}

// Validate validates the plugin configuration
func (p *RateLimiterPlugin) Validate(config map[string]interface{}) error {
	// Check for required fields if any
	requiredFields := []string{} // No required fields for this plugin
	return p.BasePlugin.ValidateRequiredFields(requiredFields)
}

// GetConfigSchema returns the JSON schema for plugin configuration
func (p *RateLimiterPlugin) GetConfigSchema() map[string]interface{} {
	return map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"windowSizeSeconds": map[string]interface{}{
				"type":    "integer",
				"default": 60,
				"minimum": 1,
				"maximum": 3600,
				"description": "Time window in seconds for rate limiting",
			},
			"maxRequestsPerIP": map[string]interface{}{
				"type":    "integer",
				"default": 100,
				"minimum": 1,
				"maximum": 10000,
				"description": "Maximum requests allowed per IP in the time window",
			},
			"cleanupIntervalMinutes": map[string]interface{}{
				"type":    "integer",
				"default": 5,
				"minimum": 1,
				"maximum": 60,
				"description": "Interval in minutes to clean up expired records",
			},
		},
	}
}

// Initialize sets up the rate limiter with the provided configuration
func (p *RateLimiterPlugin) Initialize(config map[string]interface{}) error {
	if err := p.Validate(config); err != nil {
		return err
	}
	
	// Set default values
	p.windowSize = 1 * time.Minute
	p.maxRequestsPerIP = 100
	p.cleanupInterval = 5 * time.Minute

	// Override with provided configuration
	if window := p.GetConfigValueAsInt("windowSizeSeconds", 60); window > 0 {
		p.windowSize = time.Duration(window) * time.Second
	}

	if maxRequests := p.GetConfigValueAsInt("maxRequestsPerIP", 100); maxRequests > 0 {
		p.maxRequestsPerIP = maxRequests
	}

	if cleanup := p.GetConfigValueAsInt("cleanupIntervalMinutes", 5); cleanup > 0 {
		p.cleanupInterval = time.Duration(cleanup) * time.Minute
	}

	// Initialize counters
	p.ipRequestCounters = make(map[string]*ipCounter)
	p.stopCleanup = make(chan struct{})

	return p.BasePlugin.Initialize(config)
}

// Start starts the rate limiter plugin
func (p *RateLimiterPlugin) Start(ctx context.Context) error {
	// Start cleanup goroutine
	go p.startCleanup()
	return p.BasePlugin.Start(ctx)
}

// Stop stops the rate limiter plugin
func (p *RateLimiterPlugin) Stop(ctx context.Context) error {
	if p.stopCleanup != nil {
		close(p.stopCleanup)
	}
	return p.BasePlugin.Stop(ctx)
}

// startCleanup periodically removes expired IP records
func (p *RateLimiterPlugin) startCleanup() {
	ticker := time.NewTicker(p.cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			p.cleanup()
		case <-p.stopCleanup:
			return
		}
	}
}

// cleanup removes expired IP records
func (p *RateLimiterPlugin) cleanup() {
	cutoff := time.Now().Add(-p.windowSize)

	p.mu.Lock()
	defer p.mu.Unlock()

	removed := 0
	for ip, counter := range p.ipRequestCounters {
		if counter.lastRequest.Before(cutoff) {
			delete(p.ipRequestCounters, ip)
			removed++
		}
	}
}

// Middleware returns a middleware function that implements rate limiting
func (p *RateLimiterPlugin) Middleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := getClientIP(r)

			p.mu.Lock()

			// Get or create IP counter
			counter, exists := p.ipRequestCounters[ip]
			if !exists {
				counter = &ipCounter{
					count:       0,
					lastRequest: time.Now(),
				}
				p.ipRequestCounters[ip] = counter
			}

			// Check if window has expired
			if time.Since(counter.lastRequest) > p.windowSize {
				counter.count = 1
				counter.lastRequest = time.Now()
			} else {
				// Increment counter
				counter.count++
				counter.lastRequest = time.Now()

				// Check if rate limit exceeded
				if counter.count > p.maxRequestsPerIP {
					p.mu.Unlock()
					w.Header().Set("Retry-After", fmt.Sprintf("%d", int(p.windowSize.Seconds())))
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusTooManyRequests)
					w.Write([]byte(`{"error":"Too Many Requests","message":"Rate limit exceeded"}`))
					return
				}
			}

			p.mu.Unlock()

			// Proceed to next handler
			next.ServeHTTP(w, r)
		})
	}
}

// getClientIP extracts the client IP from the request
func getClientIP(r *http.Request) string {
	// Try X-Forwarded-For header first
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		if len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}

	// Try X-Real-IP header
	if xrip := r.Header.Get("X-Real-IP"); xrip != "" {
		return xrip
	}

	// Fall back to RemoteAddr
	return strings.Split(r.RemoteAddr, ":")[0]
}

// Plugin is the exported symbol for the plugin system to load
var Plugin plugin.Plugin = NewRateLimiterPlugin()