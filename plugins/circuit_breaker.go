package plugins

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"iket/pkg/plugin"
)

// CircuitState represents the state of the circuit breaker
type CircuitState int

const (
	CircuitClosed CircuitState = iota
	CircuitOpen
	CircuitHalfOpen
)

// CircuitBreakerPlugin implements a circuit breaker pattern
type CircuitBreakerPlugin struct {
	*plugin.BasePlugin
	maxFailures     int
	timeout         time.Duration
	resetTimeout    time.Duration
	state           CircuitState
	failureCount    int
	lastFailureTime time.Time
	mutex           sync.RWMutex
}

// NewCircuitBreakerPlugin creates a new circuit breaker plugin
func NewCircuitBreakerPlugin() *CircuitBreakerPlugin {
	p := &CircuitBreakerPlugin{
		BasePlugin:  plugin.NewBasePlugin("circuit-breaker", "1.0.0", "Circuit breaker plugin for API gateway"),
		state:       CircuitClosed,
		failureCount: 0,
	}
	return p
}

// Type returns the plugin type
func (p *CircuitBreakerPlugin) Type() plugin.PluginType {
	return plugin.MiddlewarePlugin
}

// Validate validates the plugin configuration
func (p *CircuitBreakerPlugin) Validate(config map[string]interface{}) error {
	// Check for required fields if any
	requiredFields := []string{} // No required fields for this plugin
	return p.BasePlugin.ValidateRequiredFields(requiredFields)
}

// GetConfigSchema returns the JSON schema for plugin configuration
func (p *CircuitBreakerPlugin) GetConfigSchema() map[string]interface{} {
	return map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"maxFailures": map[string]interface{}{
				"type":    "integer",
				"default": 5,
				"minimum": 1,
				"maximum": 100,
				"description": "Maximum number of failures before opening the circuit",
			},
			"timeout": map[string]interface{}{
				"type":    "integer",
				"default": 60,
				"minimum": 1,
				"maximum": 3600,
				"description": "Time in seconds to wait before attempting to close the circuit",
			},
			"resetTimeout": map[string]interface{}{
				"type":    "integer",
				"default": 5,
				"minimum": 1,
				"maximum": 300,
				"description": "Time in seconds to wait in half-open state before returning to closed",
			},
		},
	}
}

// Initialize sets up the circuit breaker with the provided configuration
func (p *CircuitBreakerPlugin) Initialize(config map[string]interface{}) error {
	if err := p.Validate(config); err != nil {
		return err
	}

	// Set default values
	p.maxFailures = 5
	p.timeout = 60 * time.Second
	p.resetTimeout = 5 * time.Second

	// Override with provided configuration
	if maxFailures := p.GetConfigValueAsInt("maxFailures", 5); maxFailures > 0 {
		p.maxFailures = maxFailures
	}

	if timeoutSeconds := p.GetConfigValueAsInt("timeout", 60); timeoutSeconds > 0 {
		p.timeout = time.Duration(timeoutSeconds) * time.Second
	}

	if resetTimeoutSeconds := p.GetConfigValueAsInt("resetTimeout", 5); resetTimeoutSeconds > 0 {
		p.resetTimeout = time.Duration(resetTimeoutSeconds) * time.Second
	}

	return p.BasePlugin.Initialize(config)
}

// Start starts the circuit breaker plugin
func (p *CircuitBreakerPlugin) Start(ctx context.Context) error {
	// Start a goroutine to monitor and reset the circuit breaker state
	go p.monitorCircuit(ctx)
	return p.BasePlugin.Start(ctx)
}

// Stop stops the circuit breaker plugin
func (p *CircuitBreakerPlugin) Stop(ctx context.Context) error {
	return p.BasePlugin.Stop(ctx)
}

// monitorCircuit monitors the circuit breaker state and resets it when appropriate
func (p *CircuitBreakerPlugin) monitorCircuit(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			p.checkAndResetCircuit()
		}
	}
}

// checkAndResetCircuit checks if the circuit should be reset
func (p *CircuitBreakerPlugin) checkAndResetCircuit() {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	switch p.state {
	case CircuitOpen:
		if time.Since(p.lastFailureTime) >= p.timeout {
			p.state = CircuitHalfOpen
		}
	case CircuitHalfOpen:
		if time.Since(p.lastFailureTime) >= p.resetTimeout {
			p.state = CircuitClosed
			p.failureCount = 0
		}
	}
}

// Middleware returns a middleware function that implements circuit breaking
func (p *CircuitBreakerPlugin) Middleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if p.isCircuitOpen() {
				p.handleCircuitOpen(w, r)
				return
			}

			// Wrap the response writer to capture status codes
			wrappedWriter := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}
			
			next.ServeHTTP(wrappedWriter, r)

			// Record success or failure based on status code
			if wrappedWriter.statusCode >= 500 {
				p.recordFailure()
			} else {
				p.recordSuccess()
			}
		})
	}
}

// isCircuitOpen checks if the circuit is currently open
func (p *CircuitBreakerPlugin) isCircuitOpen() bool {
	p.mutex.RLock()
	defer p.mutex.RUnlock()

	return p.state == CircuitOpen
}

// handleCircuitOpen handles requests when the circuit is open
func (p *CircuitBreakerPlugin) handleCircuitOpen(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusServiceUnavailable)
	w.Write([]byte(`{"error":"Service Unavailable","message":"Circuit breaker is open"}`))
}

// recordSuccess records a successful request
func (p *CircuitBreakerPlugin) recordSuccess() {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	if p.state == CircuitHalfOpen {
		// If we're in half-open state and had a success, close the circuit
		p.state = CircuitClosed
		p.failureCount = 0
	} else if p.state == CircuitOpen {
		// If we're in open state, we shouldn't be getting successes
		// This shouldn't happen in normal operation, but reset if it does
		p.state = CircuitClosed
		p.failureCount = 0
	}
}

// recordFailure records a failed request
func (p *CircuitBreakerPlugin) recordFailure() {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	p.failureCount++
	p.lastFailureTime = time.Now()

	if p.failureCount >= p.maxFailures && p.state != CircuitOpen {
		p.state = CircuitOpen
	}
}

// responseWriter wraps http.ResponseWriter to capture status codes
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

// WriteHeader captures the status code
func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// Plugin is the exported symbol for the plugin system to load
var Plugin plugin.Plugin = NewCircuitBreakerPlugin()