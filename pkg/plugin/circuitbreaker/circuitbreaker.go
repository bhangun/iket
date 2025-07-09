package circuitbreaker

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"
)

type CircuitState string

const (
	StateClosed   CircuitState = "closed"
	StateOpen     CircuitState = "open"
	StateHalfOpen CircuitState = "half-open"
)

type CircuitBreakerPlugin struct {
	// Configuration
	timeout         time.Duration
	maxRetries      int
	threshold       int
	windowSize      time.Duration
	fallbackHandler http.HandlerFunc

	// State
	state           CircuitState
	failureCount    int
	lastFailureTime time.Time
	mu              sync.RWMutex
}

func (c *CircuitBreakerPlugin) Name() string {
	return "circuit_breaker"
}

func (c *CircuitBreakerPlugin) Type() string {
	return "circuit_breaker"
}

func (c *CircuitBreakerPlugin) Initialize(config map[string]interface{}) error {
	// Default values
	c.timeout = 30 * time.Second
	c.maxRetries = 3
	c.threshold = 5
	c.windowSize = 60 * time.Second
	c.fallbackHandler = func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte(`{"error":"Service temporarily unavailable","message":"Circuit breaker is open"}`))
	}

	// Override with config
	if v, ok := config["timeout"].(float64); ok {
		c.timeout = time.Duration(v) * time.Second
	}
	if v, ok := config["max_retries"].(int); ok {
		c.maxRetries = v
	}
	if v, ok := config["threshold"].(int); ok {
		c.threshold = v
	}
	if v, ok := config["window_size"].(float64); ok {
		c.windowSize = time.Duration(v) * time.Second
	}

	return nil
}

func (c *CircuitBreakerPlugin) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check circuit state
		if !c.canExecute() {
			c.fallbackHandler(w, r)
			return
		}

		// Execute with timeout and retries
		success := c.executeWithRetry(w, r, next)

		// Update circuit state
		c.updateState(success)
	})
}

func (c *CircuitBreakerPlugin) canExecute() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	switch c.state {
	case StateClosed:
		return true
	case StateHalfOpen:
		return true
	case StateOpen:
		// Check if window has passed
		if time.Since(c.lastFailureTime) > c.windowSize {
			c.mu.RUnlock()
			c.mu.Lock()
			c.state = StateHalfOpen
			c.mu.Unlock()
			c.mu.RLock()
			return true
		}
		return false
	default:
		return false
	}
}

func (c *CircuitBreakerPlugin) executeWithRetry(w http.ResponseWriter, r *http.Request, next http.Handler) bool {
	for attempt := 0; attempt <= c.maxRetries; attempt++ {
		// Create context with timeout
		ctx, cancel := context.WithTimeout(r.Context(), c.timeout)
		defer cancel()

		// Create response writer wrapper to capture status
		responseWriter := &responseWriterWrapper{ResponseWriter: w}

		// Execute request
		done := make(chan bool, 1)
		go func() {
			next.ServeHTTP(responseWriter, r.WithContext(ctx))
			done <- true
		}()

		select {
		case <-done:
			// Request completed
			if responseWriter.statusCode >= 500 {
				// Server error, consider as failure
				continue
			}
			return true // Success
		case <-ctx.Done():
			// Timeout
			if attempt == c.maxRetries {
				return false // Final failure
			}
			continue // Retry
		}
	}
	return false
}

func (c *CircuitBreakerPlugin) updateState(success bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if success {
		c.onSuccess()
	} else {
		c.onFailure()
	}
}

func (c *CircuitBreakerPlugin) onSuccess() {
	switch c.state {
	case StateClosed:
		// Reset failure count
		c.failureCount = 0
	case StateHalfOpen:
		// Transition to closed
		c.state = StateClosed
		c.failureCount = 0
	}
}

func (c *CircuitBreakerPlugin) onFailure() {
	c.failureCount++
	c.lastFailureTime = time.Now()

	switch c.state {
	case StateClosed:
		if c.failureCount >= c.threshold {
			c.state = StateOpen
		}
	case StateHalfOpen:
		// Any failure in half-open state opens the circuit
		c.state = StateOpen
	}
}

// responseWriterWrapper captures the status code
type responseWriterWrapper struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriterWrapper) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

func (rw *responseWriterWrapper) Write(b []byte) (int, error) {
	if rw.statusCode == 0 {
		rw.statusCode = http.StatusOK
	}
	return rw.ResponseWriter.Write(b)
}

// Tags returns plugin tags for discovery
func (c *CircuitBreakerPlugin) Tags() map[string]string {
	return map[string]string{
		"type":       "circuit_breaker",
		"category":   "resilience",
		"middleware": "true",
		"lifecycle":  "true",
	}
}

// Health checks if the circuit breaker is healthy
func (c *CircuitBreakerPlugin) Health() error {
	c.mu.RLock()
	defer c.mu.RUnlock()

	// Circuit breaker is healthy if it's not stuck in open state for too long
	if c.state == StateOpen && time.Since(c.lastFailureTime) > c.windowSize*2 {
		return fmt.Errorf("circuit breaker stuck in open state")
	}
	return nil
}

// Status returns human-readable status
func (c *CircuitBreakerPlugin) Status() string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return fmt.Sprintf("Circuit Breaker: %s (failures: %d)", c.state, c.failureCount)
}

// OnStart lifecycle hook
func (c *CircuitBreakerPlugin) OnStart() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.state = StateClosed
	c.failureCount = 0
	return nil
}

// OnShutdown lifecycle hook
func (c *CircuitBreakerPlugin) OnShutdown() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.state = StateClosed
	c.failureCount = 0
	return nil
}
