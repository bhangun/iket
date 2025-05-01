// plugins/rate/limiter.go
package main

import (
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

// RateLimiterPlugin implements a rate limiting plugin
type RateLimiterPlugin struct {
	name              string
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

// Plugin is the exported symbol for the plugin system to load
var Plugin RateLimiterPlugin

// Name returns the plugin name
func (p *RateLimiterPlugin) Name() string {
	return p.name
}

// Initialize sets up the rate limiter with the provided configuration
func (p *RateLimiterPlugin) Initialize(config map[string]interface{}) error {
	p.name = "rate-limiter"

	// Set default values
	p.windowSize = 1 * time.Minute
	p.maxRequestsPerIP = 100
	p.cleanupInterval = 5 * time.Minute

	// Override with provided configuration
	if window, ok := config["windowSizeSeconds"].(float64); ok {
		p.windowSize = time.Duration(window) * time.Second
	}

	if maxRequests, ok := config["maxRequestsPerIP"].(float64); ok {
		p.maxRequestsPerIP = int(maxRequests)
	}

	if cleanup, ok := config["cleanupIntervalMinutes"].(float64); ok {
		p.cleanupInterval = time.Duration(cleanup) * time.Minute
	}

	// Initialize counters
	p.ipRequestCounters = make(map[string]*ipCounter)
	p.stopCleanup = make(chan struct{})

	// Start cleanup goroutine
	go p.startCleanup()

	log.Printf("Rate limiter plugin initialized: %d requests per IP in %v",
		p.maxRequestsPerIP, p.windowSize)
	return nil
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

	for ip, counter := range p.ipRequestCounters {
		if counter.lastRequest.Before(cutoff) {
			delete(p.ipRequestCounters, ip)
		}
	}

	log.Printf("Rate limiter cleanup completed, %d IPs tracked", len(p.ipRequestCounters))
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
					w.WriteHeader(http.StatusTooManyRequests)
					w.Write([]byte("Rate limit exceeded"))
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

// Shutdown stops the cleanup goroutine
func (p *RateLimiterPlugin) Shutdown() error {
	log.Println("Shutting down rate limiter plugin")
	close(p.stopCleanup)
	return nil
}
