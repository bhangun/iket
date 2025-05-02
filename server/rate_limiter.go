package main

import (
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// RateLimiter manages rate limiting for the gateway
type RateLimiter struct {
	limiters       map[string]*rate.Limiter
	mu             sync.RWMutex
	perRouteLimit  map[string]*rate.Limiter
	globalRequests int
	globalInterval time.Duration
}

// RegisterRouteLimit sets a specific rate limit for a route
func (rl *RateLimiter) RegisterRouteLimit(route string, limit int) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	rl.perRouteLimit[route] = rate.NewLimiter(rate.Every(rl.globalInterval/time.Duration(limit)), limit)
}

// GetRouteLimiter returns a rate limiter for a specific route and IP
func (rl *RateLimiter) GetRouteLimiter(route string, ip string) *rate.Limiter {
	routeKey := route + ":" + ip

	rl.mu.RLock()
	limiter, exists := rl.limiters[routeKey]
	routeLimiter, routeExists := rl.perRouteLimit[route]
	rl.mu.RUnlock()

	if !exists {
		if routeExists {
			// Create a new limiter based on the route-specific configuration
			limit := routeLimiter.Limit()
			burst := routeLimiter.Burst()
			limiter = rate.NewLimiter(limit, burst)
		} else {
			// Fall back to the global rate limit
			limiter = rate.NewLimiter(rate.Every(rl.globalInterval/time.Duration(rl.globalRequests)), rl.globalRequests)
		}

		rl.mu.Lock()
		rl.limiters[routeKey] = limiter
		rl.mu.Unlock()
	}

	return limiter
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter(requests int, interval time.Duration) *RateLimiter {
	return &RateLimiter{
		limiters:       make(map[string]*rate.Limiter),
		perRouteLimit:  make(map[string]*rate.Limiter),
		globalRequests: requests,
		globalInterval: interval,
	}
}

// GetLimiter returns a rate limiter for a specific IP address
func (rl *RateLimiter) GetLimiter(ip string) *rate.Limiter {
	rl.mu.RLock()
	limiter, exists := rl.limiters[ip]
	rl.mu.RUnlock()

	if !exists {
		limiter = rate.NewLimiter(rate.Every(rl.globalInterval/time.Duration(rl.globalRequests)), rl.globalRequests)
		rl.mu.Lock()
		rl.limiters[ip] = limiter
		rl.mu.Unlock()
	}

	return limiter
}
