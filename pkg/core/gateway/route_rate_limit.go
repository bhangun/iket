package gateway

import (
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/bhangun/iket/pkg/config"
	"golang.org/x/time/rate"
)

type routeRateLimitBucket struct {
	mu       sync.Mutex
	limiter  *rate.Limiter
	lastSeen time.Time
}

func (g *Gateway) routeRateLimitMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			route, ok := g.matchRoute(r)
			if !ok {
				next.ServeHTTP(w, r)
				return
			}
			policy := effectiveRouteRateLimitPolicy(route)
			if policy == nil || isRateLimitExemptMethod(policy, r.Method) {
				next.ServeHTTP(w, r)
				return
			}

			keyType, bucketKey := resolveRouteRateLimitKey(r, policy)
			policy = effectiveRouteRateLimitClassPolicy(g.GetConfig(), policy, keyType, bucketKey)
			bucket := g.routeRateLimitBucket(route, policy, bucketKey)
			if !bucket.limiter.Allow() {
				g.RecordRouteLimitHitForBucket(route, "rate_limit", keyType, bucketKey)
				w.Header().Set("Retry-After", "1")
				w.Header().Set("X-RateLimit-Key-Type", keyType)
				w.Header().Set("X-RateLimit-Limit", fmt.Sprintf("%.3g", policy.RequestsPerSecond))
				w.Header().Set("X-RateLimit-Burst", fmt.Sprintf("%d", policy.Burst))
				w.WriteHeader(http.StatusTooManyRequests)
				_, _ = w.Write([]byte(`{"error":"Too Many Requests","message":"Route rate limit exceeded"}`))
				return
			}

			w.Header().Set("X-RateLimit-Key-Type", keyType)
			w.Header().Set("X-RateLimit-Limit", fmt.Sprintf("%.3g", policy.RequestsPerSecond))
			w.Header().Set("X-RateLimit-Burst", fmt.Sprintf("%d", policy.Burst))
			next.ServeHTTP(w, r)
		})
	}
}

func effectiveRouteRateLimitPolicy(route config.RouterConfig) *config.RateLimitPolicyConfig {
	if route.RateLimitPolicy != nil {
		return route.RateLimitPolicy
	}
	if route.RateLimit != nil && *route.RateLimit > 0 {
		return &config.RateLimitPolicyConfig{
			RequestsPerSecond: float64(*route.RateLimit),
			Burst:             *route.RateLimit,
			KeyBy:             "global",
		}
	}
	return nil
}

func isRateLimitExemptMethod(policy *config.RateLimitPolicyConfig, method string) bool {
	if policy == nil || len(policy.ExemptMethods) == 0 {
		return false
	}
	method = strings.ToUpper(strings.TrimSpace(method))
	for _, candidate := range policy.ExemptMethods {
		if strings.ToUpper(strings.TrimSpace(candidate)) == method {
			return true
		}
	}
	return false
}

func (g *Gateway) routeRateLimitBucket(route config.RouterConfig, policy *config.RateLimitPolicyConfig, bucketKey string) *routeRateLimitBucket {
	routeKey := routeRateLimitStateKey(route, bucketKey)
	g.rateLimitStateMu.Lock()
	defer g.rateLimitStateMu.Unlock()

	bucket, ok := g.rateLimitState[routeKey]
	if !ok {
		bucket = &routeRateLimitBucket{
			limiter:  rate.NewLimiter(rate.Limit(policy.RequestsPerSecond), policy.Burst),
			lastSeen: time.Now(),
		}
		g.rateLimitState[routeKey] = bucket
		return bucket
	}

	bucket.mu.Lock()
	defer bucket.mu.Unlock()
	bucket.lastSeen = time.Now()
	if currentLimit := float64(bucket.limiter.Limit()); currentLimit != policy.RequestsPerSecond || bucket.limiter.Burst() != policy.Burst {
		bucket.limiter = rate.NewLimiter(rate.Limit(policy.RequestsPerSecond), policy.Burst)
	}
	return bucket
}

func routeRateLimitStateKey(route config.RouterConfig, bucketKey string) string {
	methods := strings.Join(route.EffectiveMethods(), ",")
	return strings.Join([]string{route.ServiceName, route.Path, methods, bucketKey}, "|")
}

func effectiveRouteRateLimitClassPolicy(cfg *config.Config, policy *config.RateLimitPolicyConfig, keyType string, bucketKey string) *config.RateLimitPolicyConfig {
	if policy == nil || len(policy.ClassPolicies) == 0 {
		return policy
	}
	bucketClass := ResolveLimiterBucketClass(cfg, keyType, bucketKey)
	if bucketClass == "" {
		return policy
	}
	for _, classPolicy := range policy.ClassPolicies {
		effectiveClassPolicy := effectiveLimiterClassRatePolicy(cfg, classPolicy)
		if !strings.EqualFold(strings.TrimSpace(effectiveClassPolicy.BucketClass), bucketClass) {
			continue
		}
		effective := *policy
		effective.RequestsPerSecond = effectiveClassPolicy.RequestsPerSecond
		effective.Burst = effectiveClassPolicy.Burst
		return &effective
	}
	return policy
}

func effectiveLimiterClassRatePolicy(cfg *config.Config, classPolicy config.LimiterClassRatePolicyConfig) config.LimiterClassRatePolicyConfig {
	if cfg == nil || strings.TrimSpace(classPolicy.Preset) == "" {
		return classPolicy
	}
	preset, ok := cfg.Security.LimiterClassPresets[strings.TrimSpace(classPolicy.Preset)]
	if !ok {
		return classPolicy
	}
	if strings.TrimSpace(classPolicy.BucketClass) == "" {
		classPolicy.BucketClass = preset.BucketClass
	}
	if classPolicy.RequestsPerSecond <= 0 {
		classPolicy.RequestsPerSecond = preset.RateRequestsPerSecond
	}
	if classPolicy.Burst <= 0 {
		classPolicy.Burst = preset.RateBurst
	}
	return classPolicy
}
