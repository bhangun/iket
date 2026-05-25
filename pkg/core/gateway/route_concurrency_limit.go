package gateway

import (
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/bhangun/iket/pkg/config"
)

type routeConcurrencyBucket struct {
	mu          sync.Mutex
	inFlight    int
	queued      int
	maxInFlight int
	lastSeen    time.Time
}

func (g *Gateway) routeConcurrencyLimitMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			route, ok := g.matchRoute(r)
			if !ok {
				next.ServeHTTP(w, r)
				return
			}
			policy := effectiveRouteConcurrencyPolicy(route)
			if policy == nil || isConcurrencyLimitExemptMethod(policy, r.Method) {
				next.ServeHTTP(w, r)
				return
			}

			keyType, bucketKey := resolveRouteConcurrencyKey(r, policy)
			policy = effectiveRouteConcurrencyClassPolicy(g.GetConfig(), policy, keyType, bucketKey)
			bucket := g.routeConcurrencyBucket(route, policy, bucketKey)
			waited, waitDuration, acquired, queueFull := bucket.acquire(concurrencyLimitQueueDeadline(policy), policy.MaxQueueDepth)
			if !acquired {
				if queueFull {
					g.RecordRouteLimitHitForBucket(route, "concurrency_queue_full", keyType, bucketKey)
					w.Header().Set("Retry-After", "1")
					w.Header().Set("X-ConcurrencyLimit-Key-Type", keyType)
					w.Header().Set("X-ConcurrencyLimit-Max-In-Flight", strconv.Itoa(policy.MaxInFlight))
					w.Header().Set("X-ConcurrencyLimit-Queue-Full", "true")
					w.WriteHeader(http.StatusServiceUnavailable)
					_, _ = w.Write([]byte(`{"error":"Service Unavailable","message":"Route concurrency queue is full"}`))
					return
				}
				g.RecordRouteLimitHitForBucket(route, "concurrency_limit", keyType, bucketKey)
				w.Header().Set("Retry-After", "1")
				w.Header().Set("X-ConcurrencyLimit-Key-Type", keyType)
				w.Header().Set("X-ConcurrencyLimit-Max-In-Flight", strconv.Itoa(policy.MaxInFlight))
				w.WriteHeader(http.StatusTooManyRequests)
				_, _ = w.Write([]byte(`{"error":"Too Many Requests","message":"Route concurrency limit exceeded"}`))
				return
			}
			defer bucket.release()

			w.Header().Set("X-ConcurrencyLimit-Key-Type", keyType)
			w.Header().Set("X-ConcurrencyLimit-Max-In-Flight", strconv.Itoa(policy.MaxInFlight))
			if waited {
				g.RecordRouteLimitHitWithBucketAndWait(route, "concurrency_queued", keyType, bucketKey, waitDuration)
				w.Header().Set("X-ConcurrencyLimit-Queued", "true")
			}
			next.ServeHTTP(w, r)
		})
	}
}

func effectiveRouteConcurrencyPolicy(route config.RouterConfig) *config.ConcurrencyLimitPolicyConfig {
	if route.ConcurrencyLimitPolicy != nil {
		return route.ConcurrencyLimitPolicy
	}
	if strings.TrimSpace(route.ConcurrentCalls) != "" {
		if maxInFlight, err := strconv.Atoi(strings.TrimSpace(route.ConcurrentCalls)); err == nil && maxInFlight > 0 {
			return &config.ConcurrencyLimitPolicyConfig{
				MaxInFlight: maxInFlight,
				KeyBy:       "global",
			}
		}
	}
	return nil
}

func isConcurrencyLimitExemptMethod(policy *config.ConcurrencyLimitPolicyConfig, method string) bool {
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

func concurrencyLimitQueueDeadline(policy *config.ConcurrencyLimitPolicyConfig) time.Time {
	if policy == nil || strings.TrimSpace(policy.QueueTimeout) == "" {
		return time.Time{}
	}
	wait, err := time.ParseDuration(strings.TrimSpace(policy.QueueTimeout))
	if err != nil || wait <= 0 {
		return time.Time{}
	}
	return time.Now().Add(wait)
}

func (g *Gateway) routeConcurrencyBucket(route config.RouterConfig, policy *config.ConcurrencyLimitPolicyConfig, bucketKey string) *routeConcurrencyBucket {
	routeKey := routeConcurrencyStateKey(route, bucketKey)
	g.concurrencyStateMu.Lock()
	defer g.concurrencyStateMu.Unlock()

	bucket, ok := g.concurrencyState[routeKey]
	if !ok {
		bucket = &routeConcurrencyBucket{
			maxInFlight: policy.MaxInFlight,
			lastSeen:    time.Now(),
		}
		g.concurrencyState[routeKey] = bucket
		return bucket
	}

	bucket.mu.Lock()
	defer bucket.mu.Unlock()
	bucket.lastSeen = time.Now()
	bucket.maxInFlight = policy.MaxInFlight
	return bucket
}

func (b *routeConcurrencyBucket) acquire(deadline time.Time, maxQueueDepth int) (bool, time.Duration, bool, bool) {
	waited := false
	queued := false
	queuedAt := time.Time{}
	for {
		b.mu.Lock()
		if b.inFlight < b.maxInFlight {
			if queued && b.queued > 0 {
				b.queued--
			}
			b.inFlight++
			b.lastSeen = time.Now()
			b.mu.Unlock()
			if waited && !queuedAt.IsZero() {
				return waited, time.Since(queuedAt), true, false
			}
			return waited, 0, true, false
		}
		if !queued && !deadline.IsZero() {
			if maxQueueDepth > 0 && b.queued >= maxQueueDepth {
				b.mu.Unlock()
				return false, 0, false, true
			}
			b.queued++
			queued = true
			queuedAt = time.Now()
		}
		b.mu.Unlock()
		if deadline.IsZero() || !time.Now().Before(deadline) {
			if queued {
				b.mu.Lock()
				if b.queued > 0 {
					b.queued--
				}
				b.mu.Unlock()
			}
			return waited, 0, false, false
		}
		waited = true
		time.Sleep(10 * time.Millisecond)
	}
}

func (b *routeConcurrencyBucket) release() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.inFlight > 0 {
		b.inFlight--
	}
	b.lastSeen = time.Now()
}

func routeConcurrencyStateKey(route config.RouterConfig, bucketKey string) string {
	methods := strings.Join(route.EffectiveMethods(), ",")
	return strings.Join([]string{route.ServiceName, route.Path, methods, bucketKey}, "|")
}

func effectiveRouteConcurrencyClassPolicy(cfg *config.Config, policy *config.ConcurrencyLimitPolicyConfig, keyType string, bucketKey string) *config.ConcurrencyLimitPolicyConfig {
	if policy == nil || len(policy.ClassPolicies) == 0 {
		return policy
	}
	bucketClass := ResolveLimiterBucketClass(cfg, keyType, bucketKey)
	if bucketClass == "" {
		return policy
	}
	for _, classPolicy := range policy.ClassPolicies {
		effectiveClassPolicy := effectiveLimiterClassConcurrencyPolicy(cfg, classPolicy)
		if !strings.EqualFold(strings.TrimSpace(effectiveClassPolicy.BucketClass), bucketClass) {
			continue
		}
		effective := *policy
		effective.MaxInFlight = effectiveClassPolicy.MaxInFlight
		effective.QueueTimeout = effectiveClassPolicy.QueueTimeout
		effective.MaxQueueDepth = effectiveClassPolicy.MaxQueueDepth
		return &effective
	}
	return policy
}

func effectiveLimiterClassConcurrencyPolicy(cfg *config.Config, classPolicy config.LimiterClassConcurrencyPolicyConfig) config.LimiterClassConcurrencyPolicyConfig {
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
	if classPolicy.MaxInFlight <= 0 {
		classPolicy.MaxInFlight = preset.ConcurrencyMaxInFlight
	}
	if strings.TrimSpace(classPolicy.QueueTimeout) == "" {
		classPolicy.QueueTimeout = preset.ConcurrencyQueueTimeout
	}
	if classPolicy.MaxQueueDepth <= 0 {
		classPolicy.MaxQueueDepth = preset.ConcurrencyMaxQueueDepth
	}
	return classPolicy
}
