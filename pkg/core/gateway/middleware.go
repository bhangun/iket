package gateway

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"crypto/rsa"
	"errors"

	"github.com/bhangun/iket/pkg/config"
	"github.com/bhangun/iket/pkg/logging"

	"crypto/x509"
	"encoding/pem"
	"os"

	"bufio"
	"fmt"

	"github.com/golang-jwt/jwt/v4"
	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
)

// context key for client IP
type ctxKey string

const clientIPKey ctxKey = "clientIP"
const matchedRouteKey ctxKey = "matchedRoute"
const routeVarsKey ctxKey = "routeVars"
const tenantRealmKey ctxKey = "tenantRealm"
const requestIDKey ctxKey = "requestID"
const policyHitHeader = "X-Iket-Policy-Hit"

var transformTemplateRe = regexp.MustCompile(`\{\{([^}]+)\}\}`)

type matchedRouteContext struct {
	Route config.RouterConfig
	Vars  map[string]string
}

type retryingTransport struct {
	base        http.RoundTripper
	route       config.RouterConfig
	backend     config.Backend
	destination string
	hedge       *hedgeTarget
}

type hedgeTarget struct {
	backend     config.Backend
	destination string
	scheme      string
	host        string
	path        string
}

type shadowTarget struct {
	backend     config.Backend
	destination string
	scheme      string
	host        string
	path        string
}

type responseTemplateContext struct {
	headers    http.Header
	statusCode int
	body       string
}

// getIP extracts client IP from request headers or RemoteAddr
func getIP(r *http.Request) string {
	// Common proxy headers
	hdrs := []string{
		"X-Forwarded-For",
		"X-Real-Ip",
		"Proxy-Client-IP",
		"WL-Proxy-Client-IP",
	}

	for _, h := range hdrs {
		v := r.Header.Get(h)
		if v == "" {
			continue
		}
		parts := strings.Split(v, ",")
		if len(parts) > 0 {
			ip := strings.TrimSpace(parts[0])
			if ip != "" {
				return ip
			}
		}
	}

	// fallback to RemoteAddr
	if host, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr)); err == nil {
		return host
	}
	return r.RemoteAddr
}

// GetClientIP retrieves client IP from request context
func GetClientIP(r *http.Request) string {
	if ip, ok := r.Context().Value(clientIPKey).(string); ok {
		return ip
	}
	return ""
}

func GetRequestID(r *http.Request) string {
	if requestID, ok := r.Context().Value(requestIDKey).(string); ok {
		return requestID
	}
	return ""
}

func GetMatchedRoute(r *http.Request) (config.RouterConfig, bool) {
	if matched, ok := r.Context().Value(matchedRouteKey).(matchedRouteContext); ok {
		return matched.Route, true
	}
	return config.RouterConfig{}, false
}

func GetRouteVars(r *http.Request) map[string]string {
	if matched, ok := r.Context().Value(matchedRouteKey).(matchedRouteContext); ok && matched.Vars != nil {
		return matched.Vars
	}
	if vars, ok := r.Context().Value(routeVarsKey).(map[string]string); ok {
		return vars
	}
	return nil
}

func GetTenantRealm(r *http.Request) string {
	if realm, ok := r.Context().Value(tenantRealmKey).(string); ok {
		return realm
	}
	return ""
}

func corsMiddleware(route config.RouterConfig) func(http.Handler) http.Handler {
	cors := route.CORS
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if cors == nil {
				next.ServeHTTP(w, r)
				return
			}
			origin := strings.TrimSpace(r.Header.Get("Origin"))
			if origin == "" {
				next.ServeHTTP(w, r)
				return
			}
			if !corsOriginAllowed(cors, origin) {
				if r.Method == http.MethodOptions {
					w.WriteHeader(http.StatusForbidden)
					return
				}
				next.ServeHTTP(w, r)
				return
			}
			allowOrigin := corsAllowedOriginValue(cors, origin)
			headers := w.Header()
			headers.Set("Access-Control-Allow-Origin", allowOrigin)
			headers.Add("Vary", "Origin")
			if cors.AllowCredentials {
				headers.Set("Access-Control-Allow-Credentials", "true")
			}
			if len(cors.ExposedHeaders) > 0 {
				headers.Set("Access-Control-Expose-Headers", strings.Join(cors.ExposedHeaders, ", "))
			}
			if r.Method == http.MethodOptions {
				requestMethod := strings.ToUpper(strings.TrimSpace(r.Header.Get("Access-Control-Request-Method")))
				if requestMethod == "" {
					w.WriteHeader(http.StatusNoContent)
					return
				}
				if !corsMethodAllowed(route, requestMethod) {
					w.WriteHeader(http.StatusMethodNotAllowed)
					return
				}
				headers.Set("Access-Control-Allow-Methods", strings.Join(corsAllowedMethods(route), ", "))
				requestHeaders := strings.TrimSpace(r.Header.Get("Access-Control-Request-Headers"))
				if len(cors.AllowedHeaders) > 0 {
					headers.Set("Access-Control-Allow-Headers", strings.Join(cors.AllowedHeaders, ", "))
				} else if requestHeaders != "" {
					headers.Set("Access-Control-Allow-Headers", requestHeaders)
					headers.Add("Vary", "Access-Control-Request-Headers")
				}
				if cors.MaxAge > 0 {
					headers.Set("Access-Control-Max-Age", fmt.Sprintf("%d", cors.MaxAge))
				}
				w.WriteHeader(http.StatusNoContent)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func corsOriginAllowed(cors *config.CORSConfig, origin string) bool {
	if cors == nil {
		return false
	}
	origin = strings.TrimSpace(origin)
	for _, allowed := range cors.AllowedOrigins {
		allowed = strings.TrimSpace(allowed)
		if allowed == "*" || strings.EqualFold(allowed, origin) {
			return true
		}
	}
	return false
}

func corsAllowedOriginValue(cors *config.CORSConfig, origin string) string {
	if cors == nil {
		return ""
	}
	for _, allowed := range cors.AllowedOrigins {
		if strings.TrimSpace(allowed) == "*" && !cors.AllowCredentials {
			return "*"
		}
	}
	return origin
}

func corsAllowedMethods(route config.RouterConfig) []string {
	if route.CORS != nil && len(route.CORS.AllowedMethods) > 0 {
		methods := make([]string, 0, len(route.CORS.AllowedMethods))
		for _, method := range route.CORS.AllowedMethods {
			method = strings.ToUpper(strings.TrimSpace(method))
			if method != "" {
				methods = append(methods, method)
			}
		}
		return methods
	}
	methods := route.EffectiveMethods()
	normalized := make([]string, 0, len(methods))
	for _, method := range methods {
		method = strings.ToUpper(strings.TrimSpace(method))
		if method != "" {
			normalized = append(normalized, method)
		}
	}
	return normalized
}

func corsMethodAllowed(route config.RouterConfig, method string) bool {
	method = strings.ToUpper(strings.TrimSpace(method))
	for _, allowed := range corsAllowedMethods(route) {
		if allowed == method {
			return true
		}
	}
	return false
}

func rolloutBucketKey(r *http.Request) string {
	if r == nil {
		return ""
	}
	if requestID := strings.TrimSpace(r.Header.Get("X-Request-Id")); requestID != "" {
		return requestID
	}
	if forwardedFor := strings.TrimSpace(r.Header.Get("X-Forwarded-For")); forwardedFor != "" {
		return forwardedFor
	}
	if clientIP := strings.TrimSpace(GetClientIP(r)); clientIP != "" {
		return clientIP
	}
	return strings.TrimSpace(r.UserAgent()) + "|" + r.URL.Path
}

const defaultBackendCooldown = 30 * time.Second

func (g *Gateway) selectRouteBackend(route config.RouterConfig, bucketKey string) (config.Backend, string) {
	if len(route.Backends) == 0 {
		return config.Backend{}, strings.TrimSpace(route.ServiceHost)
	}
	now := time.Now().UTC()
	for _, index := range g.preferredBackendIndexes(route, bucketKey) {
		backend := route.Backends[index]
		destination := g.backendDestination(route, backend)
		if g.reserveBackend(route, backend, destination, now) {
			return backend, destination
		}
	}
	return config.Backend{}, ""
}

func (g *Gateway) backendDestination(route config.RouterConfig, backend config.Backend) string {
	if strings.TrimSpace(backend.Host) != "" {
		return strings.TrimSpace(backend.Host)
	}
	return strings.TrimSpace(route.ServiceHost)
}

func (g *Gateway) selectAlternateRouteBackend(route config.RouterConfig, selected config.Backend, bucketKey string) (config.Backend, string) {
	if len(route.Backends) < 2 {
		return config.Backend{}, ""
	}
	now := time.Now().UTC()
	for _, index := range g.preferredBackendIndexes(route, bucketKey) {
		backend := route.Backends[index]
		if backend == selected {
			continue
		}
		destination := g.backendDestination(route, backend)
		if destination == "" {
			continue
		}
		if g.isBackendAvailable(route, backend, destination, now) {
			return backend, destination
		}
	}
	return config.Backend{}, ""
}

func (g *Gateway) preferredBackendIndexes(route config.RouterConfig, bucketKey string) []int {
	indexes := make([]int, len(route.Backends))
	for i := range route.Backends {
		indexes[i] = i
	}
	start := PreferredRouteBackendIndex(route, bucketKey)
	if start < 0 {
		start = 0
	}
	if !route.AdaptiveLatencyRouting {
		return rotateBackendIndexes(indexes, start)
	}
	type scoredIndex struct {
		index       int
		score       float64
		hasLatency  bool
		staticOrder int
	}
	scored := make([]scoredIndex, 0, len(route.Backends))
	for offset := 0; offset < len(route.Backends); offset++ {
		index := (start + offset) % len(route.Backends)
		backend := route.Backends[index]
		destination := g.backendDestination(route, backend)
		state := g.backendStateSnapshot(route, backend, destination)
		score := float64(0)
		hasLatency := state.LatencyEWMA > 0
		if hasLatency {
			score = float64(state.LatencyEWMA) / float64(effectiveBackendWeight(backend))
		}
		scored = append(scored, scoredIndex{
			index:       index,
			score:       score,
			hasLatency:  hasLatency,
			staticOrder: offset,
		})
	}
	sort.SliceStable(scored, func(i, j int) bool {
		if scored[i].hasLatency != scored[j].hasLatency {
			return scored[i].hasLatency
		}
		if scored[i].hasLatency && scored[i].score != scored[j].score {
			return scored[i].score < scored[j].score
		}
		return scored[i].staticOrder < scored[j].staticOrder
	})
	ordered := make([]int, 0, len(scored))
	for _, item := range scored {
		ordered = append(ordered, item.index)
	}
	return ordered
}

func rotateBackendIndexes(indexes []int, start int) []int {
	if len(indexes) == 0 {
		return nil
	}
	ordered := make([]int, 0, len(indexes))
	for offset := 0; offset < len(indexes); offset++ {
		ordered = append(ordered, indexes[(start+offset)%len(indexes)])
	}
	return ordered
}

func (g *Gateway) backendStateSnapshot(route config.RouterConfig, backend config.Backend, destination string) backendRuntimeState {
	key := g.backendStateKey(route, backend, destination)
	g.backendStateMu.RLock()
	defer g.backendStateMu.RUnlock()
	return g.backendState[key]
}

func (g *Gateway) backendStateKey(route config.RouterConfig, backend config.Backend, destination string) string {
	return strings.TrimSpace(route.ServiceName) + "|" + strings.TrimSpace(route.Path) + "|" + strings.TrimSpace(destination) + "|" + strings.TrimSpace(backend.URLPattern)
}

func (g *Gateway) isBackendAvailable(route config.RouterConfig, backend config.Backend, destination string, now time.Time) bool {
	key := g.backendStateKey(route, backend, destination)
	g.backendStateMu.RLock()
	state, ok := g.backendState[key]
	g.backendStateMu.RUnlock()
	if !ok {
		return true
	}
	return backendCircuitState(state, now) != "open"
}

func (g *Gateway) reserveBackend(route config.RouterConfig, backend config.Backend, destination string, now time.Time) bool {
	key := g.backendStateKey(route, backend, destination)
	g.backendStateMu.Lock()
	defer g.backendStateMu.Unlock()
	state, ok := g.backendState[key]
	if !ok || state.UnhealthyUntil.IsZero() {
		return true
	}
	if now.Before(state.UnhealthyUntil) {
		return false
	}
	maxHalfOpen := backendHalfOpenMaxRequests(backend)
	if state.HalfOpenInFlight >= maxHalfOpen {
		return false
	}
	state.ProbeInFlight = true
	state.HalfOpenInFlight++
	g.backendState[key] = state
	return true
}

func (g *Gateway) recordBackendFailure(route config.RouterConfig, backend config.Backend, destination string, cause error) {
	g.recordBackendFailureWithStatus(route, backend, destination, 0, cause, time.Now().UTC())
}

func (g *Gateway) recordBackendFailureWithStatus(route config.RouterConfig, backend config.Backend, destination string, statusCode int, cause error, now time.Time) {
	key := g.backendStateKey(route, backend, destination)
	threshold := backend.FailureThreshold
	if threshold <= 0 {
		threshold = 1
	}
	cooldown := defaultBackendCooldown
	if raw := strings.TrimSpace(backend.Cooldown); raw != "" {
		if parsed, err := time.ParseDuration(raw); err == nil && parsed > 0 {
			cooldown = parsed
		}
	}
	g.backendStateMu.Lock()
	defer g.backendStateMu.Unlock()
	state := g.backendState[key]
	state.LastChecked = now
	state.LastStatusCode = statusCode
	state.ConsecutiveFailures++
	state.ConsecutiveSuccesses = 0
	state.LastFailure = now
	state.ProbeInFlight = false
	if state.HalfOpenInFlight > 0 {
		state.HalfOpenInFlight--
	}
	if cause != nil {
		state.LastError = cause.Error()
	}
	if state.ConsecutiveFailures >= threshold {
		state.UnhealthyUntil = now.Add(cooldown)
	}
	g.backendState[key] = state
}

func (g *Gateway) recordBackendSuccess(route config.RouterConfig, backend config.Backend, destination string) {
	g.recordBackendSuccessWithStatus(route, backend, destination, 0, 0, time.Now().UTC())
}

func (g *Gateway) recordBackendSuccessWithStatus(route config.RouterConfig, backend config.Backend, destination string, statusCode int, latency time.Duration, now time.Time) {
	key := g.backendStateKey(route, backend, destination)
	g.backendStateMu.Lock()
	defer g.backendStateMu.Unlock()
	state := g.backendState[key]
	state.LastChecked = now
	state.LastSuccess = now
	state.LastStatusCode = statusCode
	state.LastObservedLatency = latency
	state.LatencyEWMA = updateLatencyEWMA(state.LatencyEWMA, latency)
	state.LastError = ""
	state.ProbeInFlight = false
	if state.HalfOpenInFlight > 0 {
		state.HalfOpenInFlight--
	}
	if isBackendLatencyOutlier(backend, latency) {
		state.ConsecutiveSlowResponses++
	} else {
		state.ConsecutiveSlowResponses = 0
	}
	if !state.UnhealthyUntil.IsZero() {
		state.ConsecutiveSuccesses++
		if state.ConsecutiveSuccesses >= backendRecoverySuccessThreshold(backend) {
			state.ConsecutiveFailures = 0
			state.ConsecutiveSuccesses = 0
			state.ConsecutiveSlowResponses = 0
			state.UnhealthyUntil = time.Time{}
		}
	} else {
		state.ConsecutiveFailures = 0
		state.ConsecutiveSuccesses = 0
		slowThreshold := backendOutlierSlowResponseThreshold(backend)
		if slowThreshold > 0 && state.ConsecutiveSlowResponses >= slowThreshold {
			state.UnhealthyUntil = now.Add(backendOutlierCooldown(backend))
			state.ConsecutiveSuccesses = 0
		} else {
			state.UnhealthyUntil = time.Time{}
		}
	}
	g.backendState[key] = state
}

func AccessLogMiddleware(g *Gateway, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Wrap ResponseWriter to capture status code & content length
		rw := &responseWriter{ResponseWriter: w, statusCode: 200}

		// Extract client IP from headers or RemoteAddr
		clientIP := getIP(r)

		// Store in context so handlers can reuse it
		ctx := context.WithValue(r.Context(), clientIPKey, clientIP)

		next.ServeHTTP(rw, r.WithContext(ctx))

		duration := time.Since(start).Seconds()

		g.logger.Info("HTTP request",
			logging.String("method", r.Method),
			logging.String("path", r.URL.Path),
			logging.String("remote_addr", r.RemoteAddr), // raw TCP peer
			logging.String("client_ip", clientIP),       // parsed from headers
			logging.String("user_agent", r.UserAgent()),
			logging.Int("status_code", rw.statusCode),
			logging.Float64("duration", duration),
			logging.Int("content_length", rw.length),
		)
	})
}

func (g *Gateway) routeContextMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			match := ResolveRouteMatch(g.config.GetAllRoutesFromServices(g.logger), r.Method, r.URL.Path, r.Header, rolloutBucketKey(r))
			if !match.Matched {
				next.ServeHTTP(w, r)
				return
			}

			ctx := context.WithValue(r.Context(), matchedRouteKey, matchedRouteContext{
				Route: match.Route,
				Vars:  match.Vars,
			})
			ctx = context.WithValue(ctx, routeVarsKey, match.Vars)
			if realm := match.Vars["realm"]; realm != "" {
				ctx = context.WithValue(ctx, tenantRealmKey, realm)
			}

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

type contextKey string

const jwtClaimsKey contextKey = "jwtClaims"

// loggingMiddleware logs HTTP requests with structured logging
func (g *Gateway) loggingMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()

			// Create a response writer wrapper to capture status code
			wrapped := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

			// Get client IP
			clientIP := GetClientIP(r)

			// Process request
			next.ServeHTTP(wrapped, r)

			// Calculate duration
			duration := time.Since(start)

			// Log request details
			g.logger.Info("HTTP request",
				logging.String("method", r.Method),
				logging.String("path", r.URL.Path),
				logging.String("route_name", routeNameForLog(r)),
				logging.String("service_name", serviceNameForLog(g, r)),
				logging.String("remote_addr", r.RemoteAddr),
				logging.String("client_ip", clientIP),
				logging.String("request_id", GetRequestID(r)),
				logging.String("user_agent", r.UserAgent()),
				logging.Int("status_code", wrapped.statusCode),
				logging.Duration("duration", duration),
				logging.Int64("content_length", r.ContentLength),
			)

			// Record metrics if available
			if g.metrics != nil {
				g.metrics.RecordRequest(r.Method, r.URL.Path, wrapped.statusCode, duration.Seconds())
			}
		})
	}
}

// metricsMiddleware tracks requests in flight
func (g *Gateway) metricsMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if g.metrics != nil {
				g.metrics.TrackRequestInFlight(r.Method, r.URL.Path, true)
				defer g.metrics.TrackRequestInFlight(r.Method, r.URL.Path, false)
			}
			next.ServeHTTP(w, r)
		})
	}
}

// securityHeadersMiddleware adds security headers to responses
func (g *Gateway) securityHeadersMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Security headers
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("X-Frame-Options", "DENY")
			w.Header().Set("X-XSS-Protection", "1; mode=block")
			w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")

			// Remove server header
			w.Header().Del("Server")

			requestID := ensureRequestID(r)
			w.Header().Set("X-Request-Id", requestID)
			ctx := context.WithValue(r.Context(), requestIDKey, requestID)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// authMiddleware handles authentication for protected routes
func (g *Gateway) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if g.config.Security.EnableBasicAuth {
			user, pass, ok := r.BasicAuth()

			// Get client IP
			clientIP := GetClientIP(r)

			if !ok || user == "" || pass == "" {
				g.logger.Warn("401 Unauthorized",
					logging.String("reason", "Missing or invalid credentials"),
					logging.String("method", r.Method),
					logging.String("path", r.URL.Path),
					logging.String("remote_addr", r.RemoteAddr),
					logging.String("client_ip", clientIP),
				)
				w.Header().Set("WWW-Authenticate", "Basic realm=\"Iket Gateway\"")
				w.WriteHeader(http.StatusUnauthorized)
				w.Write([]byte("Missing or invalid credentials"))
				return
			}
			if expected, ok := g.config.Security.BasicAuthUsers[user]; !ok || expected != pass {
				g.logger.Warn("401 Unauthorized",
					logging.String("reason", "Invalid username or password"),
					logging.String("method", r.Method),
					logging.String("path", r.URL.Path),
					logging.String("remote_addr", r.RemoteAddr),
					logging.String("client_ip", clientIP),
				)
				w.Header().Set("WWW-Authenticate", "Basic realm=\"Iket Gateway\"")
				w.WriteHeader(http.StatusUnauthorized)
				w.Write([]byte("Invalid username or password"))
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// timeoutMiddleware adds request timeout
func (g *Gateway) timeoutMiddleware(timeout time.Duration) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx, cancel := context.WithTimeout(r.Context(), timeout)
			defer cancel()

			r = r.WithContext(ctx)

			// Create a channel to signal completion
			done := make(chan struct{})
			go func() {
				next.ServeHTTP(w, r)
				close(done)
			}()

			select {
			case <-done:
				// Request completed successfully
			case <-ctx.Done():
				// Request timed out
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusRequestTimeout)
				w.Write([]byte(`{"error":"Request timeout","message":"The request took too long to process"}`))
			}
		})
	}
}

// proxyHandler creates a reverse proxy handler for the given route
func (g *Gateway) proxyHandler(route config.RouterConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		fmt.Printf("proxyHandler called for path: %s\n", r.URL.Path)
		// Skip proxying for OpenAPI and Swagger UI plugin endpoints
		if r.URL.Path == "/openapi" || r.URL.Path == "/swagger-ui" || r.URL.Path == "/swagger-ui/" || strings.HasPrefix(r.URL.Path, "/swagger-ui/") {
			if next := r.Context().Value("next"); next != nil {
				h := next.(http.Handler)
				h.ServeHTTP(w, r)
				return
			}
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(`{"error":"Not Found","message":"The requested resource does not exist"}`))
			return
		}

		selectedBackend, selectedDestination := g.selectRouteBackend(route, rolloutBucketKey(r))
		if selectedDestination == "" {
			g.logger.Warn("All configured backends are currently unavailable",
				logging.String("route_path", route.Path),
				logging.String("service_name", route.ServiceName),
			)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusServiceUnavailable)
			w.Write([]byte(`{"error":"Service Unavailable","message":"All configured backends are temporarily unavailable"}`))
			return
		}

		// Use parent service's host as destination unless the selected backend overrides it.
		destination := strings.TrimSpace(selectedDestination)
		if destination == "" {
			destination = strings.TrimSpace(selectedBackend.Host)
		}
		if destination == "" {
			destination = strings.TrimSpace(route.ServiceHost)
		}
		if destination == "" {
			service := g.config.FindServiceForRoute(route.Path, r.Method, route.MatchHeaders)
			if service != nil {
				destination = strings.TrimSpace(service.Host)
			}
		}
		if destination == "" {
			g.logger.Error("No parent service found for route", nil, logging.String("route_path", route.Path), logging.String("method", r.Method))
			http.Error(w, "No backend service configured for this route", http.StatusBadGateway)
			return
		}
		service := &config.Service{Name: route.ServiceName, Host: destination}
		if route.ServiceName == "" || destination == "" {
			if resolved := g.config.FindServiceForRoute(route.Path, r.Method, route.MatchHeaders); resolved != nil {
				service = resolved
			}
		}

		// Parse destination URL
		destURL, err := url.Parse(destination)
		if err != nil {
			g.logger.Error("Failed to parse destination URL", err, logging.String("destination", destination))
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		if err := enforceAllowedUpstreamHost(destURL, route); err != nil {
			g.logger.Warn("Resolved upstream host rejected by route allowlist",
				logging.Error(err),
				logging.String("policy_reason", "upstream_host_allowlist"),
				logging.String("route_path", route.Path),
				logging.String("destination", destination),
			)
			writePolicyError(g, route, w, http.StatusForbidden, "upstream_host_allowlist", err.Error())
			return
		}
		if err := enforceRouteProtocol(r, route); err != nil {
			g.logger.Warn("Request rejected by route protocol policy",
				logging.Error(err),
				logging.String("policy_reason", "protocol"),
				logging.String("route_path", route.Path),
				logging.String("route_protocol", strings.ToLower(strings.TrimSpace(route.Protocol))),
				logging.String("request_method", r.Method),
				logging.String("content_type", r.Header.Get("Content-Type")),
			)
			status := http.StatusBadRequest
			if strings.Contains(strings.ToLower(err.Error()), "content-type") {
				status = http.StatusUnsupportedMediaType
			}
			writePolicyError(g, route, w, status, "protocol", err.Error())
			return
		}
		if err := enforceRequiredRequestHeaders(r, route); err != nil {
			g.logger.Warn("Request rejected by required header policy",
				logging.Error(err),
				logging.String("policy_reason", "required_header"),
				logging.String("route_path", route.Path),
			)
			writePolicyError(g, route, w, http.StatusBadRequest, "required_header", err.Error())
			return
		}

		origPath := r.URL.Path
		routeVars := mux.Vars(r)
		if len(routeVars) == 0 {
			routeVars = GetRouteVars(r)
		}
		proxiedPath, err := ComputeProxiedPathForBackend(service, route, selectedBackend, origPath, routeVars)
		if err != nil {
			g.logger.Error("Failed to compute proxied path", err, logging.String("route_path", route.Path), logging.String("destination", destination))
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		r.URL.Path = proxiedPath
		applyQueryTransforms(r, route)
		if err := enforceRequestBodyLimit(r, route); err != nil {
			g.logger.Warn("Request body exceeds configured route limit",
				logging.Error(err),
				logging.String("policy_reason", "request_body_size"),
				logging.String("route_path", route.Path),
				logging.Int64("max_request_body_bytes", route.MaxRequestBodyBytes),
			)
			writePolicyError(g, route, w, http.StatusRequestEntityTooLarge, "request_body_size", err.Error())
			return
		}
		if err := enforceGraphQLRoutePolicy(r, route); err != nil {
			reason := policyReasonForGraphQLError(err)
			g.logger.Warn("Request rejected by GraphQL route policy",
				logging.Error(err),
				logging.String("policy_reason", reason),
				logging.String("route_path", route.Path),
			)
			writePolicyError(g, route, w, http.StatusForbidden, reason, err.Error())
			return
		}
		if err := enforceAllowedModels(r, route); err != nil {
			reason := "model_allowlist"
			g.logger.Warn("Request model rejected by route allowlist",
				logging.Error(err),
				logging.String("policy_reason", reason),
				logging.String("route_path", route.Path),
			)
			status := http.StatusBadRequest
			if strings.Contains(err.Error(), "not allowed") {
				status = http.StatusForbidden
			}
			writePolicyError(g, route, w, status, reason, err.Error())
			return
		}
		if err := enforceAllowedTools(r, route); err != nil {
			reason := "tool_allowlist"
			g.logger.Warn("Request tool rejected by route allowlist",
				logging.Error(err),
				logging.String("policy_reason", reason),
				logging.String("route_path", route.Path),
			)
			status := http.StatusBadRequest
			if strings.Contains(err.Error(), "not allowed") {
				status = http.StatusForbidden
			}
			writePolicyError(g, route, w, status, reason, err.Error())
			return
		}
		if err := enforceTokenBudgets(r, route); err != nil {
			reason := policyReasonForRequestError(err, "token_budget")
			g.logger.Warn("Request rejected by token budget policy",
				logging.Error(err),
				logging.String("policy_reason", reason),
				logging.String("route_path", route.Path),
			)
			status := http.StatusBadRequest
			if strings.Contains(err.Error(), "exceeds") {
				status = http.StatusForbidden
			}
			writePolicyError(g, route, w, status, reason, err.Error())
			return
		}
		if err := enforceConversationBudgets(r, route); err != nil {
			reason := policyReasonForRequestError(err, "conversation_budget")
			g.logger.Warn("Request rejected by conversation budget policy",
				logging.Error(err),
				logging.String("policy_reason", reason),
				logging.String("route_path", route.Path),
			)
			status := http.StatusBadRequest
			if strings.Contains(err.Error(), "exceeds") {
				status = http.StatusForbidden
			}
			writePolicyError(g, route, w, status, reason, err.Error())
			return
		}
		if err := enforceRequestBodyPatterns(r, route); err != nil {
			reason := policyReasonForRequestError(err, "request_content_policy")
			g.logger.Warn("Request rejected by body content policy",
				logging.Error(err),
				logging.String("policy_reason", reason),
				logging.String("route_path", route.Path),
			)
			status := http.StatusBadRequest
			if strings.Contains(err.Error(), "blocked") {
				status = http.StatusForbidden
			}
			writePolicyError(g, route, w, status, reason, err.Error())
			return
		}

		// Debug WS handshake issues (Cloudflare/proxies may strip hop-by-hop headers).
		// Keep this narrow to WS endpoints to avoid noisy logs and avoid logging tokens.
		if strings.Contains(origPath, "/chat/ws") || origPath == "/ws" || strings.Contains(origPath, "/jahsy/ws") {
			upgrade := r.Header.Get("Upgrade")
			conn := r.Header.Get("Connection")
			secKey := r.Header.Get("Sec-WebSocket-Key")
			secVer := r.Header.Get("Sec-WebSocket-Version")
			g.logger.Info("WS handshake headers",
				logging.String("path", origPath),
				logging.String("upgrade", upgrade),
				logging.String("connection", conn),
				logging.Bool("has_sec_key", secKey != ""),
				logging.String("sec_version", secVer),
				logging.String("proto", r.Proto),
			)
		}

		g.logger.Info("Proxying request",
			logging.String("original_path", origPath),
			logging.String("proxied_path", r.URL.Path),
			logging.String("destination", destURL.String()),
			logging.String("backend_url_pattern", selectedBackend.URLPattern),
			logging.Int("backend_weight", effectiveBackendWeight(selectedBackend)),
		)
		if isWebSocketRequest(r) {
			g.logger.Info("Initiating WebSocket proxy", logging.String("path", r.URL.Path), logging.String("destination", destURL.String()))
			wsOpts := route.WebSocket
			if wsOpts == nil {
				wsOpts = &config.WebSocketOptions{
					HandshakeTimeout:  45 * time.Second,
					ReadBufferSize:    4096,
					WriteBufferSize:   4096,
					EnableCompression: true,
					CheckOrigin:       false,
				}
			}
			proxyWebSocket(w, r, destURL, route, g.logger, wsOpts)
			return
		}

		var hedge *hedgeTarget
		if routeHedgingAllowed(route, r.Method) && len(route.Backends) > 1 {
			hedgeBackend, hedgeDestination := g.selectAlternateRouteBackend(route, selectedBackend, rolloutBucketKey(r))
			if hedgeDestination != "" {
				hedgeURL, parseErr := url.Parse(hedgeDestination)
				if parseErr == nil {
					hedgePath, pathErr := ComputeProxiedPathForBackend(service, route, hedgeBackend, origPath, routeVars)
					if pathErr == nil {
						hedge = &hedgeTarget{
							backend:     hedgeBackend,
							destination: hedgeDestination,
							scheme:      hedgeURL.Scheme,
							host:        hedgeURL.Host,
							path:        hedgePath,
						}
					}
				}
			}
		}
		var shadow *shadowTarget
		if routeShadowAllowed(route, r.Method) && routeShadowTrafficMatches(route, rolloutBucketKey(r)) && len(route.Backends) > 1 {
			shadowBackend, shadowDestination := g.selectAlternateRouteBackend(route, selectedBackend, rolloutBucketKey(r))
			if shadowDestination != "" {
				shadowURL, parseErr := url.Parse(shadowDestination)
				if parseErr == nil {
					shadowPath, pathErr := ComputeProxiedPathForBackend(service, route, shadowBackend, origPath, routeVars)
					if pathErr == nil {
						shadow = &shadowTarget{
							backend:     shadowBackend,
							destination: shadowDestination,
							scheme:      shadowURL.Scheme,
							host:        shadowURL.Host,
							path:        shadowPath,
						}
					}
				}
			}
		}

		proxy := httputil.NewSingleHostReverseProxy(destURL)
		if strings.EqualFold(strings.TrimSpace(route.Protocol), "sse") {
			proxy.FlushInterval = -1
		}
		proxy.Director = func(req *http.Request) {
			req.URL.Scheme = destURL.Scheme
			req.URL.Host = destURL.Host
			req.Host = destURL.Host
			if err := applyRequestJSONTransforms(req, route); err != nil {
				g.logger.Warn("Failed to apply request JSON transforms",
					logging.Error(err),
					logging.String("route_path", route.Path),
				)
			}
			applyUpstreamHeaders(req, req.Header, route, nil)
		}
		proxy.Transport = &retryingTransport{
			base:        cloneDefaultTransport(),
			route:       route,
			backend:     selectedBackend,
			destination: destination,
			hedge:       hedge,
		}
		requestStart := time.Now()
		proxy.ModifyResponse = func(resp *http.Response) error {
			if shouldRecordBackendFailureStatus(resp.StatusCode) {
				g.recordBackendFailureWithStatus(route, selectedBackend, destination, resp.StatusCode, fmt.Errorf("upstream responded with status %d", resp.StatusCode), time.Now().UTC())
			} else {
				g.recordBackendSuccessWithStatus(route, selectedBackend, destination, resp.StatusCode, time.Since(requestStart), time.Now().UTC())
			}
			upstreamHeaders := resp.Header.Clone()
			applyDownstreamHeaders(resp.Header, route, resp.Request, resp.StatusCode, upstreamHeaders)
			if strings.EqualFold(strings.TrimSpace(route.Protocol), "sse") {
				if contentType := strings.ToLower(strings.TrimSpace(resp.Header.Get("Content-Type"))); contentType != "" && !strings.Contains(contentType, "text/event-stream") {
					return fmt.Errorf("sse routes require upstream responses with content-type text/event-stream")
				}
				resp.Header.Set("X-Gateway", "Iket")
				resp.Header.Set("X-Gateway-Route", route.Path)
				if requestID := GetRequestID(r); requestID != "" {
					resp.Header.Set("X-Request-Id", requestID)
				}
				if strings.TrimSpace(selectedBackend.Host) != "" {
					resp.Header.Set("X-Gateway-Backend", selectedBackend.Host)
				}
				return nil
			}
			if err := enforceResponseBodyLimit(resp, route); err != nil {
				return err
			}
			if handled, err := applySuccessResponseEnvelope(resp, route, upstreamHeaders); err != nil {
				return err
			} else if handled {
				return nil
			}
			if handled, err := applyErrorResponseEnvelope(resp, route, upstreamHeaders); err != nil {
				return err
			} else if handled {
				return nil
			}
			if err := applyResponseJSONTransforms(resp, route, upstreamHeaders); err != nil {
				return err
			}
			if handled, err := applyResponseBodyPatterns(g, resp, route); err != nil {
				return err
			} else if handled {
				return nil
			}
			resp.Header.Set("X-Gateway", "Iket")
			resp.Header.Set("X-Gateway-Route", route.Path)
			if requestID := GetRequestID(r); requestID != "" {
				resp.Header.Set("X-Request-Id", requestID)
			}
			if strings.TrimSpace(selectedBackend.Host) != "" {
				resp.Header.Set("X-Gateway-Backend", selectedBackend.Host)
			}
			return nil
		}
		proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
			g.recordBackendFailure(route, selectedBackend, destination, err)
			g.logger.Error("Proxy error", err, logging.String("destination", destination), logging.String("path", r.URL.Path))
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadGateway)
			w.Write([]byte(`{"error":"Bad Gateway","message":"Unable to reach the upstream service"}`))
		}
		if shadow != nil {
			go dispatchShadowRequest(g, cloneDefaultTransport(), r, route, shadow, g.logger)
		}
		proxy.ServeHTTP(w, r)
	}
}

func cloneDefaultTransport() *http.Transport {
	base, ok := http.DefaultTransport.(*http.Transport)
	if ok {
		return base.Clone()
	}
	return &http.Transport{}
}

func (t *retryingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	base := t.base
	if base == nil {
		base = cloneDefaultTransport()
	}
	if t.hedge != nil && routeHedgingAllowed(t.route, req.Method) {
		return t.roundTripWithHedge(base, req)
	}

	attempts := routeRetryAttempts(t.route)
	retryStatuses := routeRetryStatusSet(t.route)
	backoff := routeRetryBackoff(t.route)
	jitter := routeRetryJitter(t.route)
	attemptTimeout := backendRequestTimeout(t.backend)
	if attemptTimeout > 0 {
		if transport, ok := base.(*http.Transport); ok {
			transport = transport.Clone()
			transport.ResponseHeaderTimeout = attemptTimeout
			transport.TLSHandshakeTimeout = attemptTimeout
			transport.DialContext = (&net.Dialer{Timeout: attemptTimeout}).DialContext
			base = transport
		}
	}

	bodyBytes, err := cloneRequestBody(req)
	if err != nil {
		return nil, err
	}

	var lastResp *http.Response
	var lastErr error
	for attempt := 0; attempt < attempts; attempt++ {
		attemptReq := req.Clone(req.Context())
		if len(bodyBytes) > 0 {
			attemptReq.Body = io.NopCloser(bytes.NewReader(bodyBytes))
			attemptReq.ContentLength = int64(len(bodyBytes))
			attemptReq.GetBody = func() (io.ReadCloser, error) {
				return io.NopCloser(bytes.NewReader(bodyBytes)), nil
			}
		}
		resp, roundTripErr := base.RoundTrip(attemptReq)
		if roundTripErr == nil && !retryStatuses[resp.StatusCode] {
			return resp, nil
		}
		if !routeRetryAllowedForMethod(t.route, req.Method) {
			if resp != nil {
				return resp, nil
			}
			return nil, roundTripErr
		}
		if roundTripErr == nil {
			lastResp = resp
		} else {
			lastErr = roundTripErr
		}
		if attempt == attempts-1 {
			break
		}
		if resp != nil {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
		delay := backoff + retryJitterOffset(jitter)
		if delay > 0 {
			timer := time.NewTimer(delay)
			select {
			case <-req.Context().Done():
				timer.Stop()
				if lastErr != nil {
					return nil, lastErr
				}
				if lastResp != nil {
					return lastResp, nil
				}
				return nil, req.Context().Err()
			case <-timer.C:
			}
		}
	}

	if lastResp != nil {
		return lastResp, nil
	}
	return nil, lastErr
}

func (t *retryingTransport) roundTripWithHedge(base http.RoundTripper, req *http.Request) (*http.Response, error) {
	bodyBytes, err := cloneRequestBody(req)
	if err != nil {
		return nil, err
	}

	type result struct {
		resp *http.Response
		err  error
	}
	results := make(chan result, 2)
	ctx, cancel := context.WithCancel(req.Context())
	defer cancel()

	launch := func(host, scheme, path string) {
		attemptReq := req.Clone(ctx)
		attemptReq.URL.Scheme = scheme
		attemptReq.URL.Host = host
		attemptReq.URL.Path = path
		attemptReq.Host = host
		if len(bodyBytes) > 0 {
			attemptReq.Body = io.NopCloser(bytes.NewReader(bodyBytes))
			attemptReq.ContentLength = int64(len(bodyBytes))
			attemptReq.GetBody = func() (io.ReadCloser, error) {
				return io.NopCloser(bytes.NewReader(bodyBytes)), nil
			}
		}
		resp, roundTripErr := base.RoundTrip(attemptReq)
		select {
		case results <- result{resp: resp, err: roundTripErr}:
		case <-ctx.Done():
			if resp != nil && resp.Body != nil {
				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
			}
		}
	}

	go launch(req.URL.Host, req.URL.Scheme, req.URL.Path)
	delay := routeHedgeDelay(t.route)
	if delay <= 0 {
		delay = 1 * time.Millisecond
	}
	go func() {
		timer := time.NewTimer(delay)
		defer timer.Stop()
		select {
		case <-timer.C:
			launch(t.hedge.host, t.hedge.scheme, t.hedge.path)
		case <-ctx.Done():
			return
		}
	}()

	var firstErr error
	for i := 0; i < 2; i++ {
		result := <-results
		if result.err == nil && result.resp != nil {
			cancel()
			return result.resp, nil
		}
		if firstErr == nil {
			if result.err != nil {
				firstErr = result.err
			} else if result.resp != nil {
				firstErr = fmt.Errorf("upstream responded with status %d", result.resp.StatusCode)
			}
		}
	}
	cancel()
	return nil, firstErr
}

func cloneRequestBody(req *http.Request) ([]byte, error) {
	if req == nil || req.Body == nil {
		return nil, nil
	}
	if req.GetBody != nil {
		body, err := req.GetBody()
		if err != nil {
			return nil, err
		}
		defer body.Close()
		return io.ReadAll(body)
	}
	bodyBytes, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, err
	}
	req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	req.ContentLength = int64(len(bodyBytes))
	req.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(bodyBytes)), nil
	}
	return bodyBytes, nil
}

func enforceRequestBodyLimit(req *http.Request, route config.RouterConfig) error {
	if req == nil || req.Body == nil || route.MaxRequestBodyBytes <= 0 {
		return nil
	}
	if req.ContentLength > route.MaxRequestBodyBytes {
		return fmt.Errorf("request body exceeds configured route limit")
	}
	bodyBytes, err := cloneRequestBody(req)
	if err != nil {
		return err
	}
	if int64(len(bodyBytes)) > route.MaxRequestBodyBytes {
		return fmt.Errorf("request body exceeds configured route limit")
	}
	return nil
}

func enforceResponseBodyLimit(resp *http.Response, route config.RouterConfig) error {
	if resp == nil || resp.Body == nil || route.MaxResponseBodyBytes <= 0 {
		return nil
	}
	if resp.ContentLength > route.MaxResponseBodyBytes {
		return fmt.Errorf("response body exceeds configured route limit")
	}
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if err := resp.Body.Close(); err != nil {
		return err
	}
	if int64(len(bodyBytes)) > route.MaxResponseBodyBytes {
		return fmt.Errorf("response body exceeds configured route limit")
	}
	resp.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	resp.ContentLength = int64(len(bodyBytes))
	resp.Header.Set("Content-Length", fmt.Sprintf("%d", len(bodyBytes)))
	return nil
}

func enforceAllowedModels(req *http.Request, route config.RouterConfig) error {
	if req == nil || len(route.AllowedModels) == 0 {
		return nil
	}
	contentType := strings.ToLower(strings.TrimSpace(req.Header.Get("Content-Type")))
	if contentType != "" && !strings.Contains(contentType, "application/json") && !strings.Contains(contentType, "+json") {
		return fmt.Errorf("request model field is missing")
	}
	bodyBytes, err := cloneRequestBody(req)
	if err != nil {
		return err
	}
	if len(bytes.TrimSpace(bodyBytes)) == 0 {
		return fmt.Errorf("request model field is missing")
	}

	var payload map[string]interface{}
	if err := json.Unmarshal(bodyBytes, &payload); err != nil {
		return fmt.Errorf("request model field is missing")
	}
	modelField := strings.TrimSpace(route.ModelField)
	if modelField == "" {
		modelField = "model"
	}
	model, ok := nestedJSONStringValue(payload, modelField)
	if !ok || strings.TrimSpace(model) == "" {
		return fmt.Errorf("request model field is missing")
	}
	for _, allowed := range route.AllowedModels {
		if strings.EqualFold(strings.TrimSpace(allowed), strings.TrimSpace(model)) {
			return nil
		}
	}
	return fmt.Errorf("requested model is not allowed")
}

func enforceAllowedTools(req *http.Request, route config.RouterConfig) error {
	if req == nil || len(route.AllowedToolNames) == 0 {
		return nil
	}
	contentType := strings.ToLower(strings.TrimSpace(req.Header.Get("Content-Type")))
	if contentType != "" && !strings.Contains(contentType, "application/json") && !strings.Contains(contentType, "+json") {
		return fmt.Errorf("request tool field is missing")
	}
	bodyBytes, err := cloneRequestBody(req)
	if err != nil {
		return err
	}
	if len(bytes.TrimSpace(bodyBytes)) == 0 {
		return fmt.Errorf("request tool field is missing")
	}

	var payload map[string]interface{}
	if err := json.Unmarshal(bodyBytes, &payload); err != nil {
		return fmt.Errorf("request tool field is missing")
	}
	toolField := strings.TrimSpace(route.ToolField)
	if toolField == "" {
		toolField = "tools[].name"
	}
	toolNames := nestedJSONStringValues(payload, toolField)
	if len(toolNames) == 0 {
		return fmt.Errorf("request tool field is missing")
	}

	allowed := make(map[string]struct{}, len(route.AllowedToolNames))
	for _, name := range route.AllowedToolNames {
		normalized := strings.ToLower(strings.TrimSpace(name))
		if normalized != "" {
			allowed[normalized] = struct{}{}
		}
	}
	for _, toolName := range toolNames {
		if _, ok := allowed[strings.ToLower(strings.TrimSpace(toolName))]; !ok {
			return fmt.Errorf("requested tool is not allowed")
		}
	}
	return nil
}

func enforceTokenBudgets(req *http.Request, route config.RouterConfig) error {
	if req == nil || (route.MaxInputTokens <= 0 && route.MaxOutputTokens <= 0) {
		return nil
	}
	contentType := strings.ToLower(strings.TrimSpace(req.Header.Get("Content-Type")))
	if contentType != "" && !strings.Contains(contentType, "application/json") && !strings.Contains(contentType, "+json") {
		return fmt.Errorf("request token field is missing")
	}
	bodyBytes, err := cloneRequestBody(req)
	if err != nil {
		return err
	}
	if len(bytes.TrimSpace(bodyBytes)) == 0 {
		return fmt.Errorf("request token field is missing")
	}

	var payload map[string]interface{}
	if err := json.Unmarshal(bodyBytes, &payload); err != nil {
		return fmt.Errorf("request token field is missing")
	}
	if route.MaxInputTokens > 0 {
		field := strings.TrimSpace(route.InputTokensField)
		if field == "" {
			field = "max_prompt_tokens"
		}
		value, ok := nestedJSONIntValue(payload, field)
		if !ok {
			return fmt.Errorf("request input token field is missing")
		}
		if value > route.MaxInputTokens {
			return fmt.Errorf("requested input token budget exceeds allowed maximum")
		}
	}
	if route.MaxOutputTokens > 0 {
		field := strings.TrimSpace(route.OutputTokensField)
		if field == "" {
			field = "max_tokens"
		}
		value, ok := nestedJSONIntValue(payload, field)
		if !ok {
			return fmt.Errorf("request output token field is missing")
		}
		if value > route.MaxOutputTokens {
			return fmt.Errorf("requested output token budget exceeds allowed maximum")
		}
	}
	return nil
}

func enforceConversationBudgets(req *http.Request, route config.RouterConfig) error {
	if req == nil || (route.MaxMessages <= 0 && route.MaxToolCalls <= 0) {
		return nil
	}
	contentType := strings.ToLower(strings.TrimSpace(req.Header.Get("Content-Type")))
	if contentType != "" && !strings.Contains(contentType, "application/json") && !strings.Contains(contentType, "+json") {
		return fmt.Errorf("request conversation field is missing")
	}
	bodyBytes, err := cloneRequestBody(req)
	if err != nil {
		return err
	}
	if len(bytes.TrimSpace(bodyBytes)) == 0 {
		return fmt.Errorf("request conversation field is missing")
	}

	var payload map[string]interface{}
	if err := json.Unmarshal(bodyBytes, &payload); err != nil {
		return fmt.Errorf("request conversation field is missing")
	}
	if route.MaxMessages > 0 {
		field := strings.TrimSpace(route.MessagesField)
		if field == "" {
			field = "messages"
		}
		count, ok := nestedJSONArrayLength(payload, field)
		if !ok {
			return fmt.Errorf("request messages field is missing")
		}
		if count > route.MaxMessages {
			return fmt.Errorf("request message count exceeds allowed maximum")
		}
	}
	if route.MaxToolCalls > 0 {
		field := strings.TrimSpace(route.ToolCallsField)
		if field == "" {
			field = "tools"
		}
		count, ok := nestedJSONArrayLength(payload, field)
		if !ok {
			return fmt.Errorf("request tool calls field is missing")
		}
		if count > route.MaxToolCalls {
			return fmt.Errorf("request tool call count exceeds allowed maximum")
		}
	}
	return nil
}

func enforceRequestBodyPatterns(req *http.Request, route config.RouterConfig) error {
	if req == nil || (len(route.RequestBodyBlockRegex) == 0 && len(route.RequestBodyRequireRegex) == 0 && len(route.RequestPIIBlockTypes) == 0) {
		return nil
	}
	bodyBytes, err := cloneRequestBody(req)
	if err != nil {
		return err
	}
	if len(bodyBytes) == 0 {
		if len(route.RequestBodyRequireRegex) > 0 {
			return fmt.Errorf("request body is missing required content policy marker")
		}
		return nil
	}
	body := string(bodyBytes)
	for _, pattern := range append([]string{}, route.RequestBodyBlockRegex...) {
		matched, err := regexp.MatchString(pattern, body)
		if err != nil {
			return fmt.Errorf("request body blocked by content policy")
		}
		if matched {
			return fmt.Errorf("request body blocked by content policy")
		}
	}
	for _, pattern := range piiPatternsForTypes(route.RequestPIIBlockTypes) {
		matched, err := regexp.MatchString(pattern, body)
		if err != nil {
			return fmt.Errorf("request body blocked by content policy")
		}
		if matched {
			return fmt.Errorf("request body blocked by content policy")
		}
	}
	for _, pattern := range route.RequestBodyRequireRegex {
		matched, err := regexp.MatchString(pattern, body)
		if err != nil {
			return fmt.Errorf("request body is missing required content policy marker")
		}
		if !matched {
			return fmt.Errorf("request body is missing required content policy marker")
		}
	}
	return nil
}

func enforceAllowedUpstreamHost(destURL *url.URL, route config.RouterConfig) error {
	if destURL == nil || len(route.AllowedUpstreamHosts) == 0 {
		return nil
	}
	host := strings.TrimSpace(destURL.Hostname())
	if host == "" {
		return fmt.Errorf("resolved upstream host is not allowed")
	}
	for _, allowed := range route.AllowedUpstreamHosts {
		if strings.EqualFold(strings.TrimSpace(allowed), host) {
			return nil
		}
	}
	return fmt.Errorf("resolved upstream host is not allowed")
}

func enforceRouteProtocol(req *http.Request, route config.RouterConfig) error {
	if req == nil {
		return nil
	}
	protocol := strings.ToLower(strings.TrimSpace(route.Protocol))
	if protocol == "" || protocol == "http" {
		return nil
	}

	contentType := strings.ToLower(strings.TrimSpace(req.Header.Get("Content-Type")))
	switch protocol {
	case "graphql":
		if req.Method != http.MethodPost && req.Method != http.MethodGet {
			return fmt.Errorf("graphql routes only support GET or POST requests")
		}
		if req.Method == http.MethodPost && contentType != "" &&
			!strings.Contains(contentType, "application/json") &&
			!strings.Contains(contentType, "+json") &&
			!strings.Contains(contentType, "application/graphql") {
			return fmt.Errorf("graphql routes require a GraphQL-compatible content-type")
		}
		return nil
	case "grpc":
		if !strings.Contains(contentType, "application/grpc") {
			return fmt.Errorf("grpc routes require content-type application/grpc")
		}
		return nil
	case "grpc-web":
		if req.Method != http.MethodPost {
			return fmt.Errorf("grpc-web routes only support POST requests")
		}
		if !strings.Contains(contentType, "application/grpc-web") {
			return fmt.Errorf("grpc-web routes require content-type application/grpc-web")
		}
		if header := strings.TrimSpace(req.Header.Get("X-Grpc-Web")); header != "" && header != "1" {
			return fmt.Errorf("grpc-web routes require X-Grpc-Web header value 1 when provided")
		}
		return nil
	case "websocket":
		if !isWebSocketRequest(req) {
			return fmt.Errorf("websocket routes require a websocket upgrade request")
		}
		return nil
	case "sse":
		if req.Method != http.MethodGet && req.Method != http.MethodPost {
			return fmt.Errorf("sse routes only support GET or POST requests")
		}
		accept := strings.ToLower(strings.TrimSpace(req.Header.Get("Accept")))
		if accept != "" && !strings.Contains(accept, "text/event-stream") {
			return fmt.Errorf("sse routes require Accept text/event-stream")
		}
		return nil
	default:
		return nil
	}
}

func enforceGraphQLRoutePolicy(req *http.Request, route config.RouterConfig) error {
	if req == nil || !strings.EqualFold(strings.TrimSpace(route.Protocol), "graphql") {
		return nil
	}
	queryText, persistedQueryID, operationName, err := extractGraphQLRouteMetadata(req, route)
	if err != nil {
		return err
	}
	if !routeGraphQLIntrospectionAllowed(route) && graphQLQueryLooksLikeIntrospection(queryText) {
		return fmt.Errorf("graphql introspection is not allowed on this route")
	}
	if route.GraphQLRequirePersistedQuery && strings.TrimSpace(persistedQueryID) == "" {
		return fmt.Errorf("graphql persisted query is required on this route")
	}
	if route.GraphQLOperationNameRequired && strings.TrimSpace(operationName) == "" {
		return fmt.Errorf("graphql operation name is required on this route")
	}
	if len(route.GraphQLAllowedOperations) > 0 {
		resolvedName := strings.TrimSpace(operationName)
		if resolvedName == "" {
			resolvedName = inferGraphQLOperationName(queryText)
		}
		if strings.TrimSpace(resolvedName) == "" {
			return fmt.Errorf("graphql operation name is required to evaluate route allowlist")
		}
		if !graphQLOperationAllowed(route.GraphQLAllowedOperations, resolvedName) {
			return fmt.Errorf("graphql operation %q is not allowed on this route", resolvedName)
		}
	}
	return nil
}

func routeGraphQLIntrospectionAllowed(route config.RouterConfig) bool {
	return route.GraphQLAllowIntrospection == nil || *route.GraphQLAllowIntrospection
}

func defaultGraphQLPersistedQueryField(route config.RouterConfig) string {
	if strings.TrimSpace(route.GraphQLPersistedQueryField) != "" {
		return strings.TrimSpace(route.GraphQLPersistedQueryField)
	}
	return "extensions.persistedQuery.sha256Hash"
}

func extractGraphQLRouteMetadata(req *http.Request, route config.RouterConfig) (string, string, string, error) {
	if req == nil {
		return "", "", "", nil
	}
	if req.Method == http.MethodGet {
		queryText := strings.TrimSpace(req.URL.Query().Get("query"))
		persisted, err := extractPersistedQueryIDFromExtensions(req.URL.Query().Get("extensions"), defaultGraphQLPersistedQueryField(route))
		operationName := strings.TrimSpace(req.URL.Query().Get("operationName"))
		return queryText, persisted, operationName, err
	}

	bodyBytes, err := cloneRequestBody(req)
	if err != nil {
		return "", "", "", err
	}
	if len(bytes.TrimSpace(bodyBytes)) == 0 {
		return "", "", "", nil
	}

	contentType := strings.ToLower(strings.TrimSpace(req.Header.Get("Content-Type")))
	if strings.Contains(contentType, "application/graphql") {
		return string(bodyBytes), "", inferGraphQLOperationName(string(bodyBytes)), nil
	}

	var payload map[string]interface{}
	if err := json.Unmarshal(bodyBytes, &payload); err != nil {
		return "", "", "", nil
	}
	queryText, _ := payload["query"].(string)
	persisted := lookupJSONFieldStringValue(payload, defaultGraphQLPersistedQueryField(route))
	operationName, _ := payload["operationName"].(string)
	return strings.TrimSpace(queryText), strings.TrimSpace(persisted), strings.TrimSpace(operationName), nil
}

func extractPersistedQueryIDFromExtensions(raw string, field string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil
	}
	var payload map[string]interface{}
	if err := json.Unmarshal([]byte(raw), &payload); err != nil {
		return "", fmt.Errorf("graphql extensions payload is invalid")
	}
	return strings.TrimSpace(lookupJSONFieldStringValue(payload, field)), nil
}

func graphQLQueryLooksLikeIntrospection(query string) bool {
	query = strings.ToLower(strings.TrimSpace(query))
	if query == "" {
		return false
	}
	return strings.Contains(query, "__schema") || strings.Contains(query, "__type")
}

func graphQLOperationAllowed(allowed []string, operationName string) bool {
	operationName = strings.TrimSpace(operationName)
	if operationName == "" {
		return false
	}
	for _, allowedName := range allowed {
		if strings.EqualFold(strings.TrimSpace(allowedName), operationName) {
			return true
		}
	}
	return false
}

func inferGraphQLOperationName(query string) string {
	query = strings.TrimSpace(query)
	if query == "" {
		return ""
	}
	matches := regexp.MustCompile(`(?i)\b(query|mutation|subscription)\s+([A-Za-z_][A-Za-z0-9_]*)`).FindStringSubmatch(query)
	if len(matches) >= 3 {
		return strings.TrimSpace(matches[2])
	}
	return ""
}

func policyReasonForGraphQLError(err error) string {
	if err == nil {
		return "graphql_policy"
	}
	msg := strings.ToLower(err.Error())
	if strings.Contains(msg, "introspection") {
		return "graphql_introspection"
	}
	if strings.Contains(msg, "persisted query") {
		return "graphql_persisted_query"
	}
	if strings.Contains(msg, "operation") {
		return "graphql_operation_policy"
	}
	return "graphql_policy"
}

func enforceRequiredRequestHeaders(req *http.Request, route config.RouterConfig) error {
	if req == nil {
		return nil
	}
	for _, name := range route.RequiredRequestHeaders {
		headerName := strings.TrimSpace(name)
		if headerName == "" {
			continue
		}
		if strings.TrimSpace(req.Header.Get(headerName)) == "" {
			return fmt.Errorf("missing required request header %q", headerName)
		}
	}
	for name, pattern := range route.RequiredRequestHeaderRegex {
		headerName := strings.TrimSpace(name)
		if headerName == "" {
			continue
		}
		value := req.Header.Get(headerName)
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("missing required request header %q", headerName)
		}
		matched, err := regexp.MatchString(pattern, value)
		if err != nil {
			return fmt.Errorf("required request header %q failed validation", headerName)
		}
		if !matched {
			return fmt.Errorf("required request header %q failed validation", headerName)
		}
	}
	return nil
}

func routeRetryAttempts(route config.RouterConfig) int {
	if route.RetryCount <= 0 {
		return 1
	}
	return route.RetryCount + 1
}

func routeRetryBackoff(route config.RouterConfig) time.Duration {
	if strings.TrimSpace(route.RetryBackoff) == "" {
		return 0
	}
	backoff, err := time.ParseDuration(strings.TrimSpace(route.RetryBackoff))
	if err != nil || backoff < 0 {
		return 0
	}
	return backoff
}

func routeRetryJitter(route config.RouterConfig) time.Duration {
	if strings.TrimSpace(route.RetryJitter) == "" {
		return 0
	}
	jitter, err := time.ParseDuration(strings.TrimSpace(route.RetryJitter))
	if err != nil || jitter < 0 {
		return 0
	}
	return jitter
}

func retryJitterOffset(max time.Duration) time.Duration {
	if max <= 0 {
		return 0
	}
	n, err := rand.Int(rand.Reader, big.NewInt(max.Nanoseconds()+1))
	if err != nil {
		return 0
	}
	return time.Duration(n.Int64())
}

func routeRetryStatusSet(route config.RouterConfig) map[int]bool {
	if len(route.RetryStatuses) == 0 {
		return map[int]bool{
			http.StatusBadGateway:         true,
			http.StatusServiceUnavailable: true,
			http.StatusGatewayTimeout:     true,
			http.StatusTooManyRequests:    true,
		}
	}
	statuses := make(map[int]bool, len(route.RetryStatuses))
	for _, statusCode := range route.RetryStatuses {
		statuses[statusCode] = true
	}
	return statuses
}

func routeRetryAllowedForMethod(route config.RouterConfig, method string) bool {
	if route.RetryUnsafe {
		return true
	}
	switch strings.ToUpper(strings.TrimSpace(method)) {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace, http.MethodPut, http.MethodDelete:
		return true
	default:
		return false
	}
}

func routeHedgeDelay(route config.RouterConfig) time.Duration {
	if strings.TrimSpace(route.HedgeDelay) == "" {
		return 0
	}
	delay, err := time.ParseDuration(strings.TrimSpace(route.HedgeDelay))
	if err != nil || delay < 0 {
		return 0
	}
	return delay
}

func routeHedgingAllowed(route config.RouterConfig, method string) bool {
	if route.HedgeUnsafe {
		return true
	}
	switch strings.ToUpper(strings.TrimSpace(method)) {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace:
		return routeHedgeDelay(route) > 0
	default:
		return false
	}
}

func routeShadowAllowed(route config.RouterConfig, method string) bool {
	if route.ShadowTrafficPercent <= 0 {
		return false
	}
	if route.ShadowUnsafe {
		return true
	}
	switch strings.ToUpper(strings.TrimSpace(method)) {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace:
		return true
	default:
		return false
	}
}

func routeShadowTrafficMatches(route config.RouterConfig, bucketKey string) bool {
	if route.ShadowTrafficPercent <= 0 {
		return false
	}
	if route.ShadowTrafficPercent >= 100 {
		return true
	}
	return percentageBucketForKey(bucketKey) < route.ShadowTrafficPercent
}

func dispatchShadowRequest(g *Gateway, base http.RoundTripper, req *http.Request, route config.RouterConfig, target *shadowTarget, logger *logging.Logger) {
	if base == nil || req == nil || target == nil || g == nil {
		return
	}
	start := time.Now()
	shadowReq := req.Clone(req.Context())
	bodyBytes, err := cloneRequestBody(req)
	if err != nil {
		if logger != nil {
			logger.Warn("Skipping shadow request due to body clone failure", logging.Error(err))
		}
		return
	}
	if len(bodyBytes) > 0 {
		shadowReq.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		shadowReq.ContentLength = int64(len(bodyBytes))
		shadowReq.GetBody = func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(bodyBytes)), nil
		}
	}
	shadowReq.URL.Scheme = target.scheme
	shadowReq.URL.Host = target.host
	shadowReq.URL.Path = target.path
	shadowReq.Host = target.host
	applyUpstreamHeaders(shadowReq, shadowReq.Header, route, nil)
	shadowReq.Header.Set("X-Iket-Shadow", "true")

	resp, roundTripErr := base.RoundTrip(shadowReq)
	if roundTripErr != nil {
		g.recordShadowResult(route, target.backend, target.destination, 0, time.Since(start), roundTripErr)
		if logger != nil {
			logger.Warn("Shadow request failed", logging.Error(roundTripErr), logging.String("destination", target.destination))
		}
		return
	}
	g.recordShadowResult(route, target.backend, target.destination, resp.StatusCode, time.Since(start), nil)
	if resp != nil && resp.Body != nil {
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
}

func (g *Gateway) recordShadowResult(route config.RouterConfig, backend config.Backend, destination string, statusCode int, latency time.Duration, shadowErr error) {
	key := g.backendStateKey(route, backend, destination)
	g.backendStateMu.Lock()
	defer g.backendStateMu.Unlock()
	state := g.backendState[key]
	state.ShadowRequests++
	state.LastShadowStatusCode = statusCode
	state.LastShadowLatency = latency
	state.ShadowLatencyEWMA = updateLatencyEWMA(state.ShadowLatencyEWMA, latency)
	recordedFailure := false
	if shadowErr != nil {
		state.ShadowFailures++
		state.LastShadowError = shadowErr.Error()
		recordedFailure = true
	} else {
		state.LastShadowError = ""
	}
	if statusCode >= http.StatusInternalServerError && !recordedFailure {
		state.ShadowFailures++
		if state.LastShadowError == "" {
			state.LastShadowError = fmt.Sprintf("shadow upstream responded with status %d", statusCode)
		}
	}
	g.backendState[key] = state
}

func backendRequestTimeout(backend config.Backend) time.Duration {
	if strings.TrimSpace(backend.Timeout) == "" {
		return 0
	}
	timeout, err := time.ParseDuration(strings.TrimSpace(backend.Timeout))
	if err != nil || timeout <= 0 {
		return 0
	}
	return timeout
}

func shouldRecordBackendFailureStatus(statusCode int) bool {
	return statusCode >= http.StatusInternalServerError
}

func backendCircuitState(state backendRuntimeState, now time.Time) string {
	if !state.UnhealthyUntil.IsZero() && now.Before(state.UnhealthyUntil) {
		return "open"
	}
	if !state.UnhealthyUntil.IsZero() {
		return "half_open"
	}
	return "closed"
}

func backendHalfOpenMaxRequests(backend config.Backend) int {
	if backend.HalfOpenMaxRequests <= 0 {
		return 1
	}
	return backend.HalfOpenMaxRequests
}

func backendRecoverySuccessThreshold(backend config.Backend) int {
	if backend.RecoverySuccessThreshold <= 0 {
		return 1
	}
	return backend.RecoverySuccessThreshold
}

func backendOutlierSlowResponseThreshold(backend config.Backend) int {
	if backend.OutlierConsecutiveSlowResponses <= 0 {
		return 0
	}
	return backend.OutlierConsecutiveSlowResponses
}

func backendOutlierLatencyThreshold(backend config.Backend) time.Duration {
	if strings.TrimSpace(backend.OutlierLatencyThreshold) == "" {
		return 0
	}
	threshold, err := time.ParseDuration(strings.TrimSpace(backend.OutlierLatencyThreshold))
	if err != nil || threshold <= 0 {
		return 0
	}
	return threshold
}

func backendOutlierCooldown(backend config.Backend) time.Duration {
	if strings.TrimSpace(backend.OutlierCooldown) != "" {
		if parsed, err := time.ParseDuration(strings.TrimSpace(backend.OutlierCooldown)); err == nil && parsed > 0 {
			return parsed
		}
	}
	if strings.TrimSpace(backend.Cooldown) != "" {
		if parsed, err := time.ParseDuration(strings.TrimSpace(backend.Cooldown)); err == nil && parsed > 0 {
			return parsed
		}
	}
	return defaultBackendCooldown
}

func isBackendLatencyOutlier(backend config.Backend, latency time.Duration) bool {
	threshold := backendOutlierLatencyThreshold(backend)
	return threshold > 0 && latency >= threshold
}

func updateLatencyEWMA(current, observed time.Duration) time.Duration {
	if observed <= 0 {
		return current
	}
	if current <= 0 {
		return observed
	}
	const alpha = 0.2
	return time.Duration((1.0-alpha)*float64(current) + alpha*float64(observed))
}

var routeVarRe = regexp.MustCompile(`\{([A-Za-z0-9_]+)(:[^}]*)?\}`)

// applyURLPattern expands a backend URL pattern like "/api/{rest:.*}" using mux vars.
// If the named var is missing, and the placeholder is {rest...}, it falls back to
// deriving "rest" from the original request path and the route path prefix.
func applyURLPattern(pattern, routePath, origPath string, vars map[string]string) string {
	derivedRest := ""
	if i := findWildcardIndex(routePath); i > 0 {
		prefix := routePath[:i-1]
		if prefix != "" && prefix != "/" && strings.HasPrefix(origPath, prefix) {
			derivedRest = strings.TrimPrefix(origPath[len(prefix):], "/")
		}
	}

	out := routeVarRe.ReplaceAllStringFunc(pattern, func(m string) string {
		sub := routeVarRe.FindStringSubmatch(m)
		if len(sub) < 2 {
			return m
		}
		name := sub[1]
		val := ""
		if vars != nil {
			val = vars[name]
		}
		if val == "" && name == "rest" {
			val = derivedRest
		}
		return strings.TrimPrefix(val, "/")
	})

	out = strings.TrimSpace(out)
	if out == "" {
		return "/"
	}
	if !strings.HasPrefix(out, "/") {
		out = "/" + out
	}
	return out
}

// isWebSocketRequest checks if the request is a WebSocket upgrade
func isWebSocketRequest(r *http.Request) bool {
	upgrade := strings.ToLower(r.Header.Get("Upgrade"))
	connection := strings.ToLower(r.Header.Get("Connection"))
	if upgrade == "websocket" {
		return true
	}
	// Some proxies strip hop-by-hop headers like `Connection` and even `Upgrade`
	// before the request reaches the gateway. When a client is attempting a
	// WebSocket handshake we still usually have `Sec-WebSocket-Key`/`Version`.
	if r.Header.Get("Sec-WebSocket-Key") != "" {
		return true
	}
	if r.Header.Get("Sec-WebSocket-Version") != "" {
		return true
	}
	return upgrade == "websocket" && strings.Contains(connection, "upgrade")
}

// proxyWebSocket proxies a WebSocket connection between client and backend, with protocol-aware handling
// proxyWebSocket proxies a WebSocket connection between client and backend
func proxyWebSocket(w http.ResponseWriter, r *http.Request, destURL *url.URL, route config.RouterConfig, logger *logging.Logger, wsOpts *config.WebSocketOptions) {
	// Validate WebSocket upgrade request
	if !isWebSocketRequest(r) {
		logger.Warn("Request is not a WebSocket upgrade",
			logging.String("path", r.URL.Path))
		http.Error(w, "Not a WebSocket request", http.StatusBadRequest)
		return
	}
	// Best-effort: re-add required handshake headers if an upstream proxy stripped them.
	if strings.ToLower(r.Header.Get("Upgrade")) != "websocket" &&
		r.Header.Get("Sec-WebSocket-Key") != "" {
		r.Header.Set("Upgrade", "websocket")
	}
	if !strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade") &&
		r.Header.Get("Sec-WebSocket-Key") != "" {
		r.Header.Set("Connection", "Upgrade")
	}

	backendURL := buildBackendWebSocketURL(destURL, r.URL)

	// Create dialer with proper timeouts
	dialer := websocket.Dialer{
		HandshakeTimeout: 45 * time.Second,
		Proxy:            http.ProxyFromEnvironment,
	}
	if wsOpts != nil {
		if wsOpts.HandshakeTimeout > 0 {
			dialer.HandshakeTimeout = wsOpts.HandshakeTimeout
		}
		dialer.EnableCompression = wsOpts.EnableCompression
	}
	if backendURL.Scheme == "wss" && wsOpts != nil && wsOpts.InsecureSkipVerify {
		dialer.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}

	// Prepare request headers - exclude WebSocket specific headers
	requestHeader := http.Header{}
	for k, vv := range r.Header {
		lowerKey := strings.ToLower(k)
		// Skip WebSocket specific headers and hop-by-hop headers
		switch lowerKey {
		case "upgrade", "connection", "sec-websocket-key",
			"sec-websocket-version", "sec-websocket-extensions",
			"sec-websocket-protocol":
			continue
		default:
			requestHeader[k] = vv
		}
	}

	applyUpstreamHeaders(r, requestHeader, route, wsOpts)

	logger.Debug("Dialing backend WebSocket",
		logging.String("url", backendURL.String()),
		logging.Any("headers", requestHeader))

	// Connect to backend
	backendConn, resp, err := dialer.Dial(backendURL.String(), requestHeader)
	if err != nil {
		logger.Error("Failed to dial backend WebSocket", err,
			logging.String("url", backendURL.String()))

		if resp != nil {
			logger.Debug("Backend response",
				logging.Int("status", resp.StatusCode),
				logging.Any("headers", resp.Header))
			// Copy headers from backend response
			for k, vv := range resp.Header {
				for _, v := range vv {
					w.Header().Add(k, v)
				}
			}
			w.WriteHeader(resp.StatusCode)
			io.Copy(w, resp.Body)
		} else {
			http.Error(w, "Unable to connect to backend", http.StatusBadGateway)
		}
		return
	}
	defer backendConn.Close()

	// Upgrade client connection
	upgrader := websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool { return true }, // Allow all origins
	}

	clientConn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		logger.Error("Failed to upgrade client connection", err)
		return
	}
	defer clientConn.Close()

	// Start proxying
	errClient := make(chan error, 1)
	errBackend := make(chan error, 1)

	replicate := func(dst, src *websocket.Conn, errc chan error) {
		for {
			msgType, msg, err := src.ReadMessage()
			if err != nil {
				if websocket.IsUnexpectedCloseError(err,
					websocket.CloseNormalClosure,
					websocket.CloseGoingAway,
					websocket.CloseNoStatusReceived) {
					logger.Debug("WebSocket close error", logging.Error(err))
				}
				errc <- err
				return
			}
			err = dst.WriteMessage(msgType, msg)
			if err != nil {
				errc <- err
				return
			}
		}
	}

	go replicate(clientConn, backendConn, errClient)
	go replicate(backendConn, clientConn, errBackend)

	// Wait for either connection to close
	select {
	case err = <-errClient:
		logger.Debug("Client to backend connection closed", logging.Error(err))
	case err = <-errBackend:
		logger.Debug("Backend to client connection closed", logging.Error(err))
	}
}

func buildBackendWebSocketURL(destURL, requestURL *url.URL) url.URL {
	backendScheme := "ws"
	if destURL != nil && (destURL.Scheme == "https" || destURL.Scheme == "wss") {
		backendScheme = "wss"
	}

	path := "/"
	if destURL != nil && strings.TrimSpace(destURL.Path) != "" {
		path = destURL.Path
	} else if requestURL != nil && strings.TrimSpace(requestURL.Path) != "" {
		path = requestURL.Path
	}

	rawQuery := ""
	if requestURL != nil {
		rawQuery = requestURL.RawQuery
	}

	host := ""
	if destURL != nil {
		host = destURL.Host
	}

	return url.URL{
		Scheme:   backendScheme,
		Host:     host,
		Path:     path,
		RawQuery: rawQuery,
	}
}

// copyHeader copies headers from src to dst
func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

// websocketDial dials the backend WebSocket server
func websocketDial(r *http.Request, backendAddr string) (net.Conn, error) {
	// For production, consider using gorilla/websocket or nhooyr.io/websocket for full support
	u, err := url.Parse(backendAddr)
	if err != nil {
		return nil, err
	}
	return net.Dial("tcp", u.Host)
}

// copyWebSocketData relays data between two connections
func copyWebSocketData(dst net.Conn, src net.Conn, errc chan error) {
	buf := make([]byte, 4096)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			// Debug log: data read from src
			fmt.Printf("[copyWebSocketData] Read %d bytes from %T\n", n, src)
			written, werr := dst.Write(buf[:n])
			fmt.Printf("[copyWebSocketData] Wrote %d bytes to %T\n", written, dst)
			if werr != nil {
				errc <- werr
				return
			}
		}
		if err != nil {
			if err != io.EOF {
				fmt.Printf("[copyWebSocketData] Error: %v\n", err)
			}
			errc <- err
			return
		}
	}
}

// findWildcardIndex returns the index of the first wildcard ("{") in the path, or -1 if not found
func findWildcardIndex(path string) int {
	for i := 0; i < len(path); i++ {
		if path[i] == '{' {
			return i
		}
	}
	return -1
}

// responseWriter wraps http.ResponseWriter to capture status code
type responseWriter struct {
	http.ResponseWriter
	statusCode int
	length     int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

func (rw *responseWriter) Write(b []byte) (int, error) {
	n, err := rw.ResponseWriter.Write(b)
	rw.length += n
	return n, err
}

func (rw *responseWriter) Flush() {
	if flusher, ok := rw.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

// Add Hijack support for WebSocket proxying
func (rw *responseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if hj, ok := rw.ResponseWriter.(http.Hijacker); ok {
		return hj.Hijack()
	}
	return nil, nil, fmt.Errorf("underlying ResponseWriter does not support hijacking")
}

// jwtAuthMiddleware enforces JWT authentication
func (g *Gateway) jwtAuthMiddleware(cfg config.JWTConfig) func(http.Handler) http.Handler {
	var pubKey *rsa.PublicKey
	var useRS256 bool
	if cfg.Enabled && contains(cfg.Algorithms, "RS256") && cfg.PublicKeyFile != "" {
		k, err := loadRSAPublicKey(cfg.PublicKeyFile)
		if err == nil {
			pubKey = k
			useRS256 = true
		} else {
			g.logger.Warn("Failed to load RS256 public key", logging.Error(err))
		}
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Get client IP
			clientIP := GetClientIP(r)
			// Per-route override: if route disables JWT, skip
			if route, ok := g.matchRoute(r); ok {
				if !route.RequireJwt {
					next.ServeHTTP(w, r)
					return
				}
			}
			if !cfg.Enabled {
				next.ServeHTTP(w, r)
				return
			}
			auth := r.Header.Get("Authorization")
			if !strings.HasPrefix(auth, "Bearer ") {
				g.logger.Warn("401 Unauthorized",
					logging.String("reason", "Missing or invalid JWT"),
					logging.String("method", r.Method),
					logging.String("path", r.URL.Path),
					logging.String("remote_addr", r.RemoteAddr),
					logging.String("client_ip", clientIP),
				)
				w.WriteHeader(http.StatusUnauthorized)
				w.Write([]byte("Missing or invalid JWT"))
				return
			}
			tokenStr := strings.TrimPrefix(auth, "Bearer ")
			var token *jwt.Token
			var err error
			if useRS256 && pubKey != nil {
				token, err = jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
					if token.Method.Alg() != "RS256" {
						return nil, errors.New("unexpected signing method")
					}
					return pubKey, nil
				})
			} else {
				token, err = jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
					if token.Method.Alg() != "HS256" {
						return nil, errors.New("unexpected signing method")
					}
					return []byte(cfg.Secret), nil
				})
			}
			if err != nil || !token.Valid {
				g.logger.Warn("401 Unauthorized",
					logging.String("reason", "Invalid JWT"),
					logging.String("method", r.Method),
					logging.String("path", r.URL.Path),
					logging.String("remote_addr", r.RemoteAddr),
					logging.String("client_ip", clientIP),
				)
				w.WriteHeader(http.StatusUnauthorized)
				w.Write([]byte("Invalid JWT"))
				return
			}
			if claims, ok := token.Claims.(jwt.MapClaims); ok {
				ctx := context.WithValue(r.Context(), jwtClaimsKey, claims)
				r = r.WithContext(ctx)
			}
			next.ServeHTTP(w, r)
		})
	}
}

func contains(arr []string, s string) bool {
	for _, v := range arr {
		if v == s {
			return true
		}
	}
	return false
}

// matchRoute finds the route config for the current request
func (g *Gateway) matchRoute(r *http.Request) (config.RouterConfig, bool) {
	if route, ok := GetMatchedRoute(r); ok {
		return route, true
	}
	match := ResolveRouteMatch(g.config.GetAllRoutesFromServices(g.logger), r.Method, r.URL.Path, r.Header, rolloutBucketKey(r))
	if match.Matched {
		return match.Route, true
	}
	return config.RouterConfig{}, false
}

func ensureRequestID(r *http.Request) string {
	if requestID := r.Header.Get("X-Request-Id"); requestID != "" {
		return requestID
	}
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err == nil {
		requestID := hex.EncodeToString(buf)
		r.Header.Set("X-Request-Id", requestID)
		return requestID
	}
	requestID := fmt.Sprintf("%d", time.Now().UnixNano())
	r.Header.Set("X-Request-Id", requestID)
	return requestID
}

func normalizeForwardedHeaders(r *http.Request) {
	normalizeForwardedHeaderMap(r, r.Header)
}

func applyUpstreamHeaders(
	r *http.Request,
	headers http.Header,
	route config.RouterConfig,
	wsOpts *config.WebSocketOptions,
) {
	normalizeForwardedHeaderMap(r, headers)

	if realm := GetTenantRealm(r); realm != "" && headers.Get("X-Realm") == "" {
		headers.Set("X-Realm", realm)
	}
	if !routeTransformsEnabled(r, route, "request_headers") {
		applyRequestHeaderRedactions(headers, route)
		if wsOpts == nil {
			return
		}
		for key, value := range wsOpts.InjectHeaders {
			if strings.TrimSpace(key) == "" {
				continue
			}
			headers.Set(key, value)
		}
		return
	}

	for key, value := range route.Headers {
		if strings.TrimSpace(key) == "" {
			continue
		}
		headers.Set(key, resolveTransformTemplate(r, value))
	}

	for key, value := range route.RequestHeaders {
		if strings.TrimSpace(key) == "" {
			continue
		}
		headers.Set(key, resolveTransformTemplate(r, value))
	}
	for _, key := range route.RemoveRequestHeaders {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		headers.Del(key)
	}
	applyRequestHeaderRedactions(headers, route)

	if wsOpts == nil {
		return
	}
	for key, value := range wsOpts.InjectHeaders {
		if strings.TrimSpace(key) == "" {
			continue
		}
		headers.Set(key, value)
	}
}

func applyQueryTransforms(r *http.Request, route config.RouterConfig) {
	if r == nil || r.URL == nil {
		return
	}
	if !routeTransformsEnabled(r, route, "query") {
		return
	}

	query := r.URL.Query()
	for key, value := range route.QueryParams {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		query.Set(key, resolveTransformTemplate(r, value))
	}
	for _, key := range route.RemoveQueryParams {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		query.Del(key)
	}
	r.URL.RawQuery = query.Encode()
}

func applyDownstreamHeaders(headers http.Header, route config.RouterConfig, r *http.Request, statusCode int, upstreamHeaders http.Header) {
	if !responseTransformsEnabled(r, route, "response_headers", statusCode, upstreamHeaders) {
		return
	}
	ctx := &responseTemplateContext{headers: upstreamHeaders, statusCode: statusCode}
	for key, value := range route.ResponseHeaders {
		if strings.TrimSpace(key) == "" {
			continue
		}
		headers.Set(key, resolveTransformTemplateWithResponseContext(r, ctx, value))
	}
	for _, key := range route.RemoveResponseHeaders {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		headers.Del(key)
	}
	applyResponseHeaderRedactions(headers, route)
}

func applySuccessResponseEnvelope(resp *http.Response, route config.RouterConfig, upstreamHeaders http.Header) (bool, error) {
	if resp == nil || resp.Body == nil || resp.StatusCode < 200 || resp.StatusCode >= 400 {
		return false, nil
	}
	if len(route.SuccessResponseFields) == 0 {
		return false, nil
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return true, err
	}
	if err := resp.Body.Close(); err != nil {
		return true, err
	}

	ctx := &responseTemplateContext{
		headers:    upstreamHeaders,
		statusCode: resp.StatusCode,
		body:       string(bodyBytes),
	}
	payload := make(map[string]interface{})
	for key, value := range route.SuccessResponseFields {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		resolvedValue, err := resolveJSONTransformValue(resp.Request, ctx, value)
		if err != nil {
			return true, err
		}
		setNestedJSONField(payload, key, resolvedValue)
	}
	applyResponseJSONRedactions(payload, route)

	updatedBody, err := json.Marshal(payload)
	if err != nil {
		return true, err
	}
	resp.Body = io.NopCloser(bytes.NewReader(updatedBody))
	resp.ContentLength = int64(len(updatedBody))
	resp.Header.Set("Content-Length", fmt.Sprintf("%d", len(updatedBody)))
	resp.Header.Set("Content-Type", "application/json")
	return true, nil
}

func applyErrorResponseEnvelope(resp *http.Response, route config.RouterConfig, upstreamHeaders http.Header) (bool, error) {
	if resp == nil || resp.Body == nil || resp.StatusCode < http.StatusBadRequest {
		return false, nil
	}
	if len(route.ErrorResponseFields) == 0 {
		return false, nil
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return true, err
	}
	if err := resp.Body.Close(); err != nil {
		return true, err
	}

	ctx := &responseTemplateContext{
		headers:    upstreamHeaders,
		statusCode: resp.StatusCode,
		body:       string(bodyBytes),
	}
	payload := make(map[string]interface{})
	for key, value := range route.ErrorResponseFields {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		resolvedValue, err := resolveJSONTransformValue(resp.Request, ctx, value)
		if err != nil {
			return true, err
		}
		setNestedJSONField(payload, key, resolvedValue)
	}
	applyResponseJSONRedactions(payload, route)

	updatedBody, err := json.Marshal(payload)
	if err != nil {
		return true, err
	}
	resp.Body = io.NopCloser(bytes.NewReader(updatedBody))
	resp.ContentLength = int64(len(updatedBody))
	resp.Header.Set("Content-Length", fmt.Sprintf("%d", len(updatedBody)))
	resp.Header.Set("Content-Type", "application/json")
	return true, nil
}

func applyResponseJSONTransforms(resp *http.Response, route config.RouterConfig, upstreamHeaders http.Header) error {
	if resp == nil || resp.Body == nil {
		return nil
	}
	if !responseTransformsEnabled(resp.Request, route, "response_json", resp.StatusCode, upstreamHeaders) {
		return nil
	}
	if len(route.ResponseJSONFields) == 0 && len(route.RemoveResponseJSONFields) == 0 {
		return nil
	}
	contentType := strings.ToLower(strings.TrimSpace(resp.Header.Get("Content-Type")))
	if contentType != "" && !strings.Contains(contentType, "application/json") && !strings.Contains(contentType, "+json") {
		return nil
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if err := resp.Body.Close(); err != nil {
		return err
	}
	if len(bytes.TrimSpace(bodyBytes)) == 0 {
		resp.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		return nil
	}

	ctx := &responseTemplateContext{
		headers:    upstreamHeaders,
		statusCode: resp.StatusCode,
		body:       string(bodyBytes),
	}

	var payload map[string]interface{}
	if err := json.Unmarshal(bodyBytes, &payload); err != nil {
		resp.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		resp.ContentLength = int64(len(bodyBytes))
		resp.Header.Set("Content-Length", fmt.Sprintf("%d", len(bodyBytes)))
		return nil
	}

	for key, value := range route.ResponseJSONFields {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		resolvedValue, err := resolveJSONTransformValue(resp.Request, ctx, value)
		if err != nil {
			return err
		}
		setNestedJSONField(payload, key, resolvedValue)
	}
	for _, key := range route.RemoveResponseJSONFields {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		deleteNestedJSONField(payload, key)
	}
	applyResponseJSONRedactions(payload, route)

	updatedBody, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	resp.Body = io.NopCloser(bytes.NewReader(updatedBody))
	resp.ContentLength = int64(len(updatedBody))
	resp.Header.Set("Content-Length", fmt.Sprintf("%d", len(updatedBody)))
	return nil
}

func applyResponseBodyPatterns(g *Gateway, resp *http.Response, route config.RouterConfig) (bool, error) {
	if resp == nil || resp.Body == nil || (len(route.ResponseBodyBlockRegex) == 0 && len(route.ResponseBodyRequireRegex) == 0 && len(route.ResponsePIIBlockTypes) == 0) {
		return false, nil
	}
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return true, err
	}
	if err := resp.Body.Close(); err != nil {
		return true, err
	}
	body := string(bodyBytes)
	for _, pattern := range append([]string{}, route.ResponseBodyBlockRegex...) {
		matched, err := regexp.MatchString(pattern, body)
		if err != nil {
			return true, err
		}
		if matched {
			replaceResponseWithPolicyError(g, route, resp, http.StatusBadGateway, "Blocked Response", "Response body blocked by content policy", "response_content_policy")
			return true, nil
		}
	}
	for _, pattern := range piiPatternsForTypes(route.ResponsePIIBlockTypes) {
		matched, err := regexp.MatchString(pattern, body)
		if err != nil {
			return true, err
		}
		if matched {
			replaceResponseWithPolicyError(g, route, resp, http.StatusBadGateway, "Blocked Response", "Response body blocked by content policy", "response_pii_policy")
			return true, nil
		}
	}
	for _, pattern := range route.ResponseBodyRequireRegex {
		matched, err := regexp.MatchString(pattern, body)
		if err != nil {
			return true, err
		}
		if !matched {
			replaceResponseWithPolicyError(g, route, resp, http.StatusBadGateway, "Invalid Response", "Response body is missing required content policy marker", "response_content_policy")
			return true, nil
		}
	}
	resp.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	resp.ContentLength = int64(len(bodyBytes))
	resp.Header.Set("Content-Length", fmt.Sprintf("%d", len(bodyBytes)))
	return false, nil
}

func replaceResponseWithPolicyError(g *Gateway, route config.RouterConfig, resp *http.Response, statusCode int, code string, message string, reason string) {
	if resp == nil {
		return
	}
	if g != nil && strings.TrimSpace(reason) != "" {
		g.RecordPolicyHit(route, reason)
	}
	payload := map[string]string{
		"error":   code,
		"message": message,
	}
	bodyBytes, _ := json.Marshal(payload)
	resp.StatusCode = statusCode
	resp.Status = fmt.Sprintf("%d %s", statusCode, http.StatusText(statusCode))
	resp.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	resp.ContentLength = int64(len(bodyBytes))
	resp.Header.Set("Content-Length", fmt.Sprintf("%d", len(bodyBytes)))
	resp.Header.Set("Content-Type", "application/json")
	if strings.TrimSpace(reason) != "" {
		resp.Header.Set(policyHitHeader, reason)
	}
}

func writePolicyError(g *Gateway, route config.RouterConfig, w http.ResponseWriter, statusCode int, reason string, message string) {
	if w == nil {
		return
	}
	if g != nil && strings.TrimSpace(reason) != "" {
		g.RecordPolicyHit(route, reason)
	}
	if strings.TrimSpace(reason) != "" {
		w.Header().Set(policyHitHeader, reason)
	}
	http.Error(w, message, statusCode)
}

func policyReasonForRequestError(err error, fallback string) string {
	if err == nil {
		return fallback
	}
	message := strings.ToLower(err.Error())
	switch {
	case strings.Contains(message, "input token"):
		return "input_token_budget"
	case strings.Contains(message, "output token"):
		return "output_token_budget"
	case strings.Contains(message, "message count"):
		return "message_count_budget"
	case strings.Contains(message, "tool call count"):
		return "tool_call_budget"
	case strings.Contains(message, "required content policy marker"):
		return fallback
	case strings.Contains(message, "blocked by content policy"):
		if fallback == "request_content_policy" {
			return "request_content_policy"
		}
		return fallback
	default:
		return fallback
	}
}

func piiPatternsForTypes(types []string) []string {
	patterns := make([]string, 0, len(types))
	for _, value := range types {
		switch strings.ToLower(strings.TrimSpace(value)) {
		case "email":
			patterns = append(patterns, `(?i)\b[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}\b`)
		case "phone":
			patterns = append(patterns, `(?i)\b(?:\+?\d[\d\-\s().]{7,}\d)\b`)
		case "api_key":
			patterns = append(patterns, `(?i)\b(?:sk|pk|rk)_[a-z0-9]{8,}\b`)
		case "card":
			patterns = append(patterns, `\b(?:\d[ -]*?){13,19}\b`)
		}
	}
	return patterns
}

func responseRedactionValue(route config.RouterConfig) string {
	if strings.TrimSpace(route.RedactionValue) != "" {
		return route.RedactionValue
	}
	return "[REDACTED]"
}

func applyResponseHeaderRedactions(headers http.Header, route config.RouterConfig) {
	if headers == nil {
		return
	}
	replacement := responseRedactionValue(route)
	for _, key := range route.ResponseRedactHeaders {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		if _, exists := headers[key]; exists {
			headers.Set(key, replacement)
		}
	}
}

func applyRequestHeaderRedactions(headers http.Header, route config.RouterConfig) {
	if headers == nil {
		return
	}
	replacement := responseRedactionValue(route)
	for _, key := range route.RequestRedactHeaders {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		if _, exists := headers[key]; exists {
			headers.Set(key, replacement)
		}
	}
}

func applyResponseJSONRedactions(payload map[string]interface{}, route config.RouterConfig) {
	if payload == nil {
		return
	}
	replacement := responseRedactionValue(route)
	for _, key := range route.ResponseRedactJSONFields {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		redactNestedJSONField(payload, key, replacement)
	}
}

func applyRequestJSONRedactions(payload map[string]interface{}, route config.RouterConfig) {
	if payload == nil {
		return
	}
	replacement := responseRedactionValue(route)
	for _, key := range route.RequestRedactJSONFields {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		redactNestedJSONField(payload, key, replacement)
	}
}

func applyRequestJSONTransforms(req *http.Request, route config.RouterConfig) error {
	if req == nil || req.Body == nil {
		return nil
	}
	if !routeTransformsEnabled(req, route, "request_json") {
		return nil
	}
	if len(route.RequestJSONFields) == 0 && len(route.RemoveRequestJSONFields) == 0 && len(route.RequestRedactJSONFields) == 0 {
		return nil
	}
	contentType := strings.ToLower(strings.TrimSpace(req.Header.Get("Content-Type")))
	if contentType != "" && !strings.Contains(contentType, "application/json") && !strings.Contains(contentType, "+json") {
		return nil
	}

	bodyBytes, err := cloneRequestBody(req)
	if err != nil {
		return err
	}
	if len(bytes.TrimSpace(bodyBytes)) == 0 {
		return nil
	}

	var payload map[string]interface{}
	if err := json.Unmarshal(bodyBytes, &payload); err != nil {
		req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		req.ContentLength = int64(len(bodyBytes))
		req.GetBody = func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(bodyBytes)), nil
		}
		return nil
	}

	for key, value := range route.RequestJSONFields {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		resolvedValue, err := resolveJSONTransformValue(req, nil, value)
		if err != nil {
			return err
		}
		setNestedJSONField(payload, key, resolvedValue)
	}
	for _, key := range route.RemoveRequestJSONFields {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		deleteNestedJSONField(payload, key)
	}
	applyRequestJSONRedactions(payload, route)

	updatedBody, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req.Body = io.NopCloser(bytes.NewReader(updatedBody))
	req.ContentLength = int64(len(updatedBody))
	req.Header.Set("Content-Length", fmt.Sprintf("%d", len(updatedBody)))
	req.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(updatedBody)), nil
	}
	return nil
}

func routeHasTransformConditions(route config.RouterConfig) bool {
	return len(route.TransformWhenHeaders) > 0 ||
		len(route.TransformWhenQueryParams) > 0 ||
		len(route.TransformWhenHeaderRegex) > 0 ||
		len(route.TransformWhenQueryRegex) > 0
}

func routeScopeIsGated(route config.RouterConfig, scope string) bool {
	if !routeHasTransformConditions(route) {
		return false
	}
	if len(route.TransformScopes) == 0 {
		return true
	}
	for _, candidate := range route.TransformScopes {
		if strings.EqualFold(strings.TrimSpace(candidate), scope) {
			return true
		}
	}
	return false
}

func routeTransformsEnabled(r *http.Request, route config.RouterConfig, scope string) bool {
	if !routeHasTransformConditions(route) {
		if len(route.TransformMethods) == 0 {
			return true
		}
		if r == nil {
			return false
		}
		return routeTransformMethodMatches(r.Method, route)
	}
	if r == nil {
		return false
	}
	if !routeTransformMethodMatches(r.Method, route) {
		return false
	}
	if !routeScopeIsGated(route, scope) {
		return true
	}
	for key, expected := range route.TransformWhenHeaders {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		if r.Header.Get(key) != expected {
			return false
		}
	}
	for key, pattern := range route.TransformWhenHeaderRegex {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		matched, err := regexp.MatchString(pattern, r.Header.Get(key))
		if err != nil || !matched {
			return false
		}
	}
	if r.URL != nil {
		query := r.URL.Query()
		for key, expected := range route.TransformWhenQueryParams {
			key = strings.TrimSpace(key)
			if key == "" {
				continue
			}
			if query.Get(key) != expected {
				return false
			}
		}
		for key, pattern := range route.TransformWhenQueryRegex {
			key = strings.TrimSpace(key)
			if key == "" {
				continue
			}
			matched, err := regexp.MatchString(pattern, query.Get(key))
			if err != nil || !matched {
				return false
			}
		}
	}
	return true
}

func routeTransformMethodMatches(method string, route config.RouterConfig) bool {
	if len(route.TransformMethods) == 0 {
		return true
	}
	method = strings.ToUpper(strings.TrimSpace(method))
	for _, candidate := range route.TransformMethods {
		if strings.ToUpper(strings.TrimSpace(candidate)) == method {
			return true
		}
	}
	return false
}

func responseTransformStatusMatches(route config.RouterConfig, statusCode int) bool {
	if statusCode <= 0 {
		return true
	}
	if len(route.ResponseTransformStatusCodes) == 0 && len(route.ResponseTransformStatusClasses) == 0 {
		return true
	}
	for _, allowed := range route.ResponseTransformStatusCodes {
		if allowed == statusCode {
			return true
		}
	}
	statusClass := fmt.Sprintf("%dxx", statusCode/100)
	for _, allowedClass := range route.ResponseTransformStatusClasses {
		if strings.EqualFold(strings.TrimSpace(allowedClass), statusClass) {
			return true
		}
	}
	return false
}

func responseTransformHeadersMatch(route config.RouterConfig, headers http.Header) bool {
	if len(route.ResponseTransformWhenHeaders) == 0 && len(route.ResponseTransformHeaderRegex) == 0 {
		return true
	}
	if headers == nil {
		return false
	}
	for key, expected := range route.ResponseTransformWhenHeaders {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		if headers.Get(key) != expected {
			return false
		}
	}
	for key, pattern := range route.ResponseTransformHeaderRegex {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		matched, err := regexp.MatchString(pattern, headers.Get(key))
		if err != nil || !matched {
			return false
		}
	}
	return true
}

func responseTransformsEnabled(r *http.Request, route config.RouterConfig, scope string, statusCode int, headers http.Header) bool {
	if !routeTransformsEnabled(r, route, scope) {
		return false
	}
	if !responseTransformStatusMatches(route, statusCode) {
		return false
	}
	return responseTransformHeadersMatch(route, headers)
}

func resolveJSONTransformValue(r *http.Request, responseCtx *responseTemplateContext, value string) (interface{}, error) {
	resolved := resolveTransformTemplateWithResponseContext(r, responseCtx, value)
	trimmed := strings.TrimSpace(resolved)
	if !strings.HasPrefix(trimmed, "json:") {
		return resolved, nil
	}
	literal := strings.TrimSpace(strings.TrimPrefix(trimmed, "json:"))
	if literal == "" {
		return nil, fmt.Errorf("json: transform values must contain valid JSON")
	}
	var parsed interface{}
	if err := json.Unmarshal([]byte(literal), &parsed); err != nil {
		return nil, fmt.Errorf("json: transform values must contain valid JSON")
	}
	return parsed, nil
}

func setNestedJSONField(payload map[string]interface{}, path string, value interface{}) {
	segments := parseJSONFieldPath(path)
	if len(segments) == 0 {
		return
	}
	current := payload
	for _, segment := range segments[:len(segments)-1] {
		if !segment.hasArray() {
			next, exists := current[segment.key]
			if !exists {
				child := make(map[string]interface{})
				current[segment.key] = child
				current = child
				continue
			}
			child, ok := next.(map[string]interface{})
			if !ok {
				child = make(map[string]interface{})
				current[segment.key] = child
			}
			current = child
			continue
		}

		array := ensureJSONArray(current, segment.key)
		var child map[string]interface{}
		if segment.append {
			child = make(map[string]interface{})
			array = append(array, child)
		} else {
			array = ensureJSONArrayIndex(array, segment.index)
			existing, ok := array[segment.index].(map[string]interface{})
			if !ok {
				existing = make(map[string]interface{})
			}
			array[segment.index] = existing
			child = existing
		}
		current[segment.key] = array
		current = child
	}

	last := segments[len(segments)-1]
	if !last.hasArray() {
		current[last.key] = value
		return
	}
	array := ensureJSONArray(current, last.key)
	if last.append {
		array = append(array, value)
	} else {
		array = ensureJSONArrayIndex(array, last.index)
		array[last.index] = value
	}
	current[last.key] = array
}

func deleteNestedJSONField(payload map[string]interface{}, path string) {
	segments := parseJSONFieldPath(path)
	if len(segments) == 0 {
		return
	}
	current := payload
	for _, segment := range segments[:len(segments)-1] {
		next, ok := current[segment.key]
		if !ok {
			return
		}
		if !segment.hasArray() {
			child, ok := next.(map[string]interface{})
			if !ok {
				return
			}
			current = child
			continue
		}
		array, ok := next.([]interface{})
		if !ok || segment.index < 0 || segment.index >= len(array) {
			return
		}
		child, ok := array[segment.index].(map[string]interface{})
		if !ok {
			return
		}
		current = child
	}
	last := segments[len(segments)-1]
	if !last.hasArray() {
		delete(current, last.key)
		return
	}
	next, ok := current[last.key]
	if !ok {
		return
	}
	array, ok := next.([]interface{})
	if !ok || last.index < 0 || last.index >= len(array) {
		return
	}
	array = append(array[:last.index], array[last.index+1:]...)
	current[last.key] = array
}

func redactNestedJSONField(payload map[string]interface{}, path string, replacement string) {
	segments := parseJSONFieldPath(path)
	if len(segments) == 0 {
		return
	}
	current := payload
	for _, segment := range segments[:len(segments)-1] {
		next, ok := current[segment.key]
		if !ok {
			return
		}
		if !segment.hasArray() {
			child, ok := next.(map[string]interface{})
			if !ok {
				return
			}
			current = child
			continue
		}
		array, ok := next.([]interface{})
		if !ok || segment.index < 0 || segment.index >= len(array) {
			return
		}
		child, ok := array[segment.index].(map[string]interface{})
		if !ok {
			return
		}
		current = child
	}
	last := segments[len(segments)-1]
	if !last.hasArray() {
		if _, ok := current[last.key]; ok {
			current[last.key] = replacement
		}
		return
	}
	next, ok := current[last.key]
	if !ok {
		return
	}
	array, ok := next.([]interface{})
	if !ok || last.index < 0 || last.index >= len(array) {
		return
	}
	array[last.index] = replacement
	current[last.key] = array
}

func nestedJSONStringValue(payload map[string]interface{}, path string) (string, bool) {
	segments := parseJSONFieldPath(path)
	if len(segments) == 0 {
		return "", false
	}
	var current interface{} = payload
	for _, segment := range segments {
		obj, ok := current.(map[string]interface{})
		if !ok {
			return "", false
		}
		next, ok := obj[segment.key]
		if !ok {
			return "", false
		}
		if !segment.hasArray() {
			current = next
			continue
		}
		array, ok := next.([]interface{})
		if !ok || segment.append || segment.index < 0 || segment.index >= len(array) {
			return "", false
		}
		current = array[segment.index]
	}
	value, ok := current.(string)
	return value, ok
}

func nestedJSONStringValues(payload map[string]interface{}, path string) []string {
	segments := parseJSONFieldPath(path)
	if len(segments) == 0 {
		return nil
	}
	return collectNestedJSONStringValues(payload, segments)
}

func lookupJSONFieldStringValue(payload map[string]interface{}, path string) string {
	values := nestedJSONStringValues(payload, path)
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

func nestedJSONIntValue(payload map[string]interface{}, path string) (int, bool) {
	segments := parseJSONFieldPath(path)
	if len(segments) == 0 {
		return 0, false
	}
	var current interface{} = payload
	for _, segment := range segments {
		obj, ok := current.(map[string]interface{})
		if !ok {
			return 0, false
		}
		next, ok := obj[segment.key]
		if !ok {
			return 0, false
		}
		if !segment.hasArray() {
			current = next
			continue
		}
		array, ok := next.([]interface{})
		if !ok || segment.append || segment.index < 0 || segment.index >= len(array) {
			return 0, false
		}
		current = array[segment.index]
	}
	switch v := current.(type) {
	case float64:
		return int(v), true
	case int:
		return v, true
	case int64:
		return int(v), true
	case json.Number:
		n, err := v.Int64()
		if err != nil {
			return 0, false
		}
		return int(n), true
	default:
		return 0, false
	}
}

func nestedJSONArrayLength(payload map[string]interface{}, path string) (int, bool) {
	segments := parseJSONFieldPath(path)
	if len(segments) == 0 {
		return 0, false
	}
	var current interface{} = payload
	for _, segment := range segments {
		obj, ok := current.(map[string]interface{})
		if !ok {
			return 0, false
		}
		next, ok := obj[segment.key]
		if !ok {
			return 0, false
		}
		if !segment.hasArray() {
			current = next
			continue
		}
		array, ok := next.([]interface{})
		if !ok || segment.append || segment.index < 0 || segment.index >= len(array) {
			return 0, false
		}
		current = array[segment.index]
	}
	array, ok := current.([]interface{})
	if !ok {
		return 0, false
	}
	return len(array), true
}

func collectNestedJSONStringValues(current interface{}, segments []jsonPathSegment) []string {
	if len(segments) == 0 {
		value, ok := current.(string)
		if !ok || strings.TrimSpace(value) == "" {
			return nil
		}
		return []string{value}
	}
	obj, ok := current.(map[string]interface{})
	if !ok {
		return nil
	}
	segment := segments[0]
	next, ok := obj[segment.key]
	if !ok {
		return nil
	}
	if !segment.hasArray() {
		return collectNestedJSONStringValues(next, segments[1:])
	}
	array, ok := next.([]interface{})
	if !ok {
		return nil
	}
	if segment.append {
		values := make([]string, 0, len(array))
		for _, item := range array {
			values = append(values, collectNestedJSONStringValues(item, segments[1:])...)
		}
		return values
	}
	if segment.index < 0 || segment.index >= len(array) {
		return nil
	}
	return collectNestedJSONStringValues(array[segment.index], segments[1:])
}

type jsonPathSegment struct {
	key    string
	index  int
	append bool
}

func (s jsonPathSegment) hasArray() bool {
	return s.append || s.index >= 0
}

func parseJSONFieldPath(path string) []jsonPathSegment {
	rawParts := strings.Split(strings.TrimSpace(path), ".")
	segments := make([]jsonPathSegment, 0, len(rawParts))
	for _, raw := range rawParts {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		segment := jsonPathSegment{key: raw, index: -1}
		if strings.HasSuffix(raw, "[]") {
			segment.key = strings.TrimSpace(strings.TrimSuffix(raw, "[]"))
			segment.append = true
			segments = append(segments, segment)
			continue
		}
		if open := strings.Index(raw, "["); open >= 0 && strings.HasSuffix(raw, "]") {
			segment.key = strings.TrimSpace(raw[:open])
			indexValue := raw[open+1 : len(raw)-1]
			parsed, err := strconv.Atoi(indexValue)
			if err == nil {
				segment.index = parsed
			}
		}
		segments = append(segments, segment)
	}
	return segments
}

func ensureJSONArray(container map[string]interface{}, key string) []interface{} {
	if existing, ok := container[key]; ok {
		if array, ok := existing.([]interface{}); ok {
			return array
		}
	}
	return make([]interface{}, 0)
}

func ensureJSONArrayIndex(array []interface{}, index int) []interface{} {
	for len(array) <= index {
		array = append(array, nil)
	}
	return array
}

func resolveTransformTemplate(r *http.Request, value string) string {
	return resolveTransformTemplateWithResponseContext(r, nil, value)
}

func resolveTransformTemplateWithResponseContext(r *http.Request, responseCtx *responseTemplateContext, value string) string {
	if r == nil || !strings.Contains(value, "{{") {
		return value
	}
	return transformTemplateRe.ReplaceAllStringFunc(value, func(match string) string {
		sub := transformTemplateRe.FindStringSubmatch(match)
		if len(sub) < 2 {
			return match
		}
		token := strings.TrimSpace(sub[1])
		switch {
		case token == "realm":
			return GetTenantRealm(r)
		case token == "request_id":
			if requestID := GetRequestID(r); requestID != "" {
				return requestID
			}
			return r.Header.Get("X-Request-Id")
		case strings.HasPrefix(token, "query."):
			return r.URL.Query().Get(strings.TrimSpace(strings.TrimPrefix(token, "query.")))
		case strings.HasPrefix(token, "var."):
			return routeVarValue(r, strings.TrimSpace(strings.TrimPrefix(token, "var.")))
		case strings.HasPrefix(token, "header."):
			return r.Header.Get(strings.TrimSpace(strings.TrimPrefix(token, "header.")))
		case strings.HasPrefix(token, "response_header."):
			if responseCtx == nil || responseCtx.headers == nil {
				return ""
			}
			return responseCtx.headers.Get(strings.TrimSpace(strings.TrimPrefix(token, "response_header.")))
		case token == "response_status":
			if responseCtx == nil || responseCtx.statusCode <= 0 {
				return ""
			}
			return strconv.Itoa(responseCtx.statusCode)
		case token == "response_body":
			if responseCtx == nil {
				return ""
			}
			return responseCtx.body
		default:
			return ""
		}
	})
}

func routeVarValue(r *http.Request, name string) string {
	if name == "" || r == nil {
		return ""
	}
	if vars := GetRouteVars(r); vars != nil {
		return vars[name]
	}
	if vars := mux.Vars(r); vars != nil {
		return vars[name]
	}
	return ""
}

func normalizeForwardedHeaderMap(r *http.Request, headers http.Header) {
	clientIP := remotePeerIP(r)
	if clientIP == "" {
		clientIP = getIP(r)
	}

	if existing := headers.Get("X-Forwarded-For"); existing != "" {
		if clientIP != "" && !forwardedForContains(existing, clientIP) {
			headers.Set("X-Forwarded-For", existing+", "+clientIP)
		}
	} else if clientIP != "" {
		headers.Set("X-Forwarded-For", clientIP)
	}

	if r.TLS != nil {
		headers.Set("X-Forwarded-Proto", "https")
	} else {
		headers.Set("X-Forwarded-Proto", "http")
	}
	headers.Set("X-Forwarded-Host", originalRequestHost(r))
	if requestID := ensureRequestID(r); requestID != "" {
		headers.Set("X-Request-Id", requestID)
	}
}

func remotePeerIP(r *http.Request) string {
	if host, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr)); err == nil {
		return host
	}
	return strings.TrimSpace(r.RemoteAddr)
}

func forwardedForContains(existing, clientIP string) bool {
	for _, part := range strings.Split(existing, ",") {
		if strings.TrimSpace(part) == clientIP {
			return true
		}
	}
	return false
}

func originalRequestHost(r *http.Request) string {
	if forwardedHost := r.Header.Get("X-Forwarded-Host"); forwardedHost != "" {
		return forwardedHost
	}
	if r.Host != "" {
		return r.Host
	}
	return r.Header.Get("Host")
}

func routeNameForLog(r *http.Request) string {
	if route, ok := GetMatchedRoute(r); ok {
		if route.Name != "" {
			return route.Name
		}
		return route.Path
	}
	return ""
}

func serviceNameForLog(g *Gateway, r *http.Request) string {
	route, ok := GetMatchedRoute(r)
	if !ok {
		return ""
	}
	service := g.config.FindServiceForRoute(route.Path, r.Method, route.MatchHeaders)
	if service == nil {
		return route.ServiceName
	}
	return service.Name
}

// Helper to load an RSA public key from a PEM file
func loadRSAPublicKey(path string) (*rsa.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, errors.New("failed to decode PEM block containing public key")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("not an RSA public key")
	}
	return rsaPub, nil
}

// errorLoggingMiddleware logs all 4xx and 5xx responses
func (g *Gateway) errorLoggingMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			rw := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}
			next.ServeHTTP(rw, r)
			// Get client IP
			clientIP := GetClientIP(r)
			if rw.statusCode >= 400 {
				g.logger.Warn("HTTP error response",
					logging.Int("status_code", rw.statusCode),
					logging.String("method", r.Method),
					logging.String("path", r.URL.Path),
					logging.String("remote_addr", r.RemoteAddr),
					logging.String("client_ip", clientIP),
				)
			}
		})
	}
}
