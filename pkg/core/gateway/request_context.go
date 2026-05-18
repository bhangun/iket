package gateway

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/bhangun/iket/pkg/config"
)

type ctxKey string

const clientIPKey ctxKey = "clientIP"
const matchedRouteKey ctxKey = "matchedRoute"
const routeVarsKey ctxKey = "routeVars"
const tenantRealmKey ctxKey = "tenantRealm"
const requestIDKey ctxKey = "requestID"
const graphQLOperationKey ctxKey = "graphqlOperationName"
const policyHitHeader = "X-Iket-Policy-Hit"

type matchedRouteContext struct {
	Route config.RouterConfig
	Vars  map[string]string
}

func getIP(r *http.Request) string {
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
		if len(parts) == 0 {
			continue
		}
		ip := strings.TrimSpace(parts[0])
		if ip != "" {
			return ip
		}
	}

	if host, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr)); err == nil {
		return host
	}
	return r.RemoteAddr
}

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

func withClientIP(ctx context.Context, clientIP string) context.Context {
	return context.WithValue(ctx, clientIPKey, clientIP)
}
