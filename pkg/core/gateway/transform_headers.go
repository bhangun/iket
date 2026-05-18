package gateway

import (
	"net"
	"net/http"
	"strings"

	"github.com/bhangun/iket/pkg/config"
)

func normalizeForwardedHeaders(r *http.Request) {
	normalizeForwardedHeaderMap(r, r.Header)
}

func applyUpstreamHeaders(
	r *http.Request,
	headers http.Header,
	route config.RouterConfig,
	wsOpts *config.WebSocketOptions,
) {
	effectiveRoute := graphQLOperationRequestRoute(route, r)
	normalizeForwardedHeaderMap(r, headers)

	if realm := GetTenantRealm(r); realm != "" && headers.Get("X-Realm") == "" {
		headers.Set("X-Realm", realm)
	}
	if !routeTransformsEnabled(r, effectiveRoute, "request_headers") {
		applyRequestHeaderRedactions(headers, effectiveRoute)
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

	for key, value := range effectiveRoute.Headers {
		if strings.TrimSpace(key) == "" {
			continue
		}
		headers.Set(key, resolveTransformTemplate(r, value))
	}

	for key, value := range effectiveRoute.RequestHeaders {
		if strings.TrimSpace(key) == "" {
			continue
		}
		headers.Set(key, resolveTransformTemplate(r, value))
	}
	for _, key := range effectiveRoute.RemoveRequestHeaders {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		headers.Del(key)
	}
	applyRequestHeaderRedactions(headers, effectiveRoute)

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
	effectiveRoute := graphQLOperationRequestRoute(route, r)
	if !routeTransformsEnabled(r, effectiveRoute, "query") {
		return
	}

	query := r.URL.Query()
	for key, value := range effectiveRoute.QueryParams {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		query.Set(key, resolveTransformTemplate(r, value))
	}
	for _, key := range effectiveRoute.RemoveQueryParams {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		query.Del(key)
	}
	r.URL.RawQuery = query.Encode()
}

func applyDownstreamHeaders(headers http.Header, route config.RouterConfig, r *http.Request, statusCode int, upstreamHeaders http.Header) {
	effectiveRoute := graphQLOperationRequestRoute(route, r)
	if !responseTransformsEnabled(r, effectiveRoute, "response_headers", statusCode, upstreamHeaders) {
		return
	}
	ctx := &responseTemplateContext{headers: upstreamHeaders, statusCode: statusCode}
	for key, value := range effectiveRoute.ResponseHeaders {
		if strings.TrimSpace(key) == "" {
			continue
		}
		headers.Set(key, resolveTransformTemplateWithResponseContext(r, ctx, value))
	}
	for _, key := range effectiveRoute.RemoveResponseHeaders {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		headers.Del(key)
	}
	applyResponseHeaderRedactions(headers, effectiveRoute, effectiveRoute.ResponseRedactHeaders)
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
