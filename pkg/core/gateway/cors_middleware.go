package gateway

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/bhangun/iket/pkg/config"
)

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
