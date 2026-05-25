package gateway

import (
	"context"
	"net/http"
	"time"

	"github.com/bhangun/iket/pkg/core/authcontext"
	"github.com/bhangun/iket/pkg/core/requestcontext"
	"github.com/bhangun/iket/pkg/logging"
)

func AccessLogMiddleware(g *Gateway, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rw := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}
		clientIP := getIP(r)
		ctx := withClientIP(r.Context(), clientIP)

		next.ServeHTTP(rw, r.WithContext(ctx))

		duration := time.Since(start).Seconds()
		g.logger.Info("HTTP request",
			logging.String("method", r.Method),
			logging.String("path", r.URL.Path),
			logging.String("remote_addr", r.RemoteAddr),
			logging.String("client_ip", clientIP),
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
			ctx = requestcontext.WithAttribution(ctx, requestcontext.Attribution{
				TenantRealm: match.Vars["realm"],
				ServiceName: match.Route.ServiceName,
				RouteName:   match.Route.Name,
				RoutePath:   match.Route.Path,
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

func (g *Gateway) loggingMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			wrapped := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}
			clientIP := GetClientIP(r)

			next.ServeHTTP(wrapped, r)

			duration := time.Since(start)
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

			if g.metrics != nil {
				g.metrics.RecordRequest(r.Method, r.URL.Path, wrapped.statusCode, duration.Seconds())
			}
		})
	}
}

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

func (g *Gateway) securityHeadersMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("X-Frame-Options", "DENY")
			w.Header().Set("X-XSS-Protection", "1; mode=block")
			w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
			w.Header().Del("Server")

			requestID := ensureRequestID(r)
			w.Header().Set("X-Request-Id", requestID)
			ctx := context.WithValue(r.Context(), requestIDKey, requestID)
			ctx = requestcontext.WithAttribution(ctx, requestcontext.Attribution{RequestID: requestID})

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func (g *Gateway) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if g.config.Security.EnableBasicAuth {
			user, pass, ok := r.BasicAuth()
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
				_, _ = w.Write([]byte("Missing or invalid credentials"))
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
				_, _ = w.Write([]byte("Invalid username or password"))
				return
			}
			ctx := authcontext.WithPrincipal(r.Context(), principalFromBasicIdentity("basic_auth", user))
			r = r.WithContext(ctx)
		}
		next.ServeHTTP(w, r)
	})
}

func (g *Gateway) timeoutMiddleware(timeout time.Duration) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx, cancel := context.WithTimeout(r.Context(), timeout)
			defer cancel()

			r = r.WithContext(ctx)
			done := make(chan struct{})
			go func() {
				next.ServeHTTP(w, r)
				close(done)
			}()

			select {
			case <-done:
			case <-ctx.Done():
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusRequestTimeout)
				_, _ = w.Write([]byte(`{"error":"Request timeout","message":"The request took too long to process"}`))
			}
		})
	}
}
