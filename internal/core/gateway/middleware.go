package gateway

import (
	"context"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"iket/internal/config"
	"iket/internal/logging"
)

// loggingMiddleware logs HTTP requests with structured logging
func (g *Gateway) loggingMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()

			// Create a response writer wrapper to capture status code
			wrapped := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

			// Process request
			next.ServeHTTP(wrapped, r)

			// Calculate duration
			duration := time.Since(start)

			// Log request details
			g.logger.Info("HTTP request",
				logging.String("method", r.Method),
				logging.String("path", r.URL.Path),
				logging.String("remote_addr", r.RemoteAddr),
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

			next.ServeHTTP(w, r)
		})
	}
}

// authMiddleware handles authentication for protected routes
func (g *Gateway) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if g.config.Security.EnableBasicAuth {
			user, pass, ok := r.BasicAuth()
			if !ok || user == "" || pass == "" {
				w.Header().Set("WWW-Authenticate", "Basic realm=\"Iket Gateway\"")
				w.WriteHeader(http.StatusUnauthorized)
				w.Write([]byte("Missing or invalid credentials"))
				return
			}
			if expected, ok := g.config.Security.BasicAuthUsers[user]; !ok || expected != pass {
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
		// Parse destination URL
		destURL, err := url.Parse(route.Destination)
		if err != nil {
			g.logger.Error("Failed to parse destination URL", err,
				logging.String("destination", route.Destination))
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		// Optionally strip path prefix
		origPath := r.URL.Path
		if route.StripPath {
			prefix := route.Path
			// Remove wildcards for prefix matching
			if idx := len(prefix); idx > 0 {
				if i := findWildcardIndex(prefix); i > 0 {
					prefix = prefix[:i-1] // remove slash before wildcard
				}
			}
			if prefix != "" && prefix != "/" && len(origPath) >= len(prefix) && origPath[:len(prefix)] == prefix {
				stripped := origPath[len(prefix):]
				if !strings.HasPrefix(stripped, "/") && stripped != "" {
					stripped = "/" + stripped
				}
				if stripped == "" {
					stripped = "/"
				}
				r.URL.Path = destURL.Path + stripped
			} else {
				r.URL.Path = destURL.Path
			}
		} else {
			r.URL.Path = destURL.Path + r.URL.Path
		}

		// Log the proxying action for debugging
		g.logger.Info("Proxying request", logging.String("original_path", origPath), logging.String("proxied_path", r.URL.Path), logging.String("destination", destURL.String()))

		// Create reverse proxy
		proxy := httputil.NewSingleHostReverseProxy(destURL)

		// Customize proxy behavior
		proxy.ModifyResponse = func(resp *http.Response) error {
			// Add gateway headers
			resp.Header.Set("X-Gateway", "Iket")
			resp.Header.Set("X-Gateway-Route", route.Path)
			return nil
		}

		proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
			g.logger.Error("Proxy error", err,
				logging.String("destination", route.Destination),
				logging.String("path", r.URL.Path))

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadGateway)
			w.Write([]byte(`{"error":"Bad Gateway","message":"Unable to reach the upstream service"}`))
		}

		// Update request URL
		r.URL.Host = destURL.Host
		r.URL.Scheme = destURL.Scheme
		r.Header.Set("X-Forwarded-Host", r.Header.Get("Host"))
		r.Host = destURL.Host

		// Forward the request
		proxy.ServeHTTP(w, r)
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
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

func (rw *responseWriter) Write(b []byte) (int, error) {
	return rw.ResponseWriter.Write(b)
}
