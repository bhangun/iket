package gateway

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"time"

	"iket/internal/config"
	"iket/internal/logging"
)

var wsDNSRRState = make(map[string]int) // host -> next IP index
var wsDNSRRLock sync.Mutex

var wsActiveConns = struct {
	byRoute   map[string]int
	byRouteIP map[string]map[string]int
	sync.Mutex
}{byRoute: make(map[string]int), byRouteIP: make(map[string]map[string]int)}

var wsUpgradeTimestamps = struct {
	byRoute map[string][]time.Time
	sync.Mutex
}{byRoute: make(map[string][]time.Time)}

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

		// --- WebSocket proxy support ---
		if isWebSocketRequest(r) {
			g.logger.Info("WebSocket upgrade detected, proxying WebSocket connection", logging.String("path", r.URL.Path), logging.String("destination", destURL.String()))
			proxyWebSocket(w, r, destURL, g.logger, route.WebSocket)
			return
		}
		// --- End WebSocket proxy support ---

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

// isWebSocketRequest checks if the request is a WebSocket upgrade
func isWebSocketRequest(r *http.Request) bool {
	upgrade := strings.ToLower(r.Header.Get("Upgrade"))
	connection := strings.ToLower(r.Header.Get("Connection"))
	return upgrade == "websocket" && strings.Contains(connection, "upgrade")
}

// proxyWebSocket proxies a WebSocket connection between client and backend, with options
func proxyWebSocket(w http.ResponseWriter, r *http.Request, destURL *url.URL, logger *logging.Logger, wsOpts *config.WebSocketOptions) {
	// Parse options
	timeout := 30 * time.Second
	dnsRoundRobin := false
	injectHeaders := map[string]string{}
	allowedSubprotocols := []string{}
	if wsOpts != nil {
		if wsOpts.Timeout != "" {
			t, err := time.ParseDuration(wsOpts.Timeout)
			if err == nil {
				timeout = t
			}
		}
		dnsRoundRobin = wsOpts.DNSRoundRobin
		if wsOpts.InjectHeaders != nil {
			injectHeaders = wsOpts.InjectHeaders
		}
		if wsOpts.AllowedSubprotocols != nil {
			allowedSubprotocols = wsOpts.AllowedSubprotocols
		}
		// if wsOpts.BufferSize > 0 {
		// 	bufferSize = wsOpts.BufferSize
		// }
	}

	// --- Connection limits and rate limiting ---
	var maxConns, maxConnsPerIP, rateLimit int
	var routeKey, clientIP string
	if wsOpts != nil {
		maxConns = wsOpts.MaxConnections
		maxConnsPerIP = wsOpts.MaxConnectionsPerIP
		rateLimit = wsOpts.RateLimit
	}
	routeKey = r.URL.Path // could use route.Path if available
	clientIP, _, _ = net.SplitHostPort(r.RemoteAddr)
	if clientIP == "" {
		clientIP = r.RemoteAddr
	}
	wsActiveConns.Lock()
	if maxConns > 0 && wsActiveConns.byRoute[routeKey] >= maxConns {
		wsActiveConns.Unlock()
		logger.Warn("WebSocket maxConnections exceeded", logging.String("route", routeKey))
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte("WebSocket max connections exceeded"))
		return
	}
	if maxConnsPerIP > 0 {
		if wsActiveConns.byRouteIP[routeKey] == nil {
			wsActiveConns.byRouteIP[routeKey] = make(map[string]int)
		}
		if wsActiveConns.byRouteIP[routeKey][clientIP] >= maxConnsPerIP {
			wsActiveConns.Unlock()
			logger.Warn("WebSocket maxConnectionsPerIP exceeded", logging.String("route", routeKey), logging.String("ip", clientIP))
			w.WriteHeader(http.StatusTooManyRequests)
			w.Write([]byte("WebSocket max connections per IP exceeded"))
			return
		}
		wsActiveConns.byRouteIP[routeKey][clientIP]++
	}
	wsActiveConns.byRoute[routeKey]++
	wsActiveConns.Unlock()
	defer func() {
		wsActiveConns.Lock()
		wsActiveConns.byRoute[routeKey]--
		if maxConnsPerIP > 0 {
			wsActiveConns.byRouteIP[routeKey][clientIP]--
		}
		wsActiveConns.Unlock()
	}()
	if rateLimit > 0 {
		wsUpgradeTimestamps.Lock()
		times := wsUpgradeTimestamps.byRoute[routeKey]
		cutoff := time.Now().Add(-1 * time.Minute)
		var filtered []time.Time
		for _, t := range times {
			if t.After(cutoff) {
				filtered = append(filtered, t)
			}
		}
		if len(filtered) >= rateLimit {
			wsUpgradeTimestamps.Unlock()
			logger.Warn("WebSocket rate limit exceeded", logging.String("route", routeKey))
			w.WriteHeader(http.StatusTooManyRequests)
			w.Write([]byte("WebSocket upgrade rate limit exceeded"))
			return
		}
		filtered = append(filtered, time.Now())
		wsUpgradeTimestamps.byRoute[routeKey] = filtered
		wsUpgradeTimestamps.Unlock()
	}

	useTLS := destURL.Scheme == "https" || destURL.Scheme == "wss"
	backendHost := destURL.Hostname()
	backendPort := destURL.Port()
	if backendPort == "" {
		if useTLS {
			backendPort = "443"
		} else {
			backendPort = "80"
		}
	}

	backendAddr := backendHost + ":" + backendPort

	// DNS round robin with failover
	if dnsRoundRobin {
		ips, err := net.DefaultResolver.LookupIPAddr(r.Context(), backendHost)
		if err == nil && len(ips) > 0 {
			wsDNSRRLock.Lock()
			i := wsDNSRRState[backendHost] % len(ips)
			wsDNSRRState[backendHost] = (i + 1) % len(ips)
			wsDNSRRLock.Unlock()
			backendAddr = ips[i].String() + ":" + backendPort
			logger.Info("WebSocket DNS round robin", logging.String("resolved_ip", ips[i].String()), logging.String("backendAddr", backendAddr))
			// Failover: try next IP if connect fails (below)
		}
	}

	// Dial backend with failover if DNS round robin
	var backendConn net.Conn
	var err error
	if dnsRoundRobin {
		ips, _ := net.DefaultResolver.LookupIPAddr(r.Context(), backendHost)
		for j := 0; j < len(ips); j++ {
			tryAddr := ips[(wsDNSRRState[backendHost]+j)%len(ips)].String() + ":" + backendPort
			if useTLS {
				backendConn, err = tls.DialWithDialer(&net.Dialer{Timeout: timeout}, "tcp", tryAddr, &tls.Config{ServerName: backendHost})
			} else {
				backendConn, err = net.DialTimeout("tcp", tryAddr, timeout)
			}
			if err == nil {
				break
			}
			logger.Error("WebSocket DNS failover: connect failed", err, logging.String("tryAddr", tryAddr))
		}
	} else {
		if useTLS {
			backendConn, err = tls.DialWithDialer(&net.Dialer{Timeout: timeout}, "tcp", backendAddr, &tls.Config{ServerName: backendHost})
		} else {
			backendConn, err = net.DialTimeout("tcp", backendAddr, timeout)
		}
	}
	if err != nil {
		logger.Error("WebSocket backend dial failed", err, logging.String("backendAddr", backendAddr))
		w.WriteHeader(http.StatusBadGateway)
		w.Write([]byte("WebSocket backend connection failed"))
		return
	}
	defer backendConn.Close()

	// Hijack client connection
	hj, ok := w.(http.Hijacker)
	if !ok {
		logger.Error("ResponseWriter does not support hijacking for WebSocket", nil)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("WebSocket proxying not supported"))
		return
	}
	clientConn, _, err := hj.Hijack()
	if err != nil {
		logger.Error("Failed to hijack client connection for WebSocket", err)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("WebSocket proxying failed"))
		return
	}
	defer clientConn.Close()

	// Forward headers, subprotocols, and extensions
	for k, v := range injectHeaders {
		r.Header.Set(k, v)
	}
	if len(allowedSubprotocols) > 0 {
		r.Header.Set("Sec-WebSocket-Protocol", strings.Join(allowedSubprotocols, ", "))
	}
	// Forward Sec-WebSocket-Extensions (compression)
	if ext := r.Header.Get("Sec-WebSocket-Extensions"); ext != "" {
		r.Header.Set("Sec-WebSocket-Extensions", ext)
	}

	// Relay data between client and backend
	errc := make(chan error, 2)
	go copyWebSocketData(backendConn, clientConn, errc)
	go copyWebSocketData(clientConn, backendConn, errc)
	<-errc // wait for one side to close
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
	_, err := io.Copy(dst, src)
	errc <- err
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
