package gateway

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"time"

	"crypto/rsa"
	"errors"
	"iket/internal/config"
	"iket/internal/logging"

	"crypto/x509"
	"encoding/pem"
	"os"

	"iket/internal/core/plugin"

	"bufio"
	"fmt"

	"github.com/golang-jwt/jwt/v4"
	"github.com/gorilla/websocket"
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
				g.logger.Warn("401 Unauthorized",
					logging.String("reason", "Missing or invalid credentials"),
					logging.String("method", r.Method),
					logging.String("path", r.URL.Path),
					logging.String("remote_addr", r.RemoteAddr),
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
			// If there's a next handler in the chain, call it; otherwise, return 404
			if next := r.Context().Value("next"); next != nil {
				h := next.(http.Handler)
				h.ServeHTTP(w, r)
				return
			}
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(`{"error":"Not Found","message":"The requested resource does not exist"}`))
			return
		}

		destination := route.Destination
		// If destination starts with service://, resolve using Consul plugin
		if strings.HasPrefix(destination, "service://") {
			if p, ok := plugin.Get("consul"); ok {
				if resolver, ok := p.(interface{ ResolveService(string) (string, error) }); ok {
					addr, err := resolver.ResolveService(destination)
					if err != nil {
						g.logger.Error("Consul service resolution failed", err, logging.String("service", destination))
						http.Error(w, "Service discovery failed", http.StatusBadGateway)
						return
					}
					destination = addr
				} else {
					g.logger.Error("Consul plugin does not support ResolveService", nil)
					http.Error(w, "Service discovery not supported", http.StatusBadGateway)
					return
				}
			} else {
				g.logger.Error("Consul plugin not loaded", nil)
				http.Error(w, "Service discovery plugin not loaded", http.StatusBadGateway)
				return
			}
		}

		// Parse destination URL
		destURL, err := url.Parse(destination)
		if err != nil {
			g.logger.Error("Failed to parse destination URL", err,
				logging.String("destination", destination))
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
			g.logger.Info("Initiating WebSocket proxy",
				logging.String("path", r.URL.Path),
				logging.String("destination", destURL.String()))

			// Get WebSocket options (defaults if nil)
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

			proxyWebSocket(w, r, destURL, g.logger, wsOpts)
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

		// Forward ALL headers from the client request to the backend
		headers := http.Header{}
		for k, v := range r.Header {
			headers[k] = v
		}

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

// proxyWebSocket proxies a WebSocket connection between client and backend, with protocol-aware handling
// proxyWebSocket proxies a WebSocket connection between client and backend
func proxyWebSocket(w http.ResponseWriter, r *http.Request, destURL *url.URL, logger *logging.Logger, wsOpts *config.WebSocketOptions) {
	// Validate WebSocket upgrade request
	if !isWebSocketRequest(r) {
		logger.Warn("Request is not a WebSocket upgrade",
			logging.String("path", r.URL.Path))
		http.Error(w, "Not a WebSocket request", http.StatusBadRequest)
		return
	}

	// Determine backend scheme (ws or wss)
	backendScheme := "ws"
	if destURL.Scheme == "https" || destURL.Scheme == "wss" {
		backendScheme = "wss"
	}

	// Build backend URL
	backendURL := url.URL{
		Scheme:   backendScheme,
		Host:     destURL.Host,
		Path:     r.URL.Path,
		RawQuery: r.URL.RawQuery,
	}

	// Create dialer with proper timeouts
	dialer := websocket.Dialer{
		HandshakeTimeout: 45 * time.Second,
		Proxy:            http.ProxyFromEnvironment,
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

	// Add X-Forwarded headers
	if clientIP, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		requestHeader.Set("X-Forwarded-For", clientIP)
	}
	requestHeader.Set("X-Forwarded-Proto", "http")
	if r.TLS != nil {
		requestHeader.Set("X-Forwarded-Proto", "https")
	}
	requestHeader.Set("X-Forwarded-Host", r.Host)

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
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

func (rw *responseWriter) Write(b []byte) (int, error) {
	return rw.ResponseWriter.Write(b)
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
				)
				w.WriteHeader(http.StatusUnauthorized)
				w.Write([]byte("Invalid JWT"))
				return
			}
			if claims, ok := token.Claims.(jwt.MapClaims); ok {
				ctx := context.WithValue(r.Context(), "jwtClaims", claims)
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
	for _, route := range g.config.Routes {
		if route.Path == r.URL.Path {
			return route, true
		}
	}
	return config.RouterConfig{}, false
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
			if rw.statusCode >= 400 {
				g.logger.Warn("HTTP error response",
					logging.Int("status_code", rw.statusCode),
					logging.String("method", r.Method),
					logging.String("path", r.URL.Path),
					logging.String("remote_addr", r.RemoteAddr),
				)
			}
		})
	}
}
