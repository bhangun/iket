package websocket

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

type WebSocketPlugin struct {
	enabled        bool
	upstreamURL    string
	skipPaths      []string
	pingInterval   time.Duration
	pongWait       time.Duration
	writeWait      time.Duration
	maxMessageSize int64
	mu             sync.RWMutex
}

type WebSocketConfig struct {
	Headers map[string]string `json:"headers"`
	Query   map[string]string `json:"query"`
}

func (w *WebSocketPlugin) Name() string {
	return "websocket"
}

func (w *WebSocketPlugin) Type() string {
	return "websocket"
}

func (w *WebSocketPlugin) Initialize(config map[string]interface{}) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	// Default values
	w.enabled = false
	w.pingInterval = 30 * time.Second
	w.pongWait = 60 * time.Second
	w.writeWait = 10 * time.Second
	w.maxMessageSize = 512

	// Load configuration
	if enabled, ok := config["enabled"].(bool); ok {
		w.enabled = enabled
	}

	if !w.enabled {
		return nil
	}

	if upstreamURL, ok := config["upstream_url"].(string); ok {
		w.upstreamURL = upstreamURL
	}

	if skipPaths, ok := config["skip_paths"].([]interface{}); ok {
		for _, path := range skipPaths {
			if pathStr, ok := path.(string); ok {
				w.skipPaths = append(w.skipPaths, pathStr)
			}
		}
	}

	if pingInterval, ok := config["ping_interval"].(float64); ok {
		w.pingInterval = time.Duration(pingInterval) * time.Second
	}

	if pongWait, ok := config["pong_wait"].(float64); ok {
		w.pongWait = time.Duration(pongWait) * time.Second
	}

	if writeWait, ok := config["write_wait"].(float64); ok {
		w.writeWait = time.Duration(writeWait) * time.Second
	}

	if maxMessageSize, ok := config["max_message_size"].(float64); ok {
		w.maxMessageSize = int64(maxMessageSize)
	}

	// Validate upstream URL
	if w.upstreamURL == "" {
		return fmt.Errorf("upstream_url is required for WebSocket plugin")
	}

	// Ensure upstream URL uses WebSocket protocol
	if !strings.HasPrefix(w.upstreamURL, "ws://") && !strings.HasPrefix(w.upstreamURL, "wss://") {
		return fmt.Errorf("upstream_url must use ws:// or wss:// protocol")
	}

	return nil
}

func (ws *WebSocketPlugin) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !ws.enabled {
			next.ServeHTTP(w, r)
			return
		}

		// Skip WebSocket handling for certain paths
		if ws.shouldSkipPath(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}

		// Check if this is a WebSocket upgrade request
		if ws.isWebSocketRequest(r) {
			ws.handleWebSocket(w, r)
			return
		}

		// Continue with normal HTTP handling
		next.ServeHTTP(w, r)
	})
}

func (ws *WebSocketPlugin) shouldSkipPath(path string) bool {
	for _, skipPath := range ws.skipPaths {
		if strings.HasPrefix(path, skipPath) {
			return true
		}
	}
	return false
}

func (ws *WebSocketPlugin) isWebSocketRequest(r *http.Request) bool {
	return strings.Contains(strings.ToLower(r.Header.Get("Upgrade")), "websocket")
}

func (ws *WebSocketPlugin) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	// Create upstream URL
	upstreamURL, err := ws.buildUpstreamURL(r)
	if err != nil {
		ws.writeError(w, "Failed to build upstream URL", http.StatusBadRequest)
		return
	}

	// Create WebSocket dialer
	dialer := websocket.Dialer{
		HandshakeTimeout: 45 * time.Second,
	}

	// Connect to upstream
	upstreamConn, _, err := dialer.Dial(upstreamURL, ws.buildHeaders(r))
	if err != nil {
		ws.writeError(w, "Failed to connect to upstream", http.StatusBadGateway)
		return
	}
	defer upstreamConn.Close()

	// Upgrade client connection
	upgrader := websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool {
			return true // Allow all origins for now
		},
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
	}

	clientConn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer clientConn.Close()

	// Set connection parameters
	clientConn.SetReadLimit(ws.maxMessageSize)
	clientConn.SetReadDeadline(time.Now().Add(ws.pongWait))
	clientConn.SetPongHandler(func(string) error {
		clientConn.SetReadDeadline(time.Now().Add(ws.pongWait))
		return nil
	})

	upstreamConn.SetReadLimit(ws.maxMessageSize)
	upstreamConn.SetReadDeadline(time.Now().Add(ws.pongWait))
	upstreamConn.SetPongHandler(func(string) error {
		upstreamConn.SetReadDeadline(time.Now().Add(ws.pongWait))
		return nil
	})

	// Start ping ticker for client
	clientPingTicker := time.NewTicker(ws.pingInterval)
	defer clientPingTicker.Stop()

	// Start ping ticker for upstream
	upstreamPingTicker := time.NewTicker(ws.pingInterval)
	defer upstreamPingTicker.Stop()

	// Create channels for coordination
	clientDone := make(chan struct{})
	upstreamDone := make(chan struct{})

	// Start client to upstream proxy
	go func() {
		defer close(clientDone)
		for {
			select {
			case <-upstreamDone:
				return
			default:
				messageType, message, err := clientConn.ReadMessage()
				if err != nil {
					return
				}

				upstreamConn.SetWriteDeadline(time.Now().Add(ws.writeWait))
				if err := upstreamConn.WriteMessage(messageType, message); err != nil {
					return
				}
			}
		}
	}()

	// Start upstream to client proxy
	go func() {
		defer close(upstreamDone)
		for {
			select {
			case <-clientDone:
				return
			default:
				messageType, message, err := upstreamConn.ReadMessage()
				if err != nil {
					return
				}

				clientConn.SetWriteDeadline(time.Now().Add(ws.writeWait))
				if err := clientConn.WriteMessage(messageType, message); err != nil {
					return
				}
			}
		}
	}()

	// Handle ping/pong
	go func() {
		for {
			select {
			case <-clientDone:
				return
			case <-clientPingTicker.C:
				clientConn.SetWriteDeadline(time.Now().Add(ws.writeWait))
				if err := clientConn.WriteMessage(websocket.PingMessage, nil); err != nil {
					return
				}
			}
		}
	}()

	go func() {
		for {
			select {
			case <-upstreamDone:
				return
			case <-upstreamPingTicker.C:
				upstreamConn.SetWriteDeadline(time.Now().Add(ws.writeWait))
				if err := upstreamConn.WriteMessage(websocket.PingMessage, nil); err != nil {
					return
				}
			}
		}
	}()

	// Wait for either connection to close
	select {
	case <-clientDone:
	case <-upstreamDone:
	}
}

func (ws *WebSocketPlugin) buildUpstreamURL(r *http.Request) (string, error) {
	baseURL, err := url.Parse(ws.upstreamURL)
	if err != nil {
		return "", err
	}

	// Append the path from the original request
	baseURL.Path = r.URL.Path
	baseURL.RawQuery = r.URL.RawQuery

	return baseURL.String(), nil
}

func (ws *WebSocketPlugin) buildHeaders(r *http.Request) http.Header {
	headers := make(http.Header)

	// Copy relevant headers
	for key, values := range r.Header {
		// Skip headers that shouldn't be forwarded
		if key == "Connection" || key == "Upgrade" || key == "Sec-WebSocket-Key" ||
			key == "Sec-WebSocket-Version" || key == "Sec-WebSocket-Protocol" {
			continue
		}
		headers[key] = values
	}

	// Add WebSocket headers
	headers.Set("Connection", "Upgrade")
	headers.Set("Upgrade", "websocket")

	return headers
}

func (ws *WebSocketPlugin) writeError(w http.ResponseWriter, message string, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	response := map[string]interface{}{
		"error":   "WebSocket Error",
		"message": message,
	}
	json.NewEncoder(w).Encode(response)
}

// Tags returns plugin tags for discovery
func (ws *WebSocketPlugin) Tags() map[string]string {
	return map[string]string{
		"type":       "websocket",
		"category":   "proxy",
		"middleware": "true",
		"protocol":   "ws",
	}
}

// Health checks if the WebSocket plugin is healthy
func (ws *WebSocketPlugin) Health() error {
	ws.mu.RLock()
	defer ws.mu.RUnlock()

	if !ws.enabled {
		return fmt.Errorf("WebSocket plugin is disabled")
	}

	// Check if upstream URL is configured
	if ws.upstreamURL == "" {
		return fmt.Errorf("upstream URL not configured")
	}

	// Try to parse the upstream URL
	if _, err := url.Parse(ws.upstreamURL); err != nil {
		return fmt.Errorf("invalid upstream URL: %w", err)
	}

	return nil
}

// Status returns human-readable status
func (ws *WebSocketPlugin) Status() string {
	ws.mu.RLock()
	defer ws.mu.RUnlock()

	if !ws.enabled {
		return "WebSocket Plugin: Disabled"
	}

	return fmt.Sprintf("WebSocket Plugin: Enabled (upstream: %s, ping: %s)", ws.upstreamURL, ws.pingInterval)
}

// OnStart lifecycle hook
func (ws *WebSocketPlugin) OnStart() error {
	// Validate WebSocket config on startup
	return ws.Health()
}

// OnShutdown lifecycle hook
func (ws *WebSocketPlugin) OnShutdown() error {
	// Clean up any WebSocket-related resources if needed
	return nil
}
