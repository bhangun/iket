package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"iket/internal/config"
	"iket/internal/core/gateway"
	"iket/internal/logging"
	"iket/pkg/plugin"

	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
)

// ManagementAPI provides REST endpoints for gateway management
type ManagementAPI struct {
	gateway  *gateway.Gateway
	logger   *logging.Logger
	registry *plugin.Registry
	mu       sync.RWMutex

	// WebSocket upgrader
	upgrader websocket.Upgrader

	// Real-time update channels
	statusSubscribers  map[*websocket.Conn]bool
	metricsSubscribers map[*websocket.Conn]bool
	logsSubscribers    map[*websocket.Conn]bool
	subscriberMu       sync.RWMutex
}

// NewManagementAPI creates a new management API instance
func NewManagementAPI(gateway *gateway.Gateway, logger *logging.Logger, registry *plugin.Registry) *ManagementAPI {
	api := &ManagementAPI{
		gateway:  gateway,
		logger:   logger,
		registry: registry,
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool {
				return true // Allow all origins for now
			},
		},
		statusSubscribers:  make(map[*websocket.Conn]bool),
		metricsSubscribers: make(map[*websocket.Conn]bool),
		logsSubscribers:    make(map[*websocket.Conn]bool),
	}

	// Start real-time update goroutines
	go api.broadcastStatusUpdates()
	go api.broadcastMetricsUpdates()

	return api
}

// RegisterRoutes registers all management API routes
func (api *ManagementAPI) RegisterRoutes(router *mux.Router) {
	// API v1 routes
	v1 := router.PathPrefix("/api/v1").Subrouter()

	// Add CORS middleware for management API
	v1.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

			if r.Method == "OPTIONS" {
				w.WriteHeader(http.StatusOK)
				return
			}

			next.ServeHTTP(w, r)
		})
	})

	// Gateway management
	v1.HandleFunc("/gateway/status", api.getGatewayStatus).Methods("GET")
	v1.HandleFunc("/gateway/config", api.getGatewayConfig).Methods("GET")
	v1.HandleFunc("/gateway/config", api.updateGatewayConfig).Methods("PUT")
	v1.HandleFunc("/gateway/reload", api.reloadGateway).Methods("POST")
	v1.HandleFunc("/gateway/metrics", api.getGatewayMetrics).Methods("GET")

	// Plugin management
	v1.HandleFunc("/plugins", api.listPlugins).Methods("GET")
	v1.HandleFunc("/plugins/{name}", api.getPluginDetails).Methods("GET")
	v1.HandleFunc("/plugins/{name}/config", api.updatePluginConfig).Methods("PUT")
	v1.HandleFunc("/plugins/{name}/enable", api.enablePlugin).Methods("POST")
	v1.HandleFunc("/plugins/{name}/disable", api.disablePlugin).Methods("POST")
	v1.HandleFunc("/plugins/{name}/health", api.getPluginHealth).Methods("GET")
	v1.HandleFunc("/plugins/{name}/status", api.getPluginStatus).Methods("GET")

	// Route management
	v1.HandleFunc("/routes", api.listRoutes).Methods("GET")
	v1.HandleFunc("/routes", api.createRoute).Methods("POST")
	v1.HandleFunc("/routes/{id}", api.getRouteDetails).Methods("GET")
	v1.HandleFunc("/routes/{id}", api.updateRoute).Methods("PUT")
	v1.HandleFunc("/routes/{id}", api.deleteRoute).Methods("DELETE")
	v1.HandleFunc("/routes/{id}/enable", api.enableRoute).Methods("POST")
	v1.HandleFunc("/routes/{id}/disable", api.disableRoute).Methods("POST")

	// Monitoring & logs
	v1.HandleFunc("/logs", api.getLogs).Methods("GET")
	v1.HandleFunc("/logs/stream", api.streamLogs).Methods("GET")
	v1.HandleFunc("/metrics/system", api.getSystemMetrics).Methods("GET")

	// WebSocket endpoints
	v1.HandleFunc("/ws/status", api.wsStatus).Methods("GET")
	v1.HandleFunc("/ws/metrics", api.wsMetrics).Methods("GET")
	v1.HandleFunc("/ws/logs", api.wsLogs).Methods("GET")

	// Certificate management
	v1.HandleFunc("/certificates", api.listCertificates).Methods("GET")
	v1.HandleFunc("/certificates", api.uploadCertificate).Methods("POST")
	v1.HandleFunc("/certificates/{id}", api.deleteCertificate).Methods("DELETE")

	// Backup & restore
	v1.HandleFunc("/backup", api.createBackup).Methods("POST")
	v1.HandleFunc("/backup", api.listBackups).Methods("GET")
	v1.HandleFunc("/backup/{id}/restore", api.restoreBackup).Methods("POST")
}

// Response structures
type APIResponse struct {
	Success bool        `json:"success"`
	Message string      `json:"message,omitempty"`
	Data    interface{} `json:"data,omitempty"`
}

type ErrorResponse struct {
	Error ErrorDetails `json:"error"`
}

type ErrorDetails struct {
	Code    string                 `json:"code"`
	Message string                 `json:"message"`
	Details map[string]interface{} `json:"details,omitempty"`
}

// Gateway Status Response
type GatewayStatus struct {
	Status            string    `json:"status"`
	Uptime            string    `json:"uptime"`
	Version           string    `json:"version"`
	StartTime         time.Time `json:"start_time"`
	ConfigLoaded      bool      `json:"config_loaded"`
	LastReload        time.Time `json:"last_reload"`
	ActiveConnections int       `json:"active_connections"`
	TotalRequests     int64     `json:"total_requests"`
	ErrorCount        int       `json:"error_count"`
}

// Gateway Metrics Response
type GatewayMetrics struct {
	Requests struct {
		Total         int64   `json:"total"`
		Successful    int64   `json:"successful"`
		Failed        int64   `json:"failed"`
		RatePerMinute float64 `json:"rate_per_minute"`
	} `json:"requests"`
	ResponseTimes struct {
		Average float64 `json:"average"`
		P95     float64 `json:"p95"`
		P99     float64 `json:"p99"`
	} `json:"response_times"`
	Errors struct {
		FourXX int `json:"4xx"`
		FiveXX int `json:"5xx"`
	} `json:"errors"`
	Connections struct {
		Active int   `json:"active"`
		Total  int64 `json:"total"`
	} `json:"connections"`
}

// Plugin Response
type PluginInfo struct {
	Name    string            `json:"name"`
	Type    string            `json:"type"`
	Enabled bool              `json:"enabled"`
	Status  string            `json:"status"`
	Tags    map[string]string `json:"tags"`
}

// Route Response
type RouteInfo struct {
	ID          string                 `json:"id"`
	Path        string                 `json:"path"`
	Destination string                 `json:"destination"`
	Methods     []string               `json:"methods"`
	RequireAuth bool                   `json:"require_auth"`
	Timeout     int                    `json:"timeout"`
	StripPath   bool                   `json:"strip_path"`
	Active      bool                   `json:"active"`
	Stats       map[string]interface{} `json:"stats"`
}

// Handler implementations

func (api *ManagementAPI) getGatewayStatus(w http.ResponseWriter, r *http.Request) {
	api.mu.RLock()
	defer api.mu.RUnlock()

	// Get gateway config for status info
	_ = api.gateway.GetConfig()

	status := GatewayStatus{
		Status:            "running",
		Uptime:            "2h 15m 30s", // Calculate from start time
		Version:           "0.1.12",     // Get from gateway
		StartTime:         time.Now().Add(-2*time.Hour - 15*time.Minute - 30*time.Second),
		ConfigLoaded:      true,
		LastReload:        time.Now().Add(-30 * time.Minute),
		ActiveConnections: 42,
		TotalRequests:     15420,
		ErrorCount:        5,
	}

	api.writeJSON(w, status)
}

func (api *ManagementAPI) getGatewayConfig(w http.ResponseWriter, r *http.Request) {
	api.mu.RLock()
	defer api.mu.RUnlock()

	cfg := api.gateway.GetConfig()
	if cfg == nil {
		api.writeError(w, "Configuration not available", http.StatusInternalServerError)
		return
	}

	// Redact sensitive information
	redactedConfig := *cfg
	if redactedConfig.Security.Jwt.Secret != "" {
		redactedConfig.Security.Jwt.Secret = "REDACTED"
	}
	redactedConfig.Security.BasicAuthUsers = nil

	api.writeJSON(w, redactedConfig)
}

func (api *ManagementAPI) updateGatewayConfig(w http.ResponseWriter, r *http.Request) {
	var newConfig config.Config
	if err := json.NewDecoder(r.Body).Decode(&newConfig); err != nil {
		api.writeError(w, "Invalid configuration format", http.StatusBadRequest)
		return
	}

	// Validate configuration
	if err := newConfig.Validate(); err != nil {
		api.writeError(w, "Invalid configuration", http.StatusBadRequest)
		return
	}

	// Update gateway configuration
	if err := api.gateway.UpdateConfig(&newConfig); err != nil {
		api.writeError(w, "Failed to update configuration", http.StatusInternalServerError)
		return
	}

	response := APIResponse{
		Success: true,
		Message: "Configuration updated successfully",
		Data: map[string]interface{}{
			"reload_required": true,
		},
	}
	api.writeJSON(w, response)
}

func (api *ManagementAPI) reloadGateway(w http.ResponseWriter, r *http.Request) {
	// This would trigger a configuration reload
	// For now, just return success

	response := APIResponse{
		Success: true,
		Message: "Configuration reloaded successfully",
		Data: map[string]interface{}{
			"timestamp": time.Now(),
		},
	}
	api.writeJSON(w, response)
}

func (api *ManagementAPI) getGatewayMetrics(w http.ResponseWriter, r *http.Request) {
	metrics := GatewayMetrics{}

	// Populate with mock data for now
	metrics.Requests.Total = 15420
	metrics.Requests.Successful = 15380
	metrics.Requests.Failed = 40
	metrics.Requests.RatePerMinute = 120.0

	metrics.ResponseTimes.Average = 45.2
	metrics.ResponseTimes.P95 = 120.5
	metrics.ResponseTimes.P99 = 250.1

	metrics.Errors.FourXX = 25
	metrics.Errors.FiveXX = 15

	metrics.Connections.Active = 42
	metrics.Connections.Total = 15420

	api.writeJSON(w, metrics)
}

func (api *ManagementAPI) listPlugins(w http.ResponseWriter, r *http.Request) {
	plugins := api.registry.List()
	pluginInfos := make([]PluginInfo, 0, len(plugins))

	for _, name := range plugins {
		plugin, err := api.registry.Get(name)
		if err != nil {
			continue
		}

		info := PluginInfo{
			Name:    name,
			Type:    "unknown",
			Enabled: true,
			Status:  "healthy",
			Tags:    make(map[string]string),
		}

		// Get plugin type if available
		if typedPlugin, ok := plugin.(interface{ Type() string }); ok {
			info.Type = typedPlugin.Type()
		}

		// Get plugin tags if available
		if taggedPlugin, ok := plugin.(interface{ Tags() map[string]string }); ok {
			info.Tags = taggedPlugin.Tags()
		}

		// Check health if available
		if healthChecker, ok := plugin.(interface{ Health() error }); ok {
			if err := healthChecker.Health(); err != nil {
				info.Status = "unhealthy"
			}
		}

		pluginInfos = append(pluginInfos, info)
	}

	response := map[string]interface{}{
		"plugins": pluginInfos,
	}
	api.writeJSON(w, response)
}

func (api *ManagementAPI) getPluginDetails(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	pluginName := vars["name"]

	plugin, err := api.registry.Get(pluginName)
	if err != nil {
		api.writeError(w, "Plugin not found", http.StatusNotFound)
		return
	}

	details := map[string]interface{}{
		"name":    pluginName,
		"type":    "unknown",
		"enabled": true,
		"status":  "healthy",
	}

	// Get plugin type
	if typedPlugin, ok := plugin.(interface{ Type() string }); ok {
		details["type"] = typedPlugin.Type()
	}

	// Get plugin tags
	if taggedPlugin, ok := plugin.(interface{ Tags() map[string]string }); ok {
		details["tags"] = taggedPlugin.Tags()
	}

	// Get health status
	if healthChecker, ok := plugin.(interface{ Health() error }); ok {
		if err := healthChecker.Health(); err != nil {
			details["status"] = "unhealthy"
			details["health"] = map[string]interface{}{
				"status":  "unhealthy",
				"message": err.Error(),
			}
		} else {
			details["health"] = map[string]interface{}{
				"status":  "healthy",
				"message": "Plugin is functioning normally",
			}
		}
	}

	// Get status
	if statusReporter, ok := plugin.(interface{ Status() string }); ok {
		details["status_message"] = statusReporter.Status()
	}

	api.writeJSON(w, details)
}

func (api *ManagementAPI) updatePluginConfig(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	pluginName := vars["name"]

	var config map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&config); err != nil {
		api.writeError(w, "Invalid configuration format", http.StatusBadRequest)
		return
	}

	plugin, err := api.registry.Get(pluginName)
	if err != nil {
		api.writeError(w, "Plugin not found", http.StatusNotFound)
		return
	}

	// Reload plugin with new configuration
	if err := plugin.Initialize(config); err != nil {
		api.writeError(w, "Failed to update plugin configuration", http.StatusInternalServerError)
		return
	}

	response := APIResponse{
		Success: true,
		Message: "Plugin configuration updated",
	}
	api.writeJSON(w, response)
}

func (api *ManagementAPI) enablePlugin(w http.ResponseWriter, r *http.Request) {
	_ = mux.Vars(r)["name"] // Extract but don't use for now

	// This would enable the plugin
	// For now, just return success

	response := APIResponse{
		Success: true,
		Message: "Plugin enabled successfully",
	}
	api.writeJSON(w, response)
}

func (api *ManagementAPI) disablePlugin(w http.ResponseWriter, r *http.Request) {
	_ = mux.Vars(r)["name"] // Extract but don't use for now

	// This would disable the plugin
	// For now, just return success

	response := APIResponse{
		Success: true,
		Message: "Plugin disabled successfully",
	}
	api.writeJSON(w, response)
}

func (api *ManagementAPI) getPluginHealth(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	pluginName := vars["name"]

	plugin, err := api.registry.Get(pluginName)
	if err != nil {
		api.writeError(w, "Plugin not found", http.StatusNotFound)
		return
	}

	healthChecker, ok := plugin.(interface{ Health() error })
	if !ok {
		api.writeError(w, "Plugin does not support health checks", http.StatusNotImplemented)
		return
	}

	err = healthChecker.Health()
	health := map[string]interface{}{
		"status":     "healthy",
		"last_check": time.Now(),
		"message":    "Plugin is functioning normally",
	}

	if err != nil {
		health["status"] = "unhealthy"
		health["message"] = err.Error()
	}

	api.writeJSON(w, health)
}

func (api *ManagementAPI) getPluginStatus(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	pluginName := vars["name"]

	plugin, err := api.registry.Get(pluginName)
	if err != nil {
		api.writeError(w, "Plugin not found", http.StatusNotFound)
		return
	}

	statusReporter, ok := plugin.(interface{ Status() string })
	if !ok {
		api.writeError(w, "Plugin does not support status reporting", http.StatusNotImplemented)
		return
	}

	status := map[string]interface{}{
		"status":      statusReporter.Status(),
		"enabled":     true,
		"last_update": time.Now(),
	}

	api.writeJSON(w, status)
}

func (api *ManagementAPI) listRoutes(w http.ResponseWriter, r *http.Request) {
	cfg := api.gateway.GetConfig()
	if cfg == nil {
		api.writeError(w, "Configuration not available", http.StatusInternalServerError)
		return
	}

	routes := make([]RouteInfo, 0, len(cfg.Routes))
	for i, route := range cfg.Routes {
		timeout := 0
		if route.Timeout != nil {
			timeout = int(route.Timeout.Seconds())
		}

		routeInfo := RouteInfo{
			ID:          fmt.Sprintf("route-%d", i+1),
			Path:        route.Path,
			Destination: route.Destination,
			Methods:     route.Methods,
			RequireAuth: route.RequireAuth,
			Timeout:     timeout,
			StripPath:   route.StripPath,
			Active:      true,
			Stats: map[string]interface{}{
				"requests":          15420,
				"errors":            5,
				"avg_response_time": 45.2,
			},
		}
		routes = append(routes, routeInfo)
	}

	response := map[string]interface{}{
		"routes": routes,
	}
	api.writeJSON(w, response)
}

func (api *ManagementAPI) getRouteDetails(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	routeID := vars["id"]

	// This would get route details by ID
	// For now, return mock data

	routeDetails := map[string]interface{}{
		"id":           routeID,
		"path":         "/api/*",
		"destination":  "http://backend:3000",
		"methods":      []string{"GET", "POST", "PUT", "DELETE"},
		"require_auth": true,
		"timeout":      30,
		"strip_path":   false,
		"active":       true,
		"created_at":   time.Now().Add(-2 * time.Hour),
		"updated_at":   time.Now().Add(-30 * time.Minute),
		"stats": map[string]interface{}{
			"requests":          15420,
			"successful":        15380,
			"failed":            40,
			"avg_response_time": 45.2,
			"p95_response_time": 120.5,
			"error_rate":        0.26,
		},
	}

	api.writeJSON(w, routeDetails)
}

func (api *ManagementAPI) createRoute(w http.ResponseWriter, r *http.Request) {
	var routeConfig config.RouterConfig
	if err := json.NewDecoder(r.Body).Decode(&routeConfig); err != nil {
		api.writeError(w, "Invalid route configuration", http.StatusBadRequest)
		return
	}

	// This would create a new route
	// For now, return success

	response := APIResponse{
		Success: true,
		Message: "Route created successfully",
		Data: map[string]interface{}{
			"route_id": "route-new",
		},
	}
	api.writeJSON(w, response)
}

func (api *ManagementAPI) updateRoute(w http.ResponseWriter, r *http.Request) {
	_ = mux.Vars(r)["id"] // Extract but don't use for now

	var updates map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&updates); err != nil {
		api.writeError(w, "Invalid update data", http.StatusBadRequest)
		return
	}

	// This would update the route
	// For now, return success

	response := APIResponse{
		Success: true,
		Message: "Route updated successfully",
	}
	api.writeJSON(w, response)
}

func (api *ManagementAPI) deleteRoute(w http.ResponseWriter, r *http.Request) {
	_ = mux.Vars(r)["id"] // Extract but don't use for now

	// This would delete the route
	// For now, return success

	response := APIResponse{
		Success: true,
		Message: "Route deleted successfully",
	}
	api.writeJSON(w, response)
}

func (api *ManagementAPI) enableRoute(w http.ResponseWriter, r *http.Request) {
	_ = mux.Vars(r)["id"] // Extract but don't use for now

	// This would enable the route
	// For now, return success

	response := APIResponse{
		Success: true,
		Message: "Route enabled successfully",
	}
	api.writeJSON(w, response)
}

func (api *ManagementAPI) disableRoute(w http.ResponseWriter, r *http.Request) {
	_ = mux.Vars(r)["id"] // Extract but don't use for now

	// This would disable the route
	// For now, return success

	response := APIResponse{
		Success: true,
		Message: "Route disabled successfully",
	}
	api.writeJSON(w, response)
}

func (api *ManagementAPI) getLogs(w http.ResponseWriter, r *http.Request) {
	// Parse query parameters (not used in placeholder implementation)
	_ = r.URL.Query().Get("limit")
	_ = r.URL.Query().Get("level")
	_ = r.URL.Query().Get("since")

	// This would fetch logs based on parameters
	// For now, return mock data

	logs := []map[string]interface{}{
		{
			"timestamp":  time.Now().Add(-5 * time.Minute),
			"level":      "info",
			"message":    "Request processed successfully",
			"route_id":   "route-1",
			"client_ip":  "192.168.1.100",
			"request_id": "req-12345",
		},
		{
			"timestamp":  time.Now().Add(-3 * time.Minute),
			"level":      "error",
			"message":    "Backend service unavailable",
			"route_id":   "route-1",
			"client_ip":  "192.168.1.101",
			"request_id": "req-12346",
		},
	}

	response := map[string]interface{}{
		"logs":     logs,
		"total":    len(logs),
		"has_more": false,
	}
	api.writeJSON(w, response)
}

func (api *ManagementAPI) streamLogs(w http.ResponseWriter, r *http.Request) {
	// Set headers for Server-Sent Events
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	// Create a channel to signal client disconnect
	notify := w.(http.CloseNotifier).CloseNotify()

	// Send initial connection message
	fmt.Fprintf(w, "event: connected\ndata: {\"message\":\"Connected to log stream\"}\n\n")
	w.(http.Flusher).Flush()

	// Simulate log streaming
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-notify:
			return
		case <-ticker.C:
			logEntry := map[string]interface{}{
				"timestamp": time.Now(),
				"level":     "info",
				"message":   "Log entry from stream",
			}

			data, _ := json.Marshal(logEntry)
			fmt.Fprintf(w, "event: log\ndata: %s\n\n", data)
			w.(http.Flusher).Flush()
		}
	}
}

func (api *ManagementAPI) getSystemMetrics(w http.ResponseWriter, r *http.Request) {
	// This would get actual system metrics
	// For now, return mock data

	metrics := map[string]interface{}{
		"cpu": map[string]interface{}{
			"usage_percent": 25.5,
			"cores":         8,
		},
		"memory": map[string]interface{}{
			"total_mb":      16384,
			"used_mb":       8192,
			"usage_percent": 50.0,
		},
		"disk": map[string]interface{}{
			"total_gb":      500,
			"used_gb":       250,
			"usage_percent": 50.0,
		},
		"network": map[string]interface{}{
			"bytes_in":  1048576,
			"bytes_out": 2097152,
		},
	}

	api.writeJSON(w, metrics)
}

// WebSocket handlers

func (api *ManagementAPI) wsStatus(w http.ResponseWriter, r *http.Request) {
	conn, err := api.upgrader.Upgrade(w, r, nil)
	if err != nil {
		api.logger.Error("Failed to upgrade WebSocket connection", err)
		return
	}
	defer conn.Close()

	// Register subscriber
	api.subscriberMu.Lock()
	api.statusSubscribers[conn] = true
	api.subscriberMu.Unlock()

	// Remove subscriber when connection closes
	defer func() {
		api.subscriberMu.Lock()
		delete(api.statusSubscribers, conn)
		api.subscriberMu.Unlock()
	}()

	// Keep connection alive
	for {
		_, _, err := conn.ReadMessage()
		if err != nil {
			break
		}
	}
}

func (api *ManagementAPI) wsMetrics(w http.ResponseWriter, r *http.Request) {
	conn, err := api.upgrader.Upgrade(w, r, nil)
	if err != nil {
		api.logger.Error("Failed to upgrade WebSocket connection", err)
		return
	}
	defer conn.Close()

	// Register subscriber
	api.subscriberMu.Lock()
	api.metricsSubscribers[conn] = true
	api.subscriberMu.Unlock()

	// Remove subscriber when connection closes
	defer func() {
		api.subscriberMu.Lock()
		delete(api.metricsSubscribers, conn)
		api.subscriberMu.Unlock()
	}()

	// Keep connection alive
	for {
		_, _, err := conn.ReadMessage()
		if err != nil {
			break
		}
	}
}

func (api *ManagementAPI) wsLogs(w http.ResponseWriter, r *http.Request) {
	conn, err := api.upgrader.Upgrade(w, r, nil)
	if err != nil {
		api.logger.Error("Failed to upgrade WebSocket connection", err)
		return
	}
	defer conn.Close()

	// Register subscriber
	api.subscriberMu.Lock()
	api.logsSubscribers[conn] = true
	api.subscriberMu.Unlock()

	// Remove subscriber when connection closes
	defer func() {
		api.subscriberMu.Lock()
		delete(api.logsSubscribers, conn)
		api.subscriberMu.Unlock()
	}()

	// Keep connection alive
	for {
		_, _, err := conn.ReadMessage()
		if err != nil {
			break
		}
	}
}

// Real-time update broadcasters

func (api *ManagementAPI) broadcastStatusUpdates() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		status := map[string]interface{}{
			"type": "status_update",
			"data": map[string]interface{}{
				"status":             "running",
				"active_connections": 42,
				"total_requests":     15420,
			},
		}

		api.broadcastToSubscribers(api.statusSubscribers, status)
	}
}

func (api *ManagementAPI) broadcastMetricsUpdates() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		metrics := map[string]interface{}{
			"type": "metrics_update",
			"data": map[string]interface{}{
				"requests_per_minute": 120.0,
				"avg_response_time":   45.2,
				"error_rate":          0.26,
			},
		}

		api.broadcastToSubscribers(api.metricsSubscribers, metrics)
	}
}

func (api *ManagementAPI) broadcastToSubscribers(subscribers map[*websocket.Conn]bool, message interface{}) {
	data, err := json.Marshal(message)
	if err != nil {
		api.logger.Error("Failed to marshal message", err)
		return
	}

	api.subscriberMu.RLock()
	defer api.subscriberMu.RUnlock()

	for conn := range subscribers {
		err := conn.WriteMessage(websocket.TextMessage, data)
		if err != nil {
			api.logger.Error("Failed to send message to subscriber", err)
			// Remove failed connection
			delete(subscribers, conn)
			conn.Close()
		}
	}
}

// Certificate management (placeholder implementations)

func (api *ManagementAPI) listCertificates(w http.ResponseWriter, r *http.Request) {
	certificates := []map[string]interface{}{
		{
			"id":          "cert-1",
			"name":        "main-cert",
			"type":        "tls",
			"subject":     "CN=example.com",
			"issuer":      "CN=Let's Encrypt",
			"valid_from":  time.Now().AddDate(0, -1, 0),
			"valid_until": time.Now().AddDate(0, 2, 0),
			"status":      "valid",
		},
	}

	response := map[string]interface{}{
		"certificates": certificates,
	}
	api.writeJSON(w, response)
}

func (api *ManagementAPI) uploadCertificate(w http.ResponseWriter, r *http.Request) {
	// This would handle certificate upload
	// For now, return success

	response := APIResponse{
		Success: true,
		Message: "Certificate uploaded successfully",
		Data: map[string]interface{}{
			"certificate_id": "cert-2",
		},
	}
	api.writeJSON(w, response)
}

func (api *ManagementAPI) deleteCertificate(w http.ResponseWriter, r *http.Request) {
	_ = mux.Vars(r)["id"] // Extract but don't use for now

	// This would delete the certificate
	// For now, return success

	response := APIResponse{
		Success: true,
		Message: "Certificate deleted successfully",
	}
	api.writeJSON(w, response)
}

// Backup & restore (placeholder implementations)

func (api *ManagementAPI) createBackup(w http.ResponseWriter, r *http.Request) {
	backupID := fmt.Sprintf("backup-%s", time.Now().Format("2006-01-02-15-04"))

	response := APIResponse{
		Success: true,
		Message: "Backup created successfully",
		Data: map[string]interface{}{
			"backup_id":  backupID,
			"filename":   fmt.Sprintf("iket-backup-%s.tar.gz", time.Now().Format("2006-01-02-15-04")),
			"size_bytes": 1048576,
			"created_at": time.Now(),
		},
	}
	api.writeJSON(w, response)
}

func (api *ManagementAPI) listBackups(w http.ResponseWriter, r *http.Request) {
	backups := []map[string]interface{}{
		{
			"id":         "backup-2024-01-15-12-45",
			"filename":   "iket-backup-2024-01-15-12-45.tar.gz",
			"size_bytes": 1048576,
			"created_at": time.Now().Add(-2 * time.Hour),
		},
	}

	response := map[string]interface{}{
		"backups": backups,
	}
	api.writeJSON(w, response)
}

func (api *ManagementAPI) restoreBackup(w http.ResponseWriter, r *http.Request) {
	_ = mux.Vars(r)["id"] // Extract but don't use for now

	// This would restore the backup
	// For now, return success

	response := APIResponse{
		Success: true,
		Message: "Backup restored successfully",
		Data: map[string]interface{}{
			"restart_required": true,
		},
	}
	api.writeJSON(w, response)
}

// Helper methods

func (api *ManagementAPI) writeJSON(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

func (api *ManagementAPI) writeError(w http.ResponseWriter, message string, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	errorResponse := ErrorResponse{
		Error: ErrorDetails{
			Code:    getErrorCode(statusCode),
			Message: message,
		},
	}

	json.NewEncoder(w).Encode(errorResponse)
}

func getErrorCode(statusCode int) string {
	switch statusCode {
	case http.StatusUnauthorized:
		return "AUTHENTICATION_REQUIRED"
	case http.StatusForbidden:
		return "PERMISSION_DENIED"
	case http.StatusBadRequest:
		return "VALIDATION_ERROR"
	case http.StatusNotFound:
		return "NOT_FOUND"
	case http.StatusConflict:
		return "CONFLICT"
	default:
		return "INTERNAL_ERROR"
	}
}
