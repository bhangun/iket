package api

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/bhangun/iket/pkg/config"
	"github.com/bhangun/iket/pkg/logging"

	"github.com/bhangun/iket/pkg/core/gateway"
	"github.com/bhangun/iket/pkg/plugin"

	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
)

// ManagementAPI provides REST endpoints for gateway management
type ManagementAPI struct {
	gateway    *gateway.Gateway
	logger     *logging.Logger
	registry   *plugin.Registry
	mu         sync.RWMutex
	startedAt  time.Time
	lastReload time.Time

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
		gateway:    gateway,
		logger:     logger,
		registry:   registry,
		startedAt:  time.Now(),
		lastReload: time.Now(),
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
	v1.HandleFunc("/gateway/config/self-test", api.selfTestGatewayConfig).Methods("GET")
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
	v1.HandleFunc("/enrollment/tokens", api.createEnrollmentToken).Methods("POST")
	v1.HandleFunc("/enrollment/tokens", api.listEnrollmentTokens).Methods("GET")
	v1.HandleFunc("/enrollment/tokens/{id}", api.revokeEnrollmentToken).Methods("DELETE")

	// Backup & restore
	v1.HandleFunc("/backup", api.createBackup).Methods("POST")
	v1.HandleFunc("/backup", api.listBackups).Methods("GET")
	v1.HandleFunc("/backup/{id}/restore", api.restoreBackup).Methods("POST")

	// Service management
	v1.HandleFunc("/services", api.getServices).Methods("GET")
	v1.HandleFunc("/services", api.createService).Methods("POST")
	v1.HandleFunc("/services/{name}", api.updateService).Methods("PUT")
	v1.HandleFunc("/services/{name}", api.deleteService).Methods("DELETE")

	// Client management
	v1.HandleFunc("/clients", api.listClients).Methods("GET")
	v1.HandleFunc("/clients", api.addClient).Methods("POST")
	v1.HandleFunc("/clients/{key}", api.removeClient).Methods("DELETE")
}

func (api *ManagementAPI) RegisterEnrollmentRoutes(router *mux.Router) {
	v1 := router.PathPrefix("/api/v1").Subrouter()
	v1.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
			if r.Method == "OPTIONS" {
				w.WriteHeader(http.StatusOK)
				return
			}
			next.ServeHTTP(w, r)
		})
	})
	v1.HandleFunc("/enroll", api.enrollClientCertificate).Methods("POST")
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

type ConfigSelfTestRoute struct {
	RouteName   string            `json:"route_name"`
	ServiceName string            `json:"service_name"`
	RoutePath   string            `json:"route_path"`
	RequestPath string            `json:"request_path"`
	Matched     bool              `json:"matched"`
	RouteVars   map[string]string `json:"route_vars,omitempty"`
	ProxiedPath string            `json:"proxied_path,omitempty"`
	Destination string            `json:"destination,omitempty"`
	StripPath   bool              `json:"strip_path"`
	URLPattern  string            `json:"url_pattern,omitempty"`
	Enabled     bool              `json:"enabled"`
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
	Enabled     bool                   `json:"enabled"`
	Stats       map[string]interface{} `json:"stats"`
}

// Handler implementations
func (api *ManagementAPI) getGatewayStatus(w http.ResponseWriter, r *http.Request) {
	clientIP := gateway.GetClientIP(r)
	api.logger.Info("gateway/status requested",
		logging.String("client_ip", clientIP),
		logging.String("path", r.URL.Path),
	)

	api.mu.RLock()
	defer api.mu.RUnlock()

	// Get gateway config for status info
	_ = api.gateway.GetConfig()

	status := GatewayStatus{
		Status:            "running",
		Uptime:            time.Since(api.startedAt).Round(time.Second).String(),
		Version:           api.gateway.Version(),
		StartTime:         api.startedAt,
		ConfigLoaded:      api.gateway.GetConfig() != nil,
		LastReload:        api.lastReload,
		ActiveConnections: 0,
		TotalRequests:     int64(len(api.logger.RecentLogs(2000, ""))),
		ErrorCount:        len(api.logger.RecentLogs(2000, "error")),
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

func (api *ManagementAPI) selfTestGatewayConfig(w http.ResponseWriter, r *http.Request) {
	api.mu.RLock()
	defer api.mu.RUnlock()

	cfg := api.gateway.GetConfig()
	if cfg == nil {
		api.writeError(w, "Configuration not available", http.StatusInternalServerError)
		return
	}

	samplePath := r.URL.Query().Get("path")
	if samplePath == "" {
		samplePath = "/example"
	}
	sampleMethod := strings.ToUpper(r.URL.Query().Get("method"))
	if sampleMethod == "" {
		sampleMethod = http.MethodGet
	}

	results := make([]ConfigSelfTestRoute, 0)
	for _, serviceConfig := range cfg.Services {
		for _, service := range serviceConfig.Services {
			for _, rawRoute := range service.Routes {
				route := rawRoute
				route.Path = service.EffectiveRoutePath(rawRoute)
				route.Methods = rawRoute.EffectiveMethods()

				result := ConfigSelfTestRoute{
					RouteName:   route.Name,
					ServiceName: service.Name,
					RoutePath:   route.Path,
					RequestPath: samplePath,
					StripPath:   route.StripPath,
					Enabled:     route.IsEnabled(),
					Destination: service.Host,
				}
				if result.RouteName == "" {
					result.RouteName = route.Path
				}
				if len(route.Backends) > 0 {
					result.URLPattern = route.Backends[0].URLPattern
				}

				vars, matched := gateway.MatchRouteTemplate(route, sampleMethod, samplePath)
				result.Matched = matched
				if matched {
					result.RouteVars = vars
					proxiedPath, err := gateway.ComputeProxiedPath(&service, route, samplePath, vars)
					if err != nil {
						api.writeError(w, fmt.Sprintf("Failed to compute proxied path for route %s: %v", route.Path, err), http.StatusInternalServerError)
						return
					}
					result.ProxiedPath = proxiedPath
				}

				results = append(results, result)
			}
		}
	}

	api.writeJSON(w, map[string]interface{}{
		"sample_method": sampleMethod,
		"sample_path":   samplePath,
		"routes":        results,
	})
}

func (api *ManagementAPI) updateGatewayConfig(w http.ResponseWriter, r *http.Request) {
	strategy := r.URL.Query().Get("strategy")
	if strategy == "" {
		strategy = "replace"
	}
	dryRun := r.URL.Query().Get("dry_run") == "true"

	var input map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		api.writeError(w, "Invalid configuration format", http.StatusBadRequest)
		return
	}

	api.mu.Lock()
	defer api.mu.Unlock()

	currentCfg := api.gateway.GetConfig()
	// Create a copy for simulation to avoid modifying the live config if it's a dry run
	simCfg := *currentCfg

	if strategy == "merge" {
		currentMap := make(map[string]interface{})
		currentJSON, _ := json.Marshal(simCfg)
		json.Unmarshal(currentJSON, &currentMap)

		api.deepMerge(currentMap, input)

		mergedJSON, _ := json.Marshal(currentMap)
		if err := json.Unmarshal(mergedJSON, &simCfg); err != nil {
			api.writeError(w, "Failed to merge configuration", http.StatusInternalServerError)
			return
		}
	} else {
		newJSON, _ := json.Marshal(input)
		if err := json.Unmarshal(newJSON, &simCfg); err != nil {
			api.writeError(w, "Invalid configuration", http.StatusBadRequest)
			return
		}
	}

	// Validate configuration
	if err := simCfg.Validate(); err != nil {
		api.writeError(w, fmt.Sprintf("Invalid configuration: %v", err), http.StatusBadRequest)
		return
	}

	if dryRun {
		response := APIResponse{
			Success: true,
			Message: "[DRY RUN] Configuration is valid and merge-ready",
			Data: map[string]interface{}{
				"strategy": strategy,
				"dry_run":  true,
			},
		}
		api.writeJSON(w, response)
		return
	}

	// Update gateway configuration (Live)
	if err := api.gateway.UpdateConfig(&simCfg); err != nil {
		api.writeError(w, "Failed to update configuration", http.StatusInternalServerError)
		return
	}

	response := APIResponse{
		Success: true,
		Message: fmt.Sprintf("Configuration updated successfully using %s strategy", strategy),
		Data: map[string]interface{}{
			"reload_required": true,
		},
	}
	api.writeJSON(w, response)
}

func (api *ManagementAPI) deepMerge(dst, src map[string]interface{}) {
	for k, v := range src {
		if srcMap, ok := v.(map[string]interface{}); ok {
			if dstMap, ok := dst[k].(map[string]interface{}); ok {
				api.deepMerge(dstMap, srcMap)
				continue
			}
		}
		dst[k] = v
	}
}

func (api *ManagementAPI) reloadGateway(w http.ResponseWriter, r *http.Request) {
	if err := api.gateway.ReloadConfig(); err != nil {
		api.writeError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	api.lastReload = time.Now()

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
	allLogs := api.logger.RecentLogs(2000, "")
	errorLogs := api.logger.RecentLogs(2000, "error")
	warnLogs := api.logger.RecentLogs(2000, "warn")

	metrics.Requests.Total = int64(len(allLogs))
	metrics.Requests.Successful = metrics.Requests.Total - int64(len(errorLogs))
	metrics.Requests.Failed = int64(len(errorLogs))
	metrics.Requests.RatePerMinute = float64(len(allLogs))

	metrics.ResponseTimes.Average = 0
	metrics.ResponseTimes.P95 = 0
	metrics.ResponseTimes.P99 = 0

	metrics.Errors.FourXX = len(warnLogs)
	metrics.Errors.FiveXX = len(errorLogs)

	metrics.Connections.Active = 0
	metrics.Connections.Total = metrics.Requests.Total

	api.writeJSON(w, metrics)
}

// ListPlugins returns the list of registered plugin names.
func (m *ManagementAPI) ListPlugins() []string {
	return m.registry.List() // assuming Registry has a List() method
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
			Enabled: api.pluginEnabled(name),
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
		"enabled": api.pluginEnabled(pluginName),
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

	cfg := api.gateway.GetConfig()
	if cfg == nil {
		api.writeError(w, "Configuration not available", http.StatusInternalServerError)
		return
	}
	simCfg, err := cloneConfig(cfg)
	if err != nil {
		api.writeError(w, "Failed to prepare configuration update", http.StatusInternalServerError)
		return
	}
	simCfg.SetPluginConfig(pluginName, config)

	// Reload plugin with new configuration
	if err := plugin.Initialize(config); err != nil {
		api.writeError(w, "Failed to update plugin configuration", http.StatusInternalServerError)
		return
	}
	if err := api.gateway.UpdateConfig(simCfg); err != nil {
		api.writeError(w, "Failed to persist plugin configuration", http.StatusInternalServerError)
		return
	}

	response := APIResponse{
		Success: true,
		Message: "Plugin configuration updated",
	}
	api.writeJSON(w, response)
}

func (api *ManagementAPI) enablePlugin(w http.ResponseWriter, r *http.Request) {
	pluginName := mux.Vars(r)["name"]
	if err := api.setPluginEnabled(pluginName, true); err != nil {
		api.writeError(w, err.Error(), http.StatusBadRequest)
		return
	}

	response := APIResponse{
		Success: true,
		Message: "Plugin enabled successfully",
	}
	api.writeJSON(w, response)
}

func (api *ManagementAPI) disablePlugin(w http.ResponseWriter, r *http.Request) {
	pluginName := mux.Vars(r)["name"]
	if err := api.setPluginEnabled(pluginName, false); err != nil {
		api.writeError(w, err.Error(), http.StatusBadRequest)
		return
	}

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
		"enabled":     api.pluginEnabled(pluginName),
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

	records := api.routeRecords(cfg)
	routeInfos := make([]RouteInfo, 0, len(records))
	for _, record := range records {
		routeInfos = append(routeInfos, api.routeInfoFromRecord(record))
	}
	response := map[string]interface{}{
		"routes": routeInfos,
	}
	api.writeJSON(w, response)
}

func (api *ManagementAPI) getRouteDetails(w http.ResponseWriter, r *http.Request) {
	record, err := api.findRouteRecord(api.gateway.GetConfig(), mux.Vars(r)["id"])
	if err != nil {
		api.writeError(w, err.Error(), http.StatusNotFound)
		return
	}
	api.writeJSON(w, map[string]interface{}{
		"id":           record.ID,
		"service_name": record.Service.Name,
		"path":         record.EffectivePath,
		"raw_path":     record.Route.Path,
		"destination":  record.Service.Host,
		"methods":      record.Route.EffectiveMethods(),
		"require_auth": record.Route.RequireAuth,
		"require_jwt":  record.Route.RequireJwt,
		"strip_path":   record.Route.StripPath,
		"enabled":      record.Route.IsEnabled(),
		"backend":      record.Route.Backends,
		"scopes":       record.Route.Scopes,
		"roles":        record.Route.Roles,
		"headers":      record.Route.Headers,
	})
}

func (api *ManagementAPI) createRoute(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ServiceName string              `json:"service_name"`
		Route       config.RouterConfig `json:"route"`
		Path        string              `json:"path"`
		Method      string              `json:"method"`
		Methods     []string            `json:"methods"`
		RequireAuth bool                `json:"requireAuth"`
		StripPath   bool                `json:"stripPath"`
		RequireJwt  bool                `json:"requireJwt"`
		Enabled     *bool               `json:"enabled"`
		Backends    []config.Backend    `json:"backend"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.writeError(w, "Invalid route configuration", http.StatusBadRequest)
		return
	}
	cfg := api.gateway.GetConfig()
	simCfg, err := cloneConfig(cfg)
	if err != nil {
		api.writeError(w, "Failed to prepare configuration update", http.StatusInternalServerError)
		return
	}
	routeConfig := req.Route
	if routeConfig.Path == "" {
		routeConfig.Path = req.Path
		routeConfig.Method = req.Method
		routeConfig.Methods = req.Methods
		routeConfig.RequireAuth = req.RequireAuth
		routeConfig.StripPath = req.StripPath
		routeConfig.RequireJwt = req.RequireJwt
		routeConfig.Enabled = req.Enabled
		routeConfig.Backends = req.Backends
	}
	if routeConfig.Enabled == nil {
		routeConfig.Enabled = config.NewBool(true)
	}
	if routeConfig.Path == "" || req.ServiceName == "" {
		api.writeError(w, "service_name and route.path are required", http.StatusBadRequest)
		return
	}
	service, err := findServiceByName(simCfg, req.ServiceName)
	if err != nil {
		api.writeError(w, err.Error(), http.StatusNotFound)
		return
	}
	for _, existing := range service.Routes {
		if existing.Path == routeConfig.Path && sameMethods(existing.EffectiveMethods(), routeConfig.EffectiveMethods()) {
			api.writeError(w, "Route already exists", http.StatusConflict)
			return
		}
	}
	service.Routes = append(service.Routes, routeConfig)
	if err := api.gateway.UpdateConfig(simCfg); err != nil {
		api.writeError(w, "Failed to create route", http.StatusInternalServerError)
		return
	}
	record, _ := api.findRouteByServicePathMethod(api.gateway.GetConfig(), req.ServiceName, routeConfig.Path, routeConfig.EffectiveMethods())

	response := APIResponse{
		Success: true,
		Message: "Route created successfully",
		Data: map[string]interface{}{
			"route_id": record.ID,
		},
	}
	api.writeJSON(w, response)
}

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

	// fallback
	if host, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr)); err == nil {
		return host
	}
	return r.RemoteAddr
}

func (api *ManagementAPI) updateRoute(w http.ResponseWriter, r *http.Request) {
	var raw map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&raw); err != nil {
		api.writeError(w, "Invalid update data", http.StatusBadRequest)
		return
	}
	updateBytes, _ := json.Marshal(raw)
	var updates config.RouterConfig
	if err := json.Unmarshal(updateBytes, &updates); err != nil {
		api.writeError(w, "Invalid update data", http.StatusBadRequest)
		return
	}
	cfg := api.gateway.GetConfig()
	record, err := api.findRouteRecord(cfg, mux.Vars(r)["id"])
	if err != nil {
		api.writeError(w, err.Error(), http.StatusNotFound)
		return
	}
	simCfg, err := cloneConfig(cfg)
	if err != nil {
		api.writeError(w, "Failed to prepare configuration update", http.StatusInternalServerError)
		return
	}
	svc := &simCfg.Services[record.ServiceConfigIndex].Services[record.ServiceIndex]
	updatedRoute := svc.Routes[record.RouteIndex]
	mergeRouteUpdate(&updatedRoute, updates)
	applyRouteRawUpdate(&updatedRoute, raw)
	svc.Routes[record.RouteIndex] = updatedRoute
	if err := api.gateway.UpdateConfig(simCfg); err != nil {
		api.writeError(w, "Failed to update route", http.StatusInternalServerError)
		return
	}

	response := APIResponse{
		Success: true,
		Message: "Route updated successfully",
	}
	api.writeJSON(w, response)
}

func (api *ManagementAPI) deleteRoute(w http.ResponseWriter, r *http.Request) {
	cfg := api.gateway.GetConfig()
	record, err := api.findRouteRecord(cfg, mux.Vars(r)["id"])
	if err != nil {
		api.writeError(w, err.Error(), http.StatusNotFound)
		return
	}
	simCfg, err := cloneConfig(cfg)
	if err != nil {
		api.writeError(w, "Failed to prepare configuration update", http.StatusInternalServerError)
		return
	}
	svc := &simCfg.Services[record.ServiceConfigIndex].Services[record.ServiceIndex]
	svc.Routes = append(svc.Routes[:record.RouteIndex], svc.Routes[record.RouteIndex+1:]...)
	if err := api.gateway.UpdateConfig(simCfg); err != nil {
		api.writeError(w, "Failed to delete route", http.StatusInternalServerError)
		return
	}

	response := APIResponse{
		Success: true,
		Message: "Route deleted successfully",
	}
	api.writeJSON(w, response)
}

func (api *ManagementAPI) enableRoute(w http.ResponseWriter, r *http.Request) {
	if err := api.setRouteEnabled(mux.Vars(r)["id"], true); err != nil {
		api.writeError(w, err.Error(), http.StatusNotFound)
		return
	}

	response := APIResponse{
		Success: true,
		Message: "Route enabled successfully",
	}
	api.writeJSON(w, response)
}

func (api *ManagementAPI) disableRoute(w http.ResponseWriter, r *http.Request) {
	if err := api.setRouteEnabled(mux.Vars(r)["id"], false); err != nil {
		api.writeError(w, err.Error(), http.StatusNotFound)
		return
	}

	response := APIResponse{
		Success: true,
		Message: "Route disabled successfully",
	}
	api.writeJSON(w, response)
}

func (api *ManagementAPI) getLogs(w http.ResponseWriter, r *http.Request) {
	limit := 100
	if raw := r.URL.Query().Get("limit"); raw != "" {
		fmt.Sscanf(raw, "%d", &limit)
	}
	level := r.URL.Query().Get("level")

	logs := api.logger.RecentLogs(limit, level)
	response := map[string]interface{}{
		"logs":     logs,
		"total":    len(logs),
		"has_more": false,
	}
	api.writeJSON(w, response)
}

func (api *ManagementAPI) streamLogs(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	flusher, ok := w.(http.Flusher)
	if !ok {
		api.writeError(w, "Streaming not supported", http.StatusInternalServerError)
		return
	}

	fmt.Fprintf(w, "event: connected\ndata: {\"message\":\"Connected to log stream\"}\n\n")
	flusher.Flush()

	level := r.URL.Query().Get("level")
	backlog := 20
	if raw := r.URL.Query().Get("backlog"); raw != "" {
		fmt.Sscanf(raw, "%d", &backlog)
	}
	for _, entry := range api.logger.RecentLogs(backlog, level) {
		data, _ := json.Marshal(entry)
		fmt.Fprintf(w, "event: log\ndata: %s\n\n", data)
	}
	flusher.Flush()

	ch := api.logger.SubscribeLogs()
	defer api.logger.UnsubscribeLogs(ch)

	for {
		select {
		case <-r.Context().Done():
			return
		case entry := <-ch:
			if level != "" && !strings.EqualFold(entry.Level, level) {
				continue
			}
			data, _ := json.Marshal(entry)
			fmt.Fprintf(w, "event: log\ndata: %s\n\n", data)
			flusher.Flush()
		}
	}
}

func (api *ManagementAPI) getSystemMetrics(w http.ResponseWriter, r *http.Request) {
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	metrics := map[string]interface{}{
		"process": map[string]interface{}{
			"goroutines": runtime.NumGoroutine(),
			"cpus":       runtime.NumCPU(),
		},
		"memory": map[string]interface{}{
			"alloc_mb":      mem.Alloc / 1024 / 1024,
			"sys_mb":        mem.Sys / 1024 / 1024,
			"heap_alloc_mb": mem.HeapAlloc / 1024 / 1024,
		},
		"storage": map[string]interface{}{
			"admin_dir": adminDataDir(),
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

	level := r.URL.Query().Get("level")
	ch := api.logger.SubscribeLogs()
	defer api.logger.UnsubscribeLogs(ch)

	for _, entry := range api.logger.RecentLogs(20, level) {
		if err := conn.WriteJSON(entry); err != nil {
			return
		}
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	}()

	for {
		select {
		case <-done:
			return
		case entry := <-ch:
			if level != "" && !strings.EqualFold(entry.Level, level) {
				continue
			}
			if err := conn.WriteJSON(entry); err != nil {
				return
			}
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
	certificates, err := loadManagedCertificates()
	if err != nil {
		api.writeError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"certificates": certificates,
	}
	api.writeJSON(w, response)
}

func (api *ManagementAPI) uploadCertificate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name    string `json:"name"`
		Type    string `json:"type"`
		CertPEM string `json:"cert_pem"`
		KeyPEM  string `json:"key_pem"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.writeError(w, "Invalid certificate payload", http.StatusBadRequest)
		return
	}
	meta, err := saveManagedCertificate(req.Name, req.Type, req.CertPEM, req.KeyPEM)
	if err != nil {
		api.writeError(w, err.Error(), http.StatusBadRequest)
		return
	}

	response := APIResponse{
		Success: true,
		Message: "Certificate uploaded successfully",
		Data: map[string]interface{}{
			"certificate_id": meta["id"],
		},
	}
	api.writeJSON(w, response)
}

func (api *ManagementAPI) createEnrollmentToken(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name      string `json:"name"`
		TTLMinute int    `json:"ttl_minutes"`
		ServerURL string `json:"server_url"`
		EnrollURL string `json:"enroll_url"`
		ClientCN  string `json:"client_cn"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.writeError(w, "Invalid enrollment token payload", http.StatusBadRequest)
		return
	}

	if strings.TrimSpace(req.Name) == "" {
		req.Name = "iket-cli"
	}
	if req.TTLMinute <= 0 {
		req.TTLMinute = 15
	}
	if req.TTLMinute > 1440 {
		api.writeError(w, "ttl_minutes must be between 1 and 1440", http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(req.ClientCN) == "" {
		req.ClientCN = sanitizedClientCommonName(req.Name)
	}

	existing, err := listEnrollmentTokenRecords()
	if err != nil {
		api.writeError(w, "Failed to inspect enrollment tokens", http.StatusInternalServerError)
		return
	}
	activeCount := 0
	now := time.Now().UTC()
	for _, record := range existing {
		if isActiveEnrollmentToken(record, now) {
			activeCount++
		}
	}
	maxActive := api.gateway.GetConfig().Security.TLS.EffectiveEnrollmentMaxActive()
	if activeCount >= maxActive {
		api.writeError(w, fmt.Sprintf("active enrollment token limit reached (%d)", maxActive), http.StatusConflict)
		return
	}

	caKey, caCert, caPEM, err := loadEnrollmentCA(api.gateway.GetConfig().Security.TLS)
	if err != nil {
		api.writeError(w, err.Error(), http.StatusBadRequest)
		return
	}
	_ = caKey
	_ = caCert

	id, err := randomHex(6)
	if err != nil {
		api.writeError(w, "Failed to generate enrollment token", http.StatusInternalServerError)
		return
	}
	secret, err := randomHex(16)
	if err != nil {
		api.writeError(w, "Failed to generate enrollment token", http.StatusInternalServerError)
		return
	}

	record := enrollmentTokenRecord{
		ID:        id,
		Name:      req.Name,
		TokenHash: hashEnrollmentSecret(secret),
		CreatedAt: time.Now().UTC(),
		ExpiresAt: time.Now().UTC().Add(time.Duration(req.TTLMinute) * time.Minute),
		ServerURL: strings.TrimSpace(req.ServerURL),
		EnrollURL: strings.TrimSpace(req.EnrollURL),
		ClientCN:  req.ClientCN,
	}
	if err := saveEnrollmentTokenRecord(record); err != nil {
		api.writeError(w, "Failed to persist enrollment token", http.StatusInternalServerError)
		return
	}

	api.logger.Info("Enrollment token created",
		logging.String("event", "enrollment_token_created"),
		logging.String("token_id", id),
		logging.String("token_name", req.Name),
		logging.String("client_cn", req.ClientCN),
		logging.String("client_ip", gateway.GetClientIP(r)),
		logging.Int("ttl_minutes", req.TTLMinute),
		logging.Int("active_tokens", activeCount+1),
	)

	api.writeJSON(w, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"id":         id,
			"name":       req.Name,
			"token":      id + "." + secret,
			"expires_at": record.ExpiresAt,
			"server_url": record.ServerURL,
			"enroll_url": record.EnrollURL,
			"client_cn":  record.ClientCN,
			"ca_pem":     string(caPEM),
		},
	})
}

func (api *ManagementAPI) enrollClientCertificate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token     string `json:"token"`
		Name      string `json:"name"`
		CSRPEM    string `json:"csr_pem"`
		ServerURL string `json:"server_url"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.writeError(w, "Invalid enrollment request", http.StatusBadRequest)
		return
	}

	id, secret, err := parseEnrollmentToken(req.Token)
	if err != nil {
		api.writeError(w, err.Error(), http.StatusBadRequest)
		return
	}
	record, err := loadEnrollmentTokenRecord(id)
	if err != nil {
		api.writeError(w, err.Error(), http.StatusNotFound)
		return
	}
	if record.TokenHash != hashEnrollmentSecret(secret) {
		api.writeError(w, "Invalid enrollment token", http.StatusUnauthorized)
		return
	}
	if !record.UsedAt.IsZero() {
		api.writeError(w, "Enrollment token has already been used", http.StatusConflict)
		return
	}
	if time.Now().UTC().After(record.ExpiresAt) {
		api.writeError(w, "Enrollment token has expired", http.StatusUnauthorized)
		return
	}
	if strings.TrimSpace(req.CSRPEM) == "" {
		api.writeError(w, "csr_pem is required", http.StatusBadRequest)
		return
	}

	caKey, caCert, caPEM, err := loadEnrollmentCA(api.gateway.GetConfig().Security.TLS)
	if err != nil {
		api.writeError(w, err.Error(), http.StatusBadRequest)
		return
	}

	commonName := record.ClientCN
	if commonName == "" {
		commonName = sanitizedClientCommonName(firstNonEmpty(req.Name, record.Name, "iket-cli"))
	}
	certPEM, cert, err := signEnrollmentCSR([]byte(req.CSRPEM), commonName, caKey, caCert)
	if err != nil {
		api.writeError(w, fmt.Sprintf("Failed to sign CSR: %v", err), http.StatusBadRequest)
		return
	}

	record.UsedAt = time.Now().UTC()
	if strings.TrimSpace(req.ServerURL) != "" {
		record.ServerURL = strings.TrimSpace(req.ServerURL)
	}
	if err := saveEnrollmentTokenRecord(*record); err != nil {
		api.writeError(w, "Failed to finalize enrollment token", http.StatusInternalServerError)
		return
	}

	api.logger.Info("Enrollment token redeemed",
		logging.String("event", "enrollment_token_redeemed"),
		logging.String("token_id", record.ID),
		logging.String("token_name", record.Name),
		logging.String("client_cn", commonName),
		logging.String("client_ip", gateway.GetClientIP(r)),
	)

	api.writeJSON(w, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"cert_pem":    string(certPEM),
			"ca_pem":      string(caPEM),
			"server_url":  record.ServerURL,
			"subject":     cert.Subject.String(),
			"valid_until": cert.NotAfter,
		},
	})
}

func (api *ManagementAPI) listEnrollmentTokens(w http.ResponseWriter, r *http.Request) {
	records, err := listEnrollmentTokenRecords()
	if err != nil {
		api.writeError(w, "Failed to list enrollment tokens", http.StatusInternalServerError)
		return
	}
	now := time.Now().UTC()
	items := make([]map[string]interface{}, 0, len(records))
	activeCount := 0
	for _, record := range records {
		active := isActiveEnrollmentToken(record, now)
		if active {
			activeCount++
		}
		items = append(items, map[string]interface{}{
			"id":         record.ID,
			"name":       record.Name,
			"created_at": record.CreatedAt,
			"expires_at": record.ExpiresAt,
			"used_at":    record.UsedAt,
			"server_url": record.ServerURL,
			"enroll_url": record.EnrollURL,
			"client_cn":  record.ClientCN,
			"active":     active,
		})
	}
	api.writeJSON(w, map[string]interface{}{
		"tokens":             items,
		"active_count":       activeCount,
		"max_active_allowed": api.gateway.GetConfig().Security.TLS.EffectiveEnrollmentMaxActive(),
	})
}

func (api *ManagementAPI) revokeEnrollmentToken(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	record, err := loadEnrollmentTokenRecord(id)
	if err != nil {
		api.writeError(w, err.Error(), http.StatusNotFound)
		return
	}
	if err := deleteEnrollmentTokenRecord(id); err != nil {
		api.writeError(w, "Failed to revoke enrollment token", http.StatusInternalServerError)
		return
	}

	api.logger.Info("Enrollment token revoked",
		logging.String("event", "enrollment_token_revoked"),
		logging.String("token_id", id),
		logging.String("token_name", record.Name),
		logging.String("client_ip", gateway.GetClientIP(r)),
	)

	api.writeJSON(w, APIResponse{
		Success: true,
		Message: "Enrollment token revoked",
		Data: map[string]interface{}{
			"id":   id,
			"name": record.Name,
		},
	})
}

func (api *ManagementAPI) deleteCertificate(w http.ResponseWriter, r *http.Request) {
	if err := deleteManagedCertificate(mux.Vars(r)["id"]); err != nil {
		api.writeError(w, err.Error(), http.StatusNotFound)
		return
	}

	response := APIResponse{
		Success: true,
		Message: "Certificate deleted successfully",
	}
	api.writeJSON(w, response)
}

// Backup & restore (placeholder implementations)

func (api *ManagementAPI) createBackup(w http.ResponseWriter, r *http.Request) {
	backupID, filePath, size, err := createConfigBackup(api.gateway.GetConfig())
	if err != nil {
		api.writeError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	response := APIResponse{
		Success: true,
		Message: "Backup created successfully",
		Data: map[string]interface{}{
			"backup_id":  backupID,
			"filename":   filepath.Base(filePath),
			"size_bytes": size,
			"created_at": time.Now(),
		},
	}
	api.writeJSON(w, response)
}

func (api *ManagementAPI) listBackups(w http.ResponseWriter, r *http.Request) {
	backups, err := listConfigBackups()
	if err != nil {
		api.writeError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"backups": backups,
	}
	api.writeJSON(w, response)
}

func (api *ManagementAPI) restoreBackup(w http.ResponseWriter, r *http.Request) {
	if err := restoreConfigBackup(api.gateway, mux.Vars(r)["id"]); err != nil {
		api.writeError(w, err.Error(), http.StatusNotFound)
		return
	}
	api.lastReload = time.Now()

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

type routeRecord struct {
	ID                 string
	ServiceConfigIndex int
	ServiceIndex       int
	RouteIndex         int
	Service            config.Service
	Route              config.RouterConfig
	EffectivePath      string
}

func cloneConfig(cfg *config.Config) (*config.Config, error) {
	data, err := json.Marshal(cfg)
	if err != nil {
		return nil, err
	}
	var cloned config.Config
	if err := json.Unmarshal(data, &cloned); err != nil {
		return nil, err
	}
	return &cloned, nil
}

func (api *ManagementAPI) routeRecords(cfg *config.Config) []routeRecord {
	if cfg == nil {
		return nil
	}
	records := make([]routeRecord, 0)
	for sci, svcCfg := range cfg.Services {
		for si, svc := range svcCfg.Services {
			for ri, route := range svc.Routes {
				records = append(records, routeRecord{
					ID:                 stableRouteID(svc.Name, svc.EffectiveRoutePath(route), route.EffectiveMethods()),
					ServiceConfigIndex: sci,
					ServiceIndex:       si,
					RouteIndex:         ri,
					Service:            svc,
					Route:              route,
					EffectivePath:      svc.EffectiveRoutePath(route),
				})
			}
		}
	}
	return records
}

func (api *ManagementAPI) routeInfoFromRecord(record routeRecord) RouteInfo {
	timeout := 0
	if record.Route.Timeout != nil {
		timeout = int(record.Route.Timeout.Seconds())
	}
	return RouteInfo{
		ID:          record.ID,
		Path:        record.EffectivePath,
		Destination: record.Service.Host,
		Methods:     record.Route.EffectiveMethods(),
		RequireAuth: record.Route.RequireAuth,
		Timeout:     timeout,
		StripPath:   record.Route.StripPath,
		Enabled:     record.Route.IsEnabled(),
		Stats: map[string]interface{}{
			"requests": len(api.logger.RecentLogs(500, "")),
			"errors":   len(api.logger.RecentLogs(500, "error")),
		},
	}
}

func stableRouteID(serviceName, effectivePath string, methods []string) string {
	normalizedMethods := make([]string, len(methods))
	copy(normalizedMethods, methods)
	for i := range normalizedMethods {
		normalizedMethods[i] = strings.ToUpper(normalizedMethods[i])
	}
	payload := strings.Join([]string{serviceName, effectivePath, strings.Join(normalizedMethods, ",")}, "|")
	sum := sha1.Sum([]byte(payload))
	return fmt.Sprintf("route-%x", sum[:6])
}

func (api *ManagementAPI) findRouteRecord(cfg *config.Config, id string) (routeRecord, error) {
	for _, record := range api.routeRecords(cfg) {
		if record.ID == id {
			return record, nil
		}
	}
	return routeRecord{}, fmt.Errorf("route not found")
}

func (api *ManagementAPI) findRouteByServicePathMethod(cfg *config.Config, serviceName, path string, methods []string) (routeRecord, error) {
	for _, record := range api.routeRecords(cfg) {
		if record.Service.Name == serviceName && record.Route.Path == path && sameMethods(record.Route.EffectiveMethods(), methods) {
			return record, nil
		}
	}
	return routeRecord{}, fmt.Errorf("route not found")
}

func sameMethods(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	seen := make(map[string]int, len(a))
	for _, m := range a {
		seen[strings.ToUpper(m)]++
	}
	for _, m := range b {
		key := strings.ToUpper(m)
		if seen[key] == 0 {
			return false
		}
		seen[key]--
	}
	return true
}

func findServiceByName(cfg *config.Config, name string) (*config.Service, error) {
	for sci := range cfg.Services {
		for si := range cfg.Services[sci].Services {
			if cfg.Services[sci].Services[si].Name == name {
				return &cfg.Services[sci].Services[si], nil
			}
		}
	}
	return nil, fmt.Errorf("service not found")
}

func mergeRouteUpdate(dst *config.RouterConfig, src config.RouterConfig) {
	if src.Path != "" {
		dst.Path = src.Path
	}
	if src.Method != "" {
		dst.Method = src.Method
	}
	if len(src.Methods) > 0 {
		dst.Methods = src.Methods
	}
	if src.Enabled != nil {
		dst.Enabled = src.Enabled
	}
	if src.RequireAuth {
		dst.RequireAuth = src.RequireAuth
	}
	if src.RequireJwt {
		dst.RequireJwt = src.RequireJwt
	}
	if src.StripPath {
		dst.StripPath = src.StripPath
	}
	if src.Name != "" {
		dst.Name = src.Name
	}
	if src.Description != "" {
		dst.Description = src.Description
	}
	if len(src.Backends) > 0 {
		dst.Backends = src.Backends
	}
	if len(src.Headers) > 0 {
		dst.Headers = src.Headers
	}
	if len(src.Scopes) > 0 {
		dst.Scopes = src.Scopes
	}
	if len(src.Roles) > 0 {
		dst.Roles = src.Roles
	}
	if src.AuthPlugin != "" {
		dst.AuthPlugin = src.AuthPlugin
	}
}

func applyRouteRawUpdate(dst *config.RouterConfig, raw map[string]interface{}) {
	if value, ok := raw["requireAuth"].(bool); ok {
		dst.RequireAuth = value
	}
	if value, ok := raw["requireJwt"].(bool); ok {
		dst.RequireJwt = value
	}
	if value, ok := raw["stripPath"].(bool); ok {
		dst.StripPath = value
	}
	if value, ok := raw["enabled"].(bool); ok {
		dst.Enabled = config.NewBool(value)
	}
}

func (api *ManagementAPI) setRouteEnabled(id string, enabled bool) error {
	cfg := api.gateway.GetConfig()
	record, err := api.findRouteRecord(cfg, id)
	if err != nil {
		return err
	}
	simCfg, err := cloneConfig(cfg)
	if err != nil {
		return err
	}
	simCfg.Services[record.ServiceConfigIndex].Services[record.ServiceIndex].Routes[record.RouteIndex].Enabled = config.NewBool(enabled)
	return api.gateway.UpdateConfig(simCfg)
}

func (api *ManagementAPI) pluginEnabled(name string) bool {
	cfg := api.gateway.GetConfig()
	if cfg == nil {
		return false
	}
	pluginCfg, ok := cfg.GetPluginConfig(name)
	if !ok {
		return false
	}
	if enabled, ok := pluginCfg["enabled"].(bool); ok {
		return enabled
	}
	return true
}

func (api *ManagementAPI) setPluginEnabled(name string, enabled bool) error {
	p, err := api.registry.Get(name)
	if err != nil {
		return fmt.Errorf("plugin not found")
	}
	cfg := api.gateway.GetConfig()
	if cfg == nil {
		return fmt.Errorf("configuration not available")
	}
	simCfg, err := cloneConfig(cfg)
	if err != nil {
		return err
	}
	pluginCfg, _ := simCfg.GetPluginConfig(name)
	if pluginCfg == nil {
		pluginCfg = map[string]interface{}{}
	}
	pluginCfg["enabled"] = enabled
	simCfg.SetPluginConfig(name, pluginCfg)
	if err := p.Initialize(pluginCfg); err != nil {
		return err
	}
	return api.gateway.UpdateConfig(simCfg)
}

func adminDataDir() string {
	return filepath.Join(".iket-admin")
}

func certificatesDir() string {
	return filepath.Join(adminDataDir(), "certificates")
}

func backupsDir() string {
	return filepath.Join(adminDataDir(), "backups")
}

func enrollmentTokensDir() string {
	return filepath.Join(adminDataDir(), "enrollment-tokens")
}

type enrollmentTokenRecord struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	TokenHash string    `json:"token_hash"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	UsedAt    time.Time `json:"used_at,omitempty"`
	ServerURL string    `json:"server_url,omitempty"`
	EnrollURL string    `json:"enroll_url,omitempty"`
	ClientCN  string    `json:"client_cn,omitempty"`
}

func loadManagedCertificates() ([]map[string]interface{}, error) {
	if err := os.MkdirAll(certificatesDir(), 0755); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(certificatesDir())
	if err != nil {
		return nil, err
	}
	out := make([]map[string]interface{}, 0)
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(certificatesDir(), entry.Name()))
		if err != nil {
			continue
		}
		var meta map[string]interface{}
		if err := json.Unmarshal(data, &meta); err == nil {
			out = append(out, meta)
		}
	}
	return out, nil
}

func saveManagedCertificate(name, certType, certPEM, keyPEM string) (map[string]interface{}, error) {
	if name == "" || certPEM == "" {
		return nil, fmt.Errorf("name and cert_pem are required")
	}
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return nil, fmt.Errorf("invalid cert_pem")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("invalid certificate: %w", err)
	}
	if err := os.MkdirAll(certificatesDir(), 0755); err != nil {
		return nil, err
	}
	sum := sha1.Sum([]byte(name + cert.Subject.String() + time.Now().String()))
	id := fmt.Sprintf("%x", sum[:6])
	meta := map[string]interface{}{
		"id":          id,
		"name":        name,
		"type":        certType,
		"subject":     cert.Subject.String(),
		"issuer":      cert.Issuer.String(),
		"valid_from":  cert.NotBefore,
		"valid_until": cert.NotAfter,
		"status":      "valid",
		"cert_pem":    certPEM,
	}
	if keyPEM != "" {
		meta["key_pem"] = keyPEM
	}
	data, _ := json.MarshalIndent(meta, "", "  ")
	if err := os.WriteFile(filepath.Join(certificatesDir(), id+".json"), data, 0644); err != nil {
		return nil, err
	}
	return meta, nil
}

func deleteManagedCertificate(id string) error {
	path := filepath.Join(certificatesDir(), id+".json")
	if _, err := os.Stat(path); err != nil {
		return fmt.Errorf("certificate not found")
	}
	return os.Remove(path)
}

func saveEnrollmentTokenRecord(record enrollmentTokenRecord) error {
	if err := os.MkdirAll(enrollmentTokensDir(), 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(enrollmentTokensDir(), record.ID+".json"), data, 0600)
}

func loadEnrollmentTokenRecord(id string) (*enrollmentTokenRecord, error) {
	data, err := os.ReadFile(filepath.Join(enrollmentTokensDir(), id+".json"))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("enrollment token not found")
		}
		return nil, err
	}
	var record enrollmentTokenRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return nil, err
	}
	return &record, nil
}

func listEnrollmentTokenRecords() ([]enrollmentTokenRecord, error) {
	if err := os.MkdirAll(enrollmentTokensDir(), 0700); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(enrollmentTokensDir())
	if err != nil {
		return nil, err
	}
	out := make([]enrollmentTokenRecord, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(enrollmentTokensDir(), entry.Name()))
		if err != nil {
			continue
		}
		var record enrollmentTokenRecord
		if err := json.Unmarshal(data, &record); err == nil {
			out = append(out, record)
		}
	}
	return out, nil
}

func deleteEnrollmentTokenRecord(id string) error {
	path := filepath.Join(enrollmentTokensDir(), id+".json")
	if _, err := os.Stat(path); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("enrollment token not found")
		}
		return err
	}
	return os.Remove(path)
}

func isActiveEnrollmentToken(record enrollmentTokenRecord, now time.Time) bool {
	return record.UsedAt.IsZero() && now.Before(record.ExpiresAt)
}

func parseEnrollmentToken(token string) (string, string, error) {
	parts := strings.SplitN(strings.TrimSpace(token), ".", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", fmt.Errorf("invalid enrollment token")
	}
	return parts[0], parts[1], nil
}

func hashEnrollmentSecret(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

func randomHex(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

func loadEnrollmentCA(tlsCfg config.TLSConfig) (*rsa.PrivateKey, *x509.Certificate, []byte, error) {
	if tlsCfg.ClientCAFile == "" {
		return nil, nil, nil, fmt.Errorf("client CA is not configured")
	}
	caPEM, err := os.ReadFile(tlsCfg.ClientCAFile)
	if err != nil {
		return nil, nil, nil, err
	}
	caBlock, _ := pem.Decode(caPEM)
	if caBlock == nil {
		return nil, nil, nil, fmt.Errorf("invalid client CA certificate")
	}
	caCert, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		return nil, nil, nil, err
	}

	caKeyPath := filepath.Join(filepath.Dir(tlsCfg.ClientCAFile), "ca.key")
	caKeyPEM, err := os.ReadFile(caKeyPath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil, nil, fmt.Errorf("ca.key not found next to %s; enrollment requires a locally managed CA", tlsCfg.ClientCAFile)
		}
		return nil, nil, nil, err
	}
	keyBlock, _ := pem.Decode(caKeyPEM)
	if keyBlock == nil {
		return nil, nil, nil, fmt.Errorf("invalid ca private key")
	}
	caKey, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, nil, nil, err
	}
	return caKey, caCert, caPEM, nil
}

func signEnrollmentCSR(csrPEM []byte, commonName string, caKey *rsa.PrivateKey, caCert *x509.Certificate) ([]byte, *x509.Certificate, error) {
	block, _ := pem.Decode(csrPEM)
	if block == nil {
		return nil, nil, fmt.Errorf("invalid csr_pem")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, nil, err
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, nil, err
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{"Iket"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, csr.PublicKey, caKey)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}), cert, nil
}

func createConfigBackup(cfg *config.Config) (string, string, int64, error) {
	if err := os.MkdirAll(backupsDir(), 0755); err != nil {
		return "", "", 0, err
	}
	id := fmt.Sprintf("backup-%s", time.Now().Format("20060102-150405"))
	path := filepath.Join(backupsDir(), id+".json")
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return "", "", 0, err
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		return "", "", 0, err
	}
	return id, path, int64(len(data)), nil
}

func listConfigBackups() ([]map[string]interface{}, error) {
	if err := os.MkdirAll(backupsDir(), 0755); err != nil {
		return nil, err
	}
	files, err := os.ReadDir(backupsDir())
	if err != nil {
		return nil, err
	}
	backups := make([]map[string]interface{}, 0)
	for _, file := range files {
		if file.IsDir() || filepath.Ext(file.Name()) != ".json" {
			continue
		}
		info, err := file.Info()
		if err != nil {
			continue
		}
		backups = append(backups, map[string]interface{}{
			"id":         strings.TrimSuffix(file.Name(), ".json"),
			"filename":   file.Name(),
			"size_bytes": info.Size(),
			"created_at": info.ModTime(),
		})
	}
	return backups, nil
}

func restoreConfigBackup(gw *gateway.Gateway, id string) error {
	path := filepath.Join(backupsDir(), id+".json")
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("backup not found")
		}
		return err
	}
	var cfg config.Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return err
	}
	return gw.UpdateConfig(&cfg)
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

func sanitizedClientCommonName(name string) string {
	name = strings.TrimSpace(strings.ToLower(name))
	if name == "" {
		return "iket-cli"
	}
	var b strings.Builder
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '-' || r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		return "iket-cli"
	}
	return out
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func (api *ManagementAPI) getServices(w http.ResponseWriter, r *http.Request) {
	cfg := api.gateway.GetConfig()
	if cfg == nil {
		api.writeError(w, "Configuration not available", http.StatusInternalServerError)
		return
	}

	// Redact sensitive info if needed (e.g., backend URLs, secrets)
	services := make([]map[string]interface{}, 0)
	for _, svcConfig := range cfg.Services {
		for _, svc := range svcConfig.Services {
			serviceInfo := map[string]interface{}{
				"name":        svc.Name,
				"description": svc.Description,
				"host":        svc.Host,
				"base_path":   svc.BasePath,
				"tags":        svc.Tags,
				"group":       svc.Group,
				"scopes":      svc.Scopes,
				"routes":      make([]map[string]interface{}, 0),
			}
			for _, route := range svc.Routes {
				routeInfo := map[string]interface{}{
					"path":        route.Path,
					"method":      route.Method,
					"methods":     route.EffectiveMethods(),
					"name":        route.Name,
					"description": route.Description,
					"tags":        route.Tags,
					"group":       route.Group,
					"priority":    route.Priority,
					"enabled":     route.IsEnabled(),
					"requireAuth": route.RequireAuth,
					"requireJwt":  route.RequireJwt,
					"stripPath":   route.StripPath,
					"scopes":      route.Scopes,
					"roles":       route.Roles,
					"auth_plugin": route.AuthPlugin,
					"backend":     route.Backends,
					"rateLimit":   route.RateLimit,
					"headers":     route.Headers,
				}
				serviceInfo["routes"] = append(serviceInfo["routes"].([]map[string]interface{}), routeInfo)
			}
			services = append(services, serviceInfo)
		}
	}
	response := map[string]interface{}{
		"services": services,
	}
	api.writeJSON(w, response)
}

// POST /api/v1/services
func (api *ManagementAPI) createService(w http.ResponseWriter, r *http.Request) {
	strategy := r.URL.Query().Get("strategy")
	if strategy == "" {
		strategy = "merge"
	}
	dryRun := r.URL.Query().Get("dry_run") == "true"

	cfg := api.gateway.GetConfig()
	if cfg == nil {
		api.writeError(w, "Configuration not available", http.StatusInternalServerError)
		return
	}
	var req struct {
		Services []config.Service `json:"services"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.writeError(w, "Invalid service definition", http.StatusBadRequest)
		return
	}

	// Create a working copy for simulation
	simCfg := *cfg
	// Deep copy services slice to avoid mutating live state during merge simulation
	simServices := make([]config.ServiceConfig, len(cfg.Services))
	copy(simServices, cfg.Services)
	simCfg.Services = simServices

	if strategy == "replace" {
		simCfg.Services = []config.ServiceConfig{{Version: 1, Services: []config.Service{}}}
	} else if len(simCfg.Services) == 0 {
		simCfg.Services = []config.ServiceConfig{{Version: 1, Services: []config.Service{}}}
	}

	addedRoutes := []map[string]interface{}{}
	updatedRoutes := []map[string]interface{}{}
	addedServices := 0

	for _, newSvc := range req.Services {
		found := false
		for i, svc := range simCfg.Services[0].Services {
			if (newSvc.Name != "" && svc.Name == newSvc.Name) || (newSvc.Name == "" && svc.Host == newSvc.Host) {
				found = true
				for _, newRoute := range newSvc.Routes {
					routeFound := false
					for k, existRoute := range svc.Routes {
						if existRoute.Path == newRoute.Path && existRoute.Method == newRoute.Method {
							simCfg.Services[0].Services[i].Routes[k] = newRoute
							updatedRoutes = append(updatedRoutes, map[string]interface{}{"path": newRoute.Path, "method": newRoute.Method, "service": svc.Name})
							routeFound = true
							break
						}
					}
					if !routeFound {
						simCfg.Services[0].Services[i].Routes = append(simCfg.Services[0].Services[i].Routes, newRoute)
						addedRoutes = append(addedRoutes, map[string]interface{}{"path": newRoute.Path, "method": newRoute.Method, "service": svc.Name})
					}
				}
				if newSvc.Host != "" {
					simCfg.Services[0].Services[i].Host = newSvc.Host
				}
				break
			}
		}
		if !found {
			simCfg.Services[0].Services = append(simCfg.Services[0].Services, newSvc)
			addedServices++
			for _, newRoute := range newSvc.Routes {
				addedRoutes = append(addedRoutes, map[string]interface{}{"path": newRoute.Path, "method": newRoute.Method, "service": newSvc.Name})
			}
		}
	}

	if dryRun {
		msg := fmt.Sprintf("[DRY RUN] %d service(s) would be added, %d route(s) would be added, %d route(s) would be updated", addedServices, len(addedRoutes), len(updatedRoutes))
		api.writeJSON(w, map[string]interface{}{
			"success":        true,
			"dry_run":        true,
			"added_services": addedServices,
			"added_routes":   addedRoutes,
			"updated_routes": updatedRoutes,
			"message":        msg,
		})
		return
	}

	api.gateway.UpdateConfig(&simCfg)
	msg := fmt.Sprintf("%d service(s) added, %d route(s) added, %d route(s) updated", addedServices, len(addedRoutes), len(updatedRoutes))
	api.writeJSON(w, map[string]interface{}{
		"success":        true,
		"added_services": addedServices,
		"added_routes":   addedRoutes,
		"updated_routes": updatedRoutes,
		"message":        msg,
	})
}

// PUT /api/v1/services/{name}
func (api *ManagementAPI) updateService(w http.ResponseWriter, r *http.Request) {
	dryRun := r.URL.Query().Get("dry_run") == "true"
	cfg := api.gateway.GetConfig()
	if cfg == nil {
		api.writeError(w, "Configuration not available", http.StatusInternalServerError)
		return
	}
	name := mux.Vars(r)["name"]
	var update config.Service
	if err := json.NewDecoder(r.Body).Decode(&update); err != nil {
		api.writeError(w, "Invalid service definition", http.StatusBadRequest)
		return
	}

	// Create a working copy for simulation
	simCfg := *cfg
	// Deep copy services slice to avoid mutating live state
	simServices := make([]config.ServiceConfig, len(cfg.Services))
	for i := range cfg.Services {
		simServices[i] = cfg.Services[i]
		// Deep copy the services within each ServiceConfig
		simServices[i].Services = make([]config.Service, len(cfg.Services[i].Services))
		copy(simServices[i].Services, cfg.Services[i].Services)
	}
	simCfg.Services = simServices

	updated := false
	addedRoutes := []map[string]interface{}{}
	updatedRoutes := []map[string]interface{}{}
	for i, svcConfig := range simCfg.Services {
		for j, svc := range svcConfig.Services {
			if svc.Name == name {
				existingRoutes := svc.Routes
				for _, newRoute := range update.Routes {
					found := false
					for k, existRoute := range existingRoutes {
						if existRoute.Path == newRoute.Path && existRoute.Method == newRoute.Method {
							simCfg.Services[i].Services[j].Routes[k] = newRoute
							updatedRoutes = append(updatedRoutes, map[string]interface{}{"path": newRoute.Path, "method": newRoute.Method})
							found = true
							break
						}
					}
					if !found {
						simCfg.Services[i].Services[j].Routes = append(simCfg.Services[i].Services[j].Routes, newRoute)
						addedRoutes = append(addedRoutes, map[string]interface{}{"path": newRoute.Path, "method": newRoute.Method})
					}
				}
				// Optionally update other service fields
				simCfg.Services[i].Services[j].Description = update.Description
				simCfg.Services[i].Services[j].Host = update.Host
				simCfg.Services[i].Services[j].BasePath = update.BasePath
				simCfg.Services[i].Services[j].Tags = update.Tags
				simCfg.Services[i].Services[j].Group = update.Group
				updated = true
				break
			}
		}
	}
	if !updated {
		api.writeError(w, "Service not found", http.StatusNotFound)
		return
	}

	if dryRun {
		msg := fmt.Sprintf("[DRY RUN] %d route(s) would be updated, %d would be added for service %q", len(updatedRoutes), len(addedRoutes), name)
		api.writeJSON(w, map[string]interface{}{
			"success":        true,
			"dry_run":        true,
			"updated_routes": updatedRoutes,
			"added_routes":   addedRoutes,
			"message":        msg,
		})
		return
	}

	api.gateway.UpdateConfig(&simCfg)
	msg := fmt.Sprintf("%d route(s) updated, %d added for service %q", len(updatedRoutes), len(addedRoutes), name)
	api.writeJSON(w, map[string]interface{}{
		"success":        true,
		"updated_routes": updatedRoutes,
		"added_routes":   addedRoutes,
		"message":        msg,
	})
}

// DELETE /api/v1/services/{name}
func (api *ManagementAPI) deleteService(w http.ResponseWriter, r *http.Request) {
	cfg := api.gateway.GetConfig()
	if cfg == nil {
		api.writeError(w, "Configuration not available", http.StatusInternalServerError)
		return
	}
	name := mux.Vars(r)["name"]
	deleted := false
	for i, svcConfig := range cfg.Services {
		for j, svc := range svcConfig.Services {
			if svc.Name == name {
				cfg.Services[i].Services = append(cfg.Services[i].Services[:j], cfg.Services[i].Services[j+1:]...)
				deleted = true
				break
			}
		}
	}
	if !deleted {
		api.writeError(w, "Service not found", http.StatusNotFound)
		return
	}
	api.gateway.UpdateConfig(cfg)
	api.writeJSON(w, APIResponse{Success: true, Message: "Service deleted successfully"})
}

func (api *ManagementAPI) listClients(w http.ResponseWriter, r *http.Request) {
	p, err := api.registry.Get("apikey")
	if err != nil {
		api.writeJSON(w, map[string]interface{}{"clients": []interface{}{}})
		return
	}

	// Use reflection to call ListClients if it exists
	val := reflect.ValueOf(p)
	method := val.MethodByName("ListClients")
	if !method.IsValid() {
		api.writeError(w, "Plugin does not support client listing", http.StatusNotImplemented)
		return
	}

	results := method.Call(nil)
	api.writeJSON(w, map[string]interface{}{"clients": results[0].Interface()})
}

func (api *ManagementAPI) addClient(w http.ResponseWriter, r *http.Request) {
	var client struct {
		ID     string   `json:"id"`
		Name   string   `json:"name"`
		Key    string   `json:"key"`
		Group  string   `json:"group"`
		Scopes []string `json:"scopes"`
		Tags   []string `json:"tags"`
	}

	if err := json.NewDecoder(r.Body).Decode(&client); err != nil {
		api.writeError(w, "Invalid client data", http.StatusBadRequest)
		return
	}

	p, err := api.registry.Get("apikey")
	if err != nil {
		api.writeError(w, "API Key plugin not found or not enabled", http.StatusNotFound)
		return
	}

	// Actually, easier if we just update config and re-initialize plugin
	cfg := api.gateway.GetConfig()
	pluginCfg, ok := cfg.GetPluginConfig("apikey")
	if !ok {
		pluginCfg = make(map[string]interface{})
	}

	clients, _ := pluginCfg["clients"].([]interface{})
	// Check if key already exists
	for _, c := range clients {
		if m, ok := c.(map[string]interface{}); ok {
			if m["key"] == client.Key {
				api.writeError(w, "Client with this key already exists", http.StatusConflict)
				return
			}
		}
	}

	clients = append(clients, map[string]interface{}{
		"id":     client.ID,
		"name":   client.Name,
		"key":    client.Key,
		"group":  client.Group,
		"scopes": client.Scopes,
		"tags":   client.Tags,
	})
	pluginCfg["clients"] = clients
	cfg.SetPluginConfig("apikey", pluginCfg)

	if err := api.gateway.UpdateConfig(cfg); err != nil {
		api.writeError(w, "Failed to save configuration", http.StatusInternalServerError)
		return
	}

	// Re-initialize plugin
	if err := p.Initialize(pluginCfg); err != nil {
		api.writeError(w, "Failed to re-initialize plugin", http.StatusInternalServerError)
		return
	}

	api.writeJSON(w, APIResponse{Success: true, Message: "Client added successfully"})
}

func (api *ManagementAPI) removeClient(w http.ResponseWriter, r *http.Request) {
	key := mux.Vars(r)["key"]

	p, err := api.registry.Get("apikey")
	if err != nil {
		api.writeError(w, "API Key plugin not found", http.StatusNotFound)
		return
	}

	cfg := api.gateway.GetConfig()
	pluginCfg, ok := cfg.GetPluginConfig("apikey")
	if !ok {
		api.writeError(w, "Plugin configuration not found", http.StatusNotFound)
		return
	}

	clients, ok := pluginCfg["clients"].([]interface{})
	if !ok {
		api.writeError(w, "No clients configured", http.StatusNotFound)
		return
	}

	newClients := []interface{}{}
	found := false
	for _, c := range clients {
		if m, ok := c.(map[string]interface{}); ok {
			if m["key"] == key {
				found = true
				continue
			}
		}
		newClients = append(newClients, c)
	}

	if !found {
		api.writeError(w, "Client not found", http.StatusNotFound)
		return
	}

	pluginCfg["clients"] = newClients
	cfg.SetPluginConfig("apikey", pluginCfg)

	if err := api.gateway.UpdateConfig(cfg); err != nil {
		api.writeError(w, "Failed to save configuration", http.StatusInternalServerError)
		return
	}

	// Re-initialize plugin
	if err := p.Initialize(pluginCfg); err != nil {
		api.writeError(w, "Failed to re-initialize plugin", http.StatusInternalServerError)
		return
	}

	api.writeJSON(w, APIResponse{Success: true, Message: "Client removed successfully"})
}
