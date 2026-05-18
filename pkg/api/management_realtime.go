package api

import (
	"encoding/json"
	"fmt"
	coreerrors "github.com/bhangun/iket/pkg/core/errors"
	"github.com/bhangun/iket/pkg/logging"
	"github.com/gorilla/websocket"
	"net/http"
	"runtime"
	"strings"
	"time"
)

func (api *ManagementAPI) getLogs(w http.ResponseWriter, r *http.Request) {
	limit := 100
	if raw := r.URL.Query().Get("limit"); raw != "" {
		fmt.Sscanf(raw, "%d", &limit)
	}
	level := r.URL.Query().Get("level")
	serviceName := r.URL.Query().Get("service")
	routeName := r.URL.Query().Get("route")
	requestID := r.URL.Query().Get("request_id")

	logs := filterLogEntries(api.logger.RecentLogs(2000, level), serviceName, routeName, requestID)
	if limit > 0 && len(logs) > limit {
		logs = logs[len(logs)-limit:]
	}
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
		api.writeManagedError(w, managedError(coreerrors.CodeFeatureNotSupported, "Streaming not supported", nil), http.StatusInternalServerError)
		return
	}

	fmt.Fprintf(w, "event: connected\ndata: {\"message\":\"Connected to log stream\"}\n\n")
	flusher.Flush()

	level := r.URL.Query().Get("level")
	serviceName := r.URL.Query().Get("service")
	routeName := r.URL.Query().Get("route")
	requestID := r.URL.Query().Get("request_id")
	backlog := 20
	if raw := r.URL.Query().Get("backlog"); raw != "" {
		fmt.Sscanf(raw, "%d", &backlog)
	}
	backlogEntries := filterLogEntries(api.logger.RecentLogs(2000, level), serviceName, routeName, requestID)
	if backlog > 0 && len(backlogEntries) > backlog {
		backlogEntries = backlogEntries[len(backlogEntries)-backlog:]
	}
	for _, entry := range backlogEntries {
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
			if !logEntryMatches(entry, serviceName, routeName, requestID) {
				continue
			}
			data, _ := json.Marshal(entry)
			fmt.Fprintf(w, "event: log\ndata: %s\n\n", data)
			flusher.Flush()
		}
	}
}

func filterLogEntries(entries []logging.LogEntry, serviceName, routeName, requestID string) []logging.LogEntry {
	if serviceName == "" && routeName == "" && requestID == "" {
		return entries
	}
	filtered := make([]logging.LogEntry, 0, len(entries))
	for _, entry := range entries {
		if logEntryMatches(entry, serviceName, routeName, requestID) {
			filtered = append(filtered, entry)
		}
	}
	return filtered
}

func logEntryMatches(entry logging.LogEntry, serviceName, routeName, requestID string) bool {
	if serviceName != "" && fieldString(entry.Fields, "service_name") != serviceName {
		return false
	}
	if routeName != "" && fieldString(entry.Fields, "route_name") != routeName {
		return false
	}
	if requestID != "" && fieldString(entry.Fields, "request_id") != requestID {
		return false
	}
	return true
}

func fieldString(fields map[string]interface{}, key string) string {
	if len(fields) == 0 {
		return ""
	}
	if value, ok := fields[key]; ok {
		return fmt.Sprint(value)
	}
	return ""
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
