package api

import (
	"net/http"
	"time"

	"github.com/bhangun/iket/pkg/app"
	"github.com/bhangun/iket/pkg/core/gateway"
	"github.com/bhangun/iket/pkg/logging"
)

// Gateway Status Response
type GatewayStatus struct {
	Status            string          `json:"status"`
	Uptime            string          `json:"uptime"`
	Version           string          `json:"version"`
	Edition           app.EditionInfo `json:"edition"`
	StartTime         time.Time       `json:"start_time"`
	ConfigLoaded      bool            `json:"config_loaded"`
	LastReload        time.Time       `json:"last_reload"`
	ActiveConnections int             `json:"active_connections"`
	TotalRequests     int64           `json:"total_requests"`
	ErrorCount        int             `json:"error_count"`
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

func (api *ManagementAPI) getGatewayStatus(w http.ResponseWriter, r *http.Request) {
	clientIP := gateway.GetClientIP(r)
	api.logger.Info("gateway/status requested",
		logging.String("client_ip", clientIP),
		logging.String("path", r.URL.Path),
	)

	api.mu.RLock()
	defer api.mu.RUnlock()

	status := GatewayStatus{
		Status:            "running",
		Uptime:            time.Since(api.startedAt).Round(time.Second).String(),
		Version:           api.gateway.Version(),
		Edition:           app.CurrentEdition(),
		StartTime:         api.startedAt,
		ConfigLoaded:      api.gateway.GetConfig() != nil,
		LastReload:        api.lastReload,
		ActiveConnections: 0,
		TotalRequests:     int64(len(api.logger.RecentLogs(2000, ""))),
		ErrorCount:        len(api.logger.RecentLogs(2000, "error")),
	}

	api.writeJSON(w, status)
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

func (api *ManagementAPI) getGatewayBackends(w http.ResponseWriter, r *http.Request) {
	backends := api.gateway.BackendStatuses()
	api.writeJSON(w, map[string]interface{}{
		"backends": backends,
		"total":    len(backends),
	})
}
