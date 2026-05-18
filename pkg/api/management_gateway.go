package api

import (
	"encoding/json"
	"fmt"
	"github.com/bhangun/iket/pkg/app"
	"github.com/bhangun/iket/pkg/config"
	coreerrors "github.com/bhangun/iket/pkg/core/errors"
	"github.com/bhangun/iket/pkg/core/gateway"
	"github.com/bhangun/iket/pkg/logging"
	"net/http"
	"strconv"
	"strings"
	"time"
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

func (api *ManagementAPI) getGatewayConfig(w http.ResponseWriter, r *http.Request) {
	api.mu.RLock()
	defer api.mu.RUnlock()

	cfg := api.gateway.GetConfig()
	if cfg == nil {
		api.writeManagedError(w, managedError(coreerrors.CodeConfigNotAvailable, "Configuration not available", nil), http.StatusInternalServerError)
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
		api.writeManagedError(w, managedError(coreerrors.CodeConfigNotAvailable, "Configuration not available", nil), http.StatusInternalServerError)
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

				vars, matched := gateway.MatchRouteTemplate(route, sampleMethod, samplePath, nil)
				result.Matched = matched
				if matched {
					result.RouteVars = vars
					proxiedPath, err := gateway.ComputeProxiedPath(&service, route, samplePath, vars)
					if err != nil {
						api.writeManagedError(w, managedConfigError(fmt.Sprintf("Failed to compute proxied path for route %s", route.Path), err), http.StatusInternalServerError)
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
	proposalOnly := r.URL.Query().Get("proposal") == "true"

	var input map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		api.writeManagedError(w, managedValidationError("Invalid configuration format", err), http.StatusBadRequest)
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
			api.writeManagedError(w, managedConfigError("Failed to merge configuration", err), http.StatusInternalServerError)
			return
		}
	} else {
		newJSON, _ := json.Marshal(input)
		if err := json.Unmarshal(newJSON, &simCfg); err != nil {
			api.writeManagedError(w, managedValidationError("Invalid configuration", err), http.StatusBadRequest)
			return
		}
	}

	// Validate configuration
	if err := simCfg.Validate(); err != nil {
		api.writeManagedError(w, managedError(coreerrors.CodeConfigInvalid, "Invalid configuration", err), http.StatusBadRequest)
		return
	}

	summary := configChangeSummary(currentCfg, &simCfg)

	if dryRun {
		response := APIResponse{
			Success: true,
			Message: fmt.Sprintf("[DRY RUN] Configuration is valid and %s-ready", strategy),
			Data: map[string]interface{}{
				"strategy": strategy,
				"dry_run":  true,
				"summary":  summary,
			},
		}
		api.writeJSON(w, response)
		return
	}

	label, note, changeRef := revisionMetadataFromRequest(r)
	if proposalOnly {
		notBefore, err := proposalNotBeforeFromRequest(r)
		if err != nil {
			api.writeManagedError(w, err, http.StatusBadRequest)
			return
		}
		if err := api.enforceProposalSchedule("gateway_config_"+strategy, notBefore); err != nil {
			api.writeManagedError(w, err, http.StatusBadRequest)
			return
		}
		proposalID, err := saveConfigProposal("gateway_config_"+strategy, strategy, proposalProposerFromRequest(r), proposalEnvironmentFromRequest(r), "", "", nil, nil, nil, 0, nil, 0, 0, "", false, "", "", label, note, changeRef, notBefore, requiredProposalApprovers(api.gateway.GetConfig(), &configProposalRecord{Action: "gateway_config_" + strategy}), summary, &simCfg)
		if err != nil {
			api.writeManagedError(w, managedProposalConflict("Failed to create proposal", err), http.StatusInternalServerError)
			return
		}
		api.writeJSON(w, APIResponse{
			Success: true,
			Message: "Configuration proposal created successfully",
			Data: map[string]interface{}{
				"proposal_id":     proposalID,
				"strategy":        strategy,
				"environment":     proposalEnvironmentFromRequest(r),
				"not_before":      notBefore,
				"canary_services": proposalCanaryServicesFromRequest(r, nil),
				"canary_routes":   proposalCanaryRoutesFromRequest(r, nil),
				"canary_headers":  proposalCanaryHeadersFromRequest(r, nil),
				"canary_percent":  0,
				"summary":         summary,
			},
		})
		return
	}

	if err := api.applyManagedConfigChange(&simCfg, "gateway_config_"+strategy, label, note, changeRef, summary); err != nil {
		api.writeManagedError(w, managedConfigError("Failed to update configuration", err), http.StatusInternalServerError)
		return
	}

	response := APIResponse{
		Success: true,
		Message: fmt.Sprintf("Configuration updated successfully using %s strategy", strategy),
		Data: map[string]interface{}{
			"reload_required": true,
			"summary":         summary,
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
		api.writeManagedError(w, managedConfigError("Failed to reload configuration", err), http.StatusInternalServerError)
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

func (api *ManagementAPI) getGatewayBackends(w http.ResponseWriter, r *http.Request) {
	backends := api.gateway.BackendStatuses()
	api.writeJSON(w, map[string]interface{}{
		"backends": backends,
		"total":    len(backends),
	})
}

func (api *ManagementAPI) getGatewayRoutePolicy(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimSpace(r.URL.Query().Get("path"))
	if path == "" {
		api.writeManagedError(w, managedRequiredFieldError("path query parameter is required"), http.StatusBadRequest)
		return
	}
	method := strings.ToUpper(strings.TrimSpace(r.URL.Query().Get("method")))
	if method == "" {
		method = http.MethodGet
	}
	bucketKey := strings.TrimSpace(r.URL.Query().Get("bucket_key"))
	headers, err := gateway.ParseRoutePolicyHeaderParams(r.URL.Query()["header"])
	if err != nil {
		api.writeManagedError(w, managedValidationError(err.Error(), nil), http.StatusBadRequest)
		return
	}
	inspection, ok := api.gateway.InspectRoutePolicy(method, path, headers, bucketKey)
	if !ok {
		api.writeManagedError(w, managedError(coreerrors.CodeRouteNotFound, "route not found for the supplied method/path/header combination", nil), http.StatusNotFound)
		return
	}
	api.writeJSON(w, map[string]interface{}{
		"inspection": inspection,
	})
}

func (api *ManagementAPI) diffGatewayRoutePolicy(w http.ResponseWriter, r *http.Request) {
	fromPath := strings.TrimSpace(r.URL.Query().Get("from_path"))
	toPath := strings.TrimSpace(r.URL.Query().Get("to_path"))
	if fromPath == "" || toPath == "" {
		api.writeManagedError(w, managedRequiredFieldError("from_path and to_path query parameters are required"), http.StatusBadRequest)
		return
	}
	fromMethod := strings.ToUpper(strings.TrimSpace(r.URL.Query().Get("from_method")))
	if fromMethod == "" {
		fromMethod = http.MethodGet
	}
	toMethod := strings.ToUpper(strings.TrimSpace(r.URL.Query().Get("to_method")))
	if toMethod == "" {
		toMethod = http.MethodGet
	}
	fromBucketKey := strings.TrimSpace(r.URL.Query().Get("from_bucket_key"))
	toBucketKey := strings.TrimSpace(r.URL.Query().Get("to_bucket_key"))
	fromHeaders, err := gateway.ParseRoutePolicyHeaderParams(r.URL.Query()["from_header"])
	if err != nil {
		api.writeManagedError(w, managedValidationError("from_header "+err.Error(), nil), http.StatusBadRequest)
		return
	}
	toHeaders, err := gateway.ParseRoutePolicyHeaderParams(r.URL.Query()["to_header"])
	if err != nil {
		api.writeManagedError(w, managedValidationError("to_header "+err.Error(), nil), http.StatusBadRequest)
		return
	}
	diff, ok := api.gateway.DiffRoutePolicy(fromMethod, fromPath, fromHeaders, fromBucketKey, toMethod, toPath, toHeaders, toBucketKey)
	if !ok {
		api.writeManagedError(w, managedError(coreerrors.CodeRouteNotFound, "one or both routes were not found for the supplied comparison inputs", nil), http.StatusNotFound)
		return
	}
	api.writeJSON(w, map[string]interface{}{
		"diff": diff,
	})
}

func (api *ManagementAPI) getGatewayPolicyHits(w http.ResponseWriter, r *http.Request) {
	summary := api.gateway.PolicyHitSummary()
	window := 5 * time.Minute
	windowSource := "5m"
	if raw := strings.TrimSpace(r.URL.Query().Get("window")); raw != "" {
		if parsed, err := time.ParseDuration(raw); err == nil && parsed > 0 {
			window = parsed
			windowSource = raw
		}
	}
	recent := api.gateway.PolicyHitWindowSummary(window)
	recent.Window = windowSource
	api.writeJSON(w, map[string]interface{}{
		"total":         summary.Total,
		"updated_at":    summary.UpdatedAt,
		"reasons":       summary.Reasons,
		"routes":        summary.Routes,
		"recent_window": recent,
	})
}

func (api *ManagementAPI) getGatewayLimitHits(w http.ResponseWriter, r *http.Request) {
	summary := api.gateway.RouteLimitHitSummary()
	window := 5 * time.Minute
	windowSource := "5m"
	if raw := strings.TrimSpace(r.URL.Query().Get("window")); raw != "" {
		if parsed, err := time.ParseDuration(raw); err == nil && parsed > 0 {
			window = parsed
			windowSource = raw
		}
	}
	recent := api.gateway.RouteLimitHitWindowSummary(window)
	recent.Window = windowSource
	api.writeJSON(w, map[string]interface{}{
		"total":         summary.Total,
		"updated_at":    summary.UpdatedAt,
		"types":         summary.Types,
		"routes":        summary.Routes,
		"recent_window": recent,
	})
}

func (api *ManagementAPI) getGatewayLimitBuckets(w http.ResponseWriter, r *http.Request) {
	window, windowSource, minCount := parseGatewayLimitAlertQuery(r)
	summary := api.gateway.RouteLimitBucketSummary(window, minCount)
	summary.Window = windowSource
	api.writeJSON(w, summary)
}

func (api *ManagementAPI) getGatewayLimitClasses(w http.ResponseWriter, r *http.Request) {
	window, windowSource, minCount := parseGatewayLimitAlertQuery(r)
	summary := api.gateway.RouteLimitClassSummary(window, minCount)
	summary.Window = windowSource
	api.writeJSON(w, summary)
}

func (api *ManagementAPI) getGatewayLimitClassAlerts(w http.ResponseWriter, r *http.Request) {
	window, windowSource, minCount := parseGatewayLimitAlertQuery(r)
	summary := api.gateway.RouteLimitClassAlertSummary(window, minCount)
	summary.Window = windowSource
	api.writeJSON(w, summary)
}

func (api *ManagementAPI) notifyGatewayLimitClassAlerts(w http.ResponseWriter, r *http.Request) {
	window, windowSource, minCount := parseGatewayLimitAlertQuery(r)
	summary := api.gateway.RouteLimitClassAlertSummary(window, minCount)
	summary.Window = windowSource

	digestDeliveries := api.emitManagementEvent(managementWebhookEvent{
		Event:      "gateway.limit_class_alert_digest",
		OccurredAt: time.Now().UTC(),
		Data: map[string]interface{}{
			"window":           summary.Window,
			"window_seconds":   summary.WindowSeconds,
			"min_count":        summary.MinCount,
			"total_alerts":     summary.TotalAlerts,
			"top_bucket_class": summary.TopBucketClass,
			"by_severity":      summary.BySeverity,
			"alerts":           summary.Alerts,
		},
	})

	alertDeliveries := 0
	for _, alert := range summary.Alerts {
		alertDeliveries += api.emitManagementEvent(managementWebhookEvent{
			Event:      "gateway.limit_class_alert",
			OccurredAt: time.Now().UTC(),
			Data: map[string]interface{}{
				"window":                summary.Window,
				"window_seconds":        summary.WindowSeconds,
				"min_count":             summary.MinCount,
				"severity":              alert.Severity,
				"service_name":          alert.ServiceName,
				"route_path":            alert.RoutePath,
				"limit_type":            alert.LimitType,
				"key_type":              alert.KeyType,
				"bucket_class":          alert.BucketClass,
				"count":                 alert.Count,
				"queued_admissions":     alert.QueuedAdmissions,
				"queue_full_rejections": alert.QueueFullRejections,
				"average_queue_wait_ms": alert.AverageQueueWaitMs,
				"max_queue_wait_ms":     alert.MaxQueueWaitMs,
				"since":                 alert.Since,
			},
		})
	}

	api.writeJSON(w, map[string]interface{}{
		"window":            summary.Window,
		"min_count":         summary.MinCount,
		"total_alerts":      summary.TotalAlerts,
		"digest_deliveries": digestDeliveries,
		"alert_deliveries":  alertDeliveries,
		"alerts":            summary.Alerts,
	})
}

func (api *ManagementAPI) getGatewayLimitAlerts(w http.ResponseWriter, r *http.Request) {
	window, windowSource, minCount := parseGatewayLimitAlertQuery(r)
	cfg := api.gateway.GetConfig()
	evaluationMinCount := effectiveLimitAlertEvaluationMinCount(minCount, cfg, config.PolicyAlertNotificationPolicy{})
	if cfg != nil {
		evaluationMinCount = effectiveLimitAlertEvaluationMinCount(minCount, cfg, cfg.Security.MutationPolicy.LimitAlertNotifications)
	}
	summary := api.gateway.RouteLimitAlertSummary(window, evaluationMinCount)
	summary.Window = windowSource
	if cfg != nil {
		summary = applyLimitAlertPolicies(summary, cfg.Security.MutationPolicy.LimitAlertNotifications, cfg)
		summary.Window = windowSource
	}
	api.writeJSON(w, summary)
}

func (api *ManagementAPI) notifyGatewayLimitAlerts(w http.ResponseWriter, r *http.Request) {
	window, windowSource, minCount := parseGatewayLimitAlertQuery(r)
	summary := api.gateway.RouteLimitAlertSummary(window, minCount)
	summary.Window = windowSource
	if cfg := api.gateway.GetConfig(); cfg != nil {
		summary.Alerts = classifyRouteLimitAlerts(cfg, summary.Alerts)
	}

	digestDeliveries := api.emitManagementEvent(managementWebhookEvent{
		Event:      "gateway.limit_alert_digest",
		OccurredAt: time.Now().UTC(),
		Data: map[string]interface{}{
			"window":         summary.Window,
			"window_seconds": summary.WindowSeconds,
			"min_count":      summary.MinCount,
			"total_alerts":   summary.TotalAlerts,
			"by_severity":    summary.BySeverity,
			"alerts":         summary.Alerts,
		},
	})

	alertDeliveries := 0
	for _, alert := range summary.Alerts {
		alertDeliveries += api.emitManagementEvent(managementWebhookEvent{
			Event:      "gateway.limit_alert",
			OccurredAt: time.Now().UTC(),
			Data: map[string]interface{}{
				"window":                summary.Window,
				"window_seconds":        summary.WindowSeconds,
				"min_count":             summary.MinCount,
				"severity":              alert.Severity,
				"service_name":          alert.ServiceName,
				"route_path":            alert.RoutePath,
				"limit_type":            alert.LimitType,
				"key_type":              alert.KeyType,
				"bucket_id":             alert.BucketID,
				"bucket_class":          alert.BucketClass,
				"count":                 alert.Count,
				"queued_admissions":     alert.QueuedAdmissions,
				"queue_full_rejections": alert.QueueFullRejections,
				"average_queue_wait_ms": alert.AverageQueueWaitMs,
				"max_queue_wait_ms":     alert.MaxQueueWaitMs,
				"since":                 alert.Since,
			},
		})
	}

	api.writeJSON(w, map[string]interface{}{
		"window":            summary.Window,
		"min_count":         summary.MinCount,
		"total_alerts":      summary.TotalAlerts,
		"digest_deliveries": digestDeliveries,
		"alert_deliveries":  alertDeliveries,
		"alerts":            summary.Alerts,
	})
}

func (api *ManagementAPI) getGatewayPolicyAlerts(w http.ResponseWriter, r *http.Request) {
	window, windowSource, minCount := parseGatewayPolicyAlertQuery(r)
	summary := api.gateway.PolicyAlertSummary(window, minCount)
	summary.Window = windowSource
	api.writeJSON(w, summary)
}

func (api *ManagementAPI) notifyGatewayPolicyAlerts(w http.ResponseWriter, r *http.Request) {
	window, windowSource, minCount := parseGatewayPolicyAlertQuery(r)
	summary := api.gateway.PolicyAlertSummary(window, minCount)
	summary.Window = windowSource

	digestPayload := managementWebhookEvent{
		Event:      "gateway.policy_alert_digest",
		OccurredAt: time.Now().UTC(),
		Data: map[string]interface{}{
			"window":         summary.Window,
			"window_seconds": summary.WindowSeconds,
			"min_count":      summary.MinCount,
			"total_alerts":   summary.TotalAlerts,
			"by_severity":    summary.BySeverity,
			"alerts":         summary.Alerts,
		},
	}
	digestDeliveries := api.emitManagementEvent(digestPayload)

	alertDeliveries := 0
	for _, alert := range summary.Alerts {
		alertDeliveries += api.emitManagementEvent(managementWebhookEvent{
			Event:      "gateway.policy_alert",
			OccurredAt: time.Now().UTC(),
			Data: map[string]interface{}{
				"window":         summary.Window,
				"window_seconds": summary.WindowSeconds,
				"min_count":      summary.MinCount,
				"severity":       alert.Severity,
				"service_name":   alert.ServiceName,
				"route_path":     alert.RoutePath,
				"reason":         alert.Reason,
				"count":          alert.Count,
				"since":          alert.Since,
			},
		})
	}

	api.writeJSON(w, map[string]interface{}{
		"window":            summary.Window,
		"min_count":         summary.MinCount,
		"total_alerts":      summary.TotalAlerts,
		"digest_deliveries": digestDeliveries,
		"alert_deliveries":  alertDeliveries,
		"alerts":            summary.Alerts,
	})
}

func parseGatewayPolicyAlertQuery(r *http.Request) (time.Duration, string, int) {
	window := 5 * time.Minute
	windowSource := "5m"
	if raw := strings.TrimSpace(r.URL.Query().Get("window")); raw != "" {
		if parsed, err := time.ParseDuration(raw); err == nil && parsed > 0 {
			window = parsed
			windowSource = raw
		}
	}
	minCount := 3
	if raw := strings.TrimSpace(r.URL.Query().Get("min_count")); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil && parsed > 0 {
			minCount = parsed
		}
	}
	return window, windowSource, minCount
}

func parseGatewayLimitAlertQuery(r *http.Request) (time.Duration, string, int) {
	window := 5 * time.Minute
	windowSource := "5m"
	if raw := strings.TrimSpace(r.URL.Query().Get("window")); raw != "" {
		if parsed, err := time.ParseDuration(raw); err == nil && parsed > 0 {
			window = parsed
			windowSource = raw
		}
	}
	minCount := 3
	if raw := strings.TrimSpace(r.URL.Query().Get("min_count")); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil && parsed > 0 {
			minCount = parsed
		}
	}
	return window, windowSource, minCount
}

func policyAlertNotificationInterval(policy config.PolicyAlertNotificationPolicy) time.Duration {
	if parsed, err := time.ParseDuration(strings.TrimSpace(policy.Interval)); err == nil && parsed > 0 {
		return parsed
	}
	return 1 * time.Minute
}

func policyAlertNotificationMinInterval(policy config.PolicyAlertNotificationPolicy) time.Duration {
	if parsed, err := time.ParseDuration(strings.TrimSpace(policy.MinNotificationInterval)); err == nil && parsed > 0 {
		return parsed
	}
	return policyAlertNotificationInterval(policy)
}

func policyAlertNotificationWindow(policy config.PolicyAlertNotificationPolicy) time.Duration {
	if parsed, err := time.ParseDuration(strings.TrimSpace(policy.Window)); err == nil && parsed > 0 {
		return parsed
	}
	return 5 * time.Minute
}

func policyAlertNotificationMinCount(policy config.PolicyAlertNotificationPolicy) int {
	if policy.MinCount > 0 {
		return policy.MinCount
	}
	return 3
}

func filterPolicyAlertSummaryBySeverity(summary gateway.PolicyAlertSummary, minSeverity string) gateway.PolicyAlertSummary {
	minRank := slaBreachTierRank(minSeverity)
	if minRank <= 0 {
		return summary
	}
	filtered := gateway.PolicyAlertSummary{
		Window:        summary.Window,
		WindowSeconds: summary.WindowSeconds,
		MinCount:      summary.MinCount,
		BySeverity:    map[string]int{"warning": 0, "elevated": 0, "critical": 0},
	}
	for _, alert := range summary.Alerts {
		if slaBreachTierRank(alert.Severity) < minRank {
			continue
		}
		filtered.Alerts = append(filtered.Alerts, alert)
		filtered.BySeverity[alert.Severity]++
	}
	filtered.TotalAlerts = len(filtered.Alerts)
	return filtered
}

func gatewayPolicyAlertIncidentKey(alert gateway.PolicyAlert) string {
	return strings.TrimSpace(alert.ServiceName) + "|" + strings.TrimSpace(alert.RoutePath) + "|" + strings.TrimSpace(alert.Reason)
}

func buildGatewayPolicyAlertIncidentData(state gatewayPolicyAlertIncidentState, count int, severity string, now time.Time) map[string]interface{} {
	if count <= 0 {
		count = state.LastCount
	}
	if strings.TrimSpace(severity) == "" {
		severity = state.Severity
	}
	age := 0.0
	if !state.FirstSeenAt.IsZero() {
		age = now.Sub(state.FirstSeenAt).Seconds()
		if age < 0 {
			age = 0
		}
	}
	return map[string]interface{}{
		"incident_id":          strings.TrimSpace(state.IncidentID),
		"severity":             strings.TrimSpace(severity),
		"service_name":         strings.TrimSpace(state.ServiceName),
		"route_path":           strings.TrimSpace(state.RoutePath),
		"reason":               strings.TrimSpace(state.Reason),
		"count":                count,
		"first_seen_at":        state.FirstSeenAt,
		"last_seen_at":         state.LastSeenAt,
		"incident_age_seconds": age,
	}
}

func (api *ManagementAPI) getGatewayShadowReport(w http.ResponseWriter, r *http.Request) {
	summaries := api.gateway.ShadowRouteSummaries()
	api.writeJSON(w, map[string]interface{}{
		"routes": summaries,
		"total":  len(summaries),
	})
}

func (api *ManagementAPI) getGatewayShadowEvaluation(w http.ResponseWriter, r *http.Request) {
	evaluations := api.gateway.ShadowRouteEvaluations()
	healthy := 0
	failed := 0
	withPolicy := 0
	for _, evaluation := range evaluations {
		if evaluation.PolicyConfigured {
			withPolicy++
		}
		if evaluation.Healthy {
			healthy++
		} else {
			failed++
		}
	}
	api.writeJSON(w, map[string]interface{}{
		"routes":      evaluations,
		"total":       len(evaluations),
		"with_policy": withPolicy,
		"healthy":     healthy,
		"failed":      failed,
		"all_healthy": failed == 0,
	})
}
