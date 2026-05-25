package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	coreerrors "github.com/bhangun/iket/pkg/core/errors"
	"github.com/bhangun/iket/pkg/core/gateway"
)

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

func (api *ManagementAPI) getGatewayConfig(w http.ResponseWriter, r *http.Request) {
	api.mu.RLock()
	defer api.mu.RUnlock()

	cfg := api.gateway.GetConfig()
	if cfg == nil {
		api.writeManagedError(w, managedError(coreerrors.CodeConfigNotAvailable, "Configuration not available", nil), http.StatusInternalServerError)
		return
	}

	redactedConfig, err := gateway.RedactedConfig(cfg)
	if err != nil {
		api.writeManagedError(w, managedConfigError("Failed to redact configuration", err), http.StatusInternalServerError)
		return
	}

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
	if currentCfg == nil {
		api.writeManagedError(w, managedError(coreerrors.CodeConfigNotAvailable, "Configuration not available", nil), http.StatusInternalServerError)
		return
	}
	simCfg, err := buildGatewayConfigCandidate(currentCfg, strategy, input)
	if err != nil {
		if strategy == "merge" {
			api.writeManagedError(w, managedConfigError("Failed to merge configuration", err), http.StatusInternalServerError)
		} else {
			api.writeManagedError(w, managedValidationError("Invalid configuration", err), http.StatusBadRequest)
		}
		return
	}

	if err := simCfg.Validate(); err != nil {
		api.writeManagedError(w, managedError(coreerrors.CodeConfigInvalid, "Invalid configuration", err), http.StatusBadRequest)
		return
	}

	summary := configChangeSummary(currentCfg, simCfg)

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
		proposalID, err := saveConfigProposal("gateway_config_"+strategy, strategy, proposalProposerFromRequest(r), proposalEnvironmentFromRequest(r), "", "", nil, nil, nil, 0, nil, 0, 0, "", false, "", "", label, note, changeRef, notBefore, requiredProposalApprovers(api.gateway.GetConfig(), &configProposalRecord{Action: "gateway_config_" + strategy}), summary, simCfg)
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

	if err := api.applyManagedConfigChange(simCfg, "gateway_config_"+strategy, label, note, changeRef, summary); err != nil {
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
