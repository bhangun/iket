package api

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/bhangun/iket/pkg/config"
	coreerrors "github.com/bhangun/iket/pkg/core/errors"
	"github.com/gorilla/mux"
)

func (api *ManagementAPI) getServices(w http.ResponseWriter, r *http.Request) {
	cfg := api.gateway.GetConfig()
	if cfg == nil {
		api.writeManagedError(w, managedError(coreerrors.CodeConfigNotAvailable, "Configuration not available", nil), http.StatusInternalServerError)
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
	proposalOnly := r.URL.Query().Get("proposal") == "true"

	cfg := api.gateway.GetConfig()
	if cfg == nil {
		api.writeManagedError(w, managedError(coreerrors.CodeConfigNotAvailable, "Configuration not available", nil), http.StatusInternalServerError)
		return
	}
	var req struct {
		Services []config.Service `json:"services"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.writeManagedError(w, managedError(coreerrors.CodeServiceInvalid, "Invalid service definition", err), http.StatusBadRequest)
		return
	}

	simCfg, err := cloneConfig(cfg)
	if err != nil {
		api.writeManagedError(w, managedConfigError("Failed to prepare configuration update", err), http.StatusInternalServerError)
		return
	}

	if strategy == "replace" {
		simCfg.Services = []config.ServiceConfig{{
			Version:  1,
			Services: cloneServices(req.Services),
		}}
		summary := serviceChangeSummary(cfg, simCfg)

		if dryRun {
			msg := fmt.Sprintf("[DRY RUN] %d service(s) would replace the remote services set", len(req.Services))
			api.writeJSON(w, map[string]interface{}{
				"success":        true,
				"dry_run":        true,
				"replaced":       true,
				"services_count": len(req.Services),
				"summary":        summary,
				"message":        msg,
			})
			return
		}

		label, note, changeRef := revisionMetadataFromRequest(r)
		if proposalOnly {
			notBefore, err := proposalNotBeforeFromRequest(r)
			if err != nil {
				api.writeManagedError(w, err, http.StatusBadRequest)
				return
			}
			if err := api.enforceProposalSchedule("services_replace", notBefore); err != nil {
				api.writeManagedError(w, err, http.StatusBadRequest)
				return
			}
			canaryPercent, err := proposalCanaryPercentFromRequest(r, nil)
			if err != nil {
				api.writeManagedError(w, err, http.StatusBadRequest)
				return
			}
			canarySteps, err := proposalCanaryStepsFromRequest(r, nil)
			if err != nil {
				api.writeManagedError(w, err, http.StatusBadRequest)
				return
			}
			canaryMinRequests, err := proposalCanaryMinRequestsFromRequest(r, nil)
			if err != nil {
				api.writeManagedError(w, err, http.StatusBadRequest)
				return
			}
			canaryMaxErrorRate, err := proposalCanaryMaxErrorRateFromRequest(r, nil)
			if err != nil {
				api.writeManagedError(w, err, http.StatusBadRequest)
				return
			}
			canaryMaxP95Latency, err := proposalCanaryMaxP95LatencyFromRequest(r, nil)
			if err != nil {
				api.writeManagedError(w, err, http.StatusBadRequest)
				return
			}
			canaryAutoReconcile, err := proposalCanaryAutoReconcileFromRequest(r, nil)
			if err != nil {
				api.writeManagedError(w, err, http.StatusBadRequest)
				return
			}
			canaryAutoInterval, err := proposalCanaryAutoIntervalFromRequest(r, nil)
			if err != nil {
				api.writeManagedError(w, err, http.StatusBadRequest)
				return
			}
			canaryAutoReviewer := proposalCanaryAutoReviewerFromRequest(r, nil)
			proposalID, err := saveConfigProposal("services_replace", strategy, proposalProposerFromRequest(r), proposalEnvironmentFromRequest(r), "", "", proposalCanaryServicesFromRequest(r, nil), proposalCanaryRoutesFromRequest(r, nil), proposalCanaryHeadersFromRequest(r, nil), canaryPercent, canarySteps, canaryMinRequests, canaryMaxErrorRate, canaryMaxP95Latency, canaryAutoReconcile, canaryAutoInterval, canaryAutoReviewer, label, note, changeRef, notBefore, requiredProposalApprovers(api.gateway.GetConfig(), &configProposalRecord{Action: "services_replace"}), summary, simCfg)
			if err != nil {
				api.writeManagedError(w, managedProposalConflict("Failed to create proposal", err), http.StatusInternalServerError)
				return
			}
			api.writeJSON(w, map[string]interface{}{
				"success":                true,
				"proposal_id":            proposalID,
				"proposal_only":          true,
				"replaced":               true,
				"services_count":         len(req.Services),
				"environment":            proposalEnvironmentFromRequest(r),
				"not_before":             notBefore,
				"canary_services":        proposalCanaryServicesFromRequest(r, nil),
				"canary_routes":          proposalCanaryRoutesFromRequest(r, nil),
				"canary_headers":         proposalCanaryHeadersFromRequest(r, nil),
				"canary_percent":         canaryPercent,
				"canary_steps":           canarySteps,
				"canary_min_requests":    canaryMinRequests,
				"canary_max_error_rate":  canaryMaxErrorRate,
				"canary_max_p95_latency": canaryMaxP95Latency,
				"canary_auto":            canaryAutoReconcile,
				"canary_auto_interval":   canaryAutoInterval,
				"canary_auto_reviewer":   canaryAutoReviewer,
				"summary":                summary,
				"message":                fmt.Sprintf("%d service(s) proposed for replacement", len(req.Services)),
			})
			return
		}
		if err := api.applyManagedConfigChange(simCfg, "services_replace", label, note, changeRef, summary); err != nil {
			api.writeManagedError(w, managedConfigError("Failed to replace services", err), http.StatusInternalServerError)
			return
		}
		api.writeJSON(w, map[string]interface{}{
			"success":        true,
			"replaced":       true,
			"services_count": len(req.Services),
			"summary":        summary,
			"message":        fmt.Sprintf("%d service(s) replaced successfully", len(req.Services)),
		})
		return
	}

	if len(simCfg.Services) == 0 {
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

	summary := serviceChangeSummary(cfg, simCfg)

	if dryRun {
		msg := fmt.Sprintf("[DRY RUN] %d service(s) would be added, %d route(s) would be added, %d route(s) would be updated", addedServices, len(addedRoutes), len(updatedRoutes))
		api.writeJSON(w, map[string]interface{}{
			"success":        true,
			"dry_run":        true,
			"added_services": addedServices,
			"added_routes":   addedRoutes,
			"updated_routes": updatedRoutes,
			"summary":        summary,
			"message":        msg,
		})
		return
	}

	label, note, changeRef := revisionMetadataFromRequest(r)
	if proposalOnly {
		notBefore, err := proposalNotBeforeFromRequest(r)
		if err != nil {
			api.writeManagedError(w, err, http.StatusBadRequest)
			return
		}
		if err := api.enforceProposalSchedule("services_merge", notBefore); err != nil {
			api.writeManagedError(w, err, http.StatusBadRequest)
			return
		}
		canaryPercent, err := proposalCanaryPercentFromRequest(r, nil)
		if err != nil {
			api.writeManagedError(w, err, http.StatusBadRequest)
			return
		}
		canarySteps, err := proposalCanaryStepsFromRequest(r, nil)
		if err != nil {
			api.writeManagedError(w, err, http.StatusBadRequest)
			return
		}
		canaryMinRequests, err := proposalCanaryMinRequestsFromRequest(r, nil)
		if err != nil {
			api.writeManagedError(w, err, http.StatusBadRequest)
			return
		}
		canaryMaxErrorRate, err := proposalCanaryMaxErrorRateFromRequest(r, nil)
		if err != nil {
			api.writeManagedError(w, err, http.StatusBadRequest)
			return
		}
		canaryMaxP95Latency, err := proposalCanaryMaxP95LatencyFromRequest(r, nil)
		if err != nil {
			api.writeManagedError(w, err, http.StatusBadRequest)
			return
		}
		canaryAutoReconcile, err := proposalCanaryAutoReconcileFromRequest(r, nil)
		if err != nil {
			api.writeManagedError(w, err, http.StatusBadRequest)
			return
		}
		canaryAutoInterval, err := proposalCanaryAutoIntervalFromRequest(r, nil)
		if err != nil {
			api.writeManagedError(w, err, http.StatusBadRequest)
			return
		}
		canaryAutoReviewer := proposalCanaryAutoReviewerFromRequest(r, nil)
		proposalID, err := saveConfigProposal("services_merge", strategy, proposalProposerFromRequest(r), proposalEnvironmentFromRequest(r), "", "", proposalCanaryServicesFromRequest(r, nil), proposalCanaryRoutesFromRequest(r, nil), proposalCanaryHeadersFromRequest(r, nil), canaryPercent, canarySteps, canaryMinRequests, canaryMaxErrorRate, canaryMaxP95Latency, canaryAutoReconcile, canaryAutoInterval, canaryAutoReviewer, label, note, changeRef, notBefore, requiredProposalApprovers(api.gateway.GetConfig(), &configProposalRecord{Action: "services_merge"}), summary, simCfg)
		if err != nil {
			api.writeManagedError(w, managedProposalConflict("Failed to create proposal", err), http.StatusInternalServerError)
			return
		}
		api.writeJSON(w, map[string]interface{}{
			"success":                true,
			"proposal_id":            proposalID,
			"proposal_only":          true,
			"added_services":         addedServices,
			"added_routes":           addedRoutes,
			"updated_routes":         updatedRoutes,
			"environment":            proposalEnvironmentFromRequest(r),
			"not_before":             notBefore,
			"canary_services":        proposalCanaryServicesFromRequest(r, nil),
			"canary_routes":          proposalCanaryRoutesFromRequest(r, nil),
			"canary_headers":         proposalCanaryHeadersFromRequest(r, nil),
			"canary_percent":         canaryPercent,
			"canary_steps":           canarySteps,
			"canary_min_requests":    canaryMinRequests,
			"canary_max_error_rate":  canaryMaxErrorRate,
			"canary_max_p95_latency": canaryMaxP95Latency,
			"canary_auto":            canaryAutoReconcile,
			"canary_auto_interval":   canaryAutoInterval,
			"canary_auto_reviewer":   canaryAutoReviewer,
			"summary":                summary,
			"message":                "Service merge proposal created successfully",
		})
		return
	}
	if err := api.applyManagedConfigChange(simCfg, "services_merge", label, note, changeRef, summary); err != nil {
		api.writeManagedError(w, managedConfigError("Failed to update services", err), http.StatusInternalServerError)
		return
	}
	msg := fmt.Sprintf("%d service(s) added, %d route(s) added, %d route(s) updated", addedServices, len(addedRoutes), len(updatedRoutes))
	api.writeJSON(w, map[string]interface{}{
		"success":        true,
		"added_services": addedServices,
		"added_routes":   addedRoutes,
		"updated_routes": updatedRoutes,
		"summary":        summary,
		"message":        msg,
	})
}

// PUT /api/v1/services/{name}
func (api *ManagementAPI) updateService(w http.ResponseWriter, r *http.Request) {
	dryRun := r.URL.Query().Get("dry_run") == "true"
	cfg := api.gateway.GetConfig()
	if cfg == nil {
		api.writeManagedError(w, managedError(coreerrors.CodeConfigNotAvailable, "Configuration not available", nil), http.StatusInternalServerError)
		return
	}
	name := mux.Vars(r)["name"]
	var update config.Service
	if err := json.NewDecoder(r.Body).Decode(&update); err != nil {
		api.writeManagedError(w, managedError(coreerrors.CodeServiceInvalid, "Invalid service definition", err), http.StatusBadRequest)
		return
	}

	simCfg, err := cloneConfig(cfg)
	if err != nil {
		api.writeManagedError(w, managedConfigError("Failed to prepare configuration update", err), http.StatusInternalServerError)
		return
	}

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
		api.writeManagedError(w, managedError(coreerrors.CodeServiceNotFound, "Service not found", nil), http.StatusNotFound)
		return
	}

	serviceSummary := serviceChangeSummary(cfg, simCfg)
	if dryRun {
		msg := fmt.Sprintf("[DRY RUN] %d route(s) would be updated, %d would be added for service %q", len(updatedRoutes), len(addedRoutes), name)
		api.writeJSON(w, map[string]interface{}{
			"success":        true,
			"dry_run":        true,
			"updated_routes": updatedRoutes,
			"added_routes":   addedRoutes,
			"summary":        serviceSummary,
			"message":        msg,
		})
		return
	}

	label, note, changeRef := revisionMetadataFromRequest(r)
	if err := api.applyManagedConfigChange(simCfg, "service_update", label, note, changeRef, serviceSummary); err != nil {
		api.writeManagedError(w, managedConfigError("Failed to update service", err), http.StatusInternalServerError)
		return
	}
	msg := fmt.Sprintf("%d route(s) updated, %d added for service %q", len(updatedRoutes), len(addedRoutes), name)
	api.writeJSON(w, map[string]interface{}{
		"success":        true,
		"updated_routes": updatedRoutes,
		"added_routes":   addedRoutes,
		"summary":        serviceSummary,
		"message":        msg,
	})
}

// DELETE /api/v1/services/{name}
func (api *ManagementAPI) deleteService(w http.ResponseWriter, r *http.Request) {
	cfg := api.gateway.GetConfig()
	if cfg == nil {
		api.writeManagedError(w, managedError(coreerrors.CodeConfigNotAvailable, "Configuration not available", nil), http.StatusInternalServerError)
		return
	}
	name := mux.Vars(r)["name"]
	simCfg, err := cloneConfig(cfg)
	if err != nil {
		api.writeManagedError(w, managedConfigError("Failed to prepare configuration update", err), http.StatusInternalServerError)
		return
	}
	deleted := false
	for i, svcConfig := range simCfg.Services {
		for j, svc := range svcConfig.Services {
			if svc.Name == name {
				simCfg.Services[i].Services = append(simCfg.Services[i].Services[:j], simCfg.Services[i].Services[j+1:]...)
				deleted = true
				break
			}
		}
	}
	if !deleted {
		api.writeManagedError(w, managedError(coreerrors.CodeServiceNotFound, "Service not found", nil), http.StatusNotFound)
		return
	}
	deletedSummary := map[string]interface{}{
		"deleted_service": name,
	}
	label, note, changeRef := revisionMetadataFromRequest(r)
	if err := api.applyManagedConfigChange(simCfg, "service_delete", label, note, changeRef, deletedSummary); err != nil {
		api.writeManagedError(w, managedConfigError("Failed to delete service", err), http.StatusInternalServerError)
		return
	}
	api.writeJSON(w, APIResponse{Success: true, Message: "Service deleted successfully", Data: deletedSummary})
}
