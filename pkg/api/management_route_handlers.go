package api

import (
	"encoding/json"
	"github.com/bhangun/iket/pkg/config"
	coreerrors "github.com/bhangun/iket/pkg/core/errors"
	"github.com/gorilla/mux"
	"net"
	"net/http"
	"strings"
)

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

func (api *ManagementAPI) listRoutes(w http.ResponseWriter, r *http.Request) {
	cfg := api.gateway.GetConfig()
	if cfg == nil {
		api.writeManagedError(w, managedError(coreerrors.CodeConfigNotAvailable, "Configuration not available", nil), http.StatusInternalServerError)
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
		api.writeManagedError(w, err, http.StatusNotFound)
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
	dryRun := r.URL.Query().Get("dry_run") == "true"
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
		api.writeManagedError(w, managedValidationError("Invalid route configuration", err), http.StatusBadRequest)
		return
	}
	cfg := api.gateway.GetConfig()
	simCfg, err := cloneConfig(cfg)
	if err != nil {
		api.writeManagedError(w, managedConfigError("Failed to prepare configuration update", err), http.StatusInternalServerError)
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
		api.writeManagedError(w, managedRequiredFieldError("service_name and route.path are required"), http.StatusBadRequest)
		return
	}
	service, err := findServiceByName(simCfg, req.ServiceName)
	if err != nil {
		api.writeManagedError(w, err, http.StatusNotFound)
		return
	}
	for _, existing := range service.Routes {
		if existing.Path == routeConfig.Path && sameMethods(existing.EffectiveMethods(), routeConfig.EffectiveMethods()) {
			api.writeManagedError(w, managedError(coreerrors.CodeValidationError, "Route already exists", nil), http.StatusConflict)
			return
		}
	}
	service.Routes = append(service.Routes, routeConfig)
	summary := routeChangeSummary(nil, &routeConfig, *service)

	if dryRun {
		api.writeJSON(w, map[string]interface{}{
			"success": true,
			"dry_run": true,
			"message": "[DRY RUN] Route is valid and ready to create",
			"data": map[string]interface{}{
				"summary": summary,
			},
		})
		return
	}
	label, note, changeRef := revisionMetadataFromRequest(r)
	if err := api.applyManagedConfigChange(simCfg, "route_create", label, note, changeRef, map[string]interface{}{"summary": summary}); err != nil {
		api.writeManagedError(w, managedConfigError("Failed to create route", err), http.StatusInternalServerError)
		return
	}
	record, _ := api.findRouteByServicePathMethod(api.gateway.GetConfig(), req.ServiceName, routeConfig.Path, routeConfig.EffectiveMethods())

	response := APIResponse{
		Success: true,
		Message: "Route created successfully",
		Data: map[string]interface{}{
			"route_id": record.ID,
			"summary":  summary,
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
	dryRun := r.URL.Query().Get("dry_run") == "true"
	var raw map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&raw); err != nil {
		api.writeManagedError(w, managedValidationError("Invalid update data", err), http.StatusBadRequest)
		return
	}
	updateBytes, _ := json.Marshal(raw)
	var updates config.RouterConfig
	if err := json.Unmarshal(updateBytes, &updates); err != nil {
		api.writeManagedError(w, managedValidationError("Invalid update data", err), http.StatusBadRequest)
		return
	}
	cfg := api.gateway.GetConfig()
	record, err := api.findRouteRecord(cfg, mux.Vars(r)["id"])
	if err != nil {
		api.writeManagedError(w, err, http.StatusNotFound)
		return
	}
	simCfg, err := cloneConfig(cfg)
	if err != nil {
		api.writeManagedError(w, managedConfigError("Failed to prepare configuration update", err), http.StatusInternalServerError)
		return
	}
	svc := &simCfg.Services[record.ServiceConfigIndex].Services[record.ServiceIndex]
	updatedRoute := svc.Routes[record.RouteIndex]
	previousRoute := updatedRoute
	mergeRouteUpdate(&updatedRoute, updates)
	applyRouteRawUpdate(&updatedRoute, raw)
	svc.Routes[record.RouteIndex] = updatedRoute
	summary := routeChangeSummary(&previousRoute, &updatedRoute, *svc)

	if dryRun {
		api.writeJSON(w, map[string]interface{}{
			"success": true,
			"dry_run": true,
			"message": "[DRY RUN] Route update is valid and ready to apply",
			"data": map[string]interface{}{
				"route_id": record.ID,
				"summary":  summary,
			},
		})
		return
	}
	label, note, changeRef := revisionMetadataFromRequest(r)
	if err := api.applyManagedConfigChange(simCfg, "route_update", label, note, changeRef, map[string]interface{}{"route_id": record.ID, "summary": summary}); err != nil {
		api.writeManagedError(w, managedConfigError("Failed to update route", err), http.StatusInternalServerError)
		return
	}

	response := APIResponse{
		Success: true,
		Message: "Route updated successfully",
		Data: map[string]interface{}{
			"route_id": record.ID,
			"summary":  summary,
		},
	}
	api.writeJSON(w, response)
}

func (api *ManagementAPI) deleteRoute(w http.ResponseWriter, r *http.Request) {
	cfg := api.gateway.GetConfig()
	record, err := api.findRouteRecord(cfg, mux.Vars(r)["id"])
	if err != nil {
		api.writeManagedError(w, err, http.StatusNotFound)
		return
	}
	simCfg, err := cloneConfig(cfg)
	if err != nil {
		api.writeManagedError(w, managedConfigError("Failed to prepare configuration update", err), http.StatusInternalServerError)
		return
	}
	svc := &simCfg.Services[record.ServiceConfigIndex].Services[record.ServiceIndex]
	svc.Routes = append(svc.Routes[:record.RouteIndex], svc.Routes[record.RouteIndex+1:]...)
	label, note, changeRef := revisionMetadataFromRequest(r)
	if err := api.applyManagedConfigChange(simCfg, "route_delete", label, note, changeRef, map[string]interface{}{"route_id": record.ID}); err != nil {
		api.writeManagedError(w, managedError(coreerrors.CodeRouteError, "Failed to delete route", err), http.StatusInternalServerError)
		return
	}

	response := APIResponse{
		Success: true,
		Message: "Route deleted successfully",
	}
	api.writeJSON(w, response)
}

func (api *ManagementAPI) enableRoute(w http.ResponseWriter, r *http.Request) {
	if err := api.setRouteEnabled(r, mux.Vars(r)["id"], true); err != nil {
		api.writeManagedError(w, err, http.StatusNotFound)
		return
	}

	response := APIResponse{
		Success: true,
		Message: "Route enabled successfully",
	}
	api.writeJSON(w, response)
}

func (api *ManagementAPI) disableRoute(w http.ResponseWriter, r *http.Request) {
	if err := api.setRouteEnabled(r, mux.Vars(r)["id"], false); err != nil {
		api.writeManagedError(w, err, http.StatusNotFound)
		return
	}

	response := APIResponse{
		Success: true,
		Message: "Route disabled successfully",
	}
	api.writeJSON(w, response)
}
