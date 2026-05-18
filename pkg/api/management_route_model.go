package api

import (
	"crypto/sha1"
	"fmt"
	"github.com/bhangun/iket/pkg/config"
	coreerrors "github.com/bhangun/iket/pkg/core/errors"
	"net/http"
	"strings"
)

type routeRecord struct {
	ID                 string
	ServiceConfigIndex int
	ServiceIndex       int
	RouteIndex         int
	Service            config.Service
	Route              config.RouterConfig
	EffectivePath      string
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
	return routeRecord{}, coreerrors.ErrRouteNotFound.Clone()
}

func (api *ManagementAPI) findRouteByServicePathMethod(cfg *config.Config, serviceName, path string, methods []string) (routeRecord, error) {
	for _, record := range api.routeRecords(cfg) {
		if record.Service.Name == serviceName && record.Route.Path == path && sameMethods(record.Route.EffectiveMethods(), methods) {
			return record, nil
		}
	}
	return routeRecord{}, coreerrors.ErrRouteNotFound.Clone()
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
	return nil, coreerrors.New(coreerrors.CodeServiceNotFound, "Service not found")
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

func (api *ManagementAPI) setRouteEnabled(r *http.Request, id string, enabled bool) error {
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
	label, note, changeRef := revisionMetadataFromRequest(r)
	return api.applyManagedConfigChange(simCfg, "route_set_enabled", label, note, changeRef, map[string]interface{}{
		"route_id": id,
		"enabled":  enabled,
	})
}
