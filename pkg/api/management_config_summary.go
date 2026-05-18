package api

import (
	"encoding/json"
	"fmt"
	"github.com/bhangun/iket/pkg/config"
	"reflect"
	"sort"
	"strings"
)

func configChangeSummary(currentCfg, nextCfg *config.Config) map[string]interface{} {
	currentMap := make(map[string]interface{})
	nextMap := make(map[string]interface{})
	if data, err := json.Marshal(currentCfg); err == nil {
		_ = json.Unmarshal(data, &currentMap)
	}
	if data, err := json.Marshal(nextCfg); err == nil {
		_ = json.Unmarshal(data, &nextMap)
	}

	paths := collectChangedPaths("", currentMap, nextMap)
	topSections := make([]string, 0)
	seen := make(map[string]struct{})
	for _, path := range paths {
		section := path
		if idx := strings.Index(section, "."); idx >= 0 {
			section = section[:idx]
		}
		if _, ok := seen[section]; ok {
			continue
		}
		seen[section] = struct{}{}
		topSections = append(topSections, section)
	}
	sort.Strings(topSections)

	return map[string]interface{}{
		"changed_count":    len(paths),
		"changed_fields":   paths,
		"changed_sections": topSections,
	}
}

func collectChangedPaths(prefix string, current, next interface{}) []string {
	if reflect.DeepEqual(current, next) {
		return nil
	}

	currentMap, currentOK := current.(map[string]interface{})
	nextMap, nextOK := next.(map[string]interface{})
	if currentOK && nextOK {
		keys := make([]string, 0, len(currentMap)+len(nextMap))
		seen := make(map[string]struct{}, len(currentMap)+len(nextMap))
		for key := range currentMap {
			seen[key] = struct{}{}
			keys = append(keys, key)
		}
		for key := range nextMap {
			if _, ok := seen[key]; ok {
				continue
			}
			keys = append(keys, key)
		}
		sort.Strings(keys)

		paths := make([]string, 0)
		for _, key := range keys {
			normalizedKey := normalizeDiffKey(key)
			childPrefix := normalizedKey
			if prefix != "" {
				childPrefix = prefix + "." + normalizedKey
			}
			paths = append(paths, collectChangedPaths(childPrefix, currentMap[key], nextMap[key])...)
		}
		return paths
	}

	if prefix == "" {
		return []string{"<root>"}
	}
	return []string{prefix}
}

func normalizeDiffKey(key string) string {
	if key == "" {
		return key
	}
	return strings.ToLower(key[:1]) + key[1:]
}

func serviceChangeSummary(currentCfg, nextCfg *config.Config) map[string]interface{} {
	currentServices := flattenServices(currentCfg)
	nextServices := flattenServices(nextCfg)

	addedServices := make([]string, 0)
	removedServices := make([]string, 0)
	updatedServices := make([]string, 0)
	addedRoutes := make([]map[string]interface{}, 0)
	removedRoutes := make([]map[string]interface{}, 0)
	updatedRoutes := make([]map[string]interface{}, 0)

	currentIndex := make(map[string]config.Service, len(currentServices))
	nextIndex := make(map[string]config.Service, len(nextServices))
	for _, svc := range currentServices {
		currentIndex[serviceIdentity(svc)] = svc
	}
	for _, svc := range nextServices {
		nextIndex[serviceIdentity(svc)] = svc
	}

	for key, nextSvc := range nextIndex {
		currentSvc, exists := currentIndex[key]
		if !exists {
			addedServices = append(addedServices, displayServiceName(nextSvc))
			for _, route := range nextSvc.Routes {
				addedRoutes = append(addedRoutes, routeSummary(nextSvc, route))
			}
			continue
		}

		if serviceMetaChanged(currentSvc, nextSvc) {
			updatedServices = append(updatedServices, displayServiceName(nextSvc))
		}

		currentRoutes := routeSummaryIndex(currentSvc)
		nextRoutes := routeSummaryIndex(nextSvc)
		for routeKey, nextRoute := range nextRoutes {
			currentRoute, routeExists := currentRoutes[routeKey]
			if !routeExists {
				addedRoutes = append(addedRoutes, routeSummary(nextSvc, nextRoute))
				continue
			}
			if !reflect.DeepEqual(currentRoute, nextRoute) {
				updatedRoutes = append(updatedRoutes, routeSummary(nextSvc, nextRoute))
			}
		}
		for routeKey, currentRoute := range currentRoutes {
			if _, routeExists := nextRoutes[routeKey]; !routeExists {
				removedRoutes = append(removedRoutes, routeSummary(currentSvc, currentRoute))
			}
		}
	}

	for key, currentSvc := range currentIndex {
		if _, exists := nextIndex[key]; exists {
			continue
		}
		removedServices = append(removedServices, displayServiceName(currentSvc))
		for _, route := range currentSvc.Routes {
			removedRoutes = append(removedRoutes, routeSummary(currentSvc, route))
		}
	}

	sort.Strings(addedServices)
	sort.Strings(removedServices)
	sort.Strings(updatedServices)
	sortRouteSummaries(addedRoutes)
	sortRouteSummaries(removedRoutes)
	sortRouteSummaries(updatedRoutes)

	return map[string]interface{}{
		"added_services":   addedServices,
		"removed_services": removedServices,
		"updated_services": updatedServices,
		"added_routes":     addedRoutes,
		"removed_routes":   removedRoutes,
		"updated_routes":   updatedRoutes,
	}
}

func flattenServices(cfg *config.Config) []config.Service {
	if cfg == nil {
		return nil
	}
	services := make([]config.Service, 0)
	for _, svcCfg := range cfg.Services {
		services = append(services, svcCfg.Services...)
	}
	return services
}

func serviceIdentity(svc config.Service) string {
	if strings.TrimSpace(svc.Name) != "" {
		return "name:" + strings.TrimSpace(svc.Name)
	}
	return "host:" + strings.TrimSpace(svc.Host)
}

func displayServiceName(svc config.Service) string {
	if strings.TrimSpace(svc.Name) != "" {
		return strings.TrimSpace(svc.Name)
	}
	return strings.TrimSpace(svc.Host)
}

func serviceMetaChanged(current, next config.Service) bool {
	return current.Name != next.Name ||
		current.Description != next.Description ||
		current.Host != next.Host ||
		current.BasePath != next.BasePath ||
		!reflect.DeepEqual(current.Tags, next.Tags) ||
		current.Group != next.Group ||
		!reflect.DeepEqual(current.Scopes, next.Scopes)
}

func routeSummaryIndex(svc config.Service) map[string]config.RouterConfig {
	index := make(map[string]config.RouterConfig, len(svc.Routes))
	for _, route := range svc.Routes {
		index[stableRouteID(displayServiceName(svc), svc.EffectiveRoutePath(route), route.EffectiveMethods())] = route
	}
	return index
}

func routeSummary(svc config.Service, route config.RouterConfig) map[string]interface{} {
	return map[string]interface{}{
		"service": svc.Name,
		"path":    svc.EffectiveRoutePath(route),
		"method":  route.Method,
		"methods": route.EffectiveMethods(),
	}
}

func routeConfigSummary(svc config.Service, route config.RouterConfig) map[string]interface{} {
	return map[string]interface{}{
		"service":       svc.Name,
		"path":          route.Path,
		"effectivePath": svc.EffectiveRoutePath(route),
		"methods":       route.EffectiveMethods(),
		"enabled":       route.IsEnabled(),
		"stripPath":     route.StripPath,
		"requireAuth":   route.RequireAuth,
		"requireJwt":    route.RequireJwt,
		"backend":       route.Backends,
	}
}

func sortRouteSummaries(items []map[string]interface{}) {
	sort.SliceStable(items, func(i, j int) bool {
		left := fmt.Sprintf("%v|%v|%v", items[i]["service"], items[i]["path"], items[i]["methods"])
		right := fmt.Sprintf("%v|%v|%v", items[j]["service"], items[j]["path"], items[j]["methods"])
		return left < right
	})
}

func routeChangeSummary(current *config.RouterConfig, next *config.RouterConfig, svc config.Service) map[string]interface{} {
	summary := routeConfigSummary(svc, *next)
	if current == nil {
		summary["action"] = "create"
		return summary
	}

	currentMap := make(map[string]interface{})
	nextMap := make(map[string]interface{})
	if data, err := json.Marshal(current); err == nil {
		_ = json.Unmarshal(data, &currentMap)
	}
	if data, err := json.Marshal(next); err == nil {
		_ = json.Unmarshal(data, &nextMap)
	}

	summary["action"] = "update"
	summary["changed_fields"] = collectChangedPaths("", currentMap, nextMap)
	return summary
}
