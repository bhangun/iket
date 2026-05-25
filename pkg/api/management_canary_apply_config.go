package api

import (
	"fmt"
	"sort"
	"strings"

	"github.com/bhangun/iket/pkg/config"
)

func (api *ManagementAPI) describeProposalCanaryPlan(record *configProposalRecord) (map[string]interface{}, error) {
	if record == nil || record.Config == nil {
		return nil, fmt.Errorf("proposal has no stored configuration")
	}
	if !hasProposalCanaryPlan(record) {
		return map[string]interface{}{
			"matched_services": nil,
			"matched_routes":   nil,
		}, nil
	}

	matchedServices := make([]string, 0)
	matchedRoutes := make([]string, 0)
	for _, svcCfg := range record.Config.Services {
		for _, svc := range svcCfg.Services {
			if serviceSelectedForCanary(svc, record.CanaryServices, record.CanaryRoutes) {
				matchedServices = appendUniqueString(matchedServices, strings.TrimSpace(svc.Name))
			}
			for _, route := range svc.Routes {
				if routeSelectedForCanary(svc, route, record.CanaryRoutes) {
					matchedRoutes = appendUniqueString(matchedRoutes, fmt.Sprintf("%s:%s", strings.TrimSpace(svc.Name), strings.TrimSpace(route.Path)))
				}
			}
		}
	}
	return map[string]interface{}{
		"matched_services": matchedServices,
		"matched_routes":   matchedRoutes,
	}, nil
}

func (api *ManagementAPI) buildCanaryApplyConfig(record *configProposalRecord) (*config.Config, map[string]interface{}, error) {
	if record == nil || record.Config == nil {
		return nil, nil, fmt.Errorf("proposal has no stored configuration")
	}
	if !strings.HasPrefix(record.Action, "services_") {
		return nil, nil, fmt.Errorf("canary apply is currently supported only for service proposals")
	}
	if len(record.CanaryHeaders) > 0 {
		return api.buildHeaderScopedCanaryApplyConfig(record)
	}
	if record.CanaryPercent > 0 {
		return api.buildPercentageScopedCanaryApplyConfig(record)
	}
	current := api.gateway.GetConfig()
	if current == nil {
		return nil, nil, fmt.Errorf("current gateway configuration is not available")
	}
	nextCfg, err := cloneConfig(current)
	if err != nil {
		return nil, nil, err
	}
	planServices := make([]string, 0)
	planRoutes := make([]string, 0)
	for _, selector := range record.CanaryServices {
		selector = strings.TrimSpace(selector)
		if selector != "" {
			planServices = append(planServices, selector)
		}
	}
	for _, selector := range record.CanaryRoutes {
		selector = strings.TrimSpace(selector)
		if selector != "" {
			planRoutes = append(planRoutes, selector)
		}
	}
	changedServices := make([]string, 0)
	changedRoutes := make([]map[string]interface{}, 0)

	for _, proposalSvc := range flattenServices(record.Config) {
		if !serviceSelectedForCanary(proposalSvc, planServices, planRoutes) {
			continue
		}
		changed, routes := applyCanaryServiceToConfig(nextCfg, proposalSvc, planServices, planRoutes)
		if changed {
			changedServices = append(changedServices, displayServiceName(proposalSvc))
		}
		changedRoutes = append(changedRoutes, routes...)
	}
	if len(changedServices) == 0 && len(changedRoutes) == 0 {
		return nil, nil, fmt.Errorf("canary plan did not match any services or routes in the proposal")
	}
	sort.Strings(changedServices)
	sortRouteSummaries(changedRoutes)
	summary := serviceChangeSummary(current, nextCfg)
	summary["canary"] = true
	summary["canary_services"] = planServices
	summary["canary_routes"] = planRoutes
	summary["canary_headers"] = record.CanaryHeaders
	summary["canary_changed_services"] = changedServices
	summary["canary_changed_routes"] = changedRoutes
	return nextCfg, summary, nil
}

func (api *ManagementAPI) buildHeaderScopedCanaryApplyConfig(record *configProposalRecord) (*config.Config, map[string]interface{}, error) {
	current := api.gateway.GetConfig()
	if current == nil {
		return nil, nil, fmt.Errorf("current gateway configuration is not available")
	}
	nextCfg, err := cloneConfig(current)
	if err != nil {
		return nil, nil, err
	}
	headerMatchers := parseCanaryHeaderMatchers(record.CanaryHeaders)
	if len(headerMatchers) == 0 {
		return nil, nil, fmt.Errorf("canary headers are required for header-scoped canary rollout")
	}

	planServices := normalizeQueryList(record.CanaryServices)
	planRoutes := normalizeQueryList(record.CanaryRoutes)
	changedServices := make([]string, 0)
	changedRoutes := make([]map[string]interface{}, 0)

	for _, proposalSvc := range flattenServices(record.Config) {
		if !serviceSelectedForCanary(proposalSvc, planServices, planRoutes) {
			continue
		}
		canarySvc, routes := buildHeaderScopedCanaryService(proposalSvc, planServices, planRoutes, headerMatchers)
		if len(canarySvc.Routes) == 0 {
			continue
		}
		replaceOrAppendService(nextCfg, canarySvc)
		changedServices = appendUniqueString(changedServices, displayServiceName(proposalSvc))
		changedRoutes = append(changedRoutes, routes...)
	}
	if len(changedServices) == 0 && len(changedRoutes) == 0 {
		return nil, nil, fmt.Errorf("canary plan did not match any services or routes in the proposal")
	}
	sort.Strings(changedServices)
	sortRouteSummaries(changedRoutes)
	summary := serviceChangeSummary(current, nextCfg)
	summary["canary"] = true
	summary["canary_strategy"] = "header_scoped"
	summary["canary_services"] = planServices
	summary["canary_routes"] = planRoutes
	summary["canary_headers"] = record.CanaryHeaders
	summary["canary_changed_services"] = changedServices
	summary["canary_changed_routes"] = changedRoutes
	return nextCfg, summary, nil
}

func (api *ManagementAPI) buildPercentageScopedCanaryApplyConfig(record *configProposalRecord) (*config.Config, map[string]interface{}, error) {
	current := api.gateway.GetConfig()
	if current == nil {
		return nil, nil, fmt.Errorf("current gateway configuration is not available")
	}
	nextCfg, err := cloneConfig(current)
	if err != nil {
		return nil, nil, err
	}
	planServices := normalizeQueryList(record.CanaryServices)
	planRoutes := normalizeQueryList(record.CanaryRoutes)
	changedServices := make([]string, 0)
	changedRoutes := make([]map[string]interface{}, 0)

	for _, proposalSvc := range flattenServices(record.Config) {
		if !serviceSelectedForCanary(proposalSvc, planServices, planRoutes) {
			continue
		}
		canarySvc, routes := buildPercentageScopedCanaryService(proposalSvc, planServices, planRoutes, record.CanaryPercent)
		if len(canarySvc.Routes) == 0 {
			continue
		}
		replaceOrAppendService(nextCfg, canarySvc)
		changedServices = appendUniqueString(changedServices, displayServiceName(proposalSvc))
		changedRoutes = append(changedRoutes, routes...)
	}
	if len(changedServices) == 0 && len(changedRoutes) == 0 {
		return nil, nil, fmt.Errorf("canary plan did not match any services or routes in the proposal")
	}
	sort.Strings(changedServices)
	sortRouteSummaries(changedRoutes)
	summary := serviceChangeSummary(current, nextCfg)
	summary["canary"] = true
	summary["canary_strategy"] = "percentage"
	summary["canary_services"] = planServices
	summary["canary_routes"] = planRoutes
	summary["canary_percent"] = record.CanaryPercent
	summary["canary_changed_services"] = changedServices
	summary["canary_changed_routes"] = changedRoutes
	return nextCfg, summary, nil
}

func applyCanaryServiceToConfig(cfg *config.Config, proposalSvc config.Service, canaryServices, canaryRoutes []string) (bool, []map[string]interface{}) {
	if cfg == nil {
		return false, nil
	}
	if len(cfg.Services) == 0 {
		cfg.Services = []config.ServiceConfig{{Version: 1}}
	}
	serviceIdx, existingSvc := findServiceForCanary(cfg, proposalSvc)
	targetSvc := existingSvc
	changedRoutes := make([]map[string]interface{}, 0)
	changed := false

	serviceOnly := serviceSelectedOnlyByName(proposalSvc, canaryServices, canaryRoutes)
	if serviceOnly {
		targetSvc = proposalSvc
		changed = true
		for _, route := range proposalSvc.Routes {
			changedRoutes = append(changedRoutes, routeSummary(proposalSvc, route))
		}
	} else {
		for _, proposalRoute := range proposalSvc.Routes {
			if !routeSelectedForCanary(proposalSvc, proposalRoute, canaryRoutes) {
				continue
			}
			targetSvc, changed = mergeCanaryRoute(targetSvc, proposalSvc, proposalRoute, changed)
			changedRoutes = append(changedRoutes, routeSummary(proposalSvc, proposalRoute))
		}
	}
	if !changed {
		return false, nil
	}
	if serviceIdx >= 0 {
		cfg.Services[0].Services[serviceIdx] = targetSvc
	} else {
		cfg.Services[0].Services = append(cfg.Services[0].Services, targetSvc)
	}
	return true, changedRoutes
}

func buildHeaderScopedCanaryService(proposalSvc config.Service, canaryServices, canaryRoutes []string, headerMatchers map[string]string) (config.Service, []map[string]interface{}) {
	canarySvc := proposalSvc
	canarySvc.Name = canaryServiceName(displayServiceName(proposalSvc))
	canarySvc.Routes = nil
	changedRoutes := make([]map[string]interface{}, 0)

	serviceOnly := serviceSelectedOnlyByName(proposalSvc, canaryServices, canaryRoutes)
	for _, proposalRoute := range proposalSvc.Routes {
		if !serviceOnly && !routeSelectedForCanary(proposalSvc, proposalRoute, canaryRoutes) {
			continue
		}
		clonedRoute := proposalRoute
		clonedRoute.MatchHeaders = cloneHeaderMap(headerMatchers)
		canarySvc.Routes = append(canarySvc.Routes, clonedRoute)
		changedRoutes = append(changedRoutes, routeSummary(proposalSvc, clonedRoute))
	}
	return canarySvc, changedRoutes
}

func buildPercentageScopedCanaryService(proposalSvc config.Service, canaryServices, canaryRoutes []string, percent int) (config.Service, []map[string]interface{}) {
	canarySvc := proposalSvc
	canarySvc.Name = canaryServiceName(displayServiceName(proposalSvc))
	canarySvc.Routes = nil
	changedRoutes := make([]map[string]interface{}, 0)

	serviceOnly := serviceSelectedOnlyByName(proposalSvc, canaryServices, canaryRoutes)
	for _, proposalRoute := range proposalSvc.Routes {
		if !serviceOnly && !routeSelectedForCanary(proposalSvc, proposalRoute, canaryRoutes) {
			continue
		}
		clonedRoute := proposalRoute
		clonedRoute.MatchPercent = percent
		canarySvc.Routes = append(canarySvc.Routes, clonedRoute)
		changedRoutes = append(changedRoutes, routeSummary(proposalSvc, clonedRoute))
	}
	return canarySvc, changedRoutes
}

func replaceOrAppendService(cfg *config.Config, svc config.Service) {
	if cfg == nil {
		return
	}
	if len(cfg.Services) == 0 {
		cfg.Services = []config.ServiceConfig{{Version: 1}}
	}
	for i := range cfg.Services {
		for j := range cfg.Services[i].Services {
			if strings.EqualFold(strings.TrimSpace(cfg.Services[i].Services[j].Name), strings.TrimSpace(svc.Name)) {
				cfg.Services[i].Services[j] = svc
				return
			}
		}
	}
	cfg.Services[0].Services = append(cfg.Services[0].Services, svc)
}

func canaryServiceName(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return "canary"
	}
	return name + "__canary"
}

func parseCanaryHeaderMatchers(values []string) map[string]string {
	out := make(map[string]string)
	for _, value := range values {
		parts := strings.SplitN(strings.TrimSpace(value), "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])
		if key == "" || val == "" {
			continue
		}
		out[key] = val
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func cloneHeaderMap(src map[string]string) map[string]string {
	if len(src) == 0 {
		return nil
	}
	dst := make(map[string]string, len(src))
	for key, value := range src {
		dst[key] = value
	}
	return dst
}

func findServiceForCanary(cfg *config.Config, proposalSvc config.Service) (int, config.Service) {
	for i, svc := range cfg.Services[0].Services {
		if serviceIdentity(svc) == serviceIdentity(proposalSvc) {
			return i, svc
		}
	}
	return -1, config.Service{
		Name:        proposalSvc.Name,
		Description: proposalSvc.Description,
		Host:        proposalSvc.Host,
		BasePath:    proposalSvc.BasePath,
		Tags:        append([]string(nil), proposalSvc.Tags...),
		Group:       proposalSvc.Group,
		Scopes:      append([]string(nil), proposalSvc.Scopes...),
	}
}

func serviceSelectedForCanary(svc config.Service, canaryServices, canaryRoutes []string) bool {
	return serviceSelectedOnlyByName(svc, canaryServices, canaryRoutes) || serviceHasSelectedCanaryRoute(svc, canaryRoutes)
}

func serviceSelectedOnlyByName(svc config.Service, canaryServices, canaryRoutes []string) bool {
	if len(canaryServices) == 0 {
		return false
	}
	if len(canaryRoutes) > 0 {
		return false
	}
	for _, selector := range canaryServices {
		if strings.EqualFold(strings.TrimSpace(selector), displayServiceName(svc)) {
			return true
		}
	}
	return false
}

func serviceHasSelectedCanaryRoute(svc config.Service, canaryRoutes []string) bool {
	for _, route := range svc.Routes {
		if routeSelectedForCanary(svc, route, canaryRoutes) {
			return true
		}
	}
	return false
}

func routeSelectedForCanary(svc config.Service, route config.RouterConfig, selectors []string) bool {
	if len(selectors) == 0 {
		return false
	}
	serviceName := displayServiceName(svc)
	effectivePath := svc.EffectiveRoutePath(route)
	for _, selector := range selectors {
		serviceSelector, pathSelector := parseCanaryRouteSelector(selector)
		if pathSelector == "" {
			continue
		}
		if serviceSelector != "" && !strings.EqualFold(serviceSelector, serviceName) {
			continue
		}
		if pathSelector == route.Path || pathSelector == effectivePath {
			return true
		}
	}
	return false
}

func parseCanaryRouteSelector(selector string) (string, string) {
	selector = strings.TrimSpace(selector)
	if selector == "" {
		return "", ""
	}
	if strings.HasPrefix(selector, "/") {
		return "", selector
	}
	if idx := strings.Index(selector, ":/"); idx > 0 {
		return strings.TrimSpace(selector[:idx]), strings.TrimSpace(selector[idx+1:])
	}
	return "", selector
}

func mergeCanaryRoute(targetSvc, proposalSvc config.Service, proposalRoute config.RouterConfig, alreadyChanged bool) (config.Service, bool) {
	targetSvc.Name = proposalSvc.Name
	targetSvc.Description = proposalSvc.Description
	targetSvc.Host = proposalSvc.Host
	targetSvc.BasePath = proposalSvc.BasePath
	targetSvc.Tags = append([]string(nil), proposalSvc.Tags...)
	targetSvc.Group = proposalSvc.Group
	targetSvc.Scopes = append([]string(nil), proposalSvc.Scopes...)
	if len(targetSvc.Routes) == 0 {
		targetSvc.Routes = []config.RouterConfig{}
	}
	routeID := stableRouteID(displayServiceName(proposalSvc), proposalSvc.EffectiveRoutePath(proposalRoute), proposalRoute.EffectiveMethods())
	for i, existing := range targetSvc.Routes {
		existingID := stableRouteID(displayServiceName(targetSvc), targetSvc.EffectiveRoutePath(existing), existing.EffectiveMethods())
		if existingID == routeID {
			targetSvc.Routes[i] = proposalRoute
			return targetSvc, true
		}
	}
	targetSvc.Routes = append(targetSvc.Routes, proposalRoute)
	return targetSvc, true || alreadyChanged
}
