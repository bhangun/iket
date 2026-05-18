package config

import (
	coreerrors "github.com/bhangun/iket/pkg/core/errors"
	"github.com/bhangun/iket/pkg/logging"
	"strings"
)

// ServiceConfig represents the new service-based configuration structure
type ServiceConfig struct {
	Version  int       `yaml:"version" json:"version"`
	Services []Service `yaml:"services" json:"services"`
	CacheTTL string    `yaml:"cache_ttl" json:"cache_ttl"`
	Timeout  string    `yaml:"timeout" json:"timeout"`
}

// Service represents a service in the new configuration format
type Service struct {
	Name            string                    `yaml:"name,omitempty" json:"name,omitempty"`
	Description     string                    `yaml:"description,omitempty" json:"description,omitempty"`
	Host            string                    `yaml:"host" json:"host"`
	BasePath        string                    `yaml:"base_path,omitempty" json:"base_path,omitempty"`
	AIPolicyPresets map[string]AIPolicyPreset `yaml:"aiPolicyPresets,omitempty" json:"ai_policy_presets,omitempty"`
	Tags            []string                  `yaml:"tags,omitempty" json:"tags,omitempty"`
	Group           string                    `yaml:"group,omitempty" json:"group,omitempty"`
	Scopes          []string                  `yaml:"scopes,omitempty" json:"scopes,omitempty"`
	Routes          []RouterConfig            `yaml:"routes" json:"routes"`
}

// Backend represents a backend configuration for routes
type Backend struct {
	URLPattern                      string `yaml:"url_pattern" json:"url_pattern"`
	Host                            string `yaml:"host,omitempty" json:"host,omitempty"`
	Weight                          int    `yaml:"weight,omitempty" json:"weight,omitempty"`
	Timeout                         string `yaml:"timeout,omitempty" json:"timeout,omitempty"`
	FailureThreshold                int    `yaml:"failureThreshold,omitempty" json:"failureThreshold,omitempty"`
	Cooldown                        string `yaml:"cooldown,omitempty" json:"cooldown,omitempty"`
	HalfOpenMaxRequests             int    `yaml:"halfOpenMaxRequests,omitempty" json:"halfOpenMaxRequests,omitempty"`
	RecoverySuccessThreshold        int    `yaml:"recoverySuccessThreshold,omitempty" json:"recoverySuccessThreshold,omitempty"`
	OutlierLatencyThreshold         string `yaml:"outlierLatencyThreshold,omitempty" json:"outlierLatencyThreshold,omitempty"`
	OutlierConsecutiveSlowResponses int    `yaml:"outlierConsecutiveSlowResponses,omitempty" json:"outlierConsecutiveSlowResponses,omitempty"`
	OutlierCooldown                 string `yaml:"outlierCooldown,omitempty" json:"outlierCooldown,omitempty"`
	HealthCheckPath                 string `yaml:"healthCheckPath,omitempty" json:"healthCheckPath,omitempty"`
	HealthInterval                  string `yaml:"healthInterval,omitempty" json:"healthInterval,omitempty"`
	HealthTimeout                   string `yaml:"healthTimeout,omitempty" json:"healthTimeout,omitempty"`
}

func (s Service) EffectiveRoutePath(route RouterConfig) string {
	return joinRouteSegments(s.BasePath, route.Path)
}

func (s Service) UpstreamBasePath() string {
	return joinRouteSegments("", s.BasePath)
}

func joinRouteSegments(parts ...string) string {
	cleaned := make([]string, 0, len(parts))
	for i, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" || part == "/" {
			continue
		}
		if i == 0 && strings.Contains(part, "://") {
			cleaned = append(cleaned, strings.TrimRight(part, "/"))
			continue
		}
		cleaned = append(cleaned, strings.Trim(part, "/"))
	}

	if len(cleaned) == 0 {
		return "/"
	}

	result := strings.Join(cleaned, "/")
	if strings.Contains(cleaned[0], "://") {
		return result
	}
	return "/" + result
}

func cloneRouteWithService(route RouterConfig, service Service, globalAIPolicyPresets map[string]AIPolicyPreset) RouterConfig {
	cloned := route
	cloned.Path = service.EffectiveRoutePath(route)
	cloned.Methods = route.EffectiveMethods()
	cloned.ServiceName = service.Name
	cloned.ServiceHost = service.Host
	if len(globalAIPolicyPresets) > 0 || len(service.AIPolicyPresets) > 0 || len(route.AIPolicyPresets) > 0 {
		cloned.AIPolicyPresets = make(map[string]AIPolicyPreset, len(globalAIPolicyPresets)+len(service.AIPolicyPresets)+len(route.AIPolicyPresets))
		for name, preset := range globalAIPolicyPresets {
			cloned.AIPolicyPresets[name] = preset
		}
		for name, preset := range service.AIPolicyPresets {
			cloned.AIPolicyPresets[name] = preset
		}
		for name, preset := range route.AIPolicyPresets {
			cloned.AIPolicyPresets[name] = preset
		}
	}
	return cloned
}

// GetServiceByName finds a service by its name
func (c *Config) GetServiceByName(name string) (*Service, error) {
	for _, serviceConfig := range c.Services {
		for _, service := range serviceConfig.Services {
			if service.Name == name {
				return &service, nil
			}
		}
	}
	return nil, coreerrors.NewCodeError(coreerrors.CodeServiceNotFound, "service not found", nil)
}

// GetServiceByGroup finds all services in a specific group
func (c *Config) GetServiceByGroup(group string) []Service {
	var services []Service
	for _, serviceConfig := range c.Services {
		for _, service := range serviceConfig.Services {
			if service.Group == group {
				services = append(services, service)
			}
		}
	}
	return services
}

// GetServiceByTag finds all services with a specific tag
func (c *Config) GetServiceByTag(tag string) []Service {
	var services []Service
	for _, serviceConfig := range c.Services {
		for _, service := range serviceConfig.Services {
			for _, serviceTag := range service.Tags {
				if serviceTag == tag {
					services = append(services, service)
					break
				}
			}
		}
	}
	return services
}

// GetAllRoutesFromServices returns all routes from all services
func (c *Config) GetAllRoutesFromServices(logger *logging.Logger) []RouterConfig {
	var allRoutes []RouterConfig
	for _, serviceConfig := range c.Services {
		for _, service := range serviceConfig.Services {
			for _, route := range service.Routes {
				allRoutes = append(allRoutes, cloneRouteWithService(route, service, c.AIPolicyPresets))
			}
			if logger != nil {
				logger.Info("Loaded Services", logging.Any("service", service))
			}
		}
	}
	return allRoutes
}

// GetRouteByPathFromServices finds a route by path from service configurations
func (c *Config) GetRouteByPathFromServices(path string) (*RouterConfig, error) {
	for _, serviceConfig := range c.Services {
		for _, service := range serviceConfig.Services {
			for _, route := range service.Routes {
				if route.Path == path {
					return &route, nil
				}
			}
		}
	}
	return nil, coreerrors.ErrRouteNotFound
}

// AddService adds a new service to the configuration
func (c *Config) AddService(service Service) error {
	if len(c.Services) == 0 {
		c.Services = []ServiceConfig{{
			Version:  1,
			Services: []Service{},
		}}
	}

	c.Services[0].Services = append(c.Services[0].Services, service)
	return nil
}

// RemoveService removes a service by name
func (c *Config) RemoveService(name string) error {
	for i, serviceConfig := range c.Services {
		for j, service := range serviceConfig.Services {
			if service.Name == name {
				c.Services[i].Services = append(c.Services[i].Services[:j], c.Services[i].Services[j+1:]...)
				return nil
			}
		}
	}
	return coreerrors.NewValidationError("service", "service not found")
}

// Add helper to find parent service for a route
func (c *Config) FindServiceForRoute(path string, method string, matchHeaders map[string]string) *Service {
	for _, serviceConfig := range c.Services {
		for _, service := range serviceConfig.Services {
			for _, route := range service.Routes {
				if service.EffectiveRoutePath(route) == path && route.SupportsMethod(method) && routeHeaderMatcherMatches(route.MatchHeaders, matchHeaders) {
					return &service
				}
			}
		}
	}
	return nil
}

func routeHeaderMatcherMatches(expected, actual map[string]string) bool {
	if len(expected) == 0 {
		return true
	}
	if len(actual) == 0 {
		return false
	}
	for key, value := range expected {
		if actualValue, ok := actual[key]; !ok || !strings.EqualFold(strings.TrimSpace(actualValue), strings.TrimSpace(value)) {
			return false
		}
	}
	return true
}
