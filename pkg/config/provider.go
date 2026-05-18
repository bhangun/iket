package config

import (
	"bufio"
	"os"
	"strings"
)

// Provider defines the interface for configuration providers.
type Provider interface {
	Load() (*Config, error)
	Save(*Config) error
	Watch(func(*Config) error) error
	Close() error
}

func loadDotEnvFile(path string) {
	file, err := os.Open(path)
	if err != nil {
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || !strings.Contains(line, "=") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		if key != "" {
			os.Setenv(key, value)
		}
	}
}

func prepareLoadedConfig(cfg *Config) error {
	expandLoadedConfig(cfg)
	applyDefaultRouteBackends(cfg)
	return validateConfig(cfg)
}

func expandLoadedConfig(cfg *Config) {
	if cfg == nil {
		return
	}
	expandEnvVarsInStruct(cfg)
	for _, pluginCfg := range cfg.Plugins {
		expandEnvVarsInMap(pluginCfg)
	}
}

func applyDefaultRouteBackends(cfg *Config) {
	if cfg == nil {
		return
	}
	for serviceConfigIndex := range cfg.Services {
		for serviceIndex := range cfg.Services[serviceConfigIndex].Services {
			service := &cfg.Services[serviceConfigIndex].Services[serviceIndex]
			for routeIndex := range service.Routes {
				route := &service.Routes[routeIndex]
				if len(route.Backends) == 0 && !isPluginOrInternalRoute(route.Path) {
					route.Backends = []Backend{{URLPattern: route.Path}}
				}
				for backendIndex := range route.Backends {
					if route.Backends[backendIndex].URLPattern == "" {
						route.Backends[backendIndex].URLPattern = route.Path
					}
				}
			}
		}
	}
}

func validateConfig(cfg *Config) error {
	return NewConfigValidator().Validate(cfg)
}
