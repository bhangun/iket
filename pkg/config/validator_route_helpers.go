package config

import (
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
)

func isValidHTTPMethod(method string) bool {
	switch strings.ToUpper(strings.TrimSpace(method)) {
	case "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE":
		return true
	default:
		return false
	}
}

var routeTemplateVarPattern = regexp.MustCompile(`\{([A-Za-z0-9_]+)(:[^}]*)?\}`)

// Add helper function to check if a route is plugin/static/internal
func isPluginOrInternalRoute(path string) bool {
	pluginPaths := []string{"/openapi", "/swagger-ui", "/docs", "/docs/", "/docs/{rest:.*}"}
	for _, p := range pluginPaths {
		if strings.HasPrefix(path, p) {
			return true
		}
	}
	return false
}

func validateServiceHost(raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid host URL")
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return fmt.Errorf("host must use http or https")
	}
	if parsed.Host == "" || parsed.Hostname() == "" {
		return fmt.Errorf("host must include a hostname")
	}
	hostname := parsed.Hostname()
	if strings.Contains(hostname, ":") && net.ParseIP(hostname) == nil {
		return fmt.Errorf("host contains an invalid hostname")
	}
	if port := parsed.Port(); port != "" {
		if _, err := net.LookupPort("tcp", port); err != nil {
			return fmt.Errorf("host contains an invalid port")
		}
	}
	return nil
}

func validateBackendPattern(route RouterConfig, backend Backend) error {
	routeVars := extractTemplateVars(route.Path)
	patternVars := extractTemplateVars(backend.URLPattern)
	_, routeHasRest := routeVars["rest"]
	_, patternHasRest := patternVars["rest"]

	if route.StripPath && patternHasRest && !routeHasRest {
		return fmt.Errorf("stripPath=true with url_pattern {rest} requires route path to define {rest:.*}")
	}
	if patternHasRest && !routeHasRest {
		return fmt.Errorf("url_pattern contains {rest} but route path does not define it")
	}

	for name := range patternVars {
		if _, ok := routeVars[name]; !ok {
			return fmt.Errorf("url_pattern contains {%s} but route path does not define it", name)
		}
	}

	return nil
}

func extractTemplateVars(path string) map[string]struct{} {
	matches := routeTemplateVarPattern.FindAllStringSubmatch(path, -1)
	vars := make(map[string]struct{}, len(matches))
	for _, match := range matches {
		if len(match) > 1 {
			vars[match[1]] = struct{}{}
		}
	}
	return vars
}
