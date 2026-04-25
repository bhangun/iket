package gateway

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strings"

	"github.com/bhangun/iket/pkg/config"
	"github.com/gorilla/mux"
)

func ComputeProxiedPath(service *config.Service, route config.RouterConfig, requestPath string, vars map[string]string) (string, error) {
	if service == nil {
		return "", fmt.Errorf("service is required")
	}

	destURL, err := url.Parse(service.Host)
	if err != nil {
		return "", err
	}

	upstreamPath := requestPath
	if len(route.Backends) > 0 && route.Backends[0].URLPattern != "" {
		upstreamPath = applyURLPattern(route.Backends[0].URLPattern, route.Path, requestPath, vars)
	} else if route.StripPath {
		upstreamPath = stripRoutePath(route.Path, requestPath)
	}

	return joinURLPath(destURL.Path, upstreamPath), nil
}

func joinURLPath(parts ...string) string {
	segments := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" || part == "/" {
			continue
		}
		segments = append(segments, strings.Trim(part, "/"))
	}
	if len(segments) == 0 {
		return "/"
	}
	return "/" + strings.Join(segments, "/")
}

func stripRoutePath(routePath, requestPath string) string {
	prefix := routePath
	if i := findWildcardIndex(prefix); i > 0 {
		prefix = prefix[:i-1]
	}

	if prefix == "" || prefix == "/" {
		if requestPath == "" {
			return "/"
		}
		return requestPath
	}

	stripped := strings.TrimPrefix(requestPath, prefix)
	if stripped == "" {
		return "/"
	}
	if !strings.HasPrefix(stripped, "/") {
		return "/" + stripped
	}
	return stripped
}

func MatchRouteTemplate(route config.RouterConfig, method, path string) (map[string]string, bool) {
	router := mux.NewRouter()
	handler := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	methods := route.EffectiveMethods()
	if len(methods) == 0 && method != "" {
		methods = []string{method}
	}

	switch {
	case route.Path == "/{rest:.*}" || route.Path == "/*":
		router.PathPrefix("/").Handler(handler).Methods(methods...)
	case len(route.Path) > 2 && route.Path[len(route.Path)-2:] == "/*":
		router.PathPrefix(route.Path[:len(route.Path)-1]).Handler(handler).Methods(methods...)
	default:
		router.Handle(route.Path, handler).Methods(methods...)
	}

	req := httptest.NewRequest(method, path, nil)
	var match mux.RouteMatch
	if !router.Match(req, &match) {
		return nil, false
	}
	if match.Vars == nil {
		match.Vars = map[string]string{}
	}
	return match.Vars, true
}

type ResolvedRouteMatch struct {
	Route   config.RouterConfig
	Vars    map[string]string
	Score   int
	Matched bool
}

func ResolveRouteMatch(routes []config.RouterConfig, method, path string) ResolvedRouteMatch {
	matches := make([]ResolvedRouteMatch, 0)
	for _, route := range routes {
		if !route.IsEnabled() || !route.SupportsMethod(method) {
			continue
		}
		vars, ok := MatchRouteTemplate(route, method, path)
		if !ok {
			continue
		}
		matches = append(matches, ResolvedRouteMatch{
			Route:   route,
			Vars:    vars,
			Score:   routeSpecificityScore(route),
			Matched: true,
		})
	}

	if len(matches) == 0 {
		return ResolvedRouteMatch{}
	}

	sort.SliceStable(matches, func(i, j int) bool {
		return matches[i].Score > matches[j].Score
	})

	return matches[0]
}

func routeSpecificityScore(route config.RouterConfig) int {
	score := len(route.Path)
	score += strings.Count(route.Path, "/") * 10
	score -= len(extractRouteVarNames(route.Path)) * 5
	if containsRestWildcard(route.Path) {
		score -= 50
	}
	if strings.HasSuffix(route.Path, "/*") || route.Path == "/*" {
		score -= 50
	}
	return score
}

func extractRouteVarNames(path string) []string {
	matches := routeVarRe.FindAllStringSubmatch(path, -1)
	names := make([]string, 0, len(matches))
	for _, match := range matches {
		if len(match) > 1 {
			names = append(names, match[1])
		}
	}
	return names
}
