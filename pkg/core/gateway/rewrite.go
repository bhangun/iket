package gateway

import (
	"fmt"
	"hash/fnv"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strings"

	"github.com/bhangun/iket/pkg/config"
	"github.com/gorilla/mux"
)

func ComputeProxiedPath(service *config.Service, route config.RouterConfig, requestPath string, vars map[string]string) (string, error) {
	backend := config.Backend{}
	if len(route.Backends) > 0 {
		backend = route.Backends[0]
	}
	return ComputeProxiedPathForBackend(service, route, backend, requestPath, vars)
}

func ComputeProxiedPathForBackend(service *config.Service, route config.RouterConfig, backend config.Backend, requestPath string, vars map[string]string) (string, error) {
	if service == nil {
		return "", fmt.Errorf("service is required")
	}

	destURL, err := url.Parse(service.Host)
	if err != nil {
		return "", err
	}

	upstreamPath := requestPath
	if strings.TrimSpace(backend.URLPattern) != "" {
		upstreamPath = applyURLPattern(backend.URLPattern, route.Path, requestPath, vars)
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

func MatchRouteTemplate(route config.RouterConfig, method, path string, headers http.Header) (map[string]string, bool) {
	router := mux.NewRouter()
	handler := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	methods := route.EffectiveMethods()
	if len(methods) == 0 && method != "" {
		methods = []string{method}
	}

	var registered *mux.Route
	switch {
	case route.Path == "/{rest:.*}" || route.Path == "/*":
		registered = router.PathPrefix("/").Handler(handler).Methods(methods...)
	case len(route.Path) > 2 && route.Path[len(route.Path)-2:] == "/*":
		registered = router.PathPrefix(route.Path[:len(route.Path)-1]).Handler(handler).Methods(methods...)
	default:
		registered = router.Handle(route.Path, handler).Methods(methods...)
	}
	if registered != nil && len(route.MatchHeaders) > 0 {
		headerPairs := make([]string, 0, len(route.MatchHeaders)*2)
		for key, value := range route.MatchHeaders {
			headerPairs = append(headerPairs, key, value)
		}
		registered.Headers(headerPairs...)
	}

	req := httptest.NewRequest(method, path, nil)
	for key, values := range headers {
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}
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

func ResolveRouteMatch(routes []config.RouterConfig, method, path string, headers http.Header, bucketKey string) ResolvedRouteMatch {
	matches := make([]ResolvedRouteMatch, 0)
	for _, route := range routes {
		if !route.IsEnabled() || !route.SupportsMethod(method) {
			continue
		}
		vars, ok := MatchRouteTemplate(route, method, path, headers)
		if !ok {
			continue
		}
		if !routeTrafficGateMatches(route, bucketKey) {
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
	score += len(route.MatchHeaders) * 25
	if route.MatchPercent > 0 {
		score += 15
	}
	if containsRestWildcard(route.Path) {
		score -= 50
	}
	if strings.HasSuffix(route.Path, "/*") || route.Path == "/*" {
		score -= 50
	}
	return score
}

func routeTrafficGateMatches(route config.RouterConfig, bucketKey string) bool {
	if route.MatchPercent <= 0 {
		return true
	}
	if route.MatchPercent >= 100 {
		return true
	}
	return percentageBucketForKey(bucketKey) < route.MatchPercent
}

func percentageBucketForKey(key string) int {
	key = strings.TrimSpace(key)
	if key == "" {
		key = "default"
	}
	h := fnv.New32a()
	_, _ = h.Write([]byte(key))
	return int(h.Sum32() % 100)
}

func SelectRouteBackend(route config.RouterConfig, bucketKey string) config.Backend {
	if len(route.Backends) == 0 {
		return config.Backend{}
	}
	if len(route.Backends) == 1 {
		return route.Backends[0]
	}
	totalWeight := 0
	for _, backend := range route.Backends {
		totalWeight += effectiveBackendWeight(backend)
	}
	if totalWeight <= 0 {
		return route.Backends[0]
	}
	bucket := weightedBackendBucketForKey(bucketKey, totalWeight)
	running := 0
	for _, backend := range route.Backends {
		running += effectiveBackendWeight(backend)
		if bucket < running {
			return backend
		}
	}
	return route.Backends[len(route.Backends)-1]
}

func effectiveBackendWeight(backend config.Backend) int {
	if backend.Weight <= 0 {
		return 1
	}
	return backend.Weight
}

func weightedBackendBucketForKey(key string, totalWeight int) int {
	if totalWeight <= 0 {
		return 0
	}
	key = strings.TrimSpace(key)
	if key == "" {
		key = "default"
	}
	h := fnv.New32a()
	_, _ = h.Write([]byte("backend|" + key))
	return int(h.Sum32() % uint32(totalWeight))
}

func PreferredRouteBackendIndex(route config.RouterConfig, bucketKey string) int {
	if len(route.Backends) == 0 {
		return -1
	}
	if len(route.Backends) == 1 {
		return 0
	}
	totalWeight := 0
	for _, backend := range route.Backends {
		totalWeight += effectiveBackendWeight(backend)
	}
	if totalWeight <= 0 {
		return 0
	}
	bucket := weightedBackendBucketForKey(bucketKey, totalWeight)
	running := 0
	for i, backend := range route.Backends {
		running += effectiveBackendWeight(backend)
		if bucket < running {
			return i
		}
	}
	return len(route.Backends) - 1
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
