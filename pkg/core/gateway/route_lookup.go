package gateway

import (
	"net/http"

	"github.com/bhangun/iket/pkg/config"
)

func (g *Gateway) matchRoute(r *http.Request) (config.RouterConfig, bool) {
	if route, ok := GetMatchedRoute(r); ok {
		return route, true
	}
	match := ResolveRouteMatch(g.config.GetAllRoutesFromServices(g.logger), r.Method, r.URL.Path, r.Header, rolloutBucketKey(r))
	if match.Matched {
		return match.Route, true
	}
	return config.RouterConfig{}, false
}
