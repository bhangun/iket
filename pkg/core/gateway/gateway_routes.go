package gateway

import (
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/bhangun/iket/pkg/config"
	"github.com/bhangun/iket/pkg/logging"
	"github.com/bhangun/iket/pkg/plugin"

	"github.com/gorilla/mux"
)

// setupRoutes configures all the routes for the gateway.
func (g *Gateway) setupRoutes() error {
	allRoutes := g.config.GetAllRoutesFromServices(g.logger)
	sort.SliceStable(allRoutes, func(i, j int) bool {
		return routeSpecificityScore(allRoutes[i]) > routeSpecificityScore(allRoutes[j])
	})
	g.logger.Info("Loaded routes from config", logging.Int("count", len(allRoutes)))

	g.router.HandleFunc("/health", g.healthHandler).Methods(http.MethodGet)
	g.router.HandleFunc("/metrics", g.metricsHandler).Methods(http.MethodGet)
	g.router.Handle("/admin/config", g.adminAuthMiddleware(http.HandlerFunc(g.configHandler))).Methods(http.MethodGet)
	g.router.Handle("/admin/version", g.adminAuthMiddleware(http.HandlerFunc(g.versionHandler))).Methods(http.MethodGet)

	for _, route := range allRoutes {
		if !route.IsEnabled() {
			continue
		}
		if err := g.addProxyRoute(route); err != nil {
			return fmt.Errorf("failed to add route %s: %w", route.Path, err)
		}
	}

	g.registerPluginHTTPRoutes()
	g.router.NotFoundHandler = http.HandlerFunc(g.notFoundHandler)
	return nil
}

// addProxyRoute adds a proxy route to the router.
func (g *Gateway) addProxyRoute(route config.RouterConfig) error {
	var handler http.Handler = http.HandlerFunc(g.proxyHandler(route))

	if route.RequireAuth {
		if route.AuthPlugin != "" {
			p, err := g.pluginRegistry.Get(route.AuthPlugin)
			if err == nil {
				if mp, ok := p.(plugin.MiddlewarePlugin); ok {
					handler = mp.Middleware(handler)
				}
			}
		} else {
			for pluginName, pluginConfig := range g.config.Plugins {
				p, err := g.pluginRegistry.Get(pluginName)
				if err == nil {
					if err := p.Initialize(pluginConfig); err == nil {
						if mp, ok := p.(plugin.MiddlewarePlugin); ok {
							handler = mp.Middleware(handler)
						}
					}
				}
			}
		}

		if len(route.Roles) > 0 {
			handler = requireRolesMiddleware(route.Roles)(handler)
		}

		service := g.config.FindServiceForRoute(route.Path, "", route.MatchHeaders)
		if service != nil {
			if service.Group != "" {
				handler = requireGroupMiddleware(service.Group)(handler)
			}

			allRequiredScopes := append([]string{}, service.Scopes...)
			allRequiredScopes = append(allRequiredScopes, route.Scopes...)
			if len(allRequiredScopes) > 0 {
				handler = requireScopesMiddleware(allRequiredScopes)(handler)
			}
		} else if len(route.Scopes) > 0 {
			handler = requireScopesMiddleware(route.Scopes)(handler)
		}
	}

	if effectiveRouteRateLimitPolicy(route) != nil {
		handler = g.routeRateLimitMiddleware()(handler)
	}
	if effectiveRouteConcurrencyPolicy(route) != nil {
		handler = g.routeConcurrencyLimitMiddleware()(handler)
	}

	if route.Timeout != nil {
		handler = g.timeoutMiddleware(*route.Timeout)(handler)
	}
	if route.CORS != nil {
		handler = corsMiddleware(route)(handler)
	}

	if route.Path == "/{rest:.*}" || route.Path == "/*" {
		registered := g.router.PathPrefix("/").Handler(handler).Methods(route.EffectiveMethodsForRegistration()...)
		applyRouteHeaderMatchers(registered, route.MatchHeaders)
		g.logRegisteredRoute("Added wildcard route (PathPrefix)", route)
	} else if strings.HasSuffix(route.Path, "/*") {
		prefix := route.Path[:len(route.Path)-1]
		registered := g.router.PathPrefix(prefix).Handler(handler).Methods(route.EffectiveMethodsForRegistration()...)
		applyRouteHeaderMatchers(registered, route.MatchHeaders)
		g.logRegisteredRoute("Added wildcard route (PathPrefix)", route)
	} else if route.Path == "/" {
		registered := g.router.Handle(route.Path, handler).Methods(route.EffectiveMethodsForRegistration()...)
		applyRouteHeaderMatchers(registered, route.MatchHeaders)
		g.logRegisteredRoute("Added root route", route)
	} else if containsRestWildcard(route.Path) {
		registered := g.router.Handle(route.Path, handler).Methods(route.EffectiveMethodsForRegistration()...)
		applyRouteHeaderMatchers(registered, route.MatchHeaders)
		g.logRegisteredRoute("Added regex wildcard route", route)
	} else {
		registered := g.router.Handle(route.Path, handler).Methods(route.EffectiveMethodsForRegistration()...)
		applyRouteHeaderMatchers(registered, route.MatchHeaders)
		g.logRegisteredRoute("Added route", route)
	}

	return nil
}

func (g *Gateway) logRegisteredRoute(message string, route config.RouterConfig) {
	service := g.config.FindServiceForRoute(route.Path, "", route.MatchHeaders)
	backend := ""
	if service != nil {
		backend = service.Host
	}
	g.logger.Info(message, logging.String("path", route.Path), logging.String("backend", backend))
}

func applyRouteHeaderMatchers(route *mux.Route, headers map[string]string) {
	if route == nil || len(headers) == 0 {
		return
	}
	headerPairs := make([]string, 0, len(headers)*2)
	for key, value := range headers {
		headerPairs = append(headerPairs, key, value)
	}
	route.Headers(headerPairs...)
}

// containsRestWildcard checks if the path contains a {rest:.*} wildcard.
func containsRestWildcard(path string) bool {
	return path == "/{rest:.*}" || (len(path) >= 9 && path[len(path)-9:] == "{rest:.*}")
}
