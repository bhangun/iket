package gateway

import (
	"net/http"
	"strings"
)

func (g *Gateway) registerPluginHTTPRoutes() {
	if p, err := g.pluginRegistry.Get("billing"); err == nil {
		if handlerProvider, ok := p.(interface{ Routes() http.Handler }); ok {
			g.router.PathPrefix("/plugin/billing/").Handler(
				http.StripPrefix("/plugin/billing", handlerProvider.Routes()),
			)
		}
	}

	for pluginName, pluginConfig := range g.config.Plugins {
		if pluginName == "openapi" {
			g.registerOpenAPIPluginPlaceholders(pluginConfig)
		}
	}
}

func (g *Gateway) registerOpenAPIPluginPlaceholders(pluginConfig map[string]interface{}) {
	servePath := "/openapi"
	swaggerUI := false
	if v, ok := pluginConfig["path"].(string); ok && v != "" {
		servePath = v
	}
	if v, ok := pluginConfig["swagger_ui"].(bool); ok {
		swaggerUI = v
	}
	g.router.HandleFunc(servePath, func(w http.ResponseWriter, r *http.Request) {}).Methods(http.MethodGet)
	if swaggerUI {
		g.router.PathPrefix("/swagger-ui/").HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
		g.router.HandleFunc("/swagger-ui", func(w http.ResponseWriter, r *http.Request) {}).Methods(http.MethodGet)
	}
}

func servePluginRouteIfMatched(w http.ResponseWriter, r *http.Request) bool {
	if r == nil || r.URL == nil || !isPluginRoutePath(r.URL.Path) {
		return false
	}
	if next := r.Context().Value("next"); next != nil {
		if h, ok := next.(http.Handler); ok {
			h.ServeHTTP(w, r)
			return true
		}
	}
	w.WriteHeader(http.StatusNotFound)
	w.Write([]byte(`{"error":"Not Found","message":"The requested resource does not exist"}`))
	return true
}

func isPluginRoutePath(path string) bool {
	return path == "/openapi" ||
		path == "/swagger-ui" ||
		path == "/swagger-ui/" ||
		strings.HasPrefix(path, "/swagger-ui/")
}
