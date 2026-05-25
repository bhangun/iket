package gateway

import (
	"net/http"

	"github.com/bhangun/iket/pkg/config"
	"github.com/bhangun/iket/pkg/core/authcontext"
	"github.com/bhangun/iket/pkg/logging"
	"github.com/bhangun/iket/pkg/plugin"
)

// setupMiddleware configures the middleware chain.
func (g *Gateway) setupMiddleware() error {
	g.router.Use(g.routeContextMiddleware())
	if len(g.config.Security.Clients) > 0 {
		g.router.Use(g.clientCredentialAuthMiddleware())
	}
	g.router.Use(g.loggingMiddleware())
	g.router.Use(g.metricsMiddleware())
	g.router.Use(g.securityHeadersMiddleware())

	if g.config.Security.Jwt.Enabled {
		jwtCfg := config.JWTConfig{
			Enabled:       g.config.Security.Jwt.Enabled,
			Secret:        g.config.Security.Jwt.Secret,
			Algorithms:    g.config.Security.Jwt.Algorithms,
			PublicKeyFile: g.config.Security.Jwt.PublicKeyFile,
			Required:      g.config.Security.Jwt.Required,
		}
		g.router.Use(g.jwtAuthMiddleware(jwtCfg))
	}

	for pluginName, pluginConfig := range g.config.Plugins {
		p, err := g.pluginRegistry.Get(pluginName)
		if err != nil {
			g.logger.Warn("Plugin not found", logging.String("plugin", pluginName), logging.Error(err))
			continue
		}
		if err := p.Initialize(pluginConfig); err != nil {
			g.logger.Warn("Failed to initialize global plugin", logging.String("plugin", pluginName), logging.Error(err))
			continue
		}
		if mp, ok := p.(plugin.MiddlewarePlugin); ok {
			g.router.Use(mp.Middleware)
		}
	}

	g.router.Use(g.errorLoggingMiddleware())
	return nil
}

// clientCredentialAuthMiddleware enforces HTTP Basic Auth using security.clients.
func (g *Gateway) clientCredentialAuthMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			matched := false
			requireAuth := true
			for _, route := range g.config.GetAllRoutesFromServices(g.logger) {
				if !route.IsEnabled() {
					continue
				}
				if !route.SupportsMethod(r.Method) {
					continue
				}
				if route.Path == r.URL.Path || containsRestWildcard(route.Path) {
					matched = true
					requireAuth = route.RequireAuth
					break
				}
			}
			if matched && !requireAuth {
				next.ServeHTTP(w, r)
				return
			}

			user, pass, ok := r.BasicAuth()
			if !ok || user == "" || pass == "" {
				w.Header().Set("WWW-Authenticate", "Basic realm=\"Iket Gateway\"")
				w.WriteHeader(http.StatusUnauthorized)
				w.Write([]byte("Missing or invalid client credentials"))
				return
			}
			if secret, ok := g.config.Security.Clients[user]; !ok || secret != pass {
				w.Header().Set("WWW-Authenticate", "Basic realm=\"Iket Gateway\"")
				w.WriteHeader(http.StatusUnauthorized)
				w.Write([]byte("Invalid client credentials"))
				return
			}
			ctx := authcontext.WithPrincipal(r.Context(), principalFromBasicIdentity("client_credentials", user))
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// requireRolesMiddleware returns a middleware that enforces at least one required role.
func requireRolesMiddleware(requiredRoles []string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			matched, present := authcontext.HasAnyRole(r.Context(), requiredRoles)
			if !present {
				w.WriteHeader(http.StatusForbidden)
				w.Write([]byte(`{"error":"Forbidden","message":"No roles found in token"}`))
				return
			}
			if !matched {
				w.WriteHeader(http.StatusForbidden)
				w.Write([]byte(`{"error":"Forbidden","message":"Insufficient roles"}`))
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// requireScopesMiddleware returns a middleware that enforces at least one required scope.
func requireScopesMiddleware(requiredScopes []string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			matched, present := authcontext.HasAnyScope(r.Context(), requiredScopes)
			if !present {
				w.WriteHeader(http.StatusForbidden)
				w.Write([]byte(`{"error":"Forbidden","message":"No scopes found for authenticated principal"}`))
				return
			}
			if !matched {
				w.WriteHeader(http.StatusForbidden)
				w.Write([]byte(`{"error":"Forbidden","message":"Insufficient scopes"}`))
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// requireGroupMiddleware returns a middleware that enforces the required client group.
func requireGroupMiddleware(requiredGroup string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			matched, present := authcontext.HasGroup(r.Context(), requiredGroup)
			if !present || !matched {
				w.WriteHeader(http.StatusForbidden)
				w.Write([]byte(`{"error":"Forbidden","message":"Principal group mismatch"}`))
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
