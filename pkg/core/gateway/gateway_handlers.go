package gateway

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/bhangun/iket/pkg/core/authcontext"
	"github.com/bhangun/iket/pkg/logging"
)

// healthHandler handles health check requests.
func (g *Gateway) healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"UP","timestamp":"` + time.Now().Format(time.RFC3339) + `"}`))
}

// metricsHandler handles metrics requests.
func (g *Gateway) metricsHandler(w http.ResponseWriter, r *http.Request) {
	if g.metrics != nil {
		g.metrics.ServeHTTP(w, r)
	} else {
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte(`{"error":"Metrics not available"}`))
	}
}

// notFoundHandler handles 404 requests.
func (g *Gateway) notFoundHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Printf("notFoundHandler called for path: %s\n", r.URL.Path)
	clientIP := GetClientIP(r)
	g.logger.Warn("404 Not Found",
		logging.String("method", r.Method),
		logging.String("path", r.URL.Path),
		logging.String("remote_addr", r.RemoteAddr),
		logging.String("client_ip", clientIP),
	)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotFound)
	w.Write([]byte(`{"error":"Not Found","message":"The requested resource does not exist"}`))
}

// configHandler returns the current configuration as JSON, with secrets redacted.
func (g *Gateway) configHandler(w http.ResponseWriter, r *http.Request) {
	cfg, err := RedactedConfig(g.GetConfig())
	if err != nil {
		http.Error(w, "failed to redact configuration", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(cfg)
}

// adminAuthMiddleware enforces Basic Auth for admin endpoints.
func (g *Gateway) adminAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clientIP := GetClientIP(r)
		g.logger.Debug("Admin request", logging.String("client_ip", clientIP))
		user, pass, ok := r.BasicAuth()
		if !ok || user == "" || pass == "" {
			g.logger.Warn("401 Unauthorized (admin endpoint)",
				logging.String("reason", "Missing or invalid admin credentials"),
				logging.String("method", r.Method),
				logging.String("path", r.URL.Path),
				logging.String("remote_addr", r.RemoteAddr),
				logging.String("client_ip", clientIP),
			)
			w.Header().Set("WWW-Authenticate", "Basic realm=\"Iket Admin\"")
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("Missing or invalid admin credentials"))
			return
		}
		if expected, ok := g.config.Security.BasicAuthUsers[user]; !ok || expected != pass {
			g.logger.Warn("401 Unauthorized (admin endpoint)",
				logging.String("reason", "Invalid admin credentials"),
				logging.String("method", r.Method),
				logging.String("path", r.URL.Path),
				logging.String("remote_addr", r.RemoteAddr),
				logging.String("client_ip", clientIP),
			)
			w.Header().Set("WWW-Authenticate", "Basic realm=\"Iket Admin\"")
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("Invalid admin credentials"))
			return
		}
		ctx := authcontext.WithPrincipal(r.Context(), principalFromBasicIdentity("admin_basic_auth", user))
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// versionHandler returns the current version as JSON.
func (g *Gateway) versionHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"version": g.version})
}
