package gateway

import (
	"net/http"

	"github.com/bhangun/iket/pkg/logging"
)

func (g *Gateway) errorLoggingMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			rw := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}
			next.ServeHTTP(rw, r)
			clientIP := GetClientIP(r)
			if rw.statusCode >= 400 {
				g.logger.Warn("HTTP error response",
					logging.Int("status_code", rw.statusCode),
					logging.String("method", r.Method),
					logging.String("path", r.URL.Path),
					logging.String("remote_addr", r.RemoteAddr),
					logging.String("client_ip", clientIP),
				)
			}
		})
	}
}
