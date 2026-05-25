package gateway

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net/http"
	"os"
	"strings"

	"github.com/bhangun/iket/pkg/config"
	"github.com/bhangun/iket/pkg/core/authcontext"
	"github.com/bhangun/iket/pkg/logging"
	"github.com/golang-jwt/jwt/v4"
)

func (g *Gateway) jwtAuthMiddleware(cfg config.JWTConfig) func(http.Handler) http.Handler {
	var pubKey *rsa.PublicKey
	var useRS256 bool
	if cfg.Enabled && contains(cfg.Algorithms, "RS256") && cfg.PublicKeyFile != "" {
		k, err := loadRSAPublicKey(cfg.PublicKeyFile)
		if err == nil {
			pubKey = k
			useRS256 = true
		} else {
			g.logger.Warn("Failed to load RS256 public key", logging.Error(err))
		}
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			clientIP := GetClientIP(r)
			if route, ok := g.matchRoute(r); ok {
				if !route.RequireJwt {
					next.ServeHTTP(w, r)
					return
				}
			}
			if !cfg.Enabled {
				next.ServeHTTP(w, r)
				return
			}
			auth := r.Header.Get("Authorization")
			if !strings.HasPrefix(auth, "Bearer ") {
				g.logger.Warn("401 Unauthorized",
					logging.String("reason", "Missing or invalid JWT"),
					logging.String("method", r.Method),
					logging.String("path", r.URL.Path),
					logging.String("remote_addr", r.RemoteAddr),
					logging.String("client_ip", clientIP),
				)
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte("Missing or invalid JWT"))
				return
			}
			tokenStr := strings.TrimPrefix(auth, "Bearer ")
			var token *jwt.Token
			var err error
			if useRS256 && pubKey != nil {
				token, err = jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
					if token.Method.Alg() != "RS256" {
						return nil, errors.New("unexpected signing method")
					}
					return pubKey, nil
				})
			} else {
				token, err = jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
					if token.Method.Alg() != "HS256" {
						return nil, errors.New("unexpected signing method")
					}
					return []byte(cfg.Secret), nil
				})
			}
			if err != nil || !token.Valid {
				g.logger.Warn("401 Unauthorized",
					logging.String("reason", "Invalid JWT"),
					logging.String("method", r.Method),
					logging.String("path", r.URL.Path),
					logging.String("remote_addr", r.RemoteAddr),
					logging.String("client_ip", clientIP),
				)
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte("Invalid JWT"))
				return
			}
			if claims, ok := token.Claims.(jwt.MapClaims); ok {
				ctx := context.WithValue(r.Context(), jwtClaimsKey, claims)
				ctx = authcontext.WithPrincipal(ctx, principalFromMapClaims(claims))
				r = r.WithContext(ctx)
			}
			next.ServeHTTP(w, r)
		})
	}
}

func contains(arr []string, s string) bool {
	for _, v := range arr {
		if v == s {
			return true
		}
	}
	return false
}

func loadRSAPublicKey(path string) (*rsa.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, errors.New("failed to decode PEM block containing public key")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("not an RSA public key")
	}
	return rsaPub, nil
}
