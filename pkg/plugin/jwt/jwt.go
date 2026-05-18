package jwt

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"

	coreerrors "github.com/bhangun/iket/pkg/core/errors"
	"github.com/bhangun/iket/pkg/plugin"
	"github.com/golang-jwt/jwt/v4"
)

type JWTPlugin struct {
	enabled       bool
	secret        string
	publicKey     *rsa.PublicKey
	algorithms    []string
	issuer        string
	audience      string
	skipPaths     []string
	claimsContext string
	mu            sync.RWMutex
}

type Claims struct {
	UserID   string            `json:"user_id"`
	Username string            `json:"username"`
	Email    string            `json:"email"`
	Roles    []string          `json:"roles"`
	Custom   map[string]string `json:"custom,omitempty"`
	jwt.RegisteredClaims
}

func (j *JWTPlugin) Name() string {
	return "jwt"
}

func (j *JWTPlugin) Type() string {
	return "jwt"
}

func (j *JWTPlugin) Initialize(config map[string]interface{}) error {
	j.mu.Lock()
	defer j.mu.Unlock()

	// Default values
	j.enabled = false
	j.algorithms = []string{"HS256", "RS256"}
	j.claimsContext = "jwt_claims"

	// Load configuration
	if enabled, ok := config["enabled"].(bool); ok {
		j.enabled = enabled
	}

	if !j.enabled {
		return nil
	}

	if secret, ok := config["secret"].(string); ok {
		j.secret = secret
	}

	if publicKeyFile, ok := config["public_key_file"].(string); ok && publicKeyFile != "" {
		if err := j.loadPublicKey(publicKeyFile); err != nil {
			return coreerrors.NewConfigError("failed to load public key", err)
		}
	}

	if issuer, ok := config["issuer"].(string); ok {
		j.issuer = issuer
	}

	if audience, ok := config["audience"].(string); ok {
		j.audience = audience
	}

	if skipPaths, ok := config["skip_paths"].([]interface{}); ok {
		for _, path := range skipPaths {
			if pathStr, ok := path.(string); ok {
				j.skipPaths = append(j.skipPaths, pathStr)
			}
		}
	}

	if claimsContext, ok := config["claims_context"].(string); ok {
		j.claimsContext = claimsContext
	}

	return nil
}

func (j *JWTPlugin) loadPublicKey(filename string) error {
	data, err := os.ReadFile(filename)
	if err != nil {
		return coreerrors.NewConfigError("failed to read public key file", err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return coreerrors.NewCodeError(coreerrors.CodeCertificatePEMInvalid, "failed to decode PEM block", nil)
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return coreerrors.NewConfigError("failed to parse public key", err)
	}

	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return coreerrors.NewConfigError("public key is not RSA", nil)
	}

	j.publicKey = rsaPub
	return nil
}

func (j *JWTPlugin) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !j.enabled {
			next.ServeHTTP(w, r)
			return
		}

		// Skip JWT validation for certain paths
		if j.shouldSkipValidation(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}

		// Extract and validate JWT token
		claims, err := j.validateToken(r)
		if err != nil {
			j.writeError(w, "Invalid JWT token", http.StatusUnauthorized)
			return
		}

		// Add claims to request context
		ctx := context.WithValue(r.Context(), j.claimsContext, claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (j *JWTPlugin) shouldSkipValidation(path string) bool {
	for _, skipPath := range j.skipPaths {
		if strings.HasPrefix(path, skipPath) {
			return true
		}
	}
	return false
}

func (j *JWTPlugin) validateToken(r *http.Request) (*Claims, error) {
	// Extract token from Authorization header
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return nil, coreerrors.NewCodeError(coreerrors.CodeAuthenticationRequired, "missing authorization header", nil)
	}

	if !strings.HasPrefix(authHeader, "Bearer ") {
		return nil, coreerrors.NewCodeError(coreerrors.CodeUnauthorized, "invalid authorization header format", nil)
	}

	tokenString := strings.TrimPrefix(authHeader, "Bearer ")

	// Parse and validate token
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, j.getKeyFunc())
	if err != nil {
		return nil, coreerrors.NewCodeError(coreerrors.CodeUnauthorized, "failed to parse token", err)
	}

	if !token.Valid {
		return nil, coreerrors.NewCodeError(coreerrors.CodeUnauthorized, "invalid token", nil)
	}

	claims, ok := token.Claims.(*Claims)
	if !ok {
		return nil, coreerrors.NewCodeError(coreerrors.CodeUnauthorized, "invalid claims type", nil)
	}

	// Validate issuer if configured
	if j.issuer != "" && claims.Issuer != j.issuer {
		return nil, coreerrors.NewCodeError(coreerrors.CodeUnauthorized, "invalid issuer", nil)
	}

	// Validate audience if configured
	if j.audience != "" {
		validAudience := false
		for _, aud := range claims.Audience {
			if aud == j.audience {
				validAudience = true
				break
			}
		}
		if !validAudience {
			return nil, coreerrors.NewCodeError(coreerrors.CodeUnauthorized, "invalid audience", nil)
		}
	}

	return claims, nil
}

func (j *JWTPlugin) getKeyFunc() jwt.Keyfunc {
	return func(token *jwt.Token) (interface{}, error) {
		// Check algorithm
		algo := token.Method.Alg()

		validAlgo := false
		for _, validAlg := range j.algorithms {
			if algo == validAlg {
				validAlgo = true
				break
			}
		}
		if !validAlgo {
			return nil, coreerrors.NewCodeError(coreerrors.CodeUnauthorized, fmt.Sprintf("unsupported algorithm: %s", algo), nil)
		}

		// Return appropriate key based on algorithm
		switch algo {
		case "HS256", "HS384", "HS512":
			if j.secret == "" {
				return nil, coreerrors.NewRequiredFieldError("secret key required for HMAC algorithms")
			}
			return []byte(j.secret), nil
		case "RS256", "RS384", "RS512":
			if j.publicKey == nil {
				return nil, coreerrors.NewRequiredFieldError("public key required for RSA algorithms")
			}
			return j.publicKey, nil
		default:
			return nil, coreerrors.NewCodeError(coreerrors.CodeUnauthorized, fmt.Sprintf("unsupported algorithm: %s", algo), nil)
		}
	}
}

func (j *JWTPlugin) writeError(w http.ResponseWriter, message string, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	response := map[string]interface{}{
		"error":   "JWT Error",
		"message": message,
	}
	json.NewEncoder(w).Encode(response)
}

// GetClaimsFromContext extracts JWT claims from request context
func (j *JWTPlugin) GetClaimsFromContext(ctx context.Context) (*Claims, bool) {
	claims, ok := ctx.Value(j.claimsContext).(*Claims)
	return claims, ok
}

// Tags returns plugin tags for discovery
func (j *JWTPlugin) Tags() map[string]string {
	return map[string]string{
		"type":       "jwt",
		"category":   "auth",
		"middleware": "true",
		"algorithms": strings.Join(j.algorithms, ","),
	}
}

// Health checks if the JWT plugin is healthy
func (j *JWTPlugin) Health() error {
	j.mu.RLock()
	defer j.mu.RUnlock()

	if !j.enabled {
		return coreerrors.NewCodeError(coreerrors.CodePluginUnsupported, "JWT plugin is disabled", nil)
	}

	// Check if we have either secret or public key
	if j.secret == "" && j.publicKey == nil {
		return coreerrors.NewRequiredFieldError("neither secret nor public key configured")
	}

	return nil
}

// Status returns human-readable status
func (j *JWTPlugin) Status() string {
	j.mu.RLock()
	defer j.mu.RUnlock()

	if !j.enabled {
		return "JWT Plugin: Disabled"
	}

	status := fmt.Sprintf("JWT Plugin: Enabled (algorithms: %s", strings.Join(j.algorithms, ","))
	if j.issuer != "" {
		status += fmt.Sprintf(", issuer: %s", j.issuer)
	}
	if j.audience != "" {
		status += fmt.Sprintf(", audience: %s", j.audience)
	}
	status += ")"

	return status
}

// OnStart lifecycle hook
func (j *JWTPlugin) OnStart() error {
	// Validate JWT config on startup
	return j.Health()
}

// OnShutdown lifecycle hook
func (j *JWTPlugin) OnShutdown() error {
	// Clean up any JWT-related resources if needed
	return nil
}

func init() {
	plugin.RegisterFactory("jwt", func(config map[string]interface{}) (plugin.Plugin, error) {
		p := &JWTPlugin{}
		if err := p.Initialize(config); err != nil {
			return nil, err
		}
		return p, nil
	})
}
