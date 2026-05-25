package gateway

import (
	"net/http"
	"strings"

	"github.com/bhangun/iket/pkg/config"
	"github.com/bhangun/iket/pkg/core/authcontext"
	"github.com/bhangun/iket/pkg/core/credentials"
	"github.com/golang-jwt/jwt/v4"
)

type routeLimitKeyPolicy struct {
	keyBy     string
	keyHeader string
}

func resolveRouteRateLimitKey(r *http.Request, policy *config.RateLimitPolicyConfig) (string, string) {
	if policy == nil {
		return globalLimitBucketKey()
	}
	return resolveRouteLimitKey(r, routeLimitKeyPolicy{
		keyBy:     policy.KeyBy,
		keyHeader: policy.KeyHeader,
	})
}

func resolveRouteConcurrencyKey(r *http.Request, policy *config.ConcurrencyLimitPolicyConfig) (string, string) {
	if policy == nil {
		return globalLimitBucketKey()
	}
	return resolveRouteLimitKey(r, routeLimitKeyPolicy{
		keyBy:     policy.KeyBy,
		keyHeader: policy.KeyHeader,
	})
}

func resolveRouteLimitKey(r *http.Request, policy routeLimitKeyPolicy) (string, string) {
	switch config.NormalizeLimitKeyType(policy.keyBy) {
	case "", config.LimitKeyGlobal:
		return globalLimitBucketKey()
	case config.LimitKeyIP:
		return config.LimitKeyIP, GetClientIP(r)
	case config.LimitKeyHeader:
		return config.LimitKeyHeader, headerBucketKey(policy.keyHeader, r.Header.Get(strings.TrimSpace(policy.keyHeader)))
	case config.LimitKeyAPIKey:
		if key := apiKeyBucketKey(r); key != "" {
			return config.LimitKeyAPIKey, key
		}
		return missingLimitBucketKey(config.LimitKeyAPIKey)
	case config.LimitKeyJWTSub:
		if subject := jwtSubjectBucketKey(r); subject != "" {
			return config.LimitKeyJWTSub, subject
		}
		return missingLimitBucketKey(config.LimitKeyJWTSub)
	case config.LimitKeyPrincipal:
		if key := principalBucketKey(r); key != "" {
			return config.LimitKeyPrincipal, key
		}
		return missingLimitBucketKey(config.LimitKeyPrincipal)
	default:
		return globalLimitBucketKey()
	}
}

func globalLimitBucketKey() (string, string) {
	return "global", "global"
}

func missingLimitBucketKey(keyType string) (string, string) {
	return keyType, "__missing__"
}

func headerBucketKey(headerName string, headerValue string) string {
	headerName = strings.ToLower(strings.TrimSpace(headerName))
	headerValue = strings.TrimSpace(headerValue)
	if headerValue == "" {
		return headerName + ":__missing__"
	}
	if isSensitiveLimitHeader(headerName) {
		return headerName + ":fingerprint:" + credentials.APIKeyFingerprint(headerValue)
	}
	return headerName + ":" + headerValue
}

func isSensitiveLimitHeader(headerName string) bool {
	headerName = strings.ReplaceAll(strings.ToLower(strings.TrimSpace(headerName)), "_", "-")
	switch headerName {
	case "authorization", "proxy-authorization", "cookie", "set-cookie", "x-api-key", "api-key", "x-auth-token", "x-access-token", "x-csrf-token", "x-xsrf-token":
		return true
	}
	return strings.Contains(headerName, "token") ||
		strings.Contains(headerName, "secret") ||
		strings.Contains(headerName, "password") ||
		strings.Contains(headerName, "credential") ||
		strings.Contains(headerName, "apikey") ||
		strings.Contains(headerName, "api-key")
}

func principalBucketKey(r *http.Request) string {
	identity, ok := authcontext.PrincipalIdentityFromContext(r.Context())
	if !ok {
		return ""
	}
	return principalIdentityBucketKey(identity)
}

func principalIdentityBucketKey(identity authcontext.PrincipalIdentity) string {
	kind := strings.ToLower(strings.TrimSpace(identity.Kind))
	source := strings.ToLower(strings.TrimSpace(identity.Source))
	value := strings.TrimSpace(identity.Value)
	if kind == "" || value == "" {
		return ""
	}
	if identity.Sensitive {
		return kind + "_fingerprint:" + credentials.APIKeyFingerprint(value)
	}
	if kind == authcontext.PrincipalIdentityClient {
		return kind + ":" + value
	}
	if source != "" {
		return kind + ":" + source + ":" + value
	}
	return kind + ":" + value
}

func apiKeyBucketKey(r *http.Request) string {
	if principal, ok := authcontext.PrincipalFromContext(r.Context()); ok {
		if key := apiKeyPrincipalBucketKey(principal); key != "" {
			return key
		}
	}
	if user, _, ok := r.BasicAuth(); ok && strings.TrimSpace(user) != "" {
		return "basic:" + strings.TrimSpace(user)
	}
	if headerValue := strings.TrimSpace(r.Header.Get("X-API-Key")); headerValue != "" {
		return apiKeyFingerprintBucketKey(headerValue)
	}
	return ""
}

func apiKeyPrincipalBucketKey(principal authcontext.Principal) string {
	source := strings.ToLower(strings.TrimSpace(principal.Source))
	switch source {
	case "apikey":
		if clientID := firstNonEmpty(strings.TrimSpace(principal.ClientID), strings.TrimSpace(principal.Subject), strings.TrimSpace(principal.UserID)); clientID != "" {
			return "apikey:" + clientID
		}
		if principal.Custom != nil {
			if fingerprint := strings.TrimSpace(principal.Custom["key_fingerprint"]); fingerprint != "" {
				return "apikey_fingerprint:" + fingerprint
			}
		}
	case "client_credentials":
		if clientID := firstNonEmpty(strings.TrimSpace(principal.ClientID), strings.TrimSpace(principal.Subject), strings.TrimSpace(principal.UserID)); clientID != "" {
			return "basic:" + clientID
		}
	}
	return ""
}

func apiKeyFingerprintBucketKey(key string) string {
	if fingerprint := credentials.APIKeyFingerprint(key); fingerprint != "" {
		return "apikey_fingerprint:" + fingerprint
	}
	return ""
}

func jwtSubjectBucketKey(r *http.Request) string {
	if principal, ok := authcontext.PrincipalFromContext(r.Context()); ok && isJWTSubjectPrincipal(principal.Source) {
		return firstNonEmpty(strings.TrimSpace(principal.Subject), strings.TrimSpace(principal.UserID))
	}
	if claims, ok := r.Context().Value(jwtClaimsKey).(jwt.MapClaims); ok {
		return stringClaim(claims, "sub")
	}
	return ""
}

func isJWTSubjectPrincipal(source string) bool {
	switch strings.ToLower(strings.TrimSpace(source)) {
	case "jwt", "oauth2":
		return true
	default:
		return false
	}
}
