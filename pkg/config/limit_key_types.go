package config

import "strings"

const (
	LimitKeyGlobal    = "global"
	LimitKeyIP        = "ip"
	LimitKeyHeader    = "header"
	LimitKeyAPIKey    = "api_key"
	LimitKeyJWTSub    = "jwt_sub"
	LimitKeyPrincipal = "principal"
)

const (
	SupportedRouteLimitKeyByValues      = "global, ip, header, api_key, jwt_sub, or principal"
	SupportedBucketedLimitKeyTypeValues = "ip, header, api_key, jwt_sub, or principal"
)

func NormalizeLimitKeyType(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func IsRouteLimitKeyBy(value string) bool {
	switch NormalizeLimitKeyType(value) {
	case "", LimitKeyGlobal, LimitKeyIP, LimitKeyHeader, LimitKeyAPIKey, LimitKeyJWTSub, LimitKeyPrincipal:
		return true
	default:
		return false
	}
}

func IsBucketedLimitKeyType(value string) bool {
	switch NormalizeLimitKeyType(value) {
	case LimitKeyIP, LimitKeyHeader, LimitKeyAPIKey, LimitKeyJWTSub, LimitKeyPrincipal:
		return true
	default:
		return false
	}
}
