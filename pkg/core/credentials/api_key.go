package credentials

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"strings"
)

const (
	APIKeyHashAlgorithm = "sha256"
	APIKeyHashPrefix    = APIKeyHashAlgorithm + ":"
	apiKeySHA256HexSize = sha256.Size * 2
)

// APIKeyFingerprint returns a stable, non-secret identifier for a plaintext API
// key. It is safe to expose for lookup/correlation, but it is still derived
// from the secret and should not be used as an authenticator.
func APIKeyFingerprint(key string) string {
	key = strings.TrimSpace(key)
	if key == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])
}

// APIKeyHash returns the canonical at-rest representation for API keys.
func APIKeyHash(key string) string {
	fingerprint := APIKeyFingerprint(key)
	if fingerprint == "" {
		return ""
	}
	return APIKeyHashPrefix + fingerprint
}

// NormalizeAPIKeyHash accepts the canonical "sha256:<hex>" representation and
// older bare SHA-256 hex values, returning the canonical representation when
// possible.
func NormalizeAPIKeyHash(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	lower := strings.ToLower(value)
	if strings.HasPrefix(lower, APIKeyHashPrefix) {
		hexValue := strings.TrimPrefix(lower, APIKeyHashPrefix)
		if isSHA256Hex(hexValue) {
			return APIKeyHashPrefix + hexValue
		}
		return value
	}
	if isSHA256Hex(lower) {
		return APIKeyHashPrefix + lower
	}
	return value
}

func APIKeyFingerprintFromHash(value string) string {
	value = NormalizeAPIKeyHash(value)
	if !strings.HasPrefix(value, APIKeyHashPrefix) {
		return ""
	}
	return strings.TrimPrefix(value, APIKeyHashPrefix)
}

func VerifyAPIKey(candidate, storedHash string) bool {
	candidateFingerprint := APIKeyFingerprint(candidate)
	storedFingerprint := APIKeyFingerprintFromHash(storedHash)
	if candidateFingerprint == "" || storedFingerprint == "" {
		return false
	}
	if len(candidateFingerprint) != len(storedFingerprint) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(candidateFingerprint), []byte(storedFingerprint)) == 1
}

func isSHA256Hex(value string) bool {
	if len(value) != apiKeySHA256HexSize {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}
