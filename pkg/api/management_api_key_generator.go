package api

import (
	"crypto/rand"
	"encoding/base64"
	"strings"
)

const (
	defaultAPIKeyPrefix = "iket_live_"
	defaultAPIKeyBytes  = 32
)

type APIKeyGenerator interface {
	GenerateAPIKey() (string, error)
}

// CryptoRandAPIKeyGenerator is the community default API key issuer. It avoids
// shelling out to openssl and keeps the implementation swappable for enterprise
// KMS/HSM providers.
type CryptoRandAPIKeyGenerator struct {
	Prefix string
	Bytes  int
}

func (g CryptoRandAPIKeyGenerator) GenerateAPIKey() (string, error) {
	size := g.Bytes
	if size <= 0 {
		size = defaultAPIKeyBytes
	}
	prefix := strings.TrimSpace(g.Prefix)
	if prefix == "" {
		prefix = defaultAPIKeyPrefix
	}

	secret := make([]byte, size)
	if _, err := rand.Read(secret); err != nil {
		return "", err
	}
	return prefix + base64.RawURLEncoding.EncodeToString(secret), nil
}

func (api *ManagementAPI) clientAPIKeyGenerator() APIKeyGenerator {
	if api != nil && api.apiKeyGenerator != nil {
		return api.apiKeyGenerator
	}
	return CryptoRandAPIKeyGenerator{}
}
