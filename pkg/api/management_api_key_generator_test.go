package api

import (
	"strings"
	"testing"
)

func TestCryptoRandAPIKeyGeneratorUsesDefaultIketPrefix(t *testing.T) {
	key, err := (CryptoRandAPIKeyGenerator{}).GenerateAPIKey()
	if err != nil {
		t.Fatalf("failed to generate API key: %v", err)
	}
	if !strings.HasPrefix(key, defaultAPIKeyPrefix) {
		t.Fatalf("expected generated key to use %q prefix, got %q", defaultAPIKeyPrefix, key)
	}
	if len(strings.TrimPrefix(key, defaultAPIKeyPrefix)) < 32 {
		t.Fatalf("generated key payload is too short: %q", key)
	}
}
