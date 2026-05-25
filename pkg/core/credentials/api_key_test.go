package credentials

import "testing"

func TestAPIKeyHashAndVerify(t *testing.T) {
	hash := APIKeyHash("secret")
	if hash == "" || hash == "secret" {
		t.Fatalf("expected hashed key, got %q", hash)
	}
	if !VerifyAPIKey("secret", hash) {
		t.Fatalf("expected key to verify against its hash")
	}
	if VerifyAPIKey("other", hash) {
		t.Fatalf("expected different key to be rejected")
	}
}

func TestNormalizeAPIKeyHashAcceptsBareSHA256(t *testing.T) {
	hash := APIKeyHash("secret")
	fingerprint := APIKeyFingerprintFromHash(hash)

	if got := NormalizeAPIKeyHash(fingerprint); got != hash {
		t.Fatalf("expected bare fingerprint to normalize to %q, got %q", hash, got)
	}
}
