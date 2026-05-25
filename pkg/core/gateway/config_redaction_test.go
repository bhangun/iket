package gateway

import (
	"testing"

	"github.com/bhangun/iket/pkg/config"
)

func TestRedactedConfigMasksSecretsWithoutMutatingSource(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Security: config.SecurityConfig{
			EnableBasicAuth: true,
			BasicAuthUsers:  map[string]string{"admin": "admin-secret"},
			Clients:         map[string]string{"client-a": "client-secret"},
			Jwt:             config.JWTConfig{Secret: "jwt-secret"},
			NotificationWebhooks: []config.NotificationWebhook{{
				URL:           "https://hooks.example.test/events",
				SigningSecret: "webhook-secret",
			}},
		},
	}

	redacted, err := RedactedConfig(cfg)
	if err != nil {
		t.Fatalf("redacting config failed: %v", err)
	}
	if redacted.Security.Jwt.Secret != redactedConfigSecret {
		t.Fatalf("expected JWT secret to be redacted, got %q", redacted.Security.Jwt.Secret)
	}
	if redacted.Security.BasicAuthUsers != nil {
		t.Fatalf("expected basic auth users to be removed, got %+v", redacted.Security.BasicAuthUsers)
	}
	if redacted.Security.Clients != nil {
		t.Fatalf("expected clients to be removed, got %+v", redacted.Security.Clients)
	}
	if got := redacted.Security.NotificationWebhooks[0].SigningSecret; got != redactedConfigSecret {
		t.Fatalf("expected webhook signing secret to be redacted, got %q", got)
	}

	if cfg.Security.Jwt.Secret != "jwt-secret" {
		t.Fatalf("source JWT secret was mutated: %q", cfg.Security.Jwt.Secret)
	}
	if cfg.Security.BasicAuthUsers["admin"] != "admin-secret" {
		t.Fatalf("source basic auth users were mutated: %+v", cfg.Security.BasicAuthUsers)
	}
	if cfg.Security.Clients["client-a"] != "client-secret" {
		t.Fatalf("source clients were mutated: %+v", cfg.Security.Clients)
	}
	if cfg.Security.NotificationWebhooks[0].SigningSecret != "webhook-secret" {
		t.Fatalf("source webhook secret was mutated: %q", cfg.Security.NotificationWebhooks[0].SigningSecret)
	}
}
