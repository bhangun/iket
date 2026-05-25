package gateway

import (
	"encoding/json"

	"github.com/bhangun/iket/pkg/config"
)

const redactedConfigSecret = "REDACTED"

// RedactedConfig returns a deep-copied configuration snapshot with known
// credential fields removed or masked before it is exposed through admin APIs.
func RedactedConfig(cfg *config.Config) (*config.Config, error) {
	if cfg == nil {
		return nil, nil
	}

	data, err := json.Marshal(cfg)
	if err != nil {
		return nil, err
	}
	var redacted config.Config
	if err := json.Unmarshal(data, &redacted); err != nil {
		return nil, err
	}

	redactConfigSecrets(&redacted)
	return &redacted, nil
}

func redactConfigSecrets(cfg *config.Config) {
	if cfg == nil {
		return
	}
	if cfg.Security.Jwt.Secret != "" {
		cfg.Security.Jwt.Secret = redactedConfigSecret
	}
	cfg.Security.BasicAuthUsers = nil
	cfg.Security.Clients = nil
	for i := range cfg.Security.NotificationWebhooks {
		if cfg.Security.NotificationWebhooks[i].SigningSecret != "" {
			cfg.Security.NotificationWebhooks[i].SigningSecret = redactedConfigSecret
		}
	}
}
