package config

import (
	"github.com/bhangun/iket/pkg/core/errors"
	"strings"
)

type StorageConfigRule struct{}

func (r *StorageConfigRule) Validate(cfg *Config) error {
	mode := cfg.Storage.EffectiveMode()
	switch mode {
	case "sqlite", "file", "postgres":
	default:
		return errors.NewValidationError("storage.mode", "storage mode must be sqlite, file, or postgres")
	}
	if mode == "postgres" && strings.TrimSpace(cfg.Storage.PostgresURL) == "" {
		return errors.NewValidationError("storage.postgres_url", "postgres_url is required when storage mode is postgres")
	}
	return nil
}
