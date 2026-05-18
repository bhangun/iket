package config

import (
	"strings"
	"testing"
)

func TestStorageConfigRuleRejectsInvalidMode(t *testing.T) {
	cfg := &Config{
		Server:  ServerConfig{Port: 8080},
		Storage: StorageConfig{Mode: "oracle"},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "storage mode") {
		t.Fatalf("expected storage mode validation error, got %v", err)
	}
}

func TestStorageConfigRuleAllowsFileMode(t *testing.T) {
	cfg := &Config{
		Server:  ServerConfig{Port: 8080},
		Storage: StorageConfig{Mode: "file"},
	}

	if err := NewConfigValidator().Validate(cfg); err != nil {
		t.Fatalf("expected file storage mode to validate, got %v", err)
	}
}

func TestStorageConfigRuleRequiresPostgresURL(t *testing.T) {
	cfg := &Config{
		Server:  ServerConfig{Port: 8080},
		Storage: StorageConfig{Mode: "postgres"},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "postgres_url") {
		t.Fatalf("expected postgres_url validation error, got %v", err)
	}
}
