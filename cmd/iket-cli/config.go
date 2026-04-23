package main

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

type Context struct {
	ServerURL  string `yaml:"server_url"`
	CertFile   string `yaml:"cert_file"`
	KeyFile    string `yaml:"key_file"`
	CAFile     string `yaml:"ca_file"`
	SkipVerify bool   `yaml:"skip_verify"`
	Strict     bool   `yaml:"strict"`
}

type CLIConfig struct {
	CurrentContext string             `yaml:"current_context"`
	Contexts       map[string]Context `yaml:"contexts"`

	// Legacy fields for backward compatibility
	ServerURL  string `yaml:"server_url,omitempty"`
	CertFile   string `yaml:"cert_file,omitempty"`
	KeyFile    string `yaml:"key_file,omitempty"`
	CAFile     string `yaml:"ca_file,omitempty"`
	SkipVerify bool   `yaml:"skip_verify,omitempty"`
}

func loadCLIConfig() (*CLIConfig, error) {
	cfg := &CLIConfig{
		Contexts: make(map[string]Context),
	}

	home, err := os.UserHomeDir()
	if err == nil {
		configPath := filepath.Join(home, ".iket", "cli-config.yaml")
		data, err := os.ReadFile(configPath)
		if err == nil {
			if err := yaml.Unmarshal(data, cfg); err != nil {
				return nil, fmt.Errorf("failed to parse config: %w", err)
			}
		}
	}

	// Migration logic: if legacy fields are present and no contexts exist, create a 'default' context
	if cfg.ServerURL != "" && len(cfg.Contexts) == 0 {
		cfg.Contexts["default"] = Context{
			ServerURL:  cfg.ServerURL,
			CertFile:   cfg.CertFile,
			KeyFile:    cfg.KeyFile,
			CAFile:     cfg.CAFile,
			SkipVerify: cfg.SkipVerify,
		}
		cfg.CurrentContext = "default"
		// Clear legacy fields
		cfg.ServerURL = ""
		cfg.CertFile = ""
		cfg.KeyFile = ""
		cfg.CAFile = ""
		cfg.SkipVerify = false
	}

	// Ensure at least a default context exists if empty
	if len(cfg.Contexts) == 0 {
		cfg.Contexts["default"] = Context{
			ServerURL: "http://localhost:8080",
		}
		cfg.CurrentContext = "default"
	}

	return cfg, nil
}

func (c *CLIConfig) GetCurrentContext() Context {
	// Environment variables always take precedence
	envCtx := Context{
		ServerURL:  os.Getenv("IKET_SERVER_URL"),
		CertFile:   os.Getenv("IKET_CERT_FILE"),
		KeyFile:    os.Getenv("IKET_KEY_FILE"),
		CAFile:     os.Getenv("IKET_CA_FILE"),
		SkipVerify: os.Getenv("IKET_SKIP_VERIFY") == "true" || os.Getenv("IKET_SKIP_VERIFY") == "1",
	}

	if envCtx.ServerURL != "" {
		return envCtx
	}

	if ctx, ok := c.Contexts[c.CurrentContext]; ok {
		return ctx
	}

	// Fallback to first available context or default
	for _, ctx := range c.Contexts {
		return ctx
	}

	return Context{ServerURL: "http://localhost:8080"}
}

func saveCLIConfig(cfg *CLIConfig) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	configDir := filepath.Join(home, ".iket")
	if err := os.MkdirAll(configDir, 0700); err != nil {
		return err
	}

	data, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}

	return os.WriteFile(filepath.Join(configDir, "cli-config.yaml"), data, 0600)
}
