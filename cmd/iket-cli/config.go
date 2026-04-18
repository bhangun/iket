package main

import (
	"gopkg.in/yaml.v3"
	"os"
	"path/filepath"
)

type CLIConfig struct {
	ServerURL  string `yaml:"server_url"`
	CertFile   string `yaml:"cert_file"`
	KeyFile    string `yaml:"key_file"`
	CAFile     string `yaml:"ca_file"`
	SkipVerify bool   `yaml:"skip_verify"`
}

func loadCLIConfig() (*CLIConfig, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return &CLIConfig{ServerURL: "http://localhost:8080"}, nil
	}

	configPath := filepath.Join(home, ".iket", "config.yaml")
	data, err := os.ReadFile(configPath)
	if err != nil {
		return &CLIConfig{ServerURL: "http://localhost:8080"}, nil
	}

	var cfg CLIConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
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

	return os.WriteFile(filepath.Join(configDir, "config.yaml"), data, 0600)
}
