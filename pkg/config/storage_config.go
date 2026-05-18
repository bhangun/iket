package config

import (
	"strings"
)

type StorageConfig struct {
	Mode        string `yaml:"mode,omitempty" json:"mode,omitempty"`
	SQLitePath  string `yaml:"sqlite_path,omitempty" json:"sqlite_path,omitempty"`
	PostgresURL string `yaml:"postgres_url,omitempty" json:"postgres_url,omitempty"`
	MirrorFiles *bool  `yaml:"mirror_files,omitempty" json:"mirror_files,omitempty"`
}

func (s StorageConfig) EffectiveMode() string {
	if strings.TrimSpace(s.Mode) == "" {
		return "sqlite"
	}
	return strings.ToLower(strings.TrimSpace(s.Mode))
}

func (s StorageConfig) EffectiveMirrorFiles() bool {
	return s.MirrorFiles == nil || *s.MirrorFiles
}
