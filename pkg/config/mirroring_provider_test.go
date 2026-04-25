package config

import "testing"

type stubProvider struct {
	loaded *Config
	saved  *Config
}

func (s *stubProvider) Load() (*Config, error)          { return s.loaded, nil }
func (s *stubProvider) Save(cfg *Config) error          { s.saved = cfg; return nil }
func (s *stubProvider) Watch(func(*Config) error) error { return nil }
func (s *stubProvider) Close() error                    { return nil }

func TestMirroringProviderSavesPrimaryAndMirrors(t *testing.T) {
	cfg := &Config{Server: ServerConfig{Port: 8080}}
	primary := &stubProvider{loaded: cfg}
	mirror := &stubProvider{}

	provider := NewMirroringProvider(primary, mirror)
	if _, err := provider.Load(); err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if err := provider.Save(cfg); err != nil {
		t.Fatalf("Save returned error: %v", err)
	}
	if primary.saved != cfg {
		t.Fatalf("expected primary provider to receive saved config")
	}
	if mirror.saved != cfg {
		t.Fatalf("expected mirror provider to receive saved config")
	}
}
