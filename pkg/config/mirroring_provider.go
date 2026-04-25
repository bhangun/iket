package config

import "fmt"

// MirroringProvider lets one provider remain the source of truth while
// synchronizing successful writes to one or more secondary providers.
//
// This is a small future-proofing hook for setups like:
// - primary: SQLite, mirror: YAML files for humans
// - primary: Postgres, mirror: local snapshot files
// - primary: files, mirror: embedded database cache
type MirroringProvider struct {
	primary Provider
	mirrors []Provider
}

func NewMirroringProvider(primary Provider, mirrors ...Provider) *MirroringProvider {
	return &MirroringProvider{
		primary: primary,
		mirrors: mirrors,
	}
}

func (p *MirroringProvider) Load() (*Config, error) {
	if p.primary == nil {
		return nil, fmt.Errorf("primary provider is required")
	}
	return p.primary.Load()
}

func (p *MirroringProvider) Save(cfg *Config) error {
	if p.primary == nil {
		return fmt.Errorf("primary provider is required")
	}
	if err := p.primary.Save(cfg); err != nil {
		return err
	}
	for _, mirror := range p.mirrors {
		if mirror == nil {
			continue
		}
		if err := mirror.Save(cfg); err != nil {
			return err
		}
	}
	return nil
}

func (p *MirroringProvider) Watch(callback func(*Config) error) error {
	if p.primary == nil {
		return fmt.Errorf("primary provider is required")
	}
	return p.primary.Watch(callback)
}

func (p *MirroringProvider) Close() error {
	var firstErr error
	if p.primary != nil {
		if err := p.primary.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	for _, mirror := range p.mirrors {
		if mirror == nil {
			continue
		}
		if err := mirror.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}
