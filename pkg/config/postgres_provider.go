package config

import "fmt"

// PostgresProvider is a future enterprise-oriented provider scaffold.
//
// The provider contract is intentionally the same as file/sqlite so the
// gateway, management API, and CLI do not need storage-specific logic.
type PostgresProvider struct {
	url string
}

func NewPostgresProvider(url string) *PostgresProvider {
	return &PostgresProvider{url: url}
}

func (p *PostgresProvider) Load() (*Config, error) {
	return nil, fmt.Errorf("postgres provider not implemented yet")
}

func (p *PostgresProvider) Save(*Config) error {
	return fmt.Errorf("postgres provider not implemented yet")
}

func (p *PostgresProvider) Watch(func(*Config) error) error {
	return fmt.Errorf("postgres provider not implemented yet")
}

func (p *PostgresProvider) Close() error {
	return nil
}
