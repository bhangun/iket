package config

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	coreerrors "github.com/bhangun/iket/pkg/core/errors"
	"github.com/bhangun/iket/pkg/logging"
	_ "github.com/jackc/pgx/v5/stdlib"
)

const postgresSchemaVersion = 1
const postgresDriverName = "pgx"

type PostgresProvider struct {
	url         string
	logger      *logging.Logger
	bootstrap   Provider
	db          *sql.DB
	watchers    []func(*Config) error
	mu          sync.RWMutex
	stopWatcher chan struct{}
}

func NewPostgresProvider(url string, bootstrap Provider, logger *logging.Logger) *PostgresProvider {
	return &PostgresProvider{
		url:         url,
		logger:      logger,
		bootstrap:   bootstrap,
		stopWatcher: make(chan struct{}),
	}
}

func (p *PostgresProvider) Load() (*Config, error) {
	if err := p.ensureDB(); err != nil {
		return nil, err
	}

	payload, found, err := p.loadPayload()
	if err != nil {
		return nil, err
	}
	if !found && p.bootstrap != nil {
		cfg, err := p.bootstrap.Load()
		if err != nil {
			return nil, err
		}
		if err := p.Save(cfg); err != nil {
			return nil, err
		}
		return cfg, nil
	}
	if !found {
		return nil, coreerrors.NewConfigError("postgres configuration store is empty", nil)
	}

	var cfg Config
	if err := json.Unmarshal(payload, &cfg); err != nil {
		return nil, coreerrors.NewConfigError("failed to parse postgres config payload", err)
	}
	expandEnvVarsInStruct(&cfg)
	if cfg.Plugins != nil {
		for _, pluginCfg := range cfg.Plugins {
			expandEnvVarsInMap(pluginCfg)
		}
	}
	if err := NewConfigValidator().Validate(&cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (p *PostgresProvider) Save(cfg *Config) error {
	if err := NewConfigValidator().Validate(cfg); err != nil {
		return err
	}
	if err := p.ensureDB(); err != nil {
		return err
	}

	payload, err := json.Marshal(cfg)
	if err != nil {
		return coreerrors.NewConfigError("failed to marshal config for postgres", err)
	}

	_, err = p.db.Exec(`
INSERT INTO iket_config_state (id, payload_json, updated_at, source)
VALUES (1, $1::jsonb, $2, 'postgres')
ON CONFLICT(id) DO UPDATE SET
	payload_json=excluded.payload_json,
	updated_at=excluded.updated_at,
	source=excluded.source
`, string(payload), time.Now().UTC())
	if err != nil {
		return coreerrors.NewConfigError("failed to persist postgres config", err)
	}
	if p.logger != nil {
		p.logger.Info("Configuration saved to postgres", logging.String("postgres_url", redactPostgresURL(p.url)))
	}
	return nil
}

func (p *PostgresProvider) Watch(callback func(*Config) error) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.watchers = append(p.watchers, callback)
	if len(p.watchers) == 1 {
		go p.watchDB()
	}
	return nil
}

func (p *PostgresProvider) Close() error {
	close(p.stopWatcher)
	if p.db != nil {
		return p.db.Close()
	}
	return nil
}

func (p *PostgresProvider) ensureDB() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.db != nil {
		return nil
	}

	db, err := sql.Open(postgresDriverName, p.url)
	if err != nil {
		return err
	}
	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(30 * time.Minute)

	if err := db.Ping(); err != nil {
		db.Close()
		return err
	}

	if _, err := db.Exec(`
CREATE TABLE IF NOT EXISTS iket_schema_migrations (
	version INTEGER PRIMARY KEY,
	applied_at TIMESTAMPTZ NOT NULL
);
CREATE TABLE IF NOT EXISTS iket_config_state (
	id INTEGER PRIMARY KEY,
	payload_json JSONB NOT NULL,
	updated_at TIMESTAMPTZ NOT NULL,
	source TEXT NOT NULL
);
`); err != nil {
		db.Close()
		return err
	}

	p.db = db
	return p.applyMigrations()
}

func (p *PostgresProvider) loadPayload() ([]byte, bool, error) {
	var payload []byte
	err := p.db.QueryRow(`SELECT payload_json::text FROM iket_config_state WHERE id = 1`).Scan(&payload)
	if err == sql.ErrNoRows {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return payload, true, nil
}

func (p *PostgresProvider) watchDB() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	var lastUpdated time.Time
	for {
		select {
		case <-p.stopWatcher:
			return
		case <-ticker.C:
			if p.db == nil {
				continue
			}
			var updatedAt time.Time
			err := p.db.QueryRow(`SELECT updated_at FROM iket_config_state WHERE id = 1`).Scan(&updatedAt)
			if err != nil || updatedAt.IsZero() || updatedAt.Equal(lastUpdated) {
				continue
			}
			lastUpdated = updatedAt
			cfg, err := p.Load()
			if err != nil {
				if p.logger != nil {
					p.logger.Error("Failed to reload postgres config", err)
				}
				continue
			}
			p.mu.RLock()
			for _, watcher := range p.watchers {
				if err := watcher(cfg); err != nil && p.logger != nil {
					p.logger.Error("Postgres config watcher callback failed", err)
				}
			}
			p.mu.RUnlock()
		}
	}
}

func (p *PostgresProvider) applyMigrations() error {
	current, err := p.currentSchemaVersion()
	if err != nil {
		return err
	}
	if current >= postgresSchemaVersion {
		return nil
	}

	tx, err := p.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if current < 1 {
		if _, err := tx.Exec(`
CREATE INDEX IF NOT EXISTS idx_iket_config_state_updated_at
ON iket_config_state(updated_at);
`); err != nil {
			return err
		}
		if _, err := tx.Exec(`
INSERT INTO iket_schema_migrations(version, applied_at)
VALUES($1, $2)
ON CONFLICT(version) DO UPDATE SET applied_at=excluded.applied_at
`, 1, time.Now().UTC()); err != nil {
			return err
		}
		if p.logger != nil {
			p.logger.Info("Applied postgres migration", logging.Int("version", 1), logging.String("postgres_url", redactPostgresURL(p.url)))
		}
	}

	return tx.Commit()
}

func (p *PostgresProvider) currentSchemaVersion() (int, error) {
	var version int
	err := p.db.QueryRow(`SELECT COALESCE(MAX(version), 0) FROM iket_schema_migrations`).Scan(&version)
	if err != nil {
		return 0, fmt.Errorf("failed to read postgres schema version: %w", err)
	}
	return version, nil
}

func redactPostgresURL(raw string) string {
	if raw == "" {
		return raw
	}
	redacted := raw
	if idx := len("postgres://"); len(raw) > idx && raw[:idx] == "postgres://" {
		at := -1
		for i := idx; i < len(raw); i++ {
			if raw[i] == '@' {
				at = i
				break
			}
			if raw[i] == '/' || raw[i] == '?' {
				break
			}
		}
		if at > idx {
			creds := raw[idx:at]
			if colon := len(creds); colon > 0 {
				for i := 0; i < len(creds); i++ {
					if creds[i] == ':' {
						colon = i
						break
					}
				}
				if colon < len(creds) {
					redacted = raw[:idx+colon+1] + "****" + raw[at:]
				}
			}
		}
	}
	return redacted
}
