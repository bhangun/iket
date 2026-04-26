package config

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	coreerrors "github.com/bhangun/iket/pkg/core/errors"
	"github.com/bhangun/iket/pkg/logging"
	_ "modernc.org/sqlite"
)

const sqliteSchemaVersion = 1
const sqliteDriverName = "sqlite"

type SQLiteProvider struct {
	dbPath      string
	logger      *logging.Logger
	bootstrap   Provider
	db          *sql.DB
	watchers    []func(*Config) error
	mu          sync.RWMutex
	stopWatcher chan struct{}
}

func NewSQLiteProvider(dbPath string, bootstrap Provider, logger *logging.Logger) *SQLiteProvider {
	return &SQLiteProvider{
		dbPath:      dbPath,
		logger:      logger,
		bootstrap:   bootstrap,
		stopWatcher: make(chan struct{}),
	}
}

func (p *SQLiteProvider) Load() (*Config, error) {
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
		return nil, coreerrors.NewConfigError("sqlite configuration store is empty", nil)
	}

	var cfg Config
	if err := json.Unmarshal(payload, &cfg); err != nil {
		return nil, coreerrors.NewConfigError("failed to parse sqlite config payload", err)
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

func (p *SQLiteProvider) Save(cfg *Config) error {
	if err := NewConfigValidator().Validate(cfg); err != nil {
		return err
	}
	if err := p.ensureDB(); err != nil {
		return err
	}

	payload, err := json.Marshal(cfg)
	if err != nil {
		return coreerrors.NewConfigError("failed to marshal config for sqlite", err)
	}

	_, err = p.db.Exec(`
INSERT INTO iket_config_state (id, payload_json, updated_at, source)
VALUES (1, ?, ?, 'sqlite')
ON CONFLICT(id) DO UPDATE SET
	payload_json=excluded.payload_json,
	updated_at=excluded.updated_at,
	source=excluded.source
`, string(payload), time.Now().UTC().Format(time.RFC3339Nano))
	if err != nil {
		return coreerrors.NewConfigError("failed to persist sqlite config", err)
	}
	if p.logger != nil {
		p.logger.Info("Configuration saved to sqlite", logging.String("db_path", p.dbPath))
	}
	return nil
}

func (p *SQLiteProvider) Watch(callback func(*Config) error) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.watchers = append(p.watchers, callback)
	if len(p.watchers) == 1 {
		go p.watchDB()
	}
	return nil
}

func (p *SQLiteProvider) Close() error {
	close(p.stopWatcher)
	if p.db != nil {
		return p.db.Close()
	}
	return nil
}

func (p *SQLiteProvider) ensureDB() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.db != nil {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(p.dbPath), 0755); err != nil {
		return err
	}

	db, err := sql.Open(sqliteDriverName, p.dbPath)
	if err != nil {
		return err
	}
	if _, err := db.Exec(`
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS iket_schema_migrations (
	version INTEGER PRIMARY KEY,
	applied_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS iket_config_state (
	id INTEGER PRIMARY KEY CHECK (id = 1),
	payload_json TEXT NOT NULL,
	updated_at TEXT NOT NULL,
	source TEXT NOT NULL
);
`); err != nil {
		db.Close()
		return err
	}
	p.db = db
	return p.applyMigrations()
}

func (p *SQLiteProvider) loadPayload() ([]byte, bool, error) {
	var payload string
	err := p.db.QueryRow(`SELECT payload_json FROM iket_config_state WHERE id = 1`).Scan(&payload)
	if err == sql.ErrNoRows {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return []byte(payload), true, nil
}

func (p *SQLiteProvider) watchDB() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	var lastUpdated string
	for {
		select {
		case <-p.stopWatcher:
			return
		case <-ticker.C:
			if p.db == nil {
				continue
			}
			var updatedAt string
			err := p.db.QueryRow(`SELECT updated_at FROM iket_config_state WHERE id = 1`).Scan(&updatedAt)
			if err != nil || updatedAt == "" || updatedAt == lastUpdated {
				continue
			}
			lastUpdated = updatedAt
			cfg, err := p.Load()
			if err != nil {
				if p.logger != nil {
					p.logger.Error("Failed to reload sqlite config", err)
				}
				continue
			}
			p.mu.RLock()
			for _, watcher := range p.watchers {
				if err := watcher(cfg); err != nil && p.logger != nil {
					p.logger.Error("SQLite config watcher callback failed", err)
				}
			}
			p.mu.RUnlock()
		}
	}
}

func (p *SQLiteProvider) applyMigrations() error {
	current, err := p.currentSchemaVersion()
	if err != nil {
		return err
	}
	if current >= sqliteSchemaVersion {
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
INSERT OR REPLACE INTO iket_schema_migrations(version, applied_at)
VALUES(1, ?)
`, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
			return err
		}
		if p.logger != nil {
			p.logger.Info("Applied sqlite migration", logging.Int("version", 1), logging.String("db_path", p.dbPath))
		}
	}

	return tx.Commit()
}

func (p *SQLiteProvider) currentSchemaVersion() (int, error) {
	var version int
	err := p.db.QueryRow(`SELECT COALESCE(MAX(version), 0) FROM iket_schema_migrations`).Scan(&version)
	if err != nil {
		return 0, fmt.Errorf("failed to read sqlite schema version: %w", err)
	}
	return version, nil
}
