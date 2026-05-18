package config

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	coreerrors "github.com/bhangun/iket/pkg/core/errors"
	"github.com/bhangun/iket/pkg/logging"
)

type sqlProviderDialect struct {
	driverName          string
	source              string
	schemaVersion       int
	emptyStoreMessage   string
	parsePayloadMessage string
	marshalMessage      string
	persistMessage      string
	reloadMessage       string
	watcherMessage      string
	savedMessage        string
	locationLogKey      string
	locationLogValue    func(string) string
	prepareLocation     func(string) error
	configureDB         func(*sql.DB)
	initSchemaSQL       string
	migrationSQL        string
	recordMigrationSQL  string
	upsertPayloadSQL    string
	readPayloadSQL      string
	readUpdatedSQL      string
	updatedValue        func() any
}

type sqlConfigProvider struct {
	location    string
	logger      *logging.Logger
	bootstrap   Provider
	dialect     sqlProviderDialect
	db          *sql.DB
	watchers    []func(*Config) error
	mu          sync.RWMutex
	stopWatcher chan struct{}
	closeOnce   sync.Once
}

func newSQLConfigProvider(location string, bootstrap Provider, logger *logging.Logger, dialect sqlProviderDialect) *sqlConfigProvider {
	return &sqlConfigProvider{
		location:    location,
		logger:      logger,
		bootstrap:   bootstrap,
		dialect:     dialect,
		stopWatcher: make(chan struct{}),
	}
}

func (p *sqlConfigProvider) Load() (*Config, error) {
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
		return nil, coreerrors.NewConfigError(p.dialect.emptyStoreMessage, nil)
	}

	var cfg Config
	if err := json.Unmarshal(payload, &cfg); err != nil {
		return nil, coreerrors.NewConfigError(p.dialect.parsePayloadMessage, err)
	}
	if err := prepareLoadedConfig(&cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (p *sqlConfigProvider) Save(cfg *Config) error {
	if err := validateConfig(cfg); err != nil {
		return err
	}
	if err := p.ensureDB(); err != nil {
		return err
	}

	payload, err := json.Marshal(cfg)
	if err != nil {
		return coreerrors.NewConfigError(p.dialect.marshalMessage, err)
	}

	if _, err := p.db.Exec(p.dialect.upsertPayloadSQL, string(payload), p.dialect.updatedValue()); err != nil {
		return coreerrors.NewConfigError(p.dialect.persistMessage, err)
	}
	if p.logger != nil {
		p.logger.Info(p.dialect.savedMessage, logging.String(p.dialect.locationLogKey, p.redactedLocation()))
	}
	return nil
}

func (p *sqlConfigProvider) Watch(callback func(*Config) error) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.watchers = append(p.watchers, callback)
	if len(p.watchers) == 1 {
		go p.watchDB()
	}
	return nil
}

func (p *sqlConfigProvider) Close() error {
	var err error
	p.closeOnce.Do(func() {
		close(p.stopWatcher)
		if p.db != nil {
			err = p.db.Close()
		}
	})
	return err
}

func (p *sqlConfigProvider) ensureDB() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.db != nil {
		return nil
	}
	if p.dialect.prepareLocation != nil {
		if err := p.dialect.prepareLocation(p.location); err != nil {
			return err
		}
	}

	db, err := sql.Open(p.dialect.driverName, p.location)
	if err != nil {
		return err
	}
	if p.dialect.configureDB != nil {
		p.dialect.configureDB(db)
	}
	if err := db.Ping(); err != nil {
		db.Close()
		return err
	}
	if _, err := db.Exec(p.dialect.initSchemaSQL); err != nil {
		db.Close()
		return err
	}

	p.db = db
	return p.applyMigrations()
}

func (p *sqlConfigProvider) loadPayload() ([]byte, bool, error) {
	var payload string
	err := p.db.QueryRow(p.dialect.readPayloadSQL).Scan(&payload)
	if err == sql.ErrNoRows {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return []byte(payload), true, nil
}

func (p *sqlConfigProvider) watchDB() {
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
			err := p.db.QueryRow(p.dialect.readUpdatedSQL).Scan(&updatedAt)
			if err != nil || updatedAt == "" || updatedAt == lastUpdated {
				continue
			}
			lastUpdated = updatedAt
			cfg, err := p.Load()
			if err != nil {
				if p.logger != nil {
					p.logger.Error(p.dialect.reloadMessage, err)
				}
				continue
			}
			p.mu.RLock()
			for _, watcher := range p.watchers {
				if err := watcher(cfg); err != nil && p.logger != nil {
					p.logger.Error(p.dialect.watcherMessage, err)
				}
			}
			p.mu.RUnlock()
		}
	}
}

func (p *sqlConfigProvider) applyMigrations() error {
	current, err := p.currentSchemaVersion()
	if err != nil {
		return err
	}
	if current >= p.dialect.schemaVersion {
		return nil
	}

	tx, err := p.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if current < 1 {
		if _, err := tx.Exec(p.dialect.migrationSQL); err != nil {
			return err
		}
		if _, err := tx.Exec(p.dialect.recordMigrationSQL, 1, time.Now().UTC()); err != nil {
			return err
		}
		if p.logger != nil {
			p.logger.Info("Applied "+p.dialect.source+" migration", logging.Int("version", 1), logging.String(p.dialect.locationLogKey, p.redactedLocation()))
		}
	}

	return tx.Commit()
}

func (p *sqlConfigProvider) currentSchemaVersion() (int, error) {
	var version int
	err := p.db.QueryRow(`SELECT COALESCE(MAX(version), 0) FROM iket_schema_migrations`).Scan(&version)
	if err != nil {
		return 0, fmt.Errorf("failed to read %s schema version: %w", p.dialect.source, err)
	}
	return version, nil
}

func (p *sqlConfigProvider) redactedLocation() string {
	if p.dialect.locationLogValue == nil {
		return p.location
	}
	return p.dialect.locationLogValue(p.location)
}
