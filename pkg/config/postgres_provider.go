package config

import (
	"database/sql"
	"strings"
	"time"

	"github.com/bhangun/iket/pkg/logging"
	_ "github.com/jackc/pgx/v5/stdlib"
)

const postgresSchemaVersion = 1
const postgresDriverName = "pgx"

type PostgresProvider struct {
	*sqlConfigProvider
}

func NewPostgresProvider(url string, bootstrap Provider, logger *logging.Logger) *PostgresProvider {
	return &PostgresProvider{
		sqlConfigProvider: newSQLConfigProvider(url, bootstrap, logger, postgresProviderDialect()),
	}
}

func postgresProviderDialect() sqlProviderDialect {
	return sqlProviderDialect{
		driverName:          postgresDriverName,
		source:              "postgres",
		schemaVersion:       postgresSchemaVersion,
		emptyStoreMessage:   "postgres configuration store is empty",
		parsePayloadMessage: "failed to parse postgres config payload",
		marshalMessage:      "failed to marshal config for postgres",
		persistMessage:      "failed to persist postgres config",
		reloadMessage:       "Failed to reload postgres config",
		watcherMessage:      "Postgres config watcher callback failed",
		savedMessage:        "Configuration saved to postgres",
		locationLogKey:      "postgres_url",
		locationLogValue:    redactPostgresURL,
		configureDB: func(db *sql.DB) {
			db.SetMaxOpenConns(10)
			db.SetMaxIdleConns(5)
			db.SetConnMaxLifetime(30 * time.Minute)
		},
		initSchemaSQL: `
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
`,
		migrationSQL: `
CREATE INDEX IF NOT EXISTS idx_iket_config_state_updated_at
ON iket_config_state(updated_at);
`,
		recordMigrationSQL: `
INSERT INTO iket_schema_migrations(version, applied_at)
VALUES($1, $2)
ON CONFLICT(version) DO UPDATE SET applied_at=excluded.applied_at
`,
		upsertPayloadSQL: `
INSERT INTO iket_config_state (id, payload_json, updated_at, source)
VALUES (1, $1::jsonb, $2, 'postgres')
ON CONFLICT(id) DO UPDATE SET
	payload_json=excluded.payload_json,
	updated_at=excluded.updated_at,
	source=excluded.source
`,
		readPayloadSQL: `SELECT payload_json::text FROM iket_config_state WHERE id = 1`,
		readUpdatedSQL: `SELECT updated_at::text FROM iket_config_state WHERE id = 1`,
		updatedValue: func() any {
			return time.Now().UTC()
		},
	}
}

func redactPostgresURL(raw string) string {
	if raw == "" {
		return raw
	}
	const prefix = "postgres://"
	if !strings.HasPrefix(raw, prefix) {
		return raw
	}

	authStart := len(prefix)
	authEnd := strings.IndexAny(raw[authStart:], "@/?")
	if authEnd < 0 || raw[authStart+authEnd] != '@' {
		return raw
	}
	authEnd += authStart

	credentials := raw[authStart:authEnd]
	passwordStart := strings.Index(credentials, ":")
	if passwordStart < 0 {
		return raw
	}
	return raw[:authStart+passwordStart+1] + "****" + raw[authEnd:]
}
