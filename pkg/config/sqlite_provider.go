package config

import (
	"database/sql"
	"os"
	"path/filepath"
	"time"

	"github.com/bhangun/iket/pkg/logging"
	_ "modernc.org/sqlite"
)

const sqliteSchemaVersion = 1
const sqliteDriverName = "sqlite"

type SQLiteProvider struct {
	*sqlConfigProvider
}

func NewSQLiteProvider(dbPath string, bootstrap Provider, logger *logging.Logger) *SQLiteProvider {
	return &SQLiteProvider{
		sqlConfigProvider: newSQLConfigProvider(dbPath, bootstrap, logger, sqliteProviderDialect()),
	}
}

func sqliteProviderDialect() sqlProviderDialect {
	return sqlProviderDialect{
		driverName:          sqliteDriverName,
		source:              "sqlite",
		schemaVersion:       sqliteSchemaVersion,
		emptyStoreMessage:   "sqlite configuration store is empty",
		parsePayloadMessage: "failed to parse sqlite config payload",
		marshalMessage:      "failed to marshal config for sqlite",
		persistMessage:      "failed to persist sqlite config",
		reloadMessage:       "Failed to reload sqlite config",
		watcherMessage:      "SQLite config watcher callback failed",
		savedMessage:        "Configuration saved to sqlite",
		locationLogKey:      "db_path",
		prepareLocation:     prepareSQLiteLocation,
		configureDB: func(db *sql.DB) {
			db.SetMaxOpenConns(1)
		},
		initSchemaSQL: `
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
`,
		migrationSQL: `
CREATE INDEX IF NOT EXISTS idx_iket_config_state_updated_at
ON iket_config_state(updated_at);
`,
		recordMigrationSQL: `
INSERT OR REPLACE INTO iket_schema_migrations(version, applied_at)
VALUES(?, ?)
`,
		upsertPayloadSQL: `
INSERT INTO iket_config_state (id, payload_json, updated_at, source)
VALUES (1, ?, ?, 'sqlite')
ON CONFLICT(id) DO UPDATE SET
	payload_json=excluded.payload_json,
	updated_at=excluded.updated_at,
	source=excluded.source
`,
		readPayloadSQL: `SELECT payload_json FROM iket_config_state WHERE id = 1`,
		readUpdatedSQL: `SELECT updated_at FROM iket_config_state WHERE id = 1`,
		updatedValue: func() any {
			return time.Now().UTC().Format(time.RFC3339Nano)
		},
	}
}

func prepareSQLiteLocation(dbPath string) error {
	return os.MkdirAll(filepath.Dir(dbPath), 0755)
}
