package config

import (
	"database/sql"
	"path/filepath"
	"testing"

	_ "github.com/mattn/go-sqlite3"
)

func TestSQLiteProviderSaveLoad(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "iket.db")
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Services: []ServiceConfig{{
			Version: 1,
			Services: []Service{{
				Name: "identity",
				Host: "http://identity:8080",
				Routes: []RouterConfig{{
					Path:    "/login",
					Method:  "POST",
					Enabled: NewBool(true),
					Backends: []Backend{
						{URLPattern: "/login"},
					},
				}},
			}},
		}},
	}

	provider := NewSQLiteProvider(dbPath, nil, nil)
	if err := provider.Save(cfg); err != nil {
		t.Fatalf("Save returned error: %v", err)
	}

	loaded, err := provider.Load()
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if loaded.Server.Port != 8080 {
		t.Fatalf("expected port 8080, got %d", loaded.Server.Port)
	}
	if loaded.Services[0].Services[0].Name != "identity" {
		t.Fatalf("expected service identity, got %s", loaded.Services[0].Services[0].Name)
	}
}

func TestSQLiteProviderAppliesSchemaMigrations(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "iket.db")

	provider := NewSQLiteProvider(dbPath, nil, nil)
	if err := provider.ensureDB(); err != nil {
		t.Fatalf("ensureDB returned error: %v", err)
	}
	defer provider.Close()

	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		t.Fatalf("failed to open sqlite db: %v", err)
	}
	defer db.Close()

	var version int
	if err := db.QueryRow(`SELECT COALESCE(MAX(version), 0) FROM iket_schema_migrations`).Scan(&version); err != nil {
		t.Fatalf("failed to query schema version: %v", err)
	}
	if version != sqliteSchemaVersion {
		t.Fatalf("expected schema version %d, got %d", sqliteSchemaVersion, version)
	}
}
