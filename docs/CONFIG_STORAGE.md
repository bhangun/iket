# Config Storage

Iket now defaults to PostgreSQL as the primary config/state store, with
`config.yaml` and `service.yaml` remaining the user-facing mirror/import format.

That default is aimed at safer admin operations while preserving a file-based UX:

- transactional updates in the primary store
- YAML remains easy to inspect and edit
- mirrored files still fit Git-based workflows

## Future-Proof Storage Model

The codebase now includes a `MirroringProvider` in [pkg/config/mirroring_provider.go](/Users/bhangun/Workspace/workkayys/Products/Iket/iket/pkg/config/mirroring_provider.go).

This is the intended direction for storage strategies:

1. Choose one **primary provider** as the source of truth.
2. Optionally write the same config to one or more **mirror providers**.
3. Keep reads and watches bound to the primary provider.

Examples:

- Primary `FileProvider`, mirror local cache
- Primary SQLite, mirror YAML files for operator visibility
- Primary Postgres, mirror YAML files or local snapshots

## Recommendation

Current default:

- server primary store: PostgreSQL
- user-facing mirror/export: `config.yaml` and optional `service.yaml`

That means admin changes made through `iket` are persisted to PostgreSQL first, then mirrored back to files.

Storage modes:

- `--storage=postgres` (default): PostgreSQL primary, file mirror/bootstrap
- `--storage=sqlite`: SQLite primary, file mirror/bootstrap
- `--storage=file`: legacy file-primary mode

## Schema Versioning

The database-backed providers maintain internal schema migration tables:

- `iket_schema_migrations`

Current schema version:

- PostgreSQL: `1`
- SQLite: `1`

Recommended direction:

- Docker / managed installs: PostgreSQL primary
- local fallback / very small installs: SQLite primary
- operator UX: keep file import/export and optional mirroring

## Why Not Switch Immediately?

A database is not automatically faster for the current workload. Iket config is relatively small, so the real benefits of SQLite/Postgres are:

- transactional updates
- safer concurrent admin operations
- richer audit/history possibilities
- better multi-process or multi-node coordination

The current file-based mode remains fully supported. Database-backed modes preserve file import/export so operators can still work with declarative config files.
