# Config Storage

Iket currently uses file-based configuration by default through `config.yaml` and `service.yaml`.

That is still the right default for local development and small deployments because it is:

- easy to inspect and edit
- easy to version in Git
- operationally simple

## Future-Proof Storage Model

The codebase now includes a `MirroringProvider` in [pkg/config/mirroring_provider.go](/Users/bhangun/Workspace/workkayys/Products/Iket/iket/pkg/config/mirroring_provider.go).

This is the intended direction for storage strategies:

1. Choose one **primary provider** as the source of truth.
2. Optionally write the same config to one or more **mirror providers**.
3. Keep reads and watches bound to the primary provider.

Examples:

- Primary `FileProvider`, mirror SQLite cache
- Primary SQLite, mirror YAML files for operator visibility
- Primary Postgres, mirror local file snapshots

## Recommendation

Current default:

- server primary store: SQLite
- user-facing mirror/export: `config.yaml` and optional `service.yaml`

That means admin changes made through `iket` are persisted to SQLite first, then mirrored back to files.

Storage modes:

- `--storage=sqlite` (default): SQLite primary, file mirror/bootstrap
- `--storage=file`: legacy file-primary mode
- `--storage=postgres`: reserved enterprise-oriented provider path

## Schema Versioning

The SQLite provider now maintains an internal schema migration table:

- `iket_schema_migrations`

This allows Iket to evolve the database layout over time without changing the
gateway, CLI, or management API storage contract.

Current schema version: `1`

Recommended direction:

- local / single-node managed installs: SQLite primary
- enterprise / HA control-plane: Postgres primary
- operator UX: keep file import/export and optional mirroring

## Why Not Switch Immediately?

A database is not automatically faster for the current workload. Iket config is relatively small, so the real benefits of SQLite/Postgres are:

- transactional updates
- safer concurrent admin operations
- richer audit/history possibilities
- better multi-process or multi-node coordination

The current file-based mode remains fully supported. A future database provider should preserve file import/export so operators can still work with declarative config files.
