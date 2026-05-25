# Iket Agent Guide

This file is for coding agents and maintainers working inside the Iket repository.

## What Iket Is

Iket currently has two primary binaries:
- `iket`: the admin CLI & the gateway and management API server

Core responsibilities:
- route matching and upstream path rewriting
- management API for config, services, routes, plugins, logs, certificates, proposals, and backups
- mTLS-secured remote administration
- file-backed and database-backed configuration storage
- Docker and host-native operator workflows

## Repository Shape

- `cmd/iket`: server entrypoint
- `cmd/iket-cli`: CLI entrypoint and subcommands
- `pkg/core/gateway`: routing, middleware, proxying, request context
- `pkg/api`: management API handlers
- `pkg/config`: config model, validation, TLS bootstrap, storage providers
- `pkg/logging`: structured logger and in-memory live log store
- `docs`: source repo docs
- `config`: local example config files

## Current Product Defaults

These are the current assumptions agents should preserve unless a change is explicitly intentional:

- plain `iket server run` defaults to file-backed local startup
- PostgreSQL is explicit opt-in through `--database`
- first local startup scaffolds:
  - `config/config.yaml`
  - `config/service.yaml`
  - `docker-compose.yaml`
- daemon log and pid defaults are scaffold-local under `./logs`
- daemon artifacts may be redirected intentionally with:
  - `--log-dir`
  - `--pid-dir`
  - `--log-file`
  - `--pid-file`
- local scaffold restores now support:
  - listing backups
  - previewing restore targets
  - per-file restore
  - full-scaffold restore
  - confirmation by default
  - `--force` as explicit bypass

## Important Operational Gotchas

### 1. Remote TLS SANs matter

If the server is accessed remotely, `security.tls.serverNames` and `security.tls.serverIPs` must include the real hostname or IP used by the client. Otherwise the CLI will fail TLS verification even if the CA and client cert are correct.

Relevant files:
- `pkg/config/tls_bootstrap.go`
- `cmd/iket-cli/cert.go`
- `cmd/iket-cli/setup.go`
- `iket-website/docs/install.md`

### 2. Docker bind-mount permissions are a frequent first-run failure

If startup fails with:

`failed to prepare bootstrap TLS assets ... /app/certs/ca.key: permission denied`

the problem is usually host ownership or mode on `certs/` and `logs/`, not the database.

Relevant files:
- `cmd/iket-cli/docker_init.go`
- `iket-website/docs/install.md`

### 3. Remote config drift is easy to misread

When debugging Docker deployments, always verify the mounted config inside the container:

```bash
docker exec iket sh -lc 'sed -n "1,80p" /app/config/config.yaml'
docker exec iket sh -lc 'sed -n "1,80p" /app/config/service.yaml'
```

Do not assume the edited host file and the live mounted file still match.

### 4. `~/.iket/certs` is local CLI state, not the server Docker cert volume

When helping users import certs:
- server-side Docker bundle usually lives in deployment `./certs`
- client-side managed store usually lives in `~/.iket/certs/...`

Do not blur those paths in docs or error messages.

### 5. Global `-f` belongs to `--force`

The CLI already reserves `-f` globally for `--force`. Subcommands should avoid reusing that shorthand for unrelated flags like `follow`, or Cobra will panic on flag registration.

### 6. Restore and backup UX is now part of the local server contract

When changing scaffold paths, defaults, or daemon artifacts, also check:
- `iket server backups`
- `iket server restore --preview`
- `iket server restore --latest --kind ...`
- `iket server restore --all --latest`

These are no longer optional helper paths; they are part of the supported recovery flow.

## Preferred Development Workflow

### Focused tests

Run focused packages first:

```bash
go test ./pkg/config
go test ./pkg/core/gateway
go test ./cmd/iket
go test ./cmd/iket-cli
```

Then run broader coverage when the change is larger:

```bash
go test ./...
```

### When changing config loading

Touch all of:
- validation
- docs
- scaffold templates
- default example configs
- CLI flows that assume old defaults

### When changing TLS bootstrap

Check all of:
- auto-generated cert paths
- Docker scaffolds
- remote bootstrap docs
- `cert import`
- `setup docker`
- enrollment flow

### When changing routing or rewriting

Check all of:
- `pkg/core/gateway/rewrite.go`
- route matching behavior in middleware/context
- `simulate` CLI path
- self-test endpoint
- docs examples using `base_path`, `stripPath`, and `url_pattern`

### When changing server lifecycle behavior

Check all of:
- scaffold generation
- reset-defaults behavior
- timestamped backup behavior
- daemon log and pid defaults
- backup/restore preview and confirmation
- website install and CLI docs

## Commands Worth Remembering

```bash
go test ./pkg/config ./pkg/core/gateway ./cmd/iket ./cmd/iket-cli

iket simulate /path --config ./config/config.yaml --services ./config/service.yaml

iket server run --reset-defaults --init-only
iket server run -d
iket server logs --tail 100
iket server restore --all --latest --preview

docker exec iket sh -lc 'sed -n "1,80p" /app/config/config.yaml'
docker exec iket sh -lc 'ls -la /app/certs /app/logs'
```

## Expectations For Future Agent Changes

- Keep docs aligned with actual defaults.
- Prefer explicit operator guidance over implicit magic.
- If a CLI error is predictable, make it actionable.
- If a deployment pitfall is common, teach `server doctor` to catch it.
- Avoid introducing “works locally, confusing remotely” behavior without a doctor or recovery-path improvement.
- If a new local server behavior changes scaffolds or artifacts, treat backup and restore behavior as part of the feature, not an afterthought.
