# Iket Agent Guide

This file is for coding agents and maintainers working inside the Iket repository.

## What Iket Is

Iket has two primary binaries:
- `iket-server`: the gateway and management API server
- `iket`: the admin CLI

Core responsibilities:
- route matching and upstream path rewriting
- management API for config, routes, plugins, logs, certificates, and backups
- mTLS-secured remote administration
- file and database-backed config storage

## Repository Shape

- `cmd/iket`: server entrypoint
- `cmd/iket-cli`: CLI entrypoint and subcommands
- `pkg/core/gateway`: routing, middleware, proxying, request context
- `pkg/api`: management API handlers
- `pkg/config`: config model, validation, TLS bootstrap, storage providers
- `pkg/logging`: structured logger and in-memory live log store
- `docs`: install, CLI, storage, production guidance
- `config`: local example config files

## Current Architecture Assumptions

- PostgreSQL is the default primary config store.
- File config is still accepted and mirrored.
- Docker/prebuilt deployments are a first-class operator path.
- The CLI is the primary admin UX.
- mTLS is the normal admin transport.

## Important Operational Gotchas

### 1. Remote TLS SANs matter

If the server is accessed remotely, `security.tls.serverNames` and `security.tls.serverIPs` must include the real hostname or IP used by the client. Otherwise the CLI will fail TLS verification even if the CA and client cert are correct.

Relevant files:
- `pkg/config/tls_bootstrap.go`
- `cmd/iket-cli/cert.go`
- `cmd/iket-cli/setup.go`
- `docs/INSTALL.md`

### 2. Docker bind-mount permissions are a frequent first-run failure

If startup fails with:

`failed to prepare bootstrap TLS assets ... /app/certs/ca.key: permission denied`

the problem is usually host ownership or mode on `certs/` and `logs/`, not Postgres.

Relevant files:
- `cmd/iket-cli/docker_init.go`
- `docs/INSTALL.md`

### 3. Remote config drift is easy to misread

When debugging Docker deployments, always verify the mounted config inside the container:

```bash
docker exec iket sh -lc 'sed -n "1,40p" /app/config/config.yaml'
```

Do not assume the edited host file and the live mounted file still match.

### 4. `~/.iket/certs` is local CLI state, not the server Docker cert volume

When helping users import certs:
- server-side Docker bundle usually lives in deployment `./certs`
- client-side managed store usually lives in `~/.iket/certs/...`

Do not blur those paths in docs or error messages.

### 5. SSE/log streaming depends on preserving `http.Flusher`

The gateway `responseWriter` wrapper must preserve streaming interfaces. If `iket logs tail` starts returning `Streaming not supported`, check `pkg/core/gateway/middleware.go`.

## Preferred Development Workflow

### Focused tests

Run focused packages first:

```bash
go test ./pkg/config
go test ./pkg/core/gateway
go test ./cmd/iket
go test ./cmd/iket-cli
```

Then run full coverage when the change is broad:

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

## Commands Worth Remembering

```bash
go test ./pkg/config ./pkg/core/gateway ./cmd/iket ./cmd/iket-cli

iket simulate /path --config ./config/config.yaml --services ./config/service.yaml

iket push services ./config/service.yaml --strategy replace

docker exec iket sh -lc 'sed -n "1,40p" /app/config/config.yaml'
docker exec iket sh -lc 'ls -la /app/certs'
```

## Expectations For Future Agent Changes

- Keep docs aligned with actual defaults.
- Prefer explicit operator guidance over implicit magic.
- If a CLI error is predictable, make it actionable.
- If a deployment pitfall is common, teach `server doctor` to catch it.
- Avoid introducing “works locally, confusing remotely” behavior without a doctor or self-test improvement.
