# Iket Skills

This file catalogs repo-specific working skills for agents operating inside the Iket codebase.

It is intentionally lightweight and follows the spirit of [skills.md](https://skills.md):
- keep the local contract thin
- describe when a skill should be used
- keep only the relevant instructions in context
- prefer concrete workflows and validation steps over long explanations

## Remote Skill Model

If an agent is connected to `skills.md`, treat that as a remote skill registry:
- discover skills remotely
- load only the selected skill contract
- keep local repo state focused on code, tests, and generated artifacts
- do not copy unrelated skill source into this repository

For this repo, `SKILLS.md` is the local routing layer that tells an agent which Iket-specific workflow to apply.

## Skill: Local Server Lifecycle

Use this when touching:
- `cmd/iket/main.go`
- `cmd/iket-cli/run.go`
- first-run scaffold generation
- `iket server run`
- daemon/log/pid behavior
- scaffold backup or restore flows

Checklist:
- keep plain `iket server run` file-backed by default
- keep `--database` as explicit opt-in
- keep scaffold-local defaults under `config/`, `docker-compose.yaml`, and `logs/`
- verify `--log-dir` / `--pid-dir` overrides still work
- verify restore preview, confirmation, and `--force` behavior
- update CLI docs when user-facing flags or defaults change

## Skill: Routing Rewrite Work

Use this when touching:
- `pkg/core/gateway/rewrite.go`
- route matching
- `url_pattern`
- `stripPath`
- `service.base_path`
- `simulate`

Checklist:
- verify mux vars are used consistently
- test `stripPath=true/false`
- test `{rest:.*}` routes
- test joined upstream paths for double-slash regressions
- verify CLI simulation and management self-test still agree

## Skill: Remote Admin TLS Work

Use this when touching:
- TLS bootstrap
- cert generation/import
- `setup docker`
- enrollment
- context verification

Checklist:
- distinguish server cert problems from client cert problems
- distinguish server Docker `./certs` from local `~/.iket/certs`
- verify SAN behavior for remote host/IP access
- update install docs when behavior changes
- improve CLI errors if the likely operator fix is obvious

## Skill: Docker Operator UX Work

Use this when touching:
- `cmd/iket-cli/docker_init.go`
- prebuilt compose flow
- `.env` defaults
- permissions troubleshooting

Checklist:
- update scaffold templates
- update `server doctor`
- update install docs
- think about bind-mount ownership
- think about first-boot TLS bootstrap behavior
- keep container and host paths easy to reason about

## Skill: Config Storage Work

Use this when touching:
- `pkg/config/postgres_provider.go`
- `pkg/config/sqlite_provider.go`
- `pkg/config/mirroring_provider.go`
- early config parsing in `cmd/iket/main.go`

Checklist:
- verify env expansion for early startup paths
- verify bootstrap-from-file still works
- verify provider defaults match docs and scaffolds
- verify migration/version behavior
- ensure CLI push/pull assumptions still hold
- keep local-first defaults and explicit database opt-in aligned

## Skill: CLI and Admin Surface Work

Use this when touching:
- `cmd/iket-cli/*`
- management API parity
- route/service CRUD
- logs/list/tail
- proposal/canary/admin ergonomics

Checklist:
- prefer clear operator-facing errors over generic failures
- keep command behavior aligned with management API reality
- if adding a server feature, ask whether CLI exposure is needed too
- avoid shorthand collisions with global flags
- if a feature is safe or read-only, keep strict-mode behavior reasonable

## Skill: Production-Like Docker Debugging

Use this when the user is debugging a remote or Docker deployment.

Checklist:
- avoid hand-wavy advice
- ask for or infer exact mounted paths
- verify the live config inside the container
- verify actual generated cert files
- verify actual image/date when behavior differs by machine
- prefer concrete commands the operator can paste

## Minimal Debug Ladder

When a report sounds ambiguous, use this order:
1. Verify running image/version
2. Verify mounted config inside the container
3. Verify generated cert files inside the container
4. Verify ownership and permissions on host bind mounts
5. Verify live endpoint behavior from the actual client URL

## Validation Defaults

Usually enough while iterating:

```bash
go test ./pkg/config ./pkg/core/gateway ./cmd/iket ./cmd/iket-cli
```

Use a broader suite before closing larger changes:

```bash
go test ./...
```
