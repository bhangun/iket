# Iket Skills

This file lists repo-local skills and recurring workflows for agents working on Iket.

## Skill: Routing Rewrite Work

Use this when touching:
- `pkg/core/gateway/rewrite.go`
- route matching
- `url_pattern`
- `stripPath`
- `service.base_path`
- `simulate`

Checklist:
- verify `mux` vars are used consistently
- test `stripPath=true/false`
- test `{rest:.*}` cases
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
- add or improve CLI errors if the likely fix is obvious

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
- think about first-boot bootstrap behavior

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

## Skill: CLI/Admin Surface Work

Use this when touching:
- `cmd/iket-cli/*`
- management API parity
- route/service CRUD
- logs/list/tail

Checklist:
- prefer clear error messages over generic failures
- keep command behavior aligned with management API reality
- if adding a server feature, ask whether CLI exposure is needed too
- if a feature is read-only or safe, keep strict-mode behavior reasonable

## Skill: “User Is Debugging Production-Like Docker”

When the user is actively debugging a remote or Docker deployment:
- avoid hand-wavy advice
- ask for or infer exact mounted paths
- verify the live config inside the container
- verify actual generated cert files
- verify actual image digest/date when behavior differs by machine
- prefer concrete commands the operator can paste

## Minimal Debug Ladder

When a report sounds ambiguous, use this order:
1. Verify running image/version
2. Verify mounted config inside container
3. Verify generated cert files inside container
4. Verify ownership/permissions on host bind mounts
5. Verify live endpoint behavior from the actual client URL

## Testing Defaults

Usually enough while iterating:

```bash
go test ./pkg/config ./pkg/core/gateway ./cmd/iket ./cmd/iket-cli
```

Use full test suite before closing larger changes:

```bash
go test ./...
```
