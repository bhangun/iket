[![Logo][iket-logo]][iket-logo]

<!-- Badges -->
[![Build Status](https://github.com/bhangun/iket/actions/workflows/ci.yml/badge.svg)](https://github.com/bhangun/iket/actions)
[![Go Report Card](https://goreportcard.com/badge/github.com/bhangun/iket)](https://goreportcard.com/report/github.com/bhangun/iket)
[![GitHub release](https://img.shields.io/github/v/tag/bhangun/iket?label=release)](https://github.com/bhangun/iket/releases)
[![License](https://img.shields.io/github/license/bhangun/iket)](LICENSE)
[![Docker Pulls](https://img.shields.io/docker/pulls/bhangun/iket)](https://hub.docker.com/r/bhangun/iket)

# Iket API Gateway

## 📖 Introduction

**Iket** is a lightweight, extensible, pluggable API Gateway written in Go. It supports modern gateway features such as rate-limiting, JWT authentication, WebSockets, middleware chaining, hot-reloadable plugins, and secure remote administration via mTLS.

## Features

- **High-Performance Proxy**: Reverse proxy for HTTP and WebSocket APIs.
- **Service-Based Configuration**: Manage routes, backends, and policies by service.
- **Secure Administration**: Remote control via `iket` using mTLS and client certificates.
- **mTLS & TLS 1.3**: Strong encryption and mutual authentication out of the box.
- **Extensible Plugin System**: Hot-reloadable middleware and lifecycle hooks.
- **Authentication**: Built-in support for Basic Auth, JWT, and Client Credentials.
- **Observability**: Prometheus metrics, structured logging, and health checks.

## 🚀 Quickstart

### Automated Installation (Linux/macOS)

Get up and running in seconds with our ultimate installer:

**Full Gateway Setup:**
```bash
curl -fsSL https://raw.githubusercontent.com/bhangun/iket/main/scripts/install.sh | bash
```

**CLI Only (for remote administration):**
```bash
curl -fsSL https://raw.githubusercontent.com/bhangun/iket/main/scripts/install.sh | bash -s -- --cli-only
```

**Optional Source Build:**
```bash
curl -fsSL https://raw.githubusercontent.com/bhangun/iket/main/scripts/install.sh | bash -s -- --from-source
```

By default, the installer downloads prebuilt release binaries. `--from-source` is only needed if you explicitly want a local source build. In full mode it also generates mTLS certificates and sets up your initial configuration.

**Safe Uninstall:**
```bash
curl -fsSL https://raw.githubusercontent.com/bhangun/iket/main/scripts/uninstall.sh | bash
```

**Backup Then Full Remove:**
```bash
curl -fsSL https://raw.githubusercontent.com/bhangun/iket/main/scripts/uninstall.sh | bash -s -- --backup --purge-state
```

For detailed instructions and manual installation, see [docs/INSTALL.md](docs/INSTALL.md).

### Run the Gateway

```bash
# Start with default config created by installer
iket-server --config ~/.iket/config.yaml

# Default storage is PostgreSQL with file mirroring
iket-server --config ./config/config.yaml --services ./config/service.yaml

# Use explicit PostgreSQL or legacy file-primary mode if needed
iket-server --storage postgres --postgres-url "postgres://iket:iket@127.0.0.1:55432/iket?sslmode=disable" --config ./config/config.yaml --services ./config/service.yaml
iket-server --storage file --config ./config/config.yaml --services ./config/service.yaml
```

---

## 🛠️ Remote Administration with `iket`

Iket provides a powerful CLI for remote administration. It supports multiple environment profiles (contexts) and secure mTLS communication.

### Getting Started

```bash
# Guided setup to connect to a local or remote gateway
iket setup

# Trusted-host Docker bootstrap using the server CA or an existing client bundle
iket setup docker --url https://localhost:8443

# Verify the active context and certificate files
iket context test

# Create a short-lived enrollment token from an already-admin-capable context
iket enroll create-token --name laptop-admin --out ./enroll.json

# Redeem that token on another machine
iket enroll use --file ./enroll.json --name laptop-admin

# List all configured contexts (environments)
iket context list

# Switch between environments (e.g., local, docker, prod)
iket context use <context-name>
```

### Basic Commands

```bash
# Check gateway status of the active context
iket gateway status

# Compare live and shadow traffic by service/route
iket gateway shadow-report

# Evaluate shadow traffic against configured route thresholds
iket gateway shadow-evaluate

# See which gateway guardrails are firing most often
iket gateway policy-hits

# Focus on recent policy pressure
iket gateway policy-hits --window 15m

# Elevate recent policy spikes into an operator-ready alert list
iket gateway policy-alerts --window 5m --min-count 3

# Push recent policy spikes into the existing webhook pipeline
iket gateway notify-policy-alerts --window 5m --min-count 3

# Or let Iket emit them automatically from config
# security.mutationPolicy.policyAlertNotifications.enabled: true
# Background policy alerts now emit lifecycle events too:
# gateway.policy_alert_opened, gateway.policy_alert_stage_changed, gateway.policy_alert_resolved

# Simulate how Iket would match and rewrite a request without calling upstream
iket simulate /v1/auth/profile --method GET

# Short alias
iket test http://localhost/v1/auth/profile

# Simulate against local unpublished files instead of the active context
iket simulate /v1/auth/profile --method GET --config ./config/config.yaml --services ./config/service.yaml

# Preview declarative changes before applying them
iket config diff ./config/config.yaml --merge
iket service diff ./config/service.yaml --replace
iket config apply ./config/config.yaml --merge --label "identity-rollout" --note "Enable new admin TLS and service routes" --change-ref "CHG-1427"

# Create a pending proposal first, then approve it later
iket config propose ./config/config.yaml --replace --proposer "deploy-bot" --env "staging" --not-before "2026-05-18T02:00:00Z" --label "prod-rollout" --note "Replace prod config after staging signoff" --change-ref "CHG-1429"
iket proposal list
iket proposal approve prp-20260517-101530.123 --reviewer "ops-lead" --review-note "Approved after staging smoke tests"
iket proposal promote prp-20260517-101530.123 --proposer "platform-admin" --env "prod" --not-before "2026-05-19T02:00:00Z" --canary-service "identity" --canary-percent 10 --canary-step 10 --canary-step 25 --canary-step 50 --canary-step 100 --canary-min-requests 50 --canary-max-error-rate 0.02 --canary-max-p95-latency 400ms
iket proposal queue
iket proposal queue --env prod --blocked-only
iket proposal queue --status approved --ready-only
iket proposal queue --next-action needs_verification
iket proposal queue --urgency overdue
iket proposal queue --env prod --urgency aging
iket proposal digest --env prod
iket proposal digest --next-action apply
iket proposal digest --urgency aging
iket proposal notify-digest --env prod --urgency overdue
iket proposal export-digest /tmp/iket-digest-prod.yaml --env prod
iket proposal export-queue /tmp/iket-queue-prod.json --env prod --limit 20
iket proposal blocked-report --env prod
iket proposal export-blocked /tmp/iket-blocked-prod.yaml --env prod
iket proposal explain-blocked prp-20260519-020000.123
iket proposal approve-ready --reviewer "ops-lead" --env prod --status pending --next-action needs_approval --limit 5
iket proposal apply-ready --reviewer "platform-admin" --env prod --status approved --next-action apply --limit 3
iket proposal batch preview --action apply --env prod --status approved --next-action apply --urgency aging --limit 3
iket proposal batch blocked --env prod --status pending --next-action needs_approval
iket proposal batch explain --env prod --status pending --next-action needs_approval --urgency overdue
# batch explain now returns a suggested_action, a copy-pasteable suggested_command,
# a short suggested_steps remediation plan, structured suggested_step_objects,
# and a formal suggested_plan envelope with plan_id, generated_at,
# overall status, current_step metadata, per-step status fields,
# and execution_hints for mutation-vs-inspection automation
iket proposal batch export /tmp/iket-batch-prod-digest.yaml --view digest --env prod --status approved --next-action apply --limit 3
iket proposal batch export /tmp/iket-batch-prod-blocked.json --view blocked --env prod --status pending --next-action needs_approval
iket proposal batch export /tmp/iket-batch-prod-explain.json --view explain --env prod --status pending --next-action needs_approval
iket proposal batch act --action apply --dry-run --env prod --status approved --next-action apply --urgency aging --limit 3
iket proposal batch act --action export --view digest --output /tmp/iket-batch-prod-digest.yaml --env prod --status approved --next-action apply --limit 3
iket proposal batch approve --reviewer "ops-lead" --env prod --status pending --next-action needs_approval --limit 5
iket proposal batch apply --reviewer "platform-admin" --env prod --status approved --next-action apply --limit 3
# queue output now includes priority_score and priority_reason so the most urgent work rises first
# urgency thresholds are configurable through security.mutationPolicy.proposalQueue,
# including per-environment overrides for prod vs staging
# digest output now also includes an attention_required section for overdue
# SLA-breached proposals, grouped and ranked for operator triage
# proposalQueue.notifications can also emit proposal.digest / proposal.sla_breach
# automatically in the background with interval and change-based debounce controls
# notificationWebhooks can also scope queue alerts with environments: [...]
# and only escalate proposal.sla_breach after minSLABreachCount is reached
# sustained queue escalation is also supported with minConsecutiveSLABreaches
# and minSLABreachDuration for PagerDuty-style "only page if it stays bad" rules
# queue SLA events now also carry warning / elevated / critical tiers,
# and notificationWebhooks can require minSLABreachTier per receiver
# slaBreachCooldown can also suppress repeat pages for the same tier until the
# cooldown passes, while still allowing immediate re-page when the tier worsens
# queue SLA incidents now also carry an incident_id and emit proposal.sla_resolved
# when the backlog clears, so downstream systems can close the same incident cleanly
# queue SLA progression now also emits proposal.sla_stage_changed whenever the
# same incident moves through warning, elevated, and critical stages
iket proposal verify prp-20260519-020000.123
iket proposal readiness prp-20260519-020000.123
iket proposal apply prp-20260519-020000.123 --reviewer "platform-admin" --review-note "Final apply approval"
iket proposal canary status prp-20260519-020000.123
iket proposal canary evaluate prp-20260519-020000.123
iket proposal canary advance prp-20260519-020000.123 --reviewer "platform-admin" --review-note "Canary healthy, move to next step"
iket proposal canary reconcile prp-20260519-020000.123 --reviewer "platform-admin" --review-note "Evaluate and take the next rollout action automatically"
iket proposal canary expand prp-20260519-020000.123 --reviewer "platform-admin" --canary-service "billing" --canary-percent 25
iket proposal canary complete prp-20260519-020000.123 --reviewer "platform-admin" --review-note "Canary healthy, finish rollout"
iket service propose ./config/service.yaml --replace --canary-service "identity" --canary-percent 10 --canary-step 10 --canary-step 25 --canary-step 50 --canary-step 100 --canary-auto --canary-auto-interval 30s --canary-auto-reviewer "canary-controller"

# Canary rollout can be selector-based with --canary-service / --canary-route, header-gated with --canary-header,
# or traffic-based with deterministic hashing via --canary-percent 1..99. Step plans can be declared with
# repeated --canary-step flags, and active step-based canaries can be progressed with proposal canary advance.
# Canary proposals can also carry
# rollout guards like --canary-min-requests, --canary-max-error-rate, and --canary-max-p95-latency.
# proposal canary reconcile can evaluate the active canary and then advance, complete, or roll it back automatically.
# canary-auto can let the gateway perform that reconcile loop in the background at the chosen interval.
# If those guards fail during canary advance, reconcile, or completion, Iket now rolls the gateway back to the pre-canary baseline automatically.

# Rollout notifications can be pushed to external systems with security.notificationWebhooks.
# Events include proposal.approved, proposal.applied, proposal.promoted, proposal.rejected,
# proposal.shadow_ready, proposal.canary_started, proposal.canary_advanced,
# proposal.canary_completed, proposal.canary_aborted, proposal.digest,
# proposal.sla_breach, proposal.sla_stage_changed, and proposal.sla_resolved.
# notificationWebhooks also support format: generic, slack, or teams.
# Per-webhook queue routing can also filter by environments and require
# minSLABreachCount before proposal.sla_breach notifications are delivered.
# They can also require sustained bad queue state with
# minConsecutiveSLABreaches and minSLABreachDuration.
# Tier-aware escalation is also supported with minSLABreachTier, so one webhook
# can receive every warning while another only receives critical queue breaches.
# slaBreachCooldown adds incident-style repeat suppression per webhook and
# environment, but a higher queue breach tier still breaks through immediately.
# proposal.sla_breach / proposal.sla_resolved also now share an incident_id
# so alerting systems can correlate one queue incident across open and close events.
# proposal.sla_stage_changed adds the stage transition itself, including
# previous_stage, current_stage, and the same incident_id for one queue incident.
# Webhooks can also be HMAC-signed with signingSecret, signatureHeader, and timestampHeader,
# retried with retryCount and retryBackoff, and later inspected or replayed with
# iket notification deliveries / show / replay / replay-failed.

# Routes can now define multiple weighted backends too. Each backend can keep its own
# url_pattern and optionally override the upstream host, for example:
# backend:
#   - url_pattern: "/api/{rest:.*}"
#     host: "http://identity-v1:8080"
#     weight: 1
#     timeout: "750ms"
#     failureThreshold: 1
#     cooldown: "30s"
#     halfOpenMaxRequests: 2
#     recoverySuccessThreshold: 2
#     outlierLatencyThreshold: "200ms"
#     outlierConsecutiveSlowResponses: 3
#     outlierCooldown: "2m"
#     healthCheckPath: "/health"
#     healthInterval: "15s"
#     healthTimeout: "2s"
#   - url_pattern: "/api/{rest:.*}"
#     host: "http://identity-v2:8080"
#     weight: 3
# retryCount: 2
# retryBackoff: "100ms"
# retryJitter: "25ms"
# retryStatusCodes: [429, 502, 503, 504]
# retryUnsafeMethods: false   # POST/PATCH retries stay off unless you opt in
# hedgeDelay: "20ms"          # safe read methods can race a backup backend after this delay
# hedgeUnsafeMethods: false
# adaptiveLatencyRouting: true # prefer the faster healthy backend over time
# shadowTrafficPercent: 10     # mirror a slice of safe read traffic to an alternate backend
# shadowUnsafeMethods: false
# shadow requests are marked with X-Iket-Shadow: true and now contribute
# shadow success/failure, latency EWMA, and live-vs-shadow latency delta
# counters in iket gateway backends. Use iket gateway shadow-report
# for a route-level live-vs-shadow summary grouped by service/path.
# Route-level shadow guardrails can be added with:
# shadowMinRequests: 50
# shadowMaxErrorRate: 0.02
# shadowMaxLatencyDelta: "40ms"
# and evaluated with iket gateway shadow-evaluate.
# Routes can also declare a first-class CORS policy:
# cors:
#   allowedOrigins: ["https://app.example.com"]
#   allowedMethods: ["GET", "POST"]
#   allowedHeaders: ["Authorization", "Content-Type"]
#   exposedHeaders: ["X-Trace-Id"]
#   allowCredentials: true
#   maxAge: 600
# Iket will answer browser preflight OPTIONS directly and add the matching
# CORS headers to actual responses without proxying preflight upstream.
# Routes can also perform request/response header transforms at the edge:
# requestHeaders:
#   X-Tenant-Realm: "{{realm}}"
# removeRequestHeaders: ["X-Legacy-Client"]
# requestRedactHeaders: ["Authorization"]
# transformWhenHeaders:
#   X-Transform-Mode: "beta"
# transformWhenQueryParams:
#   transform: "1"
# transformWhenHeaderRegex:
#   X-Env: "^prod-[a-z]+$"
# transformWhenQueryRegex:
#   mode: "^(preview|staging)$"
# transformMethods: ["POST", "PATCH"]
# transformScopes: ["request_json", "response_json"]
# responseTransformStatusClasses: ["2xx", "5xx"]
# responseTransformWhenHeaders:
#   Content-Type: "application/problem+json"
# successResponseFields:
#   data.status: "{{response_body}}"
#   data.content_type: "{{response_header.Content-Type}}"
#   status: "success"
#   request_id: "{{request_id}}"
# errorResponseFields:
#   error.status: "json:{{response_status}}"
#   error.message: "{{response_body}}"
#   error.content_type: "{{response_header.Content-Type}}"
#   request_id: "{{request_id}}"
# redactionValue: "***"
# responseRedactHeaders: ["Authorization", "Set-Cookie"]
# maxRequestBodyBytes: 65536
# maxResponseBodyBytes: 262144
# allowedModels: ["gpt-4.1-mini", "gpt-4.1"]
# modelField: "model"
# allowedToolNames: ["web_search", "file_lookup"]
# toolField: "tools[].name"
# maxMessages: 12
# messagesField: "messages"
# maxToolCalls: 4
# toolCallsField: "tools"
# maxInputTokens: 4096
# inputTokensField: "max_prompt_tokens"
# maxOutputTokens: 512
# outputTokensField: "max_tokens"
# allowedUpstreamHosts: ["api.openai.com", "api.anthropic.com"]
# protocol: "graphql"   # http, graphql, grpc, or websocket
# requiredRequestHeaders: ["X-Agent-Session"]
# requiredRequestHeaderRegex:
#   Authorization: "^Bearer .+"
# requestJSONFields:
#   meta.realm: "{{realm}}"
#   meta.request_id: "{{request_id}}"
#   meta.content_type: "{{response_header.Content-Type}}"
#   meta.enabled: "json:true"
#   meta.count: "json:123"
#   users[0].profile.realm: "{{realm}}"
#   meta.tags[]: "{{realm}}"
# removeRequestJSONFields: ["legacy", "user.profile.legacy"]
# requestRedactJSONFields: ["messages[0].content", "tools[0].arguments.api_key"]
# requestBodyBlockRegex: ["(?i)ignore\\s+previous\\s+instructions"]
# requestBodyRequireRegex: ["SAFE_SYSTEM_PROMPT"]
# requestPIIBlockTypes: ["email", "api_key"]
# queryParams:
#   realm: "{{realm}}"
#   token_copy: "{{query.token}}"
# removeQueryParams: ["legacy"]
# responseHeaders:
#   X-Edge-Policy: "{{query.mode}}-{{request_id}}"
# removeResponseHeaders: ["X-Powered-By"]
# responseJSONFields:
#   meta.realm: "{{realm}}"
#   meta.request_id: "{{request_id}}"
#   meta.content_type: "{{response_header.Content-Type}}"
#   meta.enabled: "json:true"
#   meta.count: "json:123"
#   users[0].profile.realm: "{{realm}}"
#   meta.tags[]: "{{realm}}"
# responseRedactJSONFields: ["meta.token", "meta.api_key"]
# responseBodyBlockRegex: ["(?i)api_key"]
# responseBodyRequireRegex: ["SAFE_OUTPUT"]
# responsePIIBlockTypes: ["api_key", "email"]
# removeResponseJSONFields: ["legacy", "user.profile.legacy"]
# The older headers: {...} field still works as a backward-compatible alias
# for upstream request header injection. Query strings are preserved by default,
# then queryParams/removeQueryParams are applied before proxying upstream.
# Add transformWhenHeaders / transformWhenQueryParams for exact matches, or
# transformWhenHeaderRegex / transformWhenQueryRegex for regex matches, to gate
# these edge transforms behind request metadata. Add transformMethods to limit
# transforms to selected HTTP methods such as POST or PATCH. Add transformScopes
# to limit that gating to specific rewrite families such as request_headers,
# query, request_json, response_headers, or response_json. If transformScopes is
# omitted, the gate applies to every transform on the route for compatibility.
# Response-side transforms can also be narrowed to specific upstream statuses
# with responseTransformStatusCodes or responseTransformStatusClasses such as
# 2xx, 4xx, or 5xx, and can also be gated by upstream response headers with
# responseTransformWhenHeaders or responseTransformHeaderRegex. For consistent
# backend failures, errorResponseFields can replace 4xx/5xx bodies with a
# normalized JSON envelope, and successResponseFields can do the same for
# successful 2xx/3xx responses. For agent-facing routes, requestRedactHeaders,
# requestRedactJSONFields, responseRedactHeaders, and responseRedactJSONFields
# can mask secrets before data leaves or returns through the gateway.
# maxRequestBodyBytes and maxResponseBodyBytes can also enforce prompt/output
# size ceilings for agent or model-facing routes.
# allowedModels and modelField can enforce per-route model allowlists for
# OpenAI-compatible or agent-facing JSON APIs.
# allowedToolNames and toolField can enforce which tool names an agent request
# is allowed to declare before the payload reaches the upstream model or orchestrator.
# maxMessages / messagesField and maxToolCalls / toolCallsField can limit
# conversation fan-out and declared tool usage per agent request.
# maxInputTokens / maxOutputTokens and their field-path overrides can enforce
# prompt and completion token ceilings before the request reaches the provider.
# requestBodyBlockRegex and requestBodyRequireRegex can enforce simple body-level
# content policy, such as blocking risky prompt patterns or requiring a trusted
# safety marker before agent traffic leaves the gateway.
# requestPIIBlockTypes and responsePIIBlockTypes provide named detectors for
# common sensitive classes like email, phone, api_key, and card without writing
# raw regexes for each route.
# responseBodyBlockRegex and responseBodyRequireRegex can do the same on model
# output before it is returned to the caller. Blocked policy responses now also
# emit X-Iket-Policy-Hit with a structured reason for audit and automation, and
# iket gateway policy-hits exposes aggregated counters by reason and route plus
# a recent-window summary for hot reasons and routes.
# allowedUpstreamHosts can pin a route to approved tool or model provider
# endpoints even when clients try to reuse the route for other hosts. protocol
# can explicitly mark a route as http, graphql, grpc, grpc-web, websocket, or sse, which lets
# Iket enforce GraphQL-compatible HTTP usage, application/grpc traffic, browser-style
# application/grpc-web traffic, a real websocket upgrade, or streaming text/event-stream behavior on that route.
# GraphQL routes can also use graphqlAllowIntrospection: false and
# graphqlRequirePersistedQuery: true to block schema introspection and require
# persisted-query style requests at the gateway edge.
# SSE routes stay stream-safe by skipping buffered response body rewrites.
# security.tls.http3Enabled now adds a
# dedicated HTTP/3-over-QUIC transport module on UDP as well, so Iket can serve
# HTTPS over TCP and HTTP/3 over UDP side by side on the same or separate port.
# requiredRequestHeaders and requiredRequestHeaderRegex can reject agent or
# provider traffic unless expected control or auth headers are present and valid
# before anything leaves the gateway.
# Templated values can reference {{realm}}, {{request_id}}, {{query.name}},
# {{var.name}}, {{header.Name}}, and for response-side transforms
# {{response_header.Name}}, {{response_status}}, and {{response_body}}.
# JSON body transforms only apply to top-level object request/response bodies
# with JSON content types, and their keys can use dot paths like
# user.profile.realm, indexed paths like users[0].profile.realm, and append
# syntax like meta.tags[]. Prefix a value with json: to write typed JSON such
# as booleans, numbers, arrays, or objects.
# For promoted high-impact proposals, security.mutationPolicy can also require
# those shadow checks to pass before proposal apply succeeds, and can require
# a streak such as minShadowHealthyVerificationsForPromotedHighImpactProposals: 2.
# Backends now recover through a half-open circuit too:
# after cooldown, up to halfOpenMaxRequests can probe the backend,
# and recoverySuccessThreshold controls how many successes are required
# before the circuit closes again.
# You can also eject a backend for repeated slow responses with
# outlierLatencyThreshold, outlierConsecutiveSlowResponses, and outlierCooldown.

# Preview targeted admin changes too
iket plugin diff-config rate_limit ./plugin-rate-limit.yaml
iket route diff-update route-abc123 ./route-update.yaml

# Inspect and restore recorded config revisions
iket revision list
iket revision show rev-20260517-101530.123
iket revision diff rev-20260517-101530.123 current
iket revision restore rev-20260517-101530.123

# In strict contexts, high-impact changes should carry explicit metadata
iket service apply ./config/service.yaml --replace --label "prod-rollout" --note "Replace remote service set after staging verification" --change-ref "CHG-1428"

# The gateway can enforce the same metadata requirements for all callers
# through security.mutationPolicy in config.yaml, including scoped
# enforcement for config/services/routes/plugins/clients/revisions/high_impact,
# and can optionally block self-approval, require multiple approvals,
# require fresh approvals, verify promoted lineage, require promoted shadow
# evaluation, expire stale proposals, require a scheduled not-before time,
# or freeze apply during recurring blackout windows

# Follow remote logs; falls back to polling when live streaming is unavailable
iket logs tail
iket logs tail --service identity
iket logs list --request-id 4a92f0c8f0db4e70
iket logs trace --service identity
# prints a one-line request summary before following

# Certificate management
iket cert status
```

### Environment Overrides
You can override the active context using environment variables:
```bash
IKET_SERVER_URL=http://localhost:7100 iket gateway status
```

---

## ⚙️ Configuration

### Server Configuration (`config.yaml`)

```yaml
server:
  port: 8080
  enableLogging: true

security:
  tls:
    enabled: true
    port: 8443
    http3Enabled: true
    http3Port: 8443
    http3Datagrams: true
    certFile: "/path/to/server.crt"
    keyFile: "/path/to/server.key"
    clientCAFile: "/path/to/ca.crt"
    clientAuthType: "RequireAndVerifyClientCert"
    minVersion: "TLS1.3"
    autoGenerate: true
    generateSharedClient: false
```

`server.port` stays available for plain HTTP traffic, while `security.tls.port` serves the mTLS admin endpoint. If `http3Enabled: true` is set, Iket also starts its HTTP/3 transport module on UDP, using `http3Port` or the TLS port by default. When `autoGenerate: true`, Iket creates `ca.crt`, `ca.key`, `server.crt`, and `server.key` automatically if they are missing. Shared admin client credentials are not generated by default; `generateSharedClient: true` is an explicit opt-in for compatibility-only environments.

In Docker deployments, those generated files land in the server deployment's mounted cert directory such as `./certs/`, not automatically in the CLI-managed `~/.iket/certs`. The usual first-admin bootstrap on the trusted server host is:

```bash
iket setup docker --cert-dir ./certs --url https://<server-ip>:8443
```

For remote laptop access, make sure the server certificate SANs include the real hostname or IP you will connect to:

```yaml
security:
  tls:
    serverNames: ["localhost", "iket", "gateway.example.com"]
    serverIPs: ["127.0.0.1", "103.16.199.4"]
```

If you explicitly enable `generateSharedClient: true`, Iket also generates `client.crt` and `client.key` in that same server-side cert directory, and you can then import them with:

```bash
iket cert import --name remote-prod --cert-dir ./certs --url https://<server-ip>:8443
```

`./certs` above is the server deployment directory. `~/.iket/certs` is your local CLI store. If the server cert only contains `127.0.0.1`, remote imports and admin requests will fail until `serverNames` / `serverIPs` are updated and `server.crt` is regenerated.

`iket server doctor --mode docker` now checks the generated `server.crt` SANs against the configured `security.tls.serverNames` / `serverIPs`, and newer `iket cert import` errors include an explicit hint when the server certificate hostname or IP does not match the requested URL.

You can also point doctor at the actual admin URL you intend to use:

```bash
iket server doctor --mode docker --output ./iket-docker --url https://103.16.199.4:8443
```

For deterministic server-certificate rotation, use:

```bash
iket cert regenerate-server --config ./config/config.yaml --cert-dir ./certs --ca-dir ./certs
```

That is especially useful after changing `security.tls.serverNames` or `serverIPs`.

If Docker startup fails with `open /app/certs/ca.key: permission denied`, the host-mounted `./certs` directory is not writable by the container user. Make sure `IKET_UID` / `IKET_GID` match the host owner, clear stale root-owned cert files if needed, and prefer running `docker compose` as the same user that owns the deployment folder.
`security.tls.enrollmentPort` exposes a narrow HTTPS bootstrap endpoint for one-time certificate enrollment without opening the full admin surface.

The direct enrollment flow works best when Iket is using its local managed CA. If you point `clientCAFile` at an external CA but do not keep the signing key on the server, Iket cannot mint new client certificates and enrollment will be rejected.
Iket also caps active enrollment tokens (`security.tls.enrollmentMaxActive`, default `10`) and records token create/redeem/revoke events in the structured logs.

### Service Configuration (`service.yaml`)

```yaml
version: 1
services:
  - name: "Identity Service"
    host: "http://identity:8080/api"
    base_path: "/{realm}/auth"
    routes:
      - path: /login
        method: POST
        requireAuth: true
        stripPath: false
        backend:
          - url_pattern: /login
```

`service.base_path` is the canonical way to mount a service on the public gateway path. Route paths are evaluated relative to that base, so the example above exposes `POST /{realm}/auth/login` and proxies it to `/api/login` upstream. If your `host` already includes a path prefix, Iket will join it with the rewritten route path without introducing double slashes.

---

## 🔌 Plugin System

Iket's plugin system allows you to extend the gateway with custom middleware.

### Example MiddlewarePlugin

```go
type MyPlugin struct {}
func (p *MyPlugin) Name() string { return "myplugin" }
func (p *MyPlugin) Initialize(cfg map[string]interface{}) error { return nil }
func (p *MyPlugin) Middleware(next http.Handler) http.Handler { return next }
```

---

## 📦 Deployment

### Docker

```bash
# Generate a ready-to-run prebuilt Docker scaffold
iket server init --mode docker --output ./iket-docker --with-systemd

# Inspect the scaffold and local Docker runtime state
iket server doctor --mode docker --output ./iket-docker

# Or scaffold a host-native install instead
iket server init --mode host --output ./iket-host --with-systemd
iket server doctor --mode host --output ./iket-host

# Run the prebuilt image with your own compose file
docker compose up -d

# Or, if you have the repository checked out, use the bundled prebuilt compose file
docker compose -f docker/docker-compose.prebuilt.yaml up -d
```

For a full remote prebuilt Docker walkthrough, including config, auto-generated certs, and `iket` bootstrap, see [docs/INSTALL.md](docs/INSTALL.md#--remote-docker-installation).

`iket-cli` remains as a compatibility alias for the client binary, but `iket` is now the primary command. The gateway binary is `iket-server`.
The generated server scaffold now includes both `config/config.yaml` and `config/service.yaml`, and the host/Docker startup commands pass both files so file mirroring stays aligned with SQLite-backed storage.

---

## 👷 Contributing

* Implementation of new plugins
* Improving documentation
* Reporting bugs and security vulnerabilities

---

## 📚 Documentation

- [Installation Guide](docs/INSTALL.md)
- [CLI Command Reference](docs/CLI_COMMANDS.md)
- [API Key Management](docs/API_KEY_MANAGEMENT.md)
- [Plugin Quickstart](docs/PLUGIN_QUICKSTART.md)
- [Config Storage](docs/CONFIG_STORAGE.md)
- [API Reference](docs/API.md)

[iket-logo]: https://github.com/bhangun/repo-assets/blob/master/iket-logo.png

## License

This project is licensed under the MIT License - see the LICENSE file for details.
