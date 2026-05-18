# 🛠️ Iket Command Reference

The `iket` command is your remote control for the Iket API Gateway. It allows you to manage multiple environments, sync configurations, and modify services interactively. The gateway/server binary is `iket-server`.

---

## 🌍 Setup & Contexts
Manage different environment profiles (Local, Docker, Staging, Production).

| Command | Description |
|---------|-------------|
| `iket setup` | Guided wizard to connect to a new gateway. |
| `iket setup docker` | On a trusted server host, import an existing client bundle or mint a local admin client certificate from the server CA and create a ready-to-use mTLS context. |
| `iket server init --mode docker` | Generate a prebuilt Docker deployment scaffold with `config.yaml`, `service.yaml`, compose, and optional `.env`/systemd files. |
| `iket server init --mode host` | Generate a host-native scaffold with `config.yaml`, `service.yaml`, cert/log directories, SQLite path, and optional `.env`/systemd files. |
| `iket server doctor --mode docker` | Check scaffold files, Docker state, `certs/` and `logs/` ownership against `IKET_UID` / `IKET_GID`, container health, local ports, TLS handshakes, generated certs, server-cert SAN coverage versus configured `serverNames`/`serverIPs`, and optionally verify the cert against a real target URL via `--url` or a CLI context via `--context`. |
| `iket server doctor --mode host` | Check host scaffold files, local ports, TLS handshakes, Iket binary availability, and an optional CLI context. |
| `iket enroll create-token` | Create a short-lived enrollment token from the current admin context. |
| `iket enroll list-tokens` | List current and historical enrollment tokens. |
| `iket enroll revoke-token <id>` | Revoke an enrollment token before it is used. |
| `iket enroll use` | Redeem an enrollment token and create a local CLI context without copying the full cert bundle. |
| `iket context list` | List all saved environments. |
| `iket context use <name>` | Switch the active environment. |
| `iket context test [name]` | Verify that a context's cert files exist and that the gateway is reachable. |
| `iket context add <name>` | Manually add a context with `--url`, `--ca`, `--cert`, or `--cert-dir`. |
| `iket context delete <name>` | Remove a context profile. |
| `iket simulate <url-or-path>` | Simulate route matching and upstream path rewriting without calling the upstream service, using either the active context or `--config` / `--services` local files. |
| `iket test <url-or-path>` | Alias for `iket simulate`. |

---

## 🔄 Configuration Sync (GitOps)
Push local files to remote or pull remote state to local files.

| Command | Description |
|---------|-------------|
| `iket config apply <file> --replace` | Replace the full remote gateway config from a file. |
| `iket config apply <file> --merge` | Merge a gateway config file into the current remote config. |
| `iket config propose <file> --replace` | Create a pending proposal for full remote gateway config replacement. Supports `--proposer`, `--env`, and `--not-before`. |
| `iket config propose <file> --merge` | Create a pending proposal for merging a gateway config file into the current remote config. Supports `--proposer`, `--env`, and `--not-before`. |
| `iket config diff <file> --replace` | Preview how a full gateway config replacement would change the remote state. |
| `iket config diff <file> --merge` | Preview how a gateway config merge would change the remote state. |
| `iket service apply <file> --replace` | Replace the full remote services state from a file. |
| `iket service apply <file> --merge` | Merge a service definition file into the current remote services state. |
| `iket service propose <file> --replace` | Create a pending proposal for full remote services replacement. Supports `--proposer`, `--env`, `--not-before`, `--canary-service`, `--canary-route`, and `--canary-header`. |
| `iket service propose <file> --merge` | Create a pending proposal for merging a service definition file into the current remote services state. Supports `--proposer`, `--env`, `--not-before`, `--canary-service`, `--canary-route`, and `--canary-header`. |
| `iket service diff <file> --replace` | Preview how a full service replacement would change the remote state. |
| `iket service diff <file> --merge` | Preview how a service merge would change the remote state. |
| `iket push config <file>` | Export local gateway settings to remote. |
| `iket push services <file>` | Export local service/route definitions to remote. |
| `iket pull config [file]` | Fetch remote settings and save locally (YAML/JSON). |
| `iket pull services [file]` | Fetch remote services and save locally. |

**Strategies for Push:**
- `--strategy merge` (Default): Update existing items and add new ones.
- `--strategy replace`: Overwrite the remote state entirely with your local file.

---

## 📦 Service Management
Manage backends and groups of routes.

| Command | Description |
|---------|-------------|
| `iket service list` | List all services and their routes. |
| `iket service create -i` | **Interactive Wizard** to build a service step-by-step. |
| `iket service create <file>` | Create service from a YAML/JSON file. |
| `iket service apply <file> --replace` | Replace the entire remote services set from a service definition file. |
| `iket service apply <file> --merge` | Merge a service definition file into the current remote services set. |
| `iket service propose <file> --replace` | Create a pending proposal for replacing the entire remote services set. Supports `--proposer`, `--env`, `--not-before`, `--canary-service`, `--canary-route`, and `--canary-header`. |
| `iket service propose <file> --merge` | Create a pending proposal for merging a service definition file into the current remote services set. Supports `--proposer`, `--env`, `--not-before`, `--canary-service`, `--canary-route`, and `--canary-header`. |
| `iket service diff <file> --replace` | Preview replacing the entire remote services set from a service definition file. |
| `iket service diff <file> --merge` | Preview merging a service definition file into the current remote services set. |
| `iket service set <name>` | Update attributes like `--host` or `--desc` for a specific service. |
| `iket service delete <name>` | Remove a service and all its routes. |

---

## 🛣️ Route Management
Fine-grained control over individual API endpoints.

| Command | Description |
|---------|-------------|
| `iket route list` | List all routes across all services. |
| `iket route set <svc> <path> <method>` | Update a specific route (e.g., `--auth true`, `--enabled false`). |
| `iket route diff-create <file>` | Preview creating a route from a YAML/JSON file. |
| `iket route diff-update <id> <file>` | Preview updating a route from a YAML/JSON file. |
| `iket route enable <id>` | Enable a route by ID. |
| `iket route disable <id>` | Disable a route by ID. |

---

## ⚡ Gateway & Plugins
Monitor and control the gateway core.

| Command | Description |
|---------|-------------|
| `iket gateway status` | Check health, uptime, and request metrics. |
| `iket gateway edition` | Show the active Iket edition and advertised capabilities. |
| `iket gateway capabilities [--category gateway]` | List active edition capabilities, optionally filtered by category. |
| `iket gateway capability <key>` | Check whether the active edition supports one capability key. |
| `iket gateway extensions [--supported or --unsupported --capability commercial.billing]` | List registered management route extensions and filter by edition/capability support status. |
| `iket gateway config` | View the live gateway configuration (secrets redacted). |
| `iket gateway reload` | Force a hot-reload of all configurations. |
| `iket gateway route-policy --path /foo --method GET` | Inspect the matched route's resolved AI guardrails, applied preset stack, effective policy fields, and per-field source attribution. Supports repeatable `--header Name:Value` plus optional `--bucket-key` for percent-gated routes. |
| `iket gateway route-policy-diff --from-path /a --to-path /b` | Compare two matched route policies and list only the effective guardrail fields that differ, including each side's value and source layer. Supports per-side `--from-method` / `--to-method`, repeatable `--from-header` / `--to-header`, and `--from-bucket-key` / `--to-bucket-key`. |
| `iket gateway limit-hits [--window 5m]` | Show aggregated route limiter saturation counters for native `rateLimitPolicy` and `concurrencyLimitPolicy`, grouped by limiter type and route with a recent-window summary. Also includes current in-flight and queued depth per route, queued-admission visibility, queue-full rejections, and queue wait timing. |
| `iket gateway limit-buckets [--window 5m --min-count 1]` | Show recent limiter pressure grouped by anonymized bucket ID, with route, limiter type, key type, hit counts, and queue-pressure stats so hot tenants stand out directly. |
| `iket gateway limit-alerts [--window 5m --min-count 3]` | Detect recent limiter saturation spikes by route and limiter type and classify them by severity, including queue-full and queued-admission context. Routes with `limitAlertPolicy.groupBy: bucket` split alerts per anonymized limiter bucket as well, and `bucketPolicies` can apply stricter thresholds to matching tenants or API-key buckets. |
| `iket gateway notify-limit-alerts [--window 5m --min-count 3]` | Emit recent gateway limiter alert digests and per-alert webhook events through configured notification targets. |
| `iket gateway policy-hits [--window 5m]` | Show aggregated gateway policy-hit counters plus a recent-window summary grouped by reason and route. |
| `iket gateway policy-alerts [--window 5m --min-count 3]` | Detect recent policy-hit spikes by route and reason and classify them by severity. |
| `iket gateway notify-policy-alerts [--window 5m --min-count 3]` | Emit recent gateway policy alert digests and per-alert webhook events through configured notification targets. |
| `iket gateway shadow-report` | Show aggregated live-vs-shadow comparison data grouped by service and route. |
| `iket gateway shadow-evaluate` | Evaluate grouped shadow traffic against route-level shadow thresholds. |
| `iket plugin list` | List all available and active plugins. |
| `iket plugin diff-config <name> <file>` | Preview how a plugin config file would change the remote plugin configuration. |
| `iket plugin enable <name>` | Enable a plugin globally. |
| `iket plugin disable <name>` | Disable a plugin globally. |

---

## 🕘 Revisions
Inspect and restore recorded configuration revisions.

| Command | Description |
|---------|-------------|
| `iket revision list` | List recorded remote configuration revisions with action metadata and service/route counts. |
| `iket revision show <id>` | Show one recorded revision, including stored config and summary metadata. |
| `iket revision diff <from> <to>` | Compare two revisions, or compare a revision with `current`. |
| `iket revision restore <id>` | Restore a recorded remote configuration revision. |
| `iket proposal list` | List pending and reviewed configuration proposals. |
| `iket proposal queue` | Show proposal queue entries with readiness summaries, blockers, aging/worklist signals, urgency classification, priority score/reason, next action hints, and optional `--env`, `--status`, `--next-action`, `--urgency`, `--ready-only`, or `--blocked-only` filters. |
| `iket proposal digest` | Show a compact rollout digest with queue summary, top ready proposals, top blocked proposals, top blocker reasons, and an `attention_required` section for SLA-breached overdue proposals. Supports the same queue filters, including `--next-action` and `--urgency`. |
| `iket proposal notify-digest` | Emit the current filtered proposal queue digest through configured notification webhooks. This always emits `proposal.digest`, and also emits `proposal.sla_breach` when the filtered queue contains overdue SLA-breached proposals. Supports the same queue filters as `proposal digest`. |
| `iket proposal export-digest <file>` | Export the compact rollout digest to JSON or YAML, with optional `--env`, `--status`, `--next-action`, `--urgency`, `--ready-only`, `--blocked-only`, and `--limit` filters. |
| `iket proposal export-queue <file>` | Export the filtered proposal queue to JSON or YAML, with optional `--env`, `--status`, `--next-action`, `--urgency`, `--ready-only`, `--blocked-only`, and `--limit` filters. |
| `iket proposal blocked-report` | Aggregate blocked proposals by blocker reason, with optional `--env` and `--status` filters. |
| `iket proposal export-blocked <file>` | Export the blocked proposal report to JSON or YAML, with optional `--env` and `--status` filters. |
| `iket proposal approve-ready` | Batch-approve approval-blocked proposals oldest-first, with `--reviewer`, optional `--env`, `--status`, `--next-action needs_approval`, `--urgency`, `--limit`, and global `--dry-run` support. |
| `iket proposal apply-ready` | Batch-apply ready proposals oldest-ready-first, with `--reviewer`, optional `--env`, `--status`, `--next-action apply`, `--urgency`, `--limit`, and global `--dry-run` support. |
| `iket proposal batch preview` | Preview a filtered batch action with `--action approve|apply`, shared `--env`, `--status`, `--next-action`, `--urgency`, `--limit`, and optional reviewer metadata. |
| `iket proposal batch blocked` | Summarize blockers for the current filtered batch slice using the shared batch selector flags, including `--urgency`. |
| `iket proposal batch explain` | Explain the dominant blocker, next action, remediation direction, suggested follow-up command, machine-friendly remediation steps, and a formal `suggested_plan` envelope with current-step metadata and `execution_hints` for the current filtered batch slice. Supports the shared queue selectors, including `--urgency`. |
| `iket proposal batch export <file>` | Export a filtered batch `--view queue|digest|blocked|explain` snapshot to JSON or YAML using the shared batch selector flags, including `--urgency` and the stateful `suggested_plan` envelope plus `execution_hints` for `explain`. |
| `iket proposal batch approve` | Batch-approve a filtered proposal queue slice through the shared batch surface, including `--urgency` filtering. |
| `iket proposal batch apply` | Batch-apply a filtered ready proposal queue slice through the shared batch surface, including `--urgency` filtering. |
| `iket proposal batch act` | Unified batch entrypoint for `--action approve|apply|blocked|explain|export`, with `--dry-run` preview support for approve/apply, `--output` for export, and the same selector model including `--urgency`. |
| `iket proposal explain-blocked <id>` | Show a concise blocked diagnosis, primary blocker, and next step for one proposal. |
| `iket proposal show <id>` | Show one stored proposal, including stored config and summary metadata. |
| `iket proposal verify <id>` | Verify proposal integrity, source lineage, and live drift before apply. |
| `iket proposal readiness <id>` | Show whether a proposal is ready to apply and list the current blockers. |
| `iket proposal approve <id>` | Record an approval for a stored proposal without applying it. Supports `--reviewer` and `--review-note`. |
| `iket proposal apply <id>` | Approve and apply a stored proposal. Supports `--reviewer` and `--review-note`. |
| `iket proposal canary status <id>` | Show the current canary rollout selectors, proposal status, and verification summary. |
| `iket proposal canary evaluate <id>` | Evaluate current canary health from recent request logs against configured canary thresholds. |
| `iket proposal canary advance <id>` | Advance an active percentage canary rollout to its next planned `--canary-step`. Supports `--reviewer` and `--review-note`. |
| `iket proposal canary reconcile <id>` | Evaluate an active canary and automatically advance, complete, or roll it back. Supports `--reviewer` and `--review-note`. |
| `iket proposal canary expand <id>` | Expand a planned or active canary rollout with additional `--canary-service`, `--canary-route`, `--canary-header`, or `--canary-percent` selectors. Active canaries also support `--reviewer`, `--review-note`, and canary guard flags. |
| `iket proposal canary complete <id>` | Finish an active canary rollout and apply the full stored proposal. Supports `--reviewer` and `--review-note`. |
| `iket proposal promote <id>` | Clone a stored proposal into the next environment with fresh approvals. Supports `--proposer`, `--env`, `--not-before`, `--canary-service`, `--canary-route`, `--canary-header`, `--canary-percent`, `--canary-step`, and canary guard flags. |
| `iket proposal reject <id>` | Reject a stored proposal without applying it. Supports `--reviewer` and `--review-note`. |

Revision-aware mutating commands can also attach metadata:
- `--label "tenant-rollout"`
- `--note "Enable new identity routes before chat deploy"`
- `--change-ref "CHG-1427"`

Gateway-side enforcement is also available through `security.mutationPolicy`, so non-CLI callers can be held to the same metadata requirements. It can also be scoped to `config`, `services`, `routes`, `plugins`, `clients`, `revisions`, or `high_impact` actions instead of applying to everything. Proposal creation can record `--proposer`, `--env`, and `--not-before`, while `proposal promote` preserves lineage into the next environment and resets approvals. Proposal apply can optionally require a different reviewer, a minimum number of fresh approvals, a scheduled not-before window, promoted-proposal verification, promoted shadow evaluation, a consecutive healthy shadow-verification streak, proposal expiration, or recurring blackout windows for high-impact changes before apply succeeds. Service proposals can also move through a staged canary lifecycle with `proposal canary status`, `evaluate`, `advance`, `reconcile`, `expand`, and `complete`, and canary routes can now be activated either with header matchers like `--canary-header X-Iket-Canary=identity-v2` or deterministic traffic splitting with `--canary-percent 10`. Step-based progression can be declared with repeated `--canary-step` flags such as `10, 25, 50, 100`. Canary proposals can also set rollout guards with `--canary-min-requests`, `--canary-max-error-rate`, and `--canary-max-p95-latency`. `proposal canary reconcile` can use those guardrails to decide the next action automatically, and proposals can enable background progression with `--canary-auto`, `--canary-auto-interval`, and `--canary-auto-reviewer`. When those guards fail during canary advance, reconcile, or completion, Iket automatically restores the pre-canary baseline configuration and marks the proposal as `canary_aborted`.

Proposal queue urgency can also be tuned in `security.mutationPolicy.proposalQueue`, with default thresholds plus per-environment overrides for `readyAgingAfter`, `readyOverdueAfter`, `blockedAgingAfter`, and `blockedOverdueAfter`. That lets `--urgency overdue` mean something stricter in `prod` than in `staging` without changing CLI usage.

`security.mutationPolicy.proposalQueue.notifications` can also run queue-digest notifications automatically in the background with `enabled`, `interval`, `minNotificationInterval`, `onlyOnSLABreach`, `onlyOnChange`, and optional `environments` scoping.

Rollout notifications can be configured through `security.notificationWebhooks`. Matching webhooks receive events like `proposal.approved`, `proposal.applied`, `proposal.promoted`, `proposal.rejected`, `proposal.shadow_ready`, `proposal.canary_started`, `proposal.canary_advanced`, `proposal.canary_completed`, `proposal.canary_aborted`, `proposal.digest`, `proposal.sla_breach`, `proposal.sla_stage_changed`, and `proposal.sla_resolved`. `format` can be `generic`, `slack`, or `teams`. Webhooks can also be filtered by `environments`, and `proposal.sla_breach` deliveries can require a minimum queue size with `minSLABreachCount`, a sustained consecutive breach streak with `minConsecutiveSLABreaches`, a minimum sustained breach age with `minSLABreachDuration`, or a severity floor with `minSLABreachTier` (`warning`, `elevated`, or `critical`). `slaBreachCooldown` adds repeat-suppression per webhook/environment so the same tier does not keep paging, while a higher breach tier can still break through immediately. For limiter incidents, `security.limitAlertBucketClasses` can define reusable tenant or bucket classes, `security.limitAlertProfiles` can define reusable recipient profiles, and a webhook can reference one with `limitAlertProfile` before optionally overriding `minLimitAlertSeverity`, `limitAlertTypes`, `limitAlertKeyTypes`, `limitAlertBucketClasses`, `limitAlertBucketIDRegex`, or `limitAlertCooldown` inline. Route `limitAlertPolicy.bucketPolicies` can also reference those same named classes with `bucketClass` instead of repeating raw `keyType` and `bucketRegex` matchers. `limitAlertCooldown` now suppresses repeats per webhook plus bucket instead of suppressing different hot buckets together. Queue SLA breach, stage-changed, and resolved events now also carry a shared `incident_id` so external systems can correlate one backlog incident across open, escalation, and close notifications. Webhooks can also be HMAC-signed with `signingSecret`, `signatureHeader`, and `timestampHeader`, retried with `retryCount` and `retryBackoff`, and inspected or replayed with `iket notification deliveries`, `iket notification show <id>`, `iket notification replay <id>`, and `iket notification replay-failed`.

Routes can also define multiple weighted backends by repeating `backend` entries with `weight` and optional `host` overrides. `timeout` adds per-backend attempt limits, `retryCount`, `retryBackoff`, `retryJitter`, and `retryStatusCodes` add route-level transient retry policy, and retries now default to idempotent methods unless `retryUnsafeMethods: true` is set. `hedgeDelay` adds request hedging for safe read methods, with `hedgeUnsafeMethods: true` available as an explicit opt-in. `shadowTrafficPercent` mirrors a slice of safe read traffic to an alternate healthy backend for validation, with `shadowUnsafeMethods: true` available as an explicit opt-in. Shadow requests are marked with `X-Iket-Shadow: true`, `iket gateway backends` surfaces per-backend shadow counters and latency comparison data, `iket gateway shadow-report` adds an aggregated service/route view for live-vs-shadow drift analysis, and `iket gateway shadow-evaluate` checks those grouped results against route-level guardrails like `shadowMinRequests`, `shadowMaxErrorRate`, and `shadowMaxLatencyDelta`. `adaptiveLatencyRouting: true` lets Iket bias steady-state traffic toward the faster healthy backend using observed latency EWMA instead of only static weights. `failureThreshold`, `cooldown`, `halfOpenMaxRequests`, and `recoverySuccessThreshold` now drive a configurable half-open circuit-breaker recovery flow. `outlierLatencyThreshold`, `outlierConsecutiveSlowResponses`, and `outlierCooldown` add slow-backend ejection. `healthCheckPath`, `healthInterval`, and `healthTimeout` add active health probing. Routes can also declare a native `rateLimitPolicy` with `requestsPerSecond`, `burst`, `keyBy`, `keyHeader`, and optional `exemptMethods`, which gives Iket first-class keyed rate limiting by `global`, `ip`, `header`, `api_key`, or `jwt_sub` without relying on the older global plugin path. `rateLimitPolicy.classPolicies` can now override those budgets for named bucket classes, so the same tenant catalog used by limiter alerts can also shape live throttling. Routes can also declare a native `concurrencyLimitPolicy` with `maxInFlight`, `keyBy`, `keyHeader`, optional `queueTimeout`, optional `maxQueueDepth`, and optional `exemptMethods`, plus the legacy `concurrent_calls` shorthand for a global cap. That gives Iket first-class in-flight protection by `global`, `ip`, `header`, `api_key`, or `jwt_sub`; `queueTimeout` lets a route wait briefly for capacity instead of always rejecting immediately; `maxQueueDepth` adds an explicit queue-full boundary that returns `503 Service Unavailable` once the wait queue is saturated; and `concurrencyLimitPolicy.classPolicies` can now raise or lower those budgets for the same named bucket classes. `limitAlertPolicy` can now also override limiter incident grouping per route: `groupBy: route` keeps the default route aggregate, while `groupBy: bucket` splits overload alerts and incidents per anonymized limiter bucket so one hot tenant or API key is visible separately. `bucketPolicies` underneath that route policy can then apply stricter `minCount`, `minSeverity`, or per-limit-type thresholds to matching `jwt_sub`, `api_key`, `header`, or `ip` buckets without exposing raw bucket values in alert payloads. Routes can also declare a `cors` block with `allowedOrigins`, `allowedMethods`, `allowedHeaders`, `exposedHeaders`, `allowCredentials`, and `maxAge`; Iket answers browser preflight `OPTIONS` directly and adds CORS headers to actual responses without sending preflight requests upstream. For edge shaping, routes can also define `requestHeaders`, `removeRequestHeaders`, `requestRedactHeaders`, `requestJSONFields`, `removeRequestJSONFields`, `requestRedactJSONFields`, `requestBodyBlockRegex`, `requestBodyRequireRegex`, `requestPIIBlockTypes`, `queryParams`, `removeQueryParams`, `responseHeaders`, `removeResponseHeaders`, `responseJSONFields`, `removeResponseJSONFields`, `successResponseFields`, and `errorResponseFields`. Incoming query strings are preserved by default, then query add/remove transforms are applied before the upstream request is sent. Request and response JSON transforms apply only to top-level JSON object bodies, but their keys may use dot paths like `user.profile.realm`, indexed paths like `users[0].profile.realm`, and append syntax like `meta.tags[]`. Prefix a JSON transform value with `json:` to emit a typed JSON boolean, number, array, or object instead of a string. Add `transformWhenHeaders` / `transformWhenQueryParams` for exact-match gates, or `transformWhenHeaderRegex` / `transformWhenQueryRegex` for regex gates, to apply these edge transforms only to matching traffic. Add `transformMethods` to limit transforms to selected methods like `POST` or `PATCH`. Add `transformScopes` to limit that gating to `request_headers`, `query`, `request_json`, `response_headers`, or `response_json`; if omitted, the gate still applies to every transform on the route for compatibility. Response-side transforms can also be limited to specific statuses with `responseTransformStatusCodes` or `responseTransformStatusClasses` such as `2xx`, `4xx`, or `5xx`, and can also be gated by upstream response headers with `responseTransformWhenHeaders` or `responseTransformHeaderRegex`. `successResponseFields` can normalize backend success bodies into a stable JSON envelope, and `errorResponseFields` can do the same for 4xx/5xx errors. For agent-facing or security-sensitive routes, `requestRedactHeaders`, `requestRedactJSONFields`, `responseRedactHeaders`, `responseRedactJSONFields`, and `redactionValue` can mask secrets before data leaves or returns through the gateway, while `requestBodyBlockRegex` / `requestBodyRequireRegex` and `responseBodyBlockRegex` / `responseBodyRequireRegex` can enforce simple prompt/output content policy in both directions. `requestPIIBlockTypes` and `responsePIIBlockTypes` add named detectors for common sensitive classes like `email`, `phone`, `api_key`, and `card` without writing custom regex per route. Blocked policy responses now also emit `X-Iket-Policy-Hit` with a structured reason such as `request_content_policy`, `response_content_policy`, or `response_pii_policy`, and `iket gateway policy-hits` aggregates those guardrail hits by reason and route. `maxRequestBodyBytes` and `maxResponseBodyBytes` can also cap prompt and output sizes per route. For model-facing JSON APIs, top-level `aiPolicyPresets` can define an organization-wide shared catalog, service blocks can define `aiPolicyPresets` once as a service-local catalog, and routes can still define local `aiPolicyPresets` for closer-to-the-edge overrides. `aiPolicyPresetChain` composes multiple presets left-to-right, then `aiPolicyPreset` resolves one final shorthand layer against that merged catalog with precedence `route > service > global`, and local route fields can still add narrower overrides after that. `iket gateway route-policy` can inspect that resolved preset stack, the effective AI guardrails on the matched route, and which preset or local route field supplied each guardrail. `iket gateway route-policy-diff` can compare two matched routes and list only the differing effective guardrails with each side's value and source layer. Those presets can carry `allowedModels` / `modelField`, `allowedToolNames` / `toolField`, `maxMessages` / `messagesField`, `maxToolCalls` / `toolCallsField`, `maxInputTokens` / `inputTokensField`, `maxOutputTokens` / `outputTokensField`, `allowedUpstreamHosts`, `requiredRequestHeaders` / `requiredRequestHeaderRegex`, plus request and response content/PII policy. On GraphQL routes, `graphqlOperationPresets` can define reusable per-operation policy bundles, and `graphqlOperationPolicies` can reference one before overriding required request header, upstream host, model, tool, conversation, token, and request/response content-policy controls per named operation in addition to the existing variable, persisted-query, and complexity policy. `protocol` can also explicitly mark a route as `http`, `graphql`, `grpc`, or `websocket`, which lets Iket enforce GraphQL-compatible request patterns, `application/grpc` traffic, and websocket upgrade handshakes on a per-route basis. UDP is not proxied by this HTTP listener path. Transform values can interpolate `{{realm}}`, `{{request_id}}`, `{{query.name}}`, `{{var.name}}`, `{{header.Name}}`, and for response-side transforms `{{response_header.Name}}`, `{{response_status}}`, and `{{response_body}}`. The legacy `headers` field still works as a backward-compatible alias for upstream request header injection.

Proposal approvals and rejections can also record reviewer metadata:
- `--reviewer "ops-lead"`
- `--review-note "Approved after staging verification"`

---

## 📜 Logs
Read remote gateway logs.

| Command | Description |
|---------|-------------|
| `iket logs list` | Fetch recent logs from the remote gateway. |
| `iket logs tail` | Stream logs in real time. If SSE streaming is unavailable, it automatically falls back to polling recent logs. Both commands support `--service`, `--route`, and `--request-id` filters. |
| `iket logs trace` | Find a recent `request_id`, print a compact request summary, and follow only that request's logs. Supports `--service` and `--route` to narrow discovery. |

---

## 👥 Client & API Key Management
Manage client applications and their access permissions dynamically.

| Command | Description |
|---------|-------------|
| `iket client list` | List all registered client apps. |
| `iket client add <id>` | Register a new client (requires `--key`, supports `--group`, `--scopes`, `--name`). |
| `iket client delete <key>` | Remove a client app by its API key. |

---

## 🔐 Security & Safety

### Strict Mode
Enabled per context to prevent accidental changes in Production.
- **Trigger**: Any command that modifies state (create, set, delete, push, etc.).
- **Action**: Prompts for a manual `y/N` confirmation.
- **Revision metadata**: In strict contexts, mutating commands require `--label`, and high-impact commands like `--replace`, `delete`, `disable`, and `restore` also require both `--note` and `--change-ref` unless you use `--force`.
- **Bypass**: Use the global `--force` or `-f` flag for automation.

### mTLS Management
| Command | Description |
|---------|-------------|
| `iket cert status` | Check status of local certificates. |
| `iket cert gen` | Generate a new mTLS certificate chain (CA, Server, Client). |
| `iket cert regenerate-server` | Regenerate `server.crt` and `server.key` from the local CA using SANs from `--config` or explicit `--server-hostname` / `--server-name` / `--server-ip` flags. |
| `iket cert import` | Import `ca.crt`, `client.crt`, and `client.key` into a managed CLI context. The `--cert-dir` path must point at the source bundle you want to import, such as the server's copied Docker `certs/` directory, not just any existing `~/.iket/certs` folder. Hostname/SAN mismatch errors now include a hint to update `security.tls.serverNames` / `serverIPs`. |

`iket-cli` still works as a compatibility alias, but `iket` is now the primary client command. `iket-server` is the gateway binary.

---

## 💡 Global Flags
Applied to any command:
- `-f, --force`: Bypass Strict Mode confirmations.
- `--help`: View detailed help for any subcommand.
