# 🧶 Iket Installation Guide

## Quick Install

### Linux/macOS (Recommended)

Get up and running in seconds with our ultimate installer:

**Full Gateway Setup:**
```bash
curl -fsSL https://raw.githubusercontent.com/bhangun/iket/main/scripts/install.sh | bash
```

**CLI Only (for remote administration):**
```bash
curl -fsSL https://raw.githubusercontent.com/bhangun/iket/main/scripts/install.sh | bash -s -- --cli-only
```

**From Source (optional):**
```bash
curl -fsSL https://raw.githubusercontent.com/bhangun/iket/main/scripts/install.sh | bash -s -- --from-source
```

Prebuilt release assets are published for:
- `iket` client: Linux, macOS, and Windows
- `iket-server`: Linux, macOS, and Windows

This script automates everything for you:
*   **Auto-Dependency Check**: Detects and installs only the tools needed for the selected mode.
*   **Platform Detection**: Auto-detects Linux (Debian, Ubuntu, Fedora, RHEL, CentOS, Arch) or macOS.
*   **Prebuilt by Default**: Downloads the latest released `iket-server` and `iket` binaries.
*   **Source Preparation**: Clones the latest code from GitHub only when `--from-source` is used.
*   **Building**: Compiles `iket-server` and `iket` only in `--from-source` mode.
*   **Installation**: Moves binaries to `/usr/local/bin`.
*   **Security (mTLS)**: Generates CA, Server, and Client certificates in `~/.iket/certs` (Full mode only).
*   **Configuration**: Creates default `config.yaml` and `cli-config.yaml`.
*   **Persistence**: Configures and enables a systemd service (Full mode, Linux only).

---

## Installation Modes

### 1. Full Gateway Setup (Default)
Installs the Iket Gateway server, the CLI tool, generates certificates, and sets up a system service. Use this on the machine that will act as your API Gateway.

### 2. CLI-Only Setup (`--cli-only`)
Installs only the `iket` client binary and creates the configuration directory. Use this on your local machine or admin workstation to manage a remote Iket Gateway. By default this mode downloads a prebuilt binary and does not require Go.

### 3. Source Build Setup (`--from-source`)
Uses the local toolchain to clone and build from source. Use this if you are contributing, testing unreleased changes, or explicitly do not want prebuilt release binaries.

---

## Platform-Specific Notes

### Ubuntu / Debian / Linux Mint
The installer uses `apt-get` to automatically install requirements.
```bash
curl -fsSL https://raw.githubusercontent.com/bhangun/iket/main/scripts/install.sh | bash
```

### Fedora / RHEL / CentOS
The installer uses `dnf` or `yum` to automatically install requirements.
```bash
curl -fsSL https://raw.githubusercontent.com/bhangun/iket/main/scripts/install.sh | bash
```

### Arch Linux
The installer uses `pacman` to automatically install requirements.
```bash
curl -fsSL https://raw.githubusercontent.com/bhangun/iket/main/scripts/install.sh | bash
```

### macOS
The installer uses `Homebrew` to automatically install requirements.
```bash
curl -fsSL https://raw.githubusercontent.com/bhangun/iket/main/scripts/install.sh | bash
```

---

## Manual Installation

### From Source

If you prefer to install manually or don't have internet access on the target machine:

```bash
# Prerequisites: Go 1.23+, Make, OpenSSL
git clone https://github.com/bhangun/iket.git
cd iket

# Build binaries
make build
make build-cli

# Install to /usr/local/bin
sudo install -m 755 bin/iket-server /usr/local/bin/
sudo install -m 755 bin/iket /usr/local/bin/

# Generate initial certificates
./bin/iket cert gen --cert-dir ~/.iket/certs
```

## 🐳 Remote Docker Installation

To run Iket on a remote server using Docker, you do not need the source repository. The recommended path is the prebuilt image.

### 1. Deploy to Remote Server With Prebuilt Image
On the remote server:

```bash
mkdir -p ~/iket-docker/{config,certs,logs}
cd ~/iket-docker
```

If you already have `iket` available on the remote server, the quickest way is:

```bash
iket server init --mode docker --output ~/iket-docker --with-systemd
cd ~/iket-docker
docker compose up -d
iket server doctor --mode docker --output ~/iket-docker
```

This generates the same compose/config scaffold automatically, plus:
- `.env` for image and port overrides
- `config/service.yaml` for service and route definitions
- `iket-docker.service` if `--with-systemd` is used

The generated Docker scaffold also runs the container with the host UID/GID by default. That is important because Iket auto-generates certs and writes cert/log files into mounted host directories, and the container user must be able to write to those paths.

Create `docker-compose.yaml`:

```yaml
version: "3.8"

services:
  iket:
    image: bhangun/iket:latest
    container_name: iket
    restart: unless-stopped
    user: "${IKET_UID:-1000}:${IKET_GID:-1000}"
    ports:
      - "7100:8080"
      - "8443:8443"
      - "9443:9443"
    environment:
      - TZ=UTC
      - IKET_CERTS_DIR=/app/certs
    volumes:
      - ./config:/app/config:ro
      - ./certs:/app/certs:rw
      - ./logs:/app/logs:rw
```

Create `config/config.yaml`:

```yaml
server:
  port: 8080
  readTimeout: "10s"
  writeTimeout: "10s"
  idleTimeout: "60s"
  enableLogging: true

security:
  tls:
    enabled: true
    port: 8443
    enrollmentPort: 9443
    enrollmentMaxActive: 10
    certFile: "/app/certs/server.crt"
    keyFile: "/app/certs/server.key"
    clientCAFile: "/app/certs/ca.crt"
    clientAuthType: "RequireAndVerifyClientCert"
    minVersion: "TLS1.2"
    serverNames: ["localhost", "iket"]
    serverIPs: ["127.0.0.1"]
    autoGenerate: true
    generateSharedClient: false
  enableBasicAuth: true
  basicAuthUsers:
    admin: "change-this-password"
  mutationPolicy:
    enabled: false
    enforcedScopes: ["all"]
    requireLabel: true
    requireNoteForHighImpact: true
    requireChangeRefForHighImpact: true
    requireDifferentReviewerForProposals: false
    minApproversForHighImpactProposals: 0
    requireNotBeforeForHighImpactProposals: false
    requireVerificationForPromotedHighImpactProposals: false
    maxProposalAge: ""
    maxApprovalAge: ""
    blockedApplyWindows: []

storage:
  mode: "postgres"
  postgres_url: "${IKET_POSTGRES_URL:-postgres://iket:iket@postgres:5432/iket?sslmode=disable}"
  mirror_files: true
```

Then start the container:

```bash
docker compose up -d
```

On first start, Iket will auto-generate the TLS assets in `./certs` if they do not exist yet:
- `ca.crt`
- `ca.key`
- `server.crt`
- `server.key`

These are generated in the server-side Docker cert volume, not automatically in the CLI's `~/.iket/certs`. For example, if your deployment folder is `~/iket-docker`, the generated files are written to `~/iket-docker/certs/`.

For remote administration, make sure the auto-generated server certificate includes the real hostname or IP that your laptop will use. Add them before first boot or before regenerating `server.crt`:

```yaml
security:
  tls:
    serverNames: ["localhost", "iket", "gateway.example.com"]
    serverIPs: ["127.0.0.1", "103.16.199.4"]
```

If the configured SANs change later, Iket now regenerates `server.crt` automatically on startup to match them.

If you want the gateway itself to enforce change metadata for all API clients, not just the `iket` CLI, enable the mutation policy:

```yaml
security:
  mutationPolicy:
    enabled: true
    enforcedScopes: ["config", "services", "high_impact"]
    requireLabel: true
    requireNoteForHighImpact: true
    requireChangeRefForHighImpact: true
    requireDifferentReviewerForProposals: true
    minApproversForHighImpactProposals: 2
    requireNotBeforeForHighImpactProposals: true
    requireVerificationForPromotedHighImpactProposals: true
    maxProposalAge: "72h"
    maxApprovalAge: "12h"
    blockedApplyWindows:
      - name: "weekend-freeze"
        days: ["sat", "sun"]
        start: "00:00"
        end: "06:00"
        timezone: "Asia/Jakarta"
        scopes: ["high_impact"]
```

With that enabled, high-impact admin mutations such as replace, delete, disable, and revision restore will be rejected unless the caller includes the required revision metadata.
The supported scopes are `all`, `config`, `services`, `routes`, `plugins`, `clients`, `revisions`, and `high_impact`. When `requireDifferentReviewerForProposals: true`, the same `--proposer` identity cannot also be used as the `--reviewer` when approving, applying, or rejecting a proposal. When `minApproversForHighImpactProposals` is greater than zero, high-impact proposals must accumulate that many distinct approvals before `iket proposal apply` will succeed. When `requireNotBeforeForHighImpactProposals: true`, high-impact proposals must also carry a `--not-before` RFC3339 timestamp, and apply will be blocked until that time arrives. `requireVerificationForPromotedHighImpactProposals: true` blocks apply for promoted high-impact proposals unless lineage verification still passes. `maxProposalAge` expires old proposals entirely, while `maxApprovalAge` only counts still-fresh approvals toward the apply threshold. `blockedApplyWindows` adds recurring blackout periods with weekday names, `HH:MM` ranges, an IANA timezone, and optional scopes; if scopes are omitted, the blackout defaults to high-impact proposal apply only.

The normal first bootstrap flow is:
1. start the server
2. wait for `ca.*` and `server.*` to appear in `./certs`
3. on the trusted server host, run `iket setup docker --cert-dir ./certs --url https://<server-ip>:8443`

`iket setup docker` is intentionally a trusted-host bootstrap path. If `client.crt` / `client.key` are not present, it will mint a local admin client certificate from the server CA and store it in the caller's managed CLI context instead of leaving a reusable shared admin key in the server cert directory.

Enrollment tokens are the follow-up path for additional admin machines, not the first bootstrap step for a fresh server.

If the certs do not appear, check `.env` and confirm the container is running with the correct:
- `IKET_UID`
- `IKET_GID`

The generated Docker stack also includes an internal `postgres` service for Iket itself. It is only reachable on the Docker network by default, so it does not consume a host PostgreSQL port unless you choose to publish one yourself.

If startup fails with:

```text
failed to prepare bootstrap TLS assets from /app/config/config.yaml: open /app/certs/ca.key: permission denied
```

that means the host-mounted `./certs` directory is not writable by the container user. This commonly happens if:
- `docker compose` was run with `sudo` and created root-owned files
- `IKET_UID` / `IKET_GID` in `.env` do not match the intended host user
- stale root-owned files already exist in `certs/` or `logs/`

Recommended recovery:

```bash
cd ~/iket-docker
grep '^IKET_UID=' .env
grep '^IKET_GID=' .env
id -u
id -g

sudo rm -f certs/ca.crt certs/ca.key certs/server.crt certs/server.key certs/client.crt certs/client.key
sudo chown -R $(id -u):$(id -g) certs logs
sudo chmod 700 certs
sudo chmod 755 logs
sudo chmod -R u+rwX certs logs

docker compose up -d --force-recreate
docker logs iket --tail 100
```

Prefer running `docker compose` as the same user that owns the deployment folder whenever possible.

If the error still persists after the quick recovery, treat it as a bind-mounted filesystem ownership mismatch on `certs/` rather than a database problem. The usual clues are:
- Postgres is healthy
- Iket reaches early startup
- the failure is exactly on creating `/app/certs/ca.key`

Most likely causes:
- `certs/ca.key` already exists and is not writable
- `certs/` is owned correctly now, but files inside it are still root-owned or too restrictive
- `.env` has `IKET_UID` / `IKET_GID` that do not match the host directory owner
- the container is running as a different UID/GID than you expect

Run these checks:

```bash
cd /home/bhangun/Infra/Iket

cat .env
ls -ld certs logs
ls -la certs
docker inspect iket --format '{{.Config.User}}'
docker compose config | grep -A3 'user:'
```

Then apply the practical cleanup:

```bash
cd /home/bhangun/Infra/Iket

sudo rm -f certs/ca.crt certs/ca.key certs/server.crt certs/server.key certs/client.crt certs/client.key
sudo chown -R $(id -u):$(id -g) certs logs
sudo chmod 700 certs
sudo chmod 755 logs
sudo chmod -R u+rwX certs logs
```

Also confirm `.env` matches your actual host user:

```bash
cd /home/bhangun/Infra/Iket
grep '^IKET_UID=' .env
grep '^IKET_GID=' .env
id -u
id -g
```

If they do not match, correct them:

```bash
sed -i "s/^IKET_UID=.*/IKET_UID=$(id -u)/" .env
sed -i "s/^IKET_GID=.*/IKET_GID=$(id -g)/" .env
```

Then recreate the stack:

```bash
sudo docker compose -f /home/bhangun/Infra/Iket/docker-compose.yaml down
sudo docker compose -f /home/bhangun/Infra/Iket/docker-compose.yaml up -d --force-recreate
docker logs --tail 100 iket
ls -la /home/bhangun/Infra/Iket/certs
```

If it still fails, the next most useful outputs are:

```bash
cd /home/bhangun/Infra/Iket
cat .env
ls -ld certs
ls -la certs
docker inspect iket --format '{{.Config.User}}'
```

Those will usually pinpoint whether the remaining problem is:
- wrong UID/GID inside the container
- stale root-owned files
- directory mode still blocking writes

### 1b. Repo-Based Docker Compose
If you do have the repository checked out on the remote server, you can also use the bundled compose files:

```bash
docker compose -f docker/docker-compose.prebuilt.yaml up -d
```

There are also ready-to-copy example files in the repo root:
- `docker-compose.prebuilt.example.yaml`
- `config.prebuilt.example.yaml`
- `.env.prebuilt.example`
- `iket-docker.service.example`

If you generated a systemd unit with `iket server init --mode docker --with-systemd`, install it with:

```bash
sudo cp ~/iket-docker/iket-docker.service /etc/systemd/system/iket-docker.service
sudo systemctl daemon-reload
sudo systemctl enable --now iket-docker
```

You can re-check the deployment scaffold and local runtime state at any time with:

```bash
iket server doctor --mode docker --output ~/iket-docker
iket server doctor --mode docker --output ~/iket-docker --context remote-prod
iket server doctor --mode docker --output ~/iket-docker --url https://103.16.199.4:8443
```

`server doctor --mode docker` now also checks:
- `certs/` and `logs/` ownership against `IKET_UID` / `IKET_GID`
- container health/status via Docker
- local reachability of the published HTTP, admin TLS, and enrollment TLS ports
- TLS handshakes against the generated CA when possible
- whether the generated `server.crt` SANs actually cover the configured `security.tls.serverNames` / `serverIPs`
- whether the generated `server.crt` covers a real target admin URL when `--url` is provided

## 🖥️ Host Installation Scaffold

For a host-native deployment without Docker:

```bash
iket server init --mode host --output ~/iket-host --with-systemd
iket-server --config ~/iket-host/config/config.yaml
iket server doctor --mode host --output ~/iket-host
```

This scaffold creates:
- `config/config.yaml`
- `config/service.yaml`
- `.env` if enabled
- `iket.service` if `--with-systemd` is used
- `certs/`
- `logs/`
- PostgreSQL connection defaults via `.env`

If you generated a systemd unit for host mode, install it with:

```bash
sudo cp ~/iket-host/iket.service /etc/systemd/system/iket.service
sudo systemctl daemon-reload
sudo systemctl enable --now iket
```

`server doctor --mode host` checks:
- required scaffold files and directories
- local port reachability from the generated config
- TLS handshakes against the generated CA when possible
- `iket-server` binary presence in `PATH`
- optional CLI context verification

Both scaffold modes now start Iket with `--config ... --services ...`, so `service.yaml` is active from first boot and file mirroring remains consistent when SQLite is the primary store.

### 2. Bootstrap CLI Access
The default and recommended config is:

```yaml
security:
  tls:
    autoGenerate: true
    generateSharedClient: false
```

That means Iket generates only `ca.*` and `server.*` on first boot. How you get a client cert depends on your admin scenario:

Option 1: Trusted server host bootstrap

Use this for the first admin on the same host that runs Iket. `iket setup docker` reads the trusted local server cert directory and mints or imports a client cert into the caller's local CLI context.

```bash
iket setup docker --cert-dir ./certs --url https://<server-ip>:8443
```

The client credentials created or imported by this command are then stored in the local CLI-managed directory, usually:

```bash
~/.iket/certs/contexts/<context-name>/
```

Option 2: Shared client bundle compatibility mode

Use this only if you explicitly set `generateSharedClient: true`, or if you already manage a dedicated reusable client bundle yourself.

```yaml
security:
  tls:
    autoGenerate: true
    generateSharedClient: true
```

Then you can import that bundle into a named context:

```bash
iket cert import --name remote-prod --cert-dir ./certs --url https://<server-ip>:8443
```

Important:
- `./certs` in that example means the server deployment's Docker cert directory.
- `~/.iket/certs` is the local CLI-managed certificate store on your laptop or workstation.
- If you run `iket cert import --cert-dir ~/.iket/certs ...`, you are importing from your local machine's existing files, not directly from the remote Docker host.

When `generateSharedClient: true` is enabled, Iket writes the shared client bundle into the same server-side Docker cert directory:
- `./certs/client.crt`
- `./certs/client.key`

If you first booted with `generateSharedClient: false` and later changed it to `true`, restart or recreate Iket after upgrading to a version that includes the shared-client regeneration fix, then confirm those two files appear.

If the Docker cert volume is only present on the remote server, copy only the client bundle files you intend to use:

```bash
mkdir -p ~/.iket/certs/remote-prod
scp <user>@<server-ip>:~/iket-docker/certs/ca.crt ~/.iket/certs/remote-prod/
scp <user>@<server-ip>:~/iket-docker/certs/client.crt ~/.iket/certs/remote-prod/
scp <user>@<server-ip>:~/iket-docker/certs/client.key ~/.iket/certs/remote-prod/
```

Then import them:

```bash
iket cert import \
  --name remote-prod \
  --url https://<server-ip>:8443 \
  --cert-dir ~/.iket/certs/remote-prod
```

Use `https://` for port `8443`. `http://<server-ip>:8443` is invalid because that port serves TLS.

If `iket cert import` fails with an error like:

```text
x509: certificate is valid for 127.0.0.1, not 103.16.199.4
```

the server certificate does not include the remote IP or hostname in its SANs yet. Update `serverNames` / `serverIPs` in `config/config.yaml`, then recreate the server so Iket regenerates `server.crt`.

Newer `iket cert import` builds also attach a direct hint to that verification error so the fix is easier to spot.

Example:

```yaml
security:
  tls:
    serverNames: ["localhost", "iket"]
    serverIPs: ["127.0.0.1", "103.16.199.4"]
```

Then on the server:

```bash
cd ~/iket-docker
docker compose up -d --force-recreate
ls -la certs
```

After that, re-copy or re-import the fresh `ca.crt`, `client.crt`, and `client.key` before testing from your laptop again.

If you want a deterministic operator workflow instead of relying on auto-regeneration, run this on the trusted server host:

```bash
cd ~/iket-docker
iket cert regenerate-server --config ./config/config.yaml --cert-dir ./certs --ca-dir ./certs
docker compose up -d --force-recreate
```

That explicitly rebuilds `server.crt` and `server.key` from the local CA using the SANs from `security.tls.serverNames` / `serverIPs`.

Option 3: Enrollment for additional remote admins

This is the preferred path for extra laptops or admin machines after the first admin already has access.

Create a short-lived enrollment token on an already-admin-capable machine:

```bash
iket enroll create-token --name laptop-admin --out ./enroll.json
```

Then move only that token bundle to the target machine and redeem it there:

```bash
iket enroll use --file ./enroll.json --name remote-prod
```

Quick checks when the cert location feels unclear:

```bash
# Server-side cert volume
ls -la ./certs

# Inside the running container
docker exec iket ls -la /app/certs
```

If you need to confirm the generated server certificate contains the expected remote IP or hostname:

```bash
openssl x509 -in ./certs/server.crt -noout -text | grep -A2 "Subject Alternative Name"
```

Expected files by mode:
- default secure mode: `ca.crt`, `ca.key`, `server.crt`, `server.key`
- shared client compatibility mode: the files above plus `client.crt`, `client.key`

To inspect or revoke bootstrap tokens from the admin-capable machine:

```bash
iket enroll list-tokens
iket enroll revoke-token <token-id>
```

Do not copy `ca.key` off the trusted server host. Prefer Option 1 for the first local admin and Option 3 for additional remote admins. Option 2 exists mainly for compatibility or explicitly managed shared-client environments.

This enrollment flow requires Iket to have access to its local CA signing key, which is the default when certificates are auto-generated and managed by Iket itself.
The bootstrap exchange now runs on the dedicated HTTPS enrollment port (`9443` by default), separate from the main mTLS admin port (`8443`).

### 4. Verify Remote Access
```bash
iket context use remote-prod
iket context test
iket gateway status
```

---

## Post-Installation Setup

### 1. Verify Installation

```bash
# Check binaries are installed
which iket iket-server

# Check versions
iket --version
iket-server --version
```

### 2. Start Gateway Service

#### Option A: Using systemd (Linux)

The installation script creates a systemd service file automatically:

```bash
# Start service
sudo systemctl start iket

# Check status
sudo systemctl status iket

# View logs
sudo journalctl -u iket -f
```

#### Option B: Manual Start

```bash
# Start Gateway with default config
iket-server --config ~/.iket/config.yaml
```

---

## Configuration

### Directory Structure

After installation, configuration and certificates are located in `~/.iket/`:

```
~/.iket/
├── config.yaml          # Gateway Server configuration
├── cli-config.yaml      # Iket CLI Context configuration (active profiles)
└── certs/               # mTLS certificates
    ├── ca.crt
    ├── server.crt
    └── client.crt
```

---

## Administration with `iket`

Once the gateway is running, use the CLI for remote control. The CLI uses a **Context** system to manage different environments.

### 1. Guided Setup
The easiest way to configure a new connection is using the `setup` command:
```bash
iket setup
```

### 2. Context Management
Manage multiple server profiles (Local, Docker, Production):
```bash
# List all configured contexts
iket context list

# Add a new context manually
iket context add prod --url https://api.example.com:8443 --ca ~/.iket/certs/ca.crt

# Switch the active context
iket context use prod
```

### 4. Multi-Environment Scenario
The Context system is designed to handle complex setups across Local, Docker, and Remote environments seamlessly.

#### Strict Mode: Preventing Accidents in Production
For critical environments (like Production), you can enable **Strict Mode**. This requires manual confirmation (`y/N`) for any state-changing commands (updates, deletes, enables/disables).

```bash
# Add a production context with strict mode enabled
iket context add prod --url https://api.iket.io:8443 --strict

# Any dangerous command will now prompt for confirmation
iket plugin disable ratelimit
# Output: ⚠️ STRICT MODE ENABLED for context "prod"
# Are you sure you want to proceed? (y/N):

# Bypass confirmation for automated scripts
iket plugin disable ratelimit --force
```

#### Configuration Sync (Push/Pull)
Maintain your configuration locally in Git and sync it to your gateways.

```bash
# Merge local gateway config into remote
iket config apply local_config.yaml --merge

# Replace the full remote gateway config
iket config apply local_config.yaml --replace

# Preview the remote gateway changes before applying them
iket config diff local_config.yaml --merge

# Attach human metadata to the recorded revision when you actually apply it
iket config apply local_config.yaml --merge --label "prod-rollout" --note "Switch tenant routes and TLS bootstrap settings" --change-ref "CHG-9001"

# Merge local services into remote
iket service apply local_service.yaml --merge

# Replace the full remote services set
iket service apply local_service.yaml --replace

# Preview the remote service changes before applying them
iket service diff local_service.yaml --replace

# Create a pending proposal first, then approve it later
iket service propose local_service.yaml --replace --proposer "deploy-bot" --env "staging" --not-before "2026-05-18T02:00:00Z" --canary-service "identity" --canary-header "X-Iket-Canary=identity-v2" --label "tenant-cutover" --note "Queue full service replacement for approval" --change-ref "CHG-9003"
iket proposal list
iket proposal approve prp-20260517-101530.123 --reviewer "ops-lead" --review-note "Approved after staging verification"
iket proposal promote prp-20260517-101530.123 --proposer "platform-admin" --env "prod" --not-before "2026-05-19T02:00:00Z" --canary-route "identity:/auth/{rest:.*}" --canary-percent 10 --canary-step 10 --canary-step 25 --canary-step 50 --canary-step 100 --canary-min-requests 50 --canary-max-error-rate 0.02 --canary-max-p95-latency 400ms
iket proposal verify prp-20260519-020000.123
iket proposal apply prp-20260519-020000.123 --reviewer "platform-admin" --review-note "Final apply approval"
iket proposal canary status prp-20260519-020000.123
iket proposal canary evaluate prp-20260519-020000.123
iket proposal canary advance prp-20260519-020000.123 --reviewer "platform-admin" --review-note "Canary healthy, move to next step"
iket proposal canary reconcile prp-20260519-020000.123 --reviewer "platform-admin" --review-note "Evaluate and take the next rollout action automatically"
iket proposal canary expand prp-20260519-020000.123 --reviewer "platform-admin" --canary-service "billing" --canary-percent 25
iket proposal canary complete prp-20260519-020000.123 --reviewer "platform-admin" --review-note "Canary healthy, finish rollout"
iket service propose ./config/service.yaml --replace --canary-service "identity" --canary-percent 10 --canary-step 10 --canary-step 25 --canary-step 50 --canary-step 100 --canary-auto --canary-auto-interval 30s --canary-auto-reviewer "canary-controller"

# proposal canary reconcile can evaluate the active canary and then advance, complete, or roll it back automatically.
# canary-auto can let the gateway perform that reconcile loop in the background at the chosen interval.
# If canary guards fail during advance, reconcile, or completion, Iket now restores the pre-canary baseline automatically
# and marks the proposal as canary_aborted.

# security.notificationWebhooks can push rollout events to external systems.
# Events include proposal.approved, proposal.applied, proposal.promoted, proposal.rejected,
# proposal.canary_started, proposal.canary_advanced, proposal.canary_completed, and proposal.canary_aborted.
# notificationWebhooks also support format: generic, slack, or teams.
# Webhooks can also be HMAC-signed with signingSecret, signatureHeader, and timestampHeader,
# retried with retryCount and retryBackoff, and later inspected or replayed with
# iket notification deliveries / show / replay / replay-failed.

# Service routes can also define multiple weighted backends. Each backend can keep
# its own url_pattern and optionally override the upstream host:
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
# retryUnsafeMethods: false
# hedgeDelay: "20ms"
# hedgeUnsafeMethods: false
# adaptiveLatencyRouting: true
# shadowTrafficPercent: 10
# shadowUnsafeMethods: false
# cooldown now feeds a configurable half-open circuit recovery flow too:
# after the cooldown expires, up to halfOpenMaxRequests can probe the backend,
# and recoverySuccessThreshold controls how many successes are required
# before reopening the backend to full traffic again.
# Repeated slow responses can also eject a backend even when it is not hard-failing,
# using outlierLatencyThreshold, outlierConsecutiveSlowResponses, and outlierCooldown.

# Preview targeted admin changes before applying them
iket plugin diff-config rate_limit ./plugin-rate-limit.yaml
iket route diff-update route-abc123 ./route-update.yaml

# Inspect and restore recorded config revisions
iket revision list
iket revision show rev-20260517-101530.123
iket revision diff rev-20260517-101530.123 current
iket revision restore rev-20260517-101530.123

# In strict contexts, high-impact changes should include both label and note
iket service apply local_service.yaml --replace --label "tenant-cutover" --note "Replace remote routes after maintenance window starts" --change-ref "CHG-9002"

# Pull remote config to local file
iket pull config my_config.yaml

# Pull remote services to local file in JSON format
iket pull services current_services.json --format json
```

For log following, `iket logs tail` now prefers live SSE streaming and automatically falls back to polling when streaming is unavailable:

```bash
iket logs tail
iket logs tail --poll-interval 5s
iket logs tail --service identity --route /jahsy/auth/{rest:.*}
iket logs list --request-id 4a92f0c8f0db4e70
iket logs trace --service identity
# prints a one-line request summary before following
```

#### Recommended Directory Structure for Certificates
```bash
~/.iket/certs/
├── staging/          # Remote Staging (Host)
│   ├── ca.crt
│   ├── client.crt
│   └── client.key
└── prod/             # Remote Production (Docker)
    ├── ca.crt
    ├── client.crt
    └── client.key
```

#### Example: Setting up 4 Environments
```bash
# 1. Local Host (Direct)
iket context add local --url http://localhost:8080

# 2. Local Docker (via mapped port)
iket context add docker --url http://localhost:7100

# 3. Remote Staging (on Host with mTLS)
iket context add staging \
  --url https://staging.iket.io:8443 \
  --ca ~/.iket/certs/staging/ca.crt \
  --cert ~/.iket/certs/staging/client.crt \
  --key ~/.iket/certs/staging/client.key

# 4. Remote Production (in Docker with mTLS)
iket context add prod \
  --url https://api.iket.io:8443 \
  --ca ~/.iket/certs/prod/ca.crt \
  --cert ~/.iket/certs/prod/client.crt \
  --key ~/.iket/certs/prod/client.key
```

#### Switching Environments
```bash
# Check staging status
iket context use staging
iket gateway status

# Switch to production
iket context use prod
iket gateway status
```

---

## Remote Administration (Client Setup)

To manage an Iket Gateway from your local computer or a different admin machine:

### 1. Install `iket` on Client Machine
Run the installer with the `--cli-only` flag:
```bash
curl -fsSL https://raw.githubusercontent.com/bhangun/iket/main/scripts/install.sh | bash -s -- --cli-only
```

### 2. Copy Certificates from Server (if using mTLS)
The CLI needs the client certificates generated on the server.

**On Client Machine:**
```bash
mkdir -p ~/.iket/certs
# Copy from server
scp <user>@<server-ip>:~/.iket/certs/{ca.crt,client.crt,client.key} ~/.iket/certs/
```

### 3. Configure CLI via Setup
Run the setup wizard on your client machine:
```bash
iket setup
```
*   **Name**: `prod` or `remote`
*   **URL**: `https://<server-ip>:8443`
*   **mTLS**: `y`
*   **Paths**: Provide absolute paths to the certificates copied in step 2.

### 4. Verify Connection
```bash
iket gateway status
```

---

## Uninstallation

### Linux/macOS

```bash
# Safe default: remove binaries/service, keep ~/.iket state
curl -fsSL https://raw.githubusercontent.com/bhangun/iket/main/scripts/uninstall.sh | bash
```

```bash
# Remove binaries/service and create a backup archive first
curl -fsSL https://raw.githubusercontent.com/bhangun/iket/main/scripts/uninstall.sh | bash -s -- --backup
```

```bash
# Full removal: backup first, then remove ~/.iket state too
curl -fsSL https://raw.githubusercontent.com/bhangun/iket/main/scripts/uninstall.sh | bash -s -- --backup --purge-state
```

```bash
# Preview what would happen without changing anything
curl -fsSL https://raw.githubusercontent.com/bhangun/iket/main/scripts/uninstall.sh | bash -s -- --dry-run
```

The uninstall script removes:
- `/usr/local/bin/iket`
- `/usr/local/bin/iket-cli`
- `/usr/local/bin/iket-server`
- `/usr/local/bin/iket-gateway`
- `/etc/systemd/system/iket.service` when present

By default it keeps `~/.iket` so your config, SQLite state, certs, backups, and CLI contexts remain available unless you explicitly pass `--purge-state`.

If you already have the repo checked out, you can run it directly:
```bash
./scripts/uninstall.sh --backup --purge-state
```

---

## Troubleshooting

### Certificate Errors

If `iket` cannot connect due to certificate issues:
1. Ensure `ca.crt` in `cli-config.yaml` matches the one used by the server.
2. Verify the server is running with `clientAuthType: "RequireAndVerifyClientCert"`.
3. Check certificate expiry: `iket cert status`.

### Port Already in Use

```bash
# Check what's using port 8080
sudo lsof -i :8080

# Kill the process
sudo kill -9 <PID>
```
