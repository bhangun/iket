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

The generated Docker scaffold also runs the container with the host UID/GID by default. That is important because Iket auto-generates certs and writes SQLite/log files into mounted host directories, and the container user must be able to write to those paths.

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
    autoGenerate: true
    generateSharedClient: false
  enableBasicAuth: true
  basicAuthUsers:
    admin: "change-this-password"

storage:
  mode: "sqlite"
  sqlite_path: "/app/.iket-admin/sqlite/iket.db"
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

The normal first bootstrap flow is:
1. start the server
2. wait for `ca.*` and `server.*` to appear in `./certs`
3. on the trusted server host, run `iket setup docker --cert-dir ./certs --url https://<server-ip>:8443`

`iket setup docker` is intentionally a trusted-host bootstrap path. If `client.crt` / `client.key` are not present, it will mint a local admin client certificate from the server CA and store it in the caller's managed CLI context instead of leaving a reusable shared admin key in the server cert directory.

Enrollment tokens are the follow-up path for additional admin machines, not the first bootstrap step for a fresh server.

If the certs do not appear, check `.env` and confirm the container is running with the correct:
- `IKET_UID`
- `IKET_GID`

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
```

`server doctor --mode docker` now also checks:
- container health/status via Docker
- local reachability of the published HTTP, admin TLS, and enrollment TLS ports
- TLS handshakes against the generated CA when possible

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
- `.iket-admin/sqlite/`

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
# Export local services to remote (merge existing)
iket push services local_service.yaml --strategy merge

# Replace remote services with local definition
iket push services local_service.yaml --strategy replace

# Pull remote config to local file
iket pull config my_config.yaml

# Pull remote services to local file in JSON format
iket pull services current_services.json --format json
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
