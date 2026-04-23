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

This script automates everything for you:
*   **Auto-Dependency Check**: Detects and installs missing tools (`git`, `go`, `make`, `openssl`).
*   **Platform Detection**: Auto-detects Linux (Debian, Ubuntu, Fedora, RHEL, CentOS, Arch) or macOS.
*   **Source Preparation**: Clones the latest code from GitHub.
*   **Building**: Compiles `iket` and `iket-cli` (or just `iket-cli` in CLI mode).
*   **Installation**: Moves binaries to `/usr/local/bin`.
*   **Security (mTLS)**: Generates CA, Server, and Client certificates in `~/.iket/certs` (Full mode only).
*   **Configuration**: Creates default `config.yaml` and `cli-config.yaml`.
*   **Persistence**: Configures and enables a systemd service (Full mode, Linux only).

---

## Installation Modes

### 1. Full Gateway Setup (Default)
Installs the Iket Gateway server, the CLI tool, generates certificates, and sets up a system service. Use this on the machine that will act as your API Gateway.

### 2. CLI-Only Setup (`--cli-only`)
Installs only the `iket-cli` binary and creates the configuration directory. Use this on your local machine or admin workstation to manage a remote Iket Gateway.

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
sudo install -m 755 bin/iket /usr/local/bin/
sudo install -m 755 bin/iket-cli /usr/local/bin/

# Generate initial certificates
./bin/iket-cli cert gen --cert-dir ~/.iket/certs
```

## 🐳 Remote Docker Installation

To run Iket on a remote server using Docker:

### 1. Deploy to Remote Server
Copy the repository to your remote server and run:
```bash
./run-docker.sh up -d
```

### 2. Extract Client Certificates
Since the Docker setup generates certificates inside a volume, you need to extract the client certificates to your local machine to enable secure remote control.

**From your Local Machine:**
```bash
# 1. Create a local certs directory
mkdir -p ~/.iket/certs/remote-prod

# 2. Copy the certificates from the remote server
# (Replace <user> and <server-ip> with your actual credentials)
scp <user>@<server-ip>:~/iket/certs/ca.crt ~/.iket/certs/remote-prod/
scp <user>@<server-ip>:~/iket/certs/client.crt ~/.iket/certs/remote-prod/
scp <user>@<server-ip>:~/iket/certs/client.key ~/.iket/certs/remote-prod/
```

### 3. Setup Local CLI Context
Now, configure your local `iket-cli` to connect to the remote Docker instance:

```bash
iket-cli context add remote-prod \
  --url https://<server-ip>:8443 \
  --ca ~/.iket/certs/remote-prod/ca.crt \
  --cert ~/.iket/certs/remote-prod/client.crt \
  --key ~/.iket/certs/remote-prod/client.key
```

### 4. Verify Remote Access
```bash
iket-cli context use remote-prod
iket-cli gateway status
```

---

## Post-Installation Setup

### 1. Verify Installation

```bash
# Check binaries are installed
which iket iket-cli

# Check versions
iket --version
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
iket --config ~/.iket/config.yaml
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

## Administration with `iket-cli`

Once the gateway is running, use the CLI for remote control. The CLI uses a **Context** system to manage different environments.

### 1. Guided Setup
The easiest way to configure a new connection is using the `setup` command:
```bash
iket-cli setup
```

### 2. Context Management
Manage multiple server profiles (Local, Docker, Production):
```bash
# List all configured contexts
iket-cli context list

# Add a new context manually
iket-cli context add prod --url https://api.example.com:8443 --ca ~/.iket/certs/ca.crt

# Switch the active context
iket-cli context use prod
```

### 4. Multi-Environment Scenario
The Context system is designed to handle complex setups across Local, Docker, and Remote environments seamlessly.

#### Strict Mode: Preventing Accidents in Production
For critical environments (like Production), you can enable **Strict Mode**. This requires manual confirmation (`y/N`) for any state-changing commands (updates, deletes, enables/disables).

```bash
# Add a production context with strict mode enabled
iket-cli context add prod --url https://api.iket.io:8443 --strict

# Any dangerous command will now prompt for confirmation
iket-cli plugin disable ratelimit
# Output: ⚠️ STRICT MODE ENABLED for context "prod"
# Are you sure you want to proceed? (y/N):

# Bypass confirmation for automated scripts
iket-cli plugin disable ratelimit --force
```

#### Configuration Sync (Push/Pull)
Maintain your configuration locally in Git and sync it to your gateways.

```bash
# Export local services to remote (merge existing)
iket-cli push services local_service.yaml --strategy merge

# Replace remote services with local definition
iket-cli push services local_service.yaml --strategy replace

# Pull remote config to local file
iket-cli pull config my_config.yaml

# Pull remote services to local file in JSON format
iket-cli pull services current_services.json --format json
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
iket-cli context add local --url http://localhost:8080

# 2. Local Docker (via mapped port)
iket-cli context add docker --url http://localhost:7100

# 3. Remote Staging (on Host with mTLS)
iket-cli context add staging \
  --url https://staging.iket.io:8443 \
  --ca ~/.iket/certs/staging/ca.crt \
  --cert ~/.iket/certs/staging/client.crt \
  --key ~/.iket/certs/staging/client.key

# 4. Remote Production (in Docker with mTLS)
iket-cli context add prod \
  --url https://api.iket.io:8443 \
  --ca ~/.iket/certs/prod/ca.crt \
  --cert ~/.iket/certs/prod/client.crt \
  --key ~/.iket/certs/prod/client.key
```

#### Switching Environments
```bash
# Check staging status
iket-cli context use staging
iket-cli gateway status

# Switch to production
iket-cli context use prod
iket-cli gateway status
```

---

## Remote Administration (Client Setup)

To manage an Iket Gateway from your local computer or a different admin machine:

### 1. Install `iket-cli` on Client Machine
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
iket-cli setup
```
*   **Name**: `prod` or `remote`
*   **URL**: `https://<server-ip>:8443`
*   **mTLS**: `y`
*   **Paths**: Provide absolute paths to the certificates copied in step 2.

### 4. Verify Connection
```bash
iket-cli gateway status
```

---

## Uninstallation

### Linux/macOS

```bash
# Stop service
sudo systemctl stop iket
sudo systemctl disable iket

# Remove binaries
sudo rm /usr/local/bin/iket /usr/local/bin/iket-cli

# Remove service file
sudo rm /etc/systemd/system/iket.service
sudo systemctl daemon-reload

# Remove configuration and certificates (optional)
rm -rf ~/.iket
```

---

## Troubleshooting

### Certificate Errors

If `iket-cli` cannot connect due to certificate issues:
1. Ensure `ca.crt` in `cli-config.yaml` matches the one used by the server.
2. Verify the server is running with `clientAuthType: "RequireAndVerifyClientCert"`.
3. Check certificate expiry: `iket-cli cert status`.

### Port Already in Use

```bash
# Check what's using port 8080
sudo lsof -i :8080

# Kill the process
sudo kill -9 <PID>
```
