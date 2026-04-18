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
├── cli-config.yaml      # Iket CLI configuration
└── certs/               # mTLS certificates
    ├── ca.crt
    ├── server.crt
    └── client.crt
```

---

## Administration with `iket-cli`

Once the gateway is running with mTLS enabled, use the CLI for remote control:

```bash
# Get gateway status
iket-cli --config ~/.iket/cli-config.yaml gateway status

# List active plugins
iket-cli --config ~/.iket/cli-config.yaml plugin list

# Discovery API config
iket-cli --config ~/.iket/cli-config.yaml gateway config
```

---

## Remote Administration (Client Setup)

To manage an Iket Gateway from your local computer or a different admin machine, follow these steps:

### 1. Install `iket-cli` on Client Machine
Run the ultimate installer with the `--cli-only` flag to get just the CLI binary:
```bash
curl -fsSL https://raw.githubusercontent.com/bhangun/iket/main/scripts/install.sh | bash -s -- --cli-only
```

### 2. Copy Certificates from Server
The CLI needs the client certificates that were generated on the server. Copy them from the server to your client machine:

**On Server:**
The files are located in `~/.iket/certs/`.

**On Client Machine:**
```bash
mkdir -p ~/.iket/certs
# Copy from server (replace <server-ip> and <user>)
scp <user>@<server-ip>:~/.iket/certs/ca.crt ~/.iket/certs/
scp <user>@<server-ip>:~/.iket/certs/client.crt ~/.iket/certs/
scp <user>@<server-ip>:~/.iket/certs/client.key ~/.iket/certs/
```

### 3. Configure CLI
Create or update `~/.iket/cli-config.yaml` on your client machine:

```yaml
server_url: "https://<server-ip>:8080"
ca_file: "/Users/<your-user>/.iket/certs/ca.crt"
cert_file: "/Users/<your-user>/.iket/certs/client.crt"
key_file: "/Users/<your-user>/.iket/certs/client.key"
skip_verify: false  # Set to false for production security
```
*Note: Use absolute paths for the certificate files.*

### 4. Verify Connection
```bash
iket-cli --config ~/.iket/cli-config.yaml gateway status
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
