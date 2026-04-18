# Iket Gateway - Production Deployment

This guide explains how to deploy Iket Gateway in production using Docker with full security features enabled, including TLS and mTLS for remote administration.

## Overview

A production Iket setup includes:
- **Iket Gateway** - Main API gateway service
- **mTLS Security** - Mutual TLS for secure remote administration via `iket-cli`
- **Identity & Access** - Integrated with JWT and Basic Auth
- **Observability** - Prometheus metrics and structured logging
- **Containerization** - Multi-stage Docker builds and secure non-root execution

## Directory Structure

After a standard installation, your production environment should look like this:

```
~/.iket/
├── config.yaml          # Gateway Server configuration
├── cli-config.yaml      # Iket CLI configuration
└── certs/               # mTLS certificates
    ├── ca.crt           # Root CA certificate
    ├── ca.key           # Root CA private key (KEEP SECURE)
    ├── server.crt       # Gateway server certificate
    ├── server.key       # Gateway server private key
    ├── client.crt       # Admin client certificate
    └── client.key       # Admin client private key
```

## Quick Start (Automated)

The easiest way to set up a production-ready environment is using the ultimate installer:

```bash
curl -fsSL https://raw.githubusercontent.com/bhangun/iket/main/scripts/install.sh | bash
```

This script will:
1. Detect your platform and install dependencies.
2. Build the latest `iket` and `iket-cli` binaries.
3. Move binaries to `/usr/local/bin`.
4. Generate a full mTLS certificate chain in `~/.iket/certs`.
5. Create default production configurations.
6. Configure and enable a systemd service (`iket.service`).

---

## 🔒 Security Configuration

### TLS & mTLS Setup

To secure the gateway and its management API, enable TLS and mTLS in `config.yaml`:

```yaml
security:
  tls:
    enabled: true
    certFile: "/home/user/.iket/certs/server.crt"
    keyFile: "/home/user/.iket/certs/server.key"
    clientCAFile: "/home/user/.iket/certs/ca.crt"
    clientAuthType: "RequireAndVerifyClientCert" # Enables mTLS
```

### Admin Authentication

In addition to mTLS, admin endpoints are protected by Basic Auth:

```yaml
security:
  enableBasicAuth: true
  basicAuthUsers:
    admin: "${ADMIN_PASSWORD}" # Use env vars for secrets
```

---

## 🚀 Remote Administration with `iket-cli`

Production environments should be managed remotely using `iket-cli`. 

### Initial Setup on Admin Machine (Client)

1. **Install CLI**: Run the installer on your admin machine.
2. **Copy Certs**: Transfer `ca.crt`, `client.crt`, and `client.key` from the server to your admin machine.
3. **Configure**: Update `~/.iket/cli-config.yaml`:

```yaml
server_url: "https://<your-server-ip>:8080"
ca_file: "/path/to/ca.crt"
cert_file: "/path/to/client.crt"
key_file: "/path/to/client.key"
skip_verify: false
```

### Common Admin Tasks

```bash
# Check status
iket-cli gateway status

# Discovery & update config
iket-cli gateway config
iket-cli gateway reload

# Manage services
iket-cli service list
iket-cli route disable <route-id>
```

---

## 📦 Docker Deployment

### Building the Image
```bash
make docker-build
```

### Running with Docker Compose
Use the provided `docker-compose.yaml` which sets up volume mounts for persistence:

```bash
# Start the gateway
make docker-run

# Run CLI commands via Docker
docker-compose run cli gateway status
```

---

## Production Features

### Security
- **Non-root user**: The Docker image runs as `iketuser`.
- **mTLS**: Every administrative request requires a valid client certificate.
- **Resource Limits**: Configured in `docker-compose.yaml` to prevent exhaustion.

### Monitoring
- **Prometheus**: Metrics available at `:8080/metrics`.
- **Structured Logging**: JSON logs for easy ingestion by ELK or Loki.
- **Health Checks**: Integrated Docker health checks.

---

## Troubleshooting

### Connectivity Issues
1. Verify the gateway is listening: `sudo lsof -i :8080` (or 8443).
2. Check logs: `sudo journalctl -u iket -f` or `docker-compose logs -f`.
3. Check certificate expiry: `iket-cli cert status`.

### Permission Issues
Ensure the user running the gateway has read access to certificates and config:
```bash
sudo chown -R $USER:$USER ~/.iket
chmod 700 ~/.iket/certs
```

## Performance Tuning

1. Adjust `readTimeout` and `writeTimeout` in `config.yaml` based on your backend latency.
2. Enable `GOGC` tuning for memory-intensive workloads.
3. Use `iket-prod` binary (built via `make build-prod`) for optimized static linking.
