# Iket Gateway - Production Deployment

This guide explains how to deploy Iket Gateway in production using Docker with full security features enabled, including TLS and mTLS for remote administration.

## Overview

A production Iket setup includes:
- **Iket Gateway** - Main API gateway service
- **mTLS Security** - Mutual TLS for secure remote administration via `iket`
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
2. Build the latest `iket-server` and `iket` binaries.
3. Move binaries to `/usr/local/bin`.
4. Generate a full mTLS certificate chain in `~/.iket/certs`.
5. Create default production configurations.
6. Configure and enable a systemd service (`iket.service`).

---

## 🔒 Security Configuration

### TLS & mTLS Setup (Production)

For production, it is **mandatory** to use TLS 1.3 and mTLS for the management API.

1.  **Configure Gateway (`config.yaml`)**:
    Ensure your server configuration points to valid production certificates:
    ```yaml
    security:
      tls:
        enabled: true
        certFile: "/etc/iket/certs/server.crt"
        keyFile: "/etc/iket/certs/server.key"
        clientCAFile: "/etc/iket/certs/ca.crt"
        clientAuthType: "RequireAndVerifyClientCert" # Mandatory for mTLS
    ```

2.  **Configure Admin CLI**:
    Use the guided setup to securely link your local CLI to the remote production instance:
    ```bash
    iket setup
    ```
    *   **URL**: Use `https://api.yourdomain.com:8443`
    *   **mTLS**: `y`
    *   **Certs**: Point to your local copies of `ca.crt`, `client.crt`, and `client.key`.

### Production Hardening
- **Firewall**: Only expose port `443` (public traffic) and `8443` (management traffic) if necessary. Ideally, keep `8443` behind a VPN.
- **Certificate Rotation**: Regularly rotate client certificates and the Server TLS certificate.
- **Non-root**: Always run the gateway as a non-privileged user (the default Docker image uses `iketuser`).

---

## 🚀 Remote Administration with `iket`

Production environments are managed via **Contexts**. This prevents accidentally running commands against the wrong environment.

### Managing Production
```bash
# 1. Switch to production context
iket context use prod

# 2. Verify connectivity
iket gateway status

# 3. Safe reloads after config changes
iket gateway reload
```

### Automatic Configuration Persistence
Iket Gateway now features **Automatic File Persistence**. When you make changes via `iket` (e.g., adding a service or updating a route), the gateway automatically saves these changes back to your `config.yaml` or `service.yaml`.

- **Atomic Writes**: Changes are written to a temporary file and then moved to the final destination. This prevents file corruption even if the system crashes during a write.
- **Sticky Changes**: All remote modifications survive gateway restarts, making the CLI a reliable tool for long-term administration.

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
3. Check certificate expiry: `iket cert status`.

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
