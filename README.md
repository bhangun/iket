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
- **Secure Administration**: Remote control via `iket-cli` using mTLS and client certificates.
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

This script automates platform detection, builds the latest binaries, generates mTLS certificates (in full mode), and sets up your initial configuration.

For detailed instructions and manual installation, see [docs/INSTALL.md](docs/INSTALL.md).

### Run the Gateway

```bash
# Start with default config created by installer
iket --config ~/.iket/config.yaml
```

---

## 🛠️ Remote Administration with `iket-cli`

Iket provides a powerful CLI for remote administration. It supports multiple environment profiles (contexts) and secure mTLS communication.

### Getting Started

```bash
# Guided setup to connect to a local or remote gateway
iket-cli setup

# List all configured contexts (environments)
iket-cli context list

# Switch between environments (e.g., local, docker, prod)
iket-cli context use <context-name>
```

### Basic Commands

```bash
# Check gateway status of the active context
iket-cli gateway status
...
# Certificate management
iket-cli cert status
```

### Environment Overrides
You can override the active context using environment variables:
```bash
IKET_SERVER_URL=http://localhost:7100 iket-cli gateway status
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
    certFile: "/path/to/server.crt"
    keyFile: "/path/to/server.key"
    clientCAFile: "/path/to/ca.crt"
    clientAuthType: "RequireAndVerifyClientCert"
```

### Service Configuration (`service.yaml`)

```yaml
version: 1
services:
  - name: "User Service"
    host: "http://user-service:8000"
    base_path: "/user"
    routes:
      - path: /register
        method: POST
        requireAuth: true
```

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
# Build and run with Docker Compose
docker-compose up --build
```

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
- [API Reference](docs/API.md)

[iket-logo]: https://github.com/bhangun/repo-assets/blob/master/iket-logo.png

## License

This project is licensed under the MIT License - see the LICENSE file for details.
