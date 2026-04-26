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
| `iket server doctor --mode docker` | Check scaffold files, Docker state, `certs/` and `logs/` ownership against `IKET_UID` / `IKET_GID`, container health, local ports, TLS handshakes, generated certs, and an optional CLI context. |
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
| `iket service set <name>` | Update attributes like `--host` or `--desc` for a specific service. |
| `iket service delete <name>` | Remove a service and all its routes. |

---

## 🛣️ Route Management
Fine-grained control over individual API endpoints.

| Command | Description |
|---------|-------------|
| `iket route list` | List all routes across all services. |
| `iket route set <svc> <path> <method>` | Update a specific route (e.g., `--auth true`, `--enabled false`). |
| `iket route enable <id>` | Enable a route by ID. |
| `iket route disable <id>` | Disable a route by ID. |

---

## ⚡ Gateway & Plugins
Monitor and control the gateway core.

| Command | Description |
|---------|-------------|
| `iket gateway status` | Check health, uptime, and request metrics. |
| `iket gateway config` | View the live gateway configuration (secrets redacted). |
| `iket gateway reload` | Force a hot-reload of all configurations. |
| `iket plugin list` | List all available and active plugins. |
| `iket plugin enable <name>` | Enable a plugin globally. |
| `iket plugin disable <name>` | Disable a plugin globally. |

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
- **Bypass**: Use the global `--force` or `-f` flag for automation.

### mTLS Management
| Command | Description |
|---------|-------------|
| `iket cert status` | Check status of local certificates. |
| `iket cert gen` | Generate a new mTLS certificate chain (CA, Server, Client). |
| `iket cert import` | Import `ca.crt`, `client.crt`, and `client.key` into a managed CLI context. |

`iket-cli` still works as a compatibility alias, but `iket` is now the primary client command. `iket-server` is the gateway binary.

---

## 💡 Global Flags
Applied to any command:
- `-f, --force`: Bypass Strict Mode confirmations.
- `--help`: View detailed help for any subcommand.
