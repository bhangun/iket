# 🛠️ Iket CLI Command Reference

The `iket-cli` is your remote control for the Iket API Gateway. It allows you to manage multiple environments, sync configurations, and modify services interactively.

---

## 🌍 Setup & Contexts
Manage different environment profiles (Local, Docker, Staging, Production).

| Command | Description |
|---------|-------------|
| `iket-cli setup` | Guided wizard to connect to a new gateway. |
| `iket-cli context list` | List all saved environments. |
| `iket-cli context use <name>` | Switch the active environment. |
| `iket-cli context add <name>` | Manually add a context with `--url`, `--ca`, `--cert`, etc. |
| `iket-cli context delete <name>` | Remove a context profile. |

---

## 🔄 Configuration Sync (GitOps)
Push local files to remote or pull remote state to local files.

| Command | Description |
|---------|-------------|
| `iket-cli push config <file>` | Export local gateway settings to remote. |
| `iket-cli push services <file>` | Export local service/route definitions to remote. |
| `iket-cli pull config [file]` | Fetch remote settings and save locally (YAML/JSON). |
| `iket-cli pull services [file]` | Fetch remote services and save locally. |

**Strategies for Push:**
- `--strategy merge` (Default): Update existing items and add new ones.
- `--strategy replace`: Overwrite the remote state entirely with your local file.

---

## 📦 Service Management
Manage backends and groups of routes.

| Command | Description |
|---------|-------------|
| `iket-cli service list` | List all services and their routes. |
| `iket-cli service create -i` | **Interactive Wizard** to build a service step-by-step. |
| `iket-cli service create <file>` | Create service from a YAML/JSON file. |
| `iket-cli service set <name>` | Update attributes like `--host` or `--desc` for a specific service. |
| `iket-cli service delete <name>` | Remove a service and all its routes. |

---

## 🛣️ Route Management
Fine-grained control over individual API endpoints.

| Command | Description |
|---------|-------------|
| `iket-cli route list` | List all routes across all services. |
| `iket-cli route set <svc> <path> <method>` | Update a specific route (e.g., `--auth true`, `--enabled false`). |
| `iket-cli route enable <id>` | Enable a route by ID. |
| `iket-cli route disable <id>` | Disable a route by ID. |

---

## ⚡ Gateway & Plugins
Monitor and control the gateway core.

| Command | Description |
|---------|-------------|
| `iket-cli gateway status` | Check health, uptime, and request metrics. |
| `iket-cli gateway config` | View the live gateway configuration (secrets redacted). |
| `iket-cli gateway reload` | Force a hot-reload of all configurations. |
| `iket-cli plugin list` | List all available and active plugins. |
| `iket-cli plugin enable <name>` | Enable a plugin globally. |
| `iket-cli plugin disable <name>` | Disable a plugin globally. |

---

## 👥 Client & API Key Management
Manage client applications and their access permissions dynamically.

| Command | Description |
|---------|-------------|
| `iket-cli client list` | List all registered client apps. |
| `iket-cli client add <id>` | Register a new client (requires `--key`, supports `--group`, `--scopes`, `--name`). |
| `iket-cli client delete <key>` | Remove a client app by its API key. |

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
| `iket-cli cert status` | Check status of local certificates. |
| `iket-cli cert gen` | Generate a new mTLS certificate chain (CA, Server, Client). |

---

## 💡 Global Flags
Applied to any command:
- `-f, --force`: Bypass Strict Mode confirmations.
- `--help`: View detailed help for any subcommand.
