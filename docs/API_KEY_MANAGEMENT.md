# 🔑 API Key Management & Authentication

The `apikey` plugin provides a robust way to manage and authenticate client applications using API keys. It supports scopes and grouping for fine-grained access control.

---

## 🚀 Overview

The API Key system allows you to:
- **Authenticate** clients via a header (`X-API-Key`) or query parameter (`api_key`).
- **Group** clients (e.g., `internal`, `partner`, `external`) to restrict access to specific service sets.
- **Scope** permissions (e.g., `read`, `write`, `admin`) at both service and route levels.
- **Inject** client identity and metadata into the request context for backend usage.

---

## 🛠️ Global Configuration

Enable the plugin in your `config.yaml`:

```yaml
plugins:
  apikey:
    enabled: true
    header_name: "X-API-Key"  # Optional, default: X-API-Key
    query_param: "api_key"    # Optional, default: api_key
    clients:
      - id: "mobile-app"
        name: "Official iOS App"
        key: "secret-key-123"
        group: "external"
        scopes: ["read", "metrics:read"]
        tags: ["prod", "mobile"]
```

---

## 🛣️ Service & Route Protection

Apply API Key protection and define requirements in your service definitions.

### 1. Group-Based Restriction
Restrict a service to a specific client group.

```yaml
name: "Inventory Service"
host: "http://inventory-api:8080"
group: "internal"  # Only clients in the 'internal' group can access this service
routes:
  - path: "/api/v1/stock"
    requireAuth: true
    auth_plugin: "apikey"
```

### 2. Scope-Based Authorization
Require specific scopes for routes. Scopes can be defined at the service level (inherited by all routes) or route level.

```yaml
name: "User Management"
host: "http://user-service:8081"
scopes: ["users:read"] # All routes in this service require 'users:read'
routes:
  - path: "/api/v1/users"
    method: "GET"
    requireAuth: true
    auth_plugin: "apikey"
    # Inherits 'users:read'

  - path: "/api/v1/users"
    method: "POST"
    requireAuth: true
    auth_plugin: "apikey"
    scopes: ["users:write"] # Requires BOTH 'users:read' AND 'users:write'
```

---

## 💻 CLI Management

Manage clients dynamically without restarting the gateway.

### List Clients
```bash
iket client list
```

### Add a Client
```bash
iket client add "partner-xyz" \
  --name "Partner Integration" \
  --key "part-key-789" \
  --group "partner" \
  --scopes "read,orders:create" \
  --tags "external,partner"
```

### Delete a Client
```bash
iket client delete "part-key-789"
```

---

## 🧠 Technical Reference

### Context Injection
When a request is authenticated, the following values are injected into the Go `request.Context()`:

| Key | Type | Description |
|-----|------|-------------|
| `apikey_client_id` | `string` | The unique ID of the client app. |
| `apikey_group` | `string` | The group the client belongs to. |
| `apikey_scopes` | `[]string` | The list of scopes assigned to the client. |

### Authorization Logic
1. **Authentication**: Validates that the provided key exists in the active client list.
2. **Group Check**: If the service has a `group` defined, the client's group must match exactly.
3. **Scope Check**: If the service or route has `scopes` defined, the client must possess **at least one** of the required scopes from the combined set (OR logic within the check, but effectively AND if you consider service vs route inheritance).

### Error Responses
- `401 Unauthorized`: Missing or invalid API key.
- `403 Forbidden`: Client group mismatch or insufficient scopes.

---

## 📝 Complete Example

**Client Definition:**
- ID: `monitoring-bot`
- Key: `bot-123`
- Group: `ops`
- Scopes: `["metrics:read", "health:check"]`

**Service Definition:**
```yaml
name: "Status Dashboard"
host: "http://status:80"
group: "ops"
routes:
  - path: "/api/metrics"
    requireAuth: true
    auth_plugin: "apikey"
    scopes: ["metrics:read"]
```

**Result:**
- `curl -H "X-API-Key: bot-123" http://gateway/api/metrics` -> **200 OK**
- `curl -H "X-API-Key: bot-123" http://gateway/api/other-internal-service` -> **403 Forbidden** (Group mismatch)
- `curl http://gateway/api/metrics` -> **401 Unauthorized** (Missing key)
