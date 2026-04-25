# Route Enabled/Disabled Feature

## Overview

The Iket API Gateway now supports enabling and disabling individual routes through the `enabled` field in the route configuration.

## Implementation

### Configuration Structure

Routes are defined within services in the `service.yaml` configuration:

```yaml
version: 1
services:
  - name: "User Service"
    host: "http://user-service:8000"
    routes:
      - path: "/api/v1/users"
        method: POST
        requireAuth: true
        enabled: true  # explicitly enabled
      - path: "/api/v1/admin"
        method: GET
        requireAuth: true
        enabled: false  # explicitly disabled
      - path: "/api/v1/public"
        method: GET
        requireAuth: false
        # enabled field not specified - defaults to true
```

### Default Behavior

- **When `enabled` is not specified**: Route is enabled by default.
- **When `enabled: true`**: Route is explicitly enabled.
- **When `enabled: false`**: Route is explicitly disabled.

---

## 🛠️ Management via `iket`

You can toggle routes in real-time without restarting the gateway using the CLI.

### 1. List Routes
To see the current status of all routes:
```bash
iket route list
```

### 2. Disable a Route
```bash
iket route disable <route-id>
```

### 3. Enable a Route
```bash
iket route enable <route-id>
```

*Note: Changes made via CLI are applied immediately to the running gateway. To make them persistent, update your `service.yaml` file.*

---

### Implementation Details

- Route registration, matching, and management now operate on routes within services.
- Disabled routes are skipped during registration and matching.

### Expected Behavior

With the above configuration:
- **`/api/v1/users`**: Enabled (explicitly set to true)
- **`/api/v1/admin`**: Disabled (explicitly set to false)
- **`/api/v1/public`**: Enabled (not specified, defaults to true)

### Notes

- Disabled routes are completely ignored by the gateway.
- No requests will be processed for disabled routes.
- The feature is backward compatible - existing configurations without the `enabled` field will work as before.
- Route statistics and monitoring will not include disabled routes.
