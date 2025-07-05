# Route Enabled/Disabled Feature

## Overview

The Iket API Gateway now supports enabling and disabling individual routes through the `enabled` field in the route configuration.

## Implementation

### Configuration Structure

Routes can now include an `enabled` field in their configuration:

```yaml
routes:
  - path: "/api/v1/users"
    destination: "http://backend:3001"
    methods: ["GET", "POST"]
    requireAuth: true
    enabled: true  # explicitly enabled

  - path: "/api/v1/admin"
    destination: "http://backend:3002"
    methods: ["GET", "POST", "PUT", "DELETE"]
    requireAuth: true
    enabled: false  # explicitly disabled

  - path: "/api/v1/public"
    destination: "http://backend:3003"
    methods: ["GET"]
    requireAuth: false
    # enabled field not specified - defaults to true
```

### Default Behavior

- **When `enabled` is not specified**: Route is enabled by default
- **When `enabled: true`**: Route is explicitly enabled
- **When `enabled: false`**: Route is explicitly disabled

### Implementation Details

The feature is implemented in three key locations:

1. **Route Registration** (`internal/core/gateway/gateway.go:setupRoutes()`)
   - Disabled routes are skipped during route registration
   - Only enabled routes are added to the router

2. **Authentication Middleware** (`internal/core/gateway/gateway.go:clientCredentialAuthMiddleware()`)
   - Disabled routes are skipped when matching for authentication requirements
   - Prevents disabled routes from being processed for auth

3. **Route Matching** (`internal/core/gateway/middleware.go:matchRoute()`)
   - Disabled routes are excluded from route matching
   - Ensures disabled routes don't interfere with request processing

### Management API Integration

The management API has been updated to:

1. **RouteInfo struct**: Changed `Active` field to `Enabled` field
2. **listRoutes endpoint**: Shows the actual enabled status of routes
3. **Default handling**: Correctly interprets routes without the `enabled` field as enabled

### Example Configuration

```yaml
server:
  port: 8080
  enableLogging: true

security:
  enableBasicAuth: false
  jwt:
    enabled: false

routes:
  - path: "/api/v1/users"
    destination: "http://backend:3001"
    methods: ["GET", "POST"]
    requireAuth: true
    enabled: true  # explicitly enabled

  - path: "/api/v1/admin"
    destination: "http://backend:3002"
    methods: ["GET", "POST", "PUT", "DELETE"]
    requireAuth: true
    enabled: false  # explicitly disabled

  - path: "/api/v1/public"
    destination: "http://backend:3003"
    methods: ["GET"]
    requireAuth: false
    # enabled field not specified - defaults to true

  - path: "/api/v1/legacy"
    destination: "http://backend:3004"
    methods: ["GET", "POST"]
    requireAuth: false
    enabled: false  # explicitly disabled

plugins:
  openapi:
    enabled: true
    path: "/openapi"
    swagger_ui: true
```

### Expected Behavior

With the above configuration:

- **`/api/v1/users`**: Enabled (explicitly set to true)
- **`/api/v1/admin`**: Disabled (explicitly set to false)
- **`/api/v1/public`**: Enabled (not specified, defaults to true)
- **`/api/v1/legacy`**: Disabled (explicitly set to false)

### Benefits

1. **Gradual Migration**: Disable old routes while keeping new ones active
2. **Maintenance**: Temporarily disable problematic routes without removing them
3. **Feature Flags**: Enable/disable features by controlling route availability
4. **Testing**: Isolate specific routes for testing purposes
5. **Rollback**: Quickly disable new routes if issues arise

### API Endpoints

The management API provides endpoints to manage route status:

- `GET /api/v1/routes` - List all routes with their enabled status
- `POST /api/v1/routes/{id}/enable` - Enable a route
- `POST /api/v1/routes/{id}/disable` - Disable a route

### Notes

- Disabled routes are completely ignored by the gateway
- No requests will be processed for disabled routes
- The feature is backward compatible - existing configurations without the `enabled` field will work as before
- Route statistics and monitoring will not include disabled routes 