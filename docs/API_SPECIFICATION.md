# Iket Management API Specification

This document defines the REST API for the Iket API Gateway management console.

## Base URL
```
http://localhost:8080/api/v1
```

## Authentication
All endpoints require authentication using HTTP Basic Auth or JWT Bearer token.

### Headers
```
Authorization: Basic <base64(username:password)>
# OR
Authorization: Bearer <jwt_token>
```

## API Endpoints

### 1. Gateway Management

#### Get Gateway Status
```http
GET /gateway/status
```

**Response:**
```json
{
  "status": "running",
  "uptime": "2h 15m 30s",
  "version": "1.0.0",
  "start_time": "2024-01-15T10:30:00Z",
  "config_loaded": true,
  "last_reload": "2024-01-15T12:45:00Z",
  "active_connections": 42,
  "total_requests": 15420,
  "error_count": 5
}
```

#### Get Gateway Configuration
```http
GET /gateway/config
```

**Response:**
```json
{
  "server": {
    "port": 8080,
    "host": "0.0.0.0",
    "plugins_dir": "./plugins"
  },
  "security": {
    "jwt": {
      "enabled": true,
      "secret": "REDACTED",
      "algorithms": ["HS256"]
    },
    "clients": {
      "client1": "REDACTED"
    }
  },
  "routes": [
    {
      "id": "route-1",
      "path": "/api/*",
      "destination": "http://backend:3000",
      "methods": ["GET", "POST"],
      "require_auth": true,
      "timeout": 30
    }
  ],
  "plugins": {
    "rate_limiter": {
      "enabled": true,
      "requests_per_second": 100
    }
  }
}
```

#### Update Gateway Configuration
```http
PUT /gateway/config
Content-Type: application/json
```

**Request Body:**
```json
{
  "server": {
    "port": 8080
  },
  "routes": [
    {
      "path": "/api/*",
      "destination": "http://backend:3000",
      "methods": ["GET", "POST"]
    }
  ]
}
```

**Response:**
```json
{
  "success": true,
  "message": "Configuration updated successfully",
  "reload_required": true
}
```

#### Reload Gateway Configuration
```http
POST /gateway/reload
```

**Response:**
```json
{
  "success": true,
  "message": "Configuration reloaded successfully",
  "timestamp": "2024-01-15T12:45:00Z"
}
```

#### Get Gateway Metrics
```http
GET /gateway/metrics
```

**Response:**
```json
{
  "requests": {
    "total": 15420,
    "successful": 15380,
    "failed": 40,
    "rate_per_minute": 120
  },
  "response_times": {
    "average": 45.2,
    "p95": 120.5,
    "p99": 250.1
  },
  "errors": {
    "4xx": 25,
    "5xx": 15
  },
  "connections": {
    "active": 42,
    "total": 15420
  }
}
```

### 2. Plugin Management

#### List All Plugins
```http
GET /plugins
```

**Response:**
```json
{
  "plugins": [
    {
      "name": "rate_limiter",
      "type": "ratelimit",
      "enabled": true,
      "status": "healthy",
      "tags": {
        "category": "security",
        "middleware": "true"
      }
    },
    {
      "name": "jwt_auth",
      "type": "auth",
      "enabled": true,
      "status": "healthy",
      "tags": {
        "category": "auth",
        "middleware": "true"
      }
    }
  ]
}
```

#### Get Plugin Details
```http
GET /plugins/{name}
```

**Response:**
```json
{
  "name": "rate_limiter",
  "type": "ratelimit",
  "enabled": true,
  "status": "healthy",
  "config": {
    "enabled": true,
    "requests_per_second": 100,
    "burst_size": 10
  },
  "health": {
    "status": "healthy",
    "last_check": "2024-01-15T12:45:00Z",
    "message": "Plugin is functioning normally"
  },
  "metrics": {
    "requests_processed": 15420,
    "requests_blocked": 150,
    "active_connections": 42
  }
}
```

#### Update Plugin Configuration
```http
PUT /plugins/{name}/config
Content-Type: application/json
```

**Request Body:**
```json
{
  "enabled": true,
  "requests_per_second": 200,
  "burst_size": 20
}
```

**Response:**
```json
{
  "success": true,
  "message": "Plugin configuration updated",
  "reload_required": false
}
```

#### Enable Plugin
```http
POST /plugins/{name}/enable
```

**Response:**
```json
{
  "success": true,
  "message": "Plugin enabled successfully"
}
```

#### Disable Plugin
```http
POST /plugins/{name}/disable
```

**Response:**
```json
{
  "success": true,
  "message": "Plugin disabled successfully"
}
```

#### Get Plugin Health
```http
GET /plugins/{name}/health
```

**Response:**
```json
{
  "status": "healthy",
  "last_check": "2024-01-15T12:45:00Z",
  "message": "Plugin is functioning normally",
  "details": {
    "connections": 42,
    "errors": 0
  }
}
```

#### Get Plugin Status
```http
GET /plugins/{name}/status
```

**Response:**
```json
{
  "status": "Rate Limiter: Enabled (requests: 15420, blocked: 150)",
  "enabled": true,
  "last_update": "2024-01-15T12:45:00Z"
}
```

### 3. Route Management

#### List All Routes
```http
GET /routes
```

**Response:**
```json
{
  "routes": [
    {
      "id": "route-1",
      "path": "/api/*",
      "destination": "http://backend:3000",
      "methods": ["GET", "POST", "PUT", "DELETE"],
      "require_auth": true,
      "timeout": 30,
      "strip_path": false,
      "active": true,
      "stats": {
        "requests": 15420,
        "errors": 5,
        "avg_response_time": 45.2
      }
    }
  ]
}
```

#### Get Route Details
```http
GET /routes/{id}
```

**Response:**
```json
{
  "id": "route-1",
  "path": "/api/*",
  "destination": "http://backend:3000",
  "methods": ["GET", "POST", "PUT", "DELETE"],
  "require_auth": true,
  "timeout": 30,
  "strip_path": false,
  "active": true,
  "created_at": "2024-01-15T10:30:00Z",
  "updated_at": "2024-01-15T12:45:00Z",
  "stats": {
    "requests": 15420,
    "successful": 15380,
    "failed": 40,
    "avg_response_time": 45.2,
    "p95_response_time": 120.5,
    "error_rate": 0.26
  }
}
```

#### Create Route
```http
POST /routes
Content-Type: application/json
```

**Request Body:**
```json
{
  "path": "/api/v2/*",
  "destination": "http://backend-v2:3001",
  "methods": ["GET", "POST"],
  "require_auth": true,
  "timeout": 60,
  "strip_path": true
}
```

**Response:**
```json
{
  "success": true,
  "route_id": "route-2",
  "message": "Route created successfully"
}
```

#### Update Route
```http
PUT /routes/{id}
Content-Type: application/json
```

**Request Body:**
```json
{
  "destination": "http://backend-new:3002",
  "timeout": 45
}
```

**Response:**
```json
{
  "success": true,
  "message": "Route updated successfully"
}
```

#### Delete Route
```http
DELETE /routes/{id}
```

**Response:**
```json
{
  "success": true,
  "message": "Route deleted successfully"
}
```

#### Enable/Disable Route
```http
POST /routes/{id}/enable
POST /routes/{id}/disable
```

**Response:**
```json
{
  "success": true,
  "message": "Route enabled/disabled successfully"
}
```

### 4. Monitoring & Logs

#### Get Recent Logs
```http
GET /logs?limit=100&level=error&since=2024-01-15T12:00:00Z
```

**Response:**
```json
{
  "logs": [
    {
      "timestamp": "2024-01-15T12:45:30Z",
      "level": "error",
      "message": "Backend service unavailable",
      "route_id": "route-1",
      "client_ip": "192.168.1.100",
      "request_id": "req-12345"
    }
  ],
  "total": 100,
  "has_more": true
}
```

#### Stream Live Logs (Server-Sent Events)
```http
GET /logs/stream
Accept: text/event-stream
```

**Response:**
```
event: log
data: {"timestamp":"2024-01-15T12:45:30Z","level":"info","message":"Request processed"}

event: log
data: {"timestamp":"2024-01-15T12:45:31Z","level":"error","message":"Backend error"}
```

#### Get System Metrics
```http
GET /metrics/system
```

**Response:**
```json
{
  "cpu": {
    "usage_percent": 25.5,
    "cores": 8
  },
  "memory": {
    "total_mb": 16384,
    "used_mb": 8192,
    "usage_percent": 50.0
  },
  "disk": {
    "total_gb": 500,
    "used_gb": 250,
    "usage_percent": 50.0
  },
  "network": {
    "bytes_in": 1048576,
    "bytes_out": 2097152
  }
}
```

### 5. Real-time Updates (WebSocket)

#### Connect to Status Updates
```http
GET /ws/status
Upgrade: websocket
```

**Message Format:**
```json
{
  "type": "status_update",
  "data": {
    "status": "running",
    "active_connections": 42,
    "total_requests": 15420
  }
}
```

#### Connect to Metrics Updates
```http
GET /ws/metrics
Upgrade: websocket
```

**Message Format:**
```json
{
  "type": "metrics_update",
  "data": {
    "requests_per_minute": 120,
    "avg_response_time": 45.2,
    "error_rate": 0.26
  }
}
```

#### Connect to Log Updates
```http
GET /ws/logs
Upgrade: websocket
```

**Message Format:**
```json
{
  "type": "log_entry",
  "data": {
    "timestamp": "2024-01-15T12:45:30Z",
    "level": "info",
    "message": "Request processed",
    "route_id": "route-1"
  }
}
```

### 6. Certificate Management

#### List Certificates
```http
GET /certificates
```

**Response:**
```json
{
  "certificates": [
    {
      "id": "cert-1",
      "name": "main-cert",
      "type": "tls",
      "subject": "CN=example.com",
      "issuer": "CN=Let's Encrypt",
      "valid_from": "2024-01-01T00:00:00Z",
      "valid_until": "2024-04-01T00:00:00Z",
      "status": "valid"
    }
  ]
}
```

#### Upload Certificate
```http
POST /certificates
Content-Type: multipart/form-data
```

**Form Data:**
- `cert_file`: Certificate file (.crt, .pem)
- `key_file`: Private key file (.key, .pem)
- `name`: Certificate name

**Response:**
```json
{
  "success": true,
  "certificate_id": "cert-2",
  "message": "Certificate uploaded successfully"
}
```

#### Delete Certificate
```http
DELETE /certificates/{id}
```

**Response:**
```json
{
  "success": true,
  "message": "Certificate deleted successfully"
}
```

### 7. Backup & Restore

#### Create Backup
```http
POST /backup
```

**Response:**
```json
{
  "success": true,
  "backup_id": "backup-2024-01-15-12-45",
  "filename": "iket-backup-2024-01-15-12-45.tar.gz",
  "size_bytes": 1048576,
  "created_at": "2024-01-15T12:45:00Z"
}
```

#### List Backups
```http
GET /backups
```

**Response:**
```json
{
  "backups": [
    {
      "id": "backup-2024-01-15-12-45",
      "filename": "iket-backup-2024-01-15-12-45.tar.gz",
      "size_bytes": 1048576,
      "created_at": "2024-01-15T12:45:00Z"
    }
  ]
}
```

#### Restore Backup
```http
POST /backup/{id}/restore
```

**Response:**
```json
{
  "success": true,
  "message": "Backup restored successfully",
  "restart_required": true
}
```

## Error Responses

All endpoints return consistent error responses:

```json
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Invalid configuration",
    "details": {
      "field": "port",
      "issue": "Port must be between 1 and 65535"
    }
  }
}
```

### Common Error Codes
- `AUTHENTICATION_REQUIRED`: Missing or invalid authentication
- `PERMISSION_DENIED`: Insufficient permissions
- `VALIDATION_ERROR`: Invalid request data
- `NOT_FOUND`: Resource not found
- `CONFLICT`: Resource conflict
- `INTERNAL_ERROR`: Server error

## Rate Limiting

API endpoints are rate-limited:
- **Read operations**: 1000 requests/minute
- **Write operations**: 100 requests/minute
- **Admin operations**: 50 requests/minute

Rate limit headers:
```
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 999
X-RateLimit-Reset: 1642248000
```

## Pagination

List endpoints support pagination:

```http
GET /routes?page=1&limit=20&sort=created_at&order=desc
```

**Response:**
```json
{
  "data": [...],
  "pagination": {
    "page": 1,
    "limit": 20,
    "total": 100,
    "pages": 5,
    "has_next": true,
    "has_prev": false
  }
}
```

## Versioning

API versioning is handled via URL path:
- Current version: `/api/v1/`
- Future versions: `/api/v2/`, `/api/v3/`, etc.

## Security

- All endpoints require authentication
- HTTPS/TLS encryption recommended
- CORS headers for web dashboard
- Input validation and sanitization
- Rate limiting to prevent abuse 