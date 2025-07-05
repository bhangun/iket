# Iket Management API Integration Guide

This guide explains how to integrate the management API with the Iket API Gateway to provide a comprehensive management console.

## Overview

The management API provides REST endpoints and WebSocket connections for:
- Gateway status monitoring
- Plugin management
- Route configuration
- Real-time metrics and logs
- Certificate management
- Backup and restore operations

## Integration Steps

### 1. Add Management API to Gateway

Update the main gateway application to include the management API:

```go
// In cmd/gateway/main.go or your main application file
package main

import (
    "iket/internal/api"
    "iket/internal/core/gateway"
    "iket/internal/logging"
    "iket/pkg/plugin"
    // ... other imports
)

func main() {
    // ... existing gateway setup ...
    
    // Create plugin registry
    registry := plugin.NewRegistry()
    
    // Register built-in plugins
    // ... plugin registration code ...
    
    // Create management API
    managementAPI := api.NewManagementAPI(gateway, logger, registry)
    
    // Register management API routes with the gateway router
    managementAPI.RegisterRoutes(gateway.GetRouter())
    
    // ... start gateway ...
}
```

### 2. Update Gateway Router Access

Add a method to the Gateway struct to expose the router for management API registration:

```go
// In internal/core/gateway/gateway.go
func (g *Gateway) GetRouter() *mux.Router {
    return g.router
}
```

### 3. Configure Authentication

Set up authentication for the management API endpoints:

```yaml
# In config.yaml
security:
  basic_auth_users:
    admin: "admin123"
    operator: "operator123"
  
  jwt:
    enabled: true
    secret: "your-jwt-secret"
    algorithms: ["HS256"]
```

### 4. Enable CORS for Web Dashboard

Add CORS middleware for the management API:

```go
// In internal/api/management.go
func (api *ManagementAPI) RegisterRoutes(router *mux.Router) {
    // Add CORS middleware for management API
    router.Use(func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            w.Header().Set("Access-Control-Allow-Origin", "*")
            w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
            w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
            
            if r.Method == "OPTIONS" {
                w.WriteHeader(http.StatusOK)
                return
            }
            
            next.ServeHTTP(w, r)
        })
    })
    
    // ... existing route registration ...
}
```

## API Endpoints

### Gateway Management

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/gateway/status` | Get gateway status |
| GET | `/api/v1/gateway/config` | Get gateway configuration |
| PUT | `/api/v1/gateway/config` | Update gateway configuration |
| POST | `/api/v1/gateway/reload` | Reload configuration |
| GET | `/api/v1/gateway/metrics` | Get gateway metrics |

### Plugin Management

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/plugins` | List all plugins |
| GET | `/api/v1/plugins/{name}` | Get plugin details |
| PUT | `/api/v1/plugins/{name}/config` | Update plugin config |
| POST | `/api/v1/plugins/{name}/enable` | Enable plugin |
| POST | `/api/v1/plugins/{name}/disable` | Disable plugin |
| GET | `/api/v1/plugins/{name}/health` | Get plugin health |
| GET | `/api/v1/plugins/{name}/status` | Get plugin status |

### Route Management

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/routes` | List all routes |
| POST | `/api/v1/routes` | Create new route |
| GET | `/api/v1/routes/{id}` | Get route details |
| PUT | `/api/v1/routes/{id}` | Update route |
| DELETE | `/api/v1/routes/{id}` | Delete route |
| POST | `/api/v1/routes/{id}/enable` | Enable route |
| POST | `/api/v1/routes/{id}/disable` | Disable route |

### Monitoring & Logs

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/logs` | Get recent logs |
| GET | `/api/v1/logs/stream` | Stream logs (SSE) |
| GET | `/api/v1/metrics/system` | Get system metrics |

### WebSocket Endpoints

| Endpoint | Description |
|----------|-------------|
| `/api/v1/ws/status` | Real-time status updates |
| `/api/v1/ws/metrics` | Real-time metrics updates |
| `/api/v1/ws/logs` | Real-time log updates |

## Client Examples

### Go Client

```go
package main

import (
    "fmt"
    "iket/example/api_client"
)

func main() {
    client := api_client.NewAPIClient("http://localhost:8080/api/v1", "admin", "admin123")
    
    // Get gateway status
    status, err := client.GetGatewayStatus()
    if err != nil {
        fmt.Printf("Error: %v\n", err)
        return
    }
    
    fmt.Printf("Gateway Status: %s\n", status.Status)
}
```

### Flutter Client

```dart
import 'package:http/http.dart' as http;
import 'dart:convert';

class IketAPIClient {
  final String baseUrl;
  final String username;
  final String password;
  
  IketAPIClient(this.baseUrl, this.username, this.password);
  
  Map<String, String> get _authHeaders {
    final credentials = base64Encode(utf8.encode('$username:$password'));
    return {
      'Authorization': 'Basic $credentials',
      'Content-Type': 'application/json',
    };
  }
  
  Future<Map<String, dynamic>> getGatewayStatus() async {
    final response = await http.get(
      Uri.parse('$baseUrl/gateway/status'),
      headers: _authHeaders,
    );
    
    if (response.statusCode == 200) {
      return json.decode(response.body);
    } else {
      throw Exception('Failed to get gateway status');
    }
  }
}
```

### JavaScript/TypeScript Client

```typescript
class IketAPIClient {
  private baseUrl: string;
  private username: string;
  private password: string;
  
  constructor(baseUrl: string, username: string, password: string) {
    this.baseUrl = baseUrl;
    this.username = username;
    this.password = password;
  }
  
  private getAuthHeaders(): Record<string, string> {
    const credentials = btoa(`${this.username}:${this.password}`);
    return {
      'Authorization': `Basic ${credentials}`,
      'Content-Type': 'application/json',
    };
  }
  
  async getGatewayStatus(): Promise<any> {
    const response = await fetch(`${this.baseUrl}/gateway/status`, {
      headers: this.getAuthHeaders(),
    });
    
    if (response.ok) {
      return response.json();
    } else {
      throw new Error('Failed to get gateway status');
    }
  }
}
```

## WebSocket Integration

### Connect to Real-time Updates

```javascript
// Status updates
const statusWs = new WebSocket('ws://localhost:8080/api/v1/ws/status');
statusWs.onmessage = (event) => {
  const data = JSON.parse(event.data);
  if (data.type === 'status_update') {
    updateGatewayStatus(data.data);
  }
};

// Metrics updates
const metricsWs = new WebSocket('ws://localhost:8080/api/v1/ws/metrics');
metricsWs.onmessage = (event) => {
  const data = JSON.parse(event.data);
  if (data.type === 'metrics_update') {
    updateMetrics(data.data);
  }
};

// Log updates
const logsWs = new WebSocket('ws://localhost:8080/api/v1/ws/logs');
logsWs.onmessage = (event) => {
  const data = JSON.parse(event.data);
  if (data.type === 'log_entry') {
    addLogEntry(data.data);
  }
};
```

## Security Considerations

### 1. Authentication

- Use strong passwords for admin accounts
- Consider implementing JWT tokens for better security
- Use HTTPS in production environments

### 2. Authorization

- Implement role-based access control (RBAC)
- Differentiate between admin and operator roles
- Restrict sensitive operations to admin users only

### 3. Network Security

- Use firewall rules to restrict access to management API
- Consider VPN access for remote management
- Implement IP whitelisting for admin access

### 4. Rate Limiting

- Apply rate limiting to management API endpoints
- Different limits for read vs write operations
- Monitor for suspicious activity

## Monitoring and Alerting

### 1. Health Checks

```bash
# Check management API health
curl -u admin:admin123 http://localhost:8080/api/v1/gateway/status
```

### 2. Metrics Collection

The management API provides metrics that can be collected by monitoring systems:

- Request rates and response times
- Plugin health status
- Route performance metrics
- System resource usage

### 3. Logging

All management API operations are logged for audit purposes:

- Configuration changes
- Plugin enable/disable operations
- Route modifications
- Authentication attempts

## Deployment Considerations

### 1. Production Configuration

```yaml
# Production config.yaml
server:
  port: 8080
  management_port: 8081  # Separate port for management API
  
security:
  basic_auth_users:
    admin: "${ADMIN_PASSWORD}"  # Use environment variables
    operator: "${OPERATOR_PASSWORD}"
  
  jwt:
    enabled: true
    secret: "${JWT_SECRET}"
    algorithms: ["HS256"]
```

### 2. Docker Deployment

```dockerfile
# Dockerfile
FROM golang:1.21-alpine AS builder
WORKDIR /app
COPY . .
RUN go build -o iket cmd/gateway/main.go

FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /root/
COPY --from=builder /app/iket .
COPY config.yaml .
EXPOSE 8080 8081
CMD ["./iket"]
```

### 3. Kubernetes Deployment

```yaml
# k8s-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: iket-gateway
spec:
  replicas: 3
  selector:
    matchLabels:
      app: iket-gateway
  template:
    metadata:
      labels:
        app: iket-gateway
    spec:
      containers:
      - name: iket-gateway
        image: iket-gateway:latest
        ports:
        - containerPort: 8080
        - containerPort: 8081
        env:
        - name: ADMIN_PASSWORD
          valueFrom:
            secretKeyRef:
              name: iket-secrets
              key: admin-password
        - name: JWT_SECRET
          valueFrom:
            secretKeyRef:
              name: iket-secrets
              key: jwt-secret
```

## Troubleshooting

### Common Issues

1. **Authentication Failures**
   - Verify username/password in configuration
   - Check that Basic Auth is properly configured
   - Ensure JWT tokens are valid (if using JWT)

2. **CORS Errors**
   - Verify CORS headers are set correctly
   - Check that the web dashboard origin is allowed
   - Ensure preflight requests are handled

3. **WebSocket Connection Issues**
   - Verify WebSocket endpoints are accessible
   - Check for proxy/firewall blocking WebSocket connections
   - Ensure proper WebSocket upgrade handling

4. **Plugin Management Issues**
   - Verify plugin registry is properly initialized
   - Check plugin configuration format
   - Ensure plugins implement required interfaces

### Debug Mode

Enable debug logging for the management API:

```go
// In your main application
logger.SetLevel(logging.DebugLevel)
```

### Health Check Endpoint

Use the built-in health check endpoint:

```bash
curl http://localhost:8080/health
```

## Next Steps

1. **Implement Role-Based Access Control (RBAC)**
2. **Add Audit Logging**
3. **Implement Configuration Validation**
4. **Add Metrics Export (Prometheus)**
5. **Create Custom Dashboard Themes**
6. **Implement Multi-Tenant Support**
7. **Add API Documentation (Swagger/OpenAPI)** 