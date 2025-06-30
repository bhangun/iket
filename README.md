[![Logo][iket-logo]][iket-logo]
# Iket API Gateway

Lighweight API gateway

## Features

- HTTP server with configurable port
- CLI client to interact with the server
- Optimized Docker multi-stage build
- Docker Compose setup
- Makefile for common tasks
- Reverse proxy for HTTP APIs
- Route-based plugin system
- Per-route authentication and rate limiting
- Wildcard and prefix routing
- Built-in support for Basic Auth and Client Credential authentication

## Authentication Options

### 1. Basic Auth (User/Password)

**config.yaml:**
```yaml
security:
  enableBasicAuth: true
  basicAuthUsers:
    alice: password123
    bob: secret456
```

**routes.yaml:**
```yaml
- path: "/docs/{rest:.*}"
  destination: "http://localhost:7001"
  methods: ["GET"]
  requireAuth: true
  stripPath: true
- path: "/openapi"
  destination: "http://localhost:7001"
  methods: ["GET", "OPTIONS"]
  requireAuth: true
  stripPath: false
```

**Usage:**
```sh
curl -u alice:password123 http://localhost:7110/openapi
```
- The browser will prompt for credentials when accessing protected routes.

### 2. Client Credential Auth (Client ID/Secret)

**config.yaml:**
```yaml
security:
  clients:
    my-client-id: my-secret
    another-client: another-secret
```

**routes.yaml:**
```yaml
- path: "/docs/{rest:.*}"
  destination: "http://localhost:7112"
  methods: ["GET"]
  requireAuth: true
  stripPath: true
- path: "/openapi"
  destination: "http://localhost:7112"
  methods: ["GET", "OPTIONS"]
  requireAuth: true
  stripPath: false
```

**Usage:**
```sh
curl -u my-client-id:my-secret http://localhost:7110/openapi
```

### 3. Public Routes
To allow public access (no authentication), set `requireAuth: false` for the route:
```yaml
- path: "/openapi"
  destination: "http://localhost:7112"
  methods: ["GET", "OPTIONS"]
  requireAuth: false
  stripPath: false
```

## Route Configuration
- `requireAuth: true` — Enforces authentication (Basic Auth or Client Credential, depending on config)
- `stripPath: true` — Strips the route prefix before proxying to the backend
- Wildcards: Use `{rest:.*}` for catch-all routes

## Example: Full Configuration

**config.yaml:**
```yaml
server:
  port: 8080
  readTimeout: "10s"
  writeTimeout: "10s"
  idleTimeout: "60s"
  enableLogging: true

security:
  enableBasicAuth: true
  basicAuthUsers:
    alice: password123
    bob: secret456
  # OR for client credential auth:
  # clients:
  #   my-client-id: my-secret

plugins: {}
```

**routes.yaml:**
```yaml
- path: "/docs/{rest:.*}"
  destination: "http://localhost:7112"
  methods: ["GET"]
  requireAuth: true
  stripPath: true
- path: "/openapi"
  destination: "http://localhost:7112"
  methods: ["GET", "OPTIONS"]
  requireAuth: true
  stripPath: false
```

## Running the Gateway

```sh
go run cmd/gateway/main.go --config=example/basic/config.yaml --routes=example/basic/routes.yaml --port=7110
```

## Notes
- Restart the gateway after changing config or routes.
- Only one authentication method (Basic Auth or Client Credential) should be enabled at a time.
- For Swagger UI, set the `url` to `/openapi` and use the "Authorize" button to enter credentials.

## Quick Start

### Local Development

```sh
# Build binaries
make build

# Run server
./bin/server --port 8080

# In another terminal, run client
./bin/client --server http://localhost:8080


# Generate Certificate
openssl req -x509 -newkey rsa:2048 -keyout saml.key -out saml.crt -days 365 -nodes -subj "/CN=localhost"


# Docker
# Build and run with Docker Compose
docker-compose up --build

# Test the client
docker-compose run client
curl -H "Authorization: Bearer $CHAT_TOKEN" http://localhost:8080/api/products


CHAT_TOKEN=$(curl -s -X POST 'http://localhost:8180/auth/realms/kychat/protocol/openid-connect/token' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'client_id=kaysir-service' \
  -d 'client_secret=wewgIfGNUq43uB4xeIHZgaC2WQaOnHau' \
  -d 'grant_type=password' \
  -d 'username=testadmin' \
  -d 'password=testadmin'| jq -r '.access_token')


## How to Use
# Secure API Gateway

A production-grade API Gateway with enterprise-level security features, built in Go.

## Features

### Core Security Features

- **TLS & mTLS Support**: Secure communications with TLS and client certificate authentication
- **Rate Limiting**: Prevents abuse with configurable global and per-route rate limiting
- **JWT Authentication**: Secure API endpoints with JSON Web Token authentication
- **IP Whitelisting**: Restrict access to specific IP addresses or networks
- **Request Validation**: Validate request payloads against schemas
- **CSRF Protection**: Prevent cross-site request forgery attacks
- **Security Headers**: Automatically add security headers to responses including:
  - X-Content-Type-Options
  - X-Frame-Options
  - X-XSS-Protection
  - Strict-Transport-Security (HSTS)
- **Request Size Limiting**: Prevent excessive request payloads
- **Timeout Management**: Configure timeouts for routes to prevent resource exhaustion

### Operational Features

- **Metrics & Monitoring**: Prometheus integration for metrics collection
- **Structured Logging**: Comprehensive logging for troubleshooting and audit
- **Health Checks**: Built-in health check endpoint
- **Plugin System**: Extensible architecture with plugin support
- **Graceful Shutdown**: Proper handling of shutdowns for zero downtime deployments
- **Circuit Breaking**: Prevent cascading failures with circuit breaker pattern
- **Tracing**: Request tracing with unique IDs for distributed systems

## Configuration

The gateway is configured via a YAML file. See the sample configuration file for details.

## Getting Started

### Prerequisites

- Go 1.18 or later
- TLS certificates (for production use)

### Installation

```bash
# Build the gateway
go build -o secure-gateway

# Run with a configuration file
./secure-gateway -config config.yaml
```

### Docker

```bash
# Build Docker image
docker build -t secure-gateway .

# Run with a configuration file
docker run -v $(pwd)/config.yaml:/app/config.yaml -p 8080:8080 secure-gateway
```

## Plugin Development

The gateway supports plugins that implement the `GatewayPlugin` interface:

```go
type GatewayPlugin interface {
	Name() string
	Initialize(config map[string]interface{}) error
	Middleware() func(http.Handler) http.Handler
	Shutdown() error
}
```

See the provided plugin example for details on implementing your own plugins.

## Security Best Practices

1. **Store Secrets Securely**: Never commit secrets to version control. Use environment variables or a secret management service.
2. **Use Strong TLS Settings**: Configure strong cipher suites and TLS 1.2+ only.
3. **Regular Updates**: Keep dependencies updated to fix security vulnerabilities.
4. **Proper Logging**: Log security events but avoid logging sensitive information.
5. **Defense in Depth**: Implement multiple layers of security.

## Production Deployment Considerations

- Deploy behind a load balancer for high availability
- Use proper secret management for credentials and certificates
- Implement proper monitoring and alerting
- Consider using a service mesh for advanced service-to-service communication
- Perform regular security audits


[iket-logo]: https://github.com/bhangun/repo-assets/blob/master/iket-logo.png

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## OpenAPI Plugin & Swagger UI

### Features
- Serve your OpenAPI spec at any path (default: `/openapi`)
- Output as YAML or JSON
- Enable/disable plugin via config
- Serve interactive Swagger UI at `/swagger-ui/`
- Serve static Swagger UI assets from embedded directory (add files to `internal/core/plugin/swaggerui/`)

### Example plugin config
```yaml
plugins:
  openapi:
    enabled: true
    spec_path: "./openapi.yaml"
    path: "/openapi"         # Optional, default: /openapi
    format: "json"           # Optional, "yaml" or "json" (default: yaml)
    swagger_ui: true          # Optional, serve Swagger UI at /swagger-ui/
```

- Visit `/openapi` (or your custom path) for the raw spec.
- Visit `/swagger-ui/` for the interactive docs.

### Static Asset Setup
- Download the contents of [swagger-ui-dist](https://github.com/swagger-api/swagger-ui/tree/master/dist)
- Place them in `internal/core/plugin/swaggerui/`
- The gateway will serve these files at `/swagger-ui/*`

### Notes
- If you change the OpenAPI plugin config, restart the gateway.
- You can disable the plugin with `enabled: false`.
- The plugin supports both YAML and JSON output, and can be used with or without Swagger UI.