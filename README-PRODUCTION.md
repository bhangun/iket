# Iket Gateway - Production Deployment

This guide explains how to deploy Iket Gateway in production using Docker with custom configuration paths.

## Overview

The production setup includes:
- **Iket Gateway** - Main API gateway service
- **PostgreSQL** - Database for configuration storage
- **Redis** - Caching and session storage
- **Keycloak** - Identity and access management
- **Custom config paths** - Flexible configuration management

## Files Structure

```
iket/
├── Dockerfile.prod                    # Production Dockerfile
├── docker-compose.prod.yaml           # Production compose file
├── docker-compose.prod.override.yaml  # Development override
├── env.prod.example                   # Environment variables template
├── scripts/deploy-prod.sh             # Deployment script
├── config/                            # Configuration directory
│   ├── config.yaml                    # Main configuration
│   ├── routes.yaml                    # Routes configuration
│   └── keycloak.yaml                  # Keycloak configuration
├── certs/                             # SSL certificates
└── plugins/                           # Custom plugins
```

## Quick Start

### 1. Setup Environment

```bash
# Copy environment template
cp env.prod.example .env.prod

# Edit environment variables
nano .env.prod
```

### 2. Configure Custom Paths

You can customize the configuration paths using environment variables:

```bash
# In .env.prod
CONFIG_PATH=/app/config/config.yaml
ROUTES_PATH=/app/config/routes.yaml
PLUGINS_DIR=/app/plugins

# Volume paths (relative to docker-compose location)
CONFIG_VOLUME=./config
CERT_VOLUME=./certs
PLUGINS_VOLUME=./plugins
```

### 3. Deploy

```bash
# Run deployment script
./scripts/deploy-prod.sh

# Or manually
docker-compose -f docker-compose.prod.yaml up -d
```

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `CONFIG_PATH` | `/app/config/config.yaml` | Path to main config file |
| `ROUTES_PATH` | `/app/config/routes.yaml` | Path to routes config file |
| `PLUGINS_DIR` | `/app/plugins` | Directory for plugins |
| `LOG_LEVEL` | `info` | Logging level |
| `CONFIG_VOLUME` | `./config` | Host path for config directory |
| `CERT_VOLUME` | `./certs` | Host path for certificates |
| `PLUGINS_VOLUME` | `./plugins` | Host path for plugins |

### Custom Config Paths

You can mount custom configuration directories:

```bash
# Example: Use different config paths
CONFIG_VOLUME=/opt/iket/config
CERT_VOLUME=/opt/iket/certs
PLUGINS_VOLUME=/opt/iket/plugins
```

### Command Line Arguments

The application supports command-line arguments for config paths:

```bash
# Default command in Dockerfile
/app/iket --config /app/config/config.yaml --routes /app/config/routes.yaml

# Custom paths
/app/iket --config /custom/path/config.yaml --routes /custom/path/routes.yaml
```

## Production Features

### Security
- Non-root user execution
- Read-only config mounts
- Secure certificate permissions
- Network isolation

### Monitoring
- Health checks for all services
- Prometheus metrics endpoint
- Structured logging
- Graceful shutdown

### Scalability
- Stateless application design
- External database storage
- Redis caching
- Load balancer ready

## Services

### Iket Gateway
- **Ports**: 8080 (HTTP), 8443 (HTTPS)
- **Health**: `http://localhost:8080/health`
- **Metrics**: `http://localhost:8080/metrics`

### PostgreSQL
- **Port**: 5432
- **Database**: iket_db
- **Purpose**: Configuration storage

### Redis
- **Port**: 6379
- **Purpose**: Caching and sessions

### Keycloak
- **Port**: 8180
- **Admin**: `http://localhost:8180/auth`
- **Purpose**: Authentication and authorization

## Development Override

For development/testing, use the override file:

```bash
# Development mode with debug logging
docker-compose -f docker-compose.prod.yaml -f docker-compose.prod.override.yaml up
```

## Troubleshooting

### Check Service Status
```bash
docker-compose -f docker-compose.prod.yaml ps
```

### View Logs
```bash
# All services
docker-compose -f docker-compose.prod.yaml logs

# Specific service
docker-compose -f docker-compose.prod.yaml logs iket
```

### Health Checks
```bash
# Gateway health
curl http://localhost:8080/health

# Keycloak health
curl http://localhost:8180/auth/health
```

### Common Issues

1. **Config not found**: Ensure config files exist in mounted volumes
2. **Permission denied**: Check file permissions on mounted directories
3. **Port conflicts**: Verify ports are not in use by other services
4. **Database connection**: Ensure PostgreSQL is running and accessible

## Backup and Recovery

### Backup Configuration
```bash
# Backup configs
tar -czf iket-config-backup-$(date +%Y%m%d).tar.gz config/ certs/ plugins/

# Backup databases
docker-compose -f docker-compose.prod.yaml exec postgres pg_dump -U iket_user iket_db > backup.sql
```

### Restore Configuration
```bash
# Restore configs
tar -xzf iket-config-backup-YYYYMMDD.tar.gz

# Restart services
docker-compose -f docker-compose.prod.yaml restart
```

## Security Considerations

1. **Change default passwords** in `.env.prod`
2. **Use strong SSL certificates** in production
3. **Restrict network access** to database ports
4. **Regular security updates** for base images
5. **Monitor logs** for suspicious activity
6. **Backup regularly** and test recovery procedures

## Performance Tuning

1. **Database connection pooling** in config
2. **Redis caching** for frequently accessed data
3. **Load balancer** for high availability
4. **Resource limits** in docker-compose
5. **Monitoring and alerting** setup




## 1. **DNS Configuration**

- **Domain Name:**  
  Register a domain (e.g., `api.example.com`) and point it to the public IP address of your server (where Iket is running).
- **DNS Record:**  
  Create an `A` record (for IPv4) or `AAAA` record (for IPv6) in your DNS provider’s dashboard:
  ```
  api.example.com  ->  <your-server-ip>
  ```

---

## 2. **TLS/SSL Configuration**

You need a TLS certificate (and private key) for your domain.  
**Options:**
- **Let’s Encrypt (Recommended, Free):** Use [certbot](https://certbot.eff.org/) or similar to generate a certificate.
- **Commercial CA:** Buy a certificate from a provider (e.g., DigiCert, Sectigo).

**You will get:**
- `fullchain.pem` or `cert.pem` (certificate)
- `privkey.pem` or `key.pem` (private key)

---

## 3. **Iket Gateway TLS Setup**

### **A. Place Certificates**
- Place your certificate and key in a directory, e.g.:
  ```
  certs/server.crt
  certs/server.key
  ```

### **B. Update Config**
Edit your `config/config.yaml` to enable TLS:

```yaml
server:
  port: 8080
  tls:
    enabled: true
    certFile: "/app/certs/server.crt"
    keyFile: "/app/certs/server.key"
    # (Optional) minVersion: "TLS12"
    # (Optional) clientCA: "/app/certs/ca.crt"  # for mTLS
  # ...other settings...
```

- Make sure the `certFile` and `keyFile` paths match where you mount/copy them in your Docker container.

### **C. Update Docker Compose (if using Docker)**
Mount the certs directory:
```yaml
services:
  iket:
    # ...
    volumes:
      - ./config:/app/config:ro
      - ./certs:/app/certs:ro
    ports:
      - "8080:8080"
      - "8443:8443"  # Expose HTTPS port
```
- Iket will listen on 8443 for HTTPS if configured.

---

## 4. **Firewall/Cloud Configuration**

- Open port **443** (or **8443** if you use that) on your server/cloud firewall.
- Make sure your DNS points to the correct public IP.

---

## 5. **Test**

- Access your gateway via `https://api.example.com` (or your chosen domain).
- You should see a valid certificate in your browser.

---

## 6. **(Optional) Redirect HTTP to HTTPS**

- You can configure Iket or a reverse proxy (like Nginx) to redirect all HTTP traffic to HTTPS for better security.

---

## **Summary Table**

| Step                | What to do                                      |
|---------------------|-------------------------------------------------|
| DNS                 | Point domain to server IP                       |
| TLS                 | Obtain cert/key, place in `certs/`              |
| Iket config         | Enable TLS in `config.yaml`                     |
| Docker              | Mount `certs/` and expose 8443                  |
| Firewall            | Open port 443/8443                              |
| Test                | Visit `https://your-domain`                     |

---



Great! Here’s a concise guide for setting up JWT authentication for both the **gateway** (server) and the **client**:

---

## 1. Gateway Side (Server) Setup

**A. For HS256 (symmetric secret):**

In your `config.yaml` (or equivalent), set:

```yaml
security:
  jwt:
    enabled: true
    secret: "your_hs256_secret"         # Shared secret for HS256
    algorithms: ["HS256"]               # or ["HS256", "RS256"] if you want both
    required: true                      # Set to true to require JWT on all routes (unless overridden per route)
```

**B. For RS256 (asymmetric public/private key):**

1. Generate a key pair (if you don’t have one):
   ```sh
   openssl genrsa -out private.pem 2048
   openssl rsa -in private.pem -pubout -out public.pem
   ```

2. In your `config.yaml`:
   ```yaml
   security:
     jwt:
       enabled: true
       publicKeyFile: "/app/certs/public.pem"  # Path inside the container or host
       algorithms: ["RS256"]
       required: true
   ```

3. Make sure the public key file is accessible to the gateway (mount it in Docker if needed).

---

## 2. Client Side (How to Call the Gateway)

**A. For HS256:**
- The client must send a valid JWT signed with the shared secret (`your_hs256_secret`).
- Example (using a JWT library, e.g., [jwt.io](https://jwt.io/) or a language-specific library):

```sh
curl -H "Authorization: Bearer <your_jwt_token>" http://localhost:8080/your/route
```

- **Note:** `<your_jwt_token>` is a JWT signed with the secret. Do **not** use the secret itself as the token.

**B. For RS256:**
- The client must send a JWT signed with the **private key** corresponding to the public key the gateway has.
- Example (using a JWT library):

```sh
curl -H "Authorization: Bearer <your_jwt_token>" http://localhost:8080/your/route
```

- **Note:** `<your_jwt_token>` is a JWT signed with the private key.

---

## 3. Generating JWTs

- Use a JWT library in your language (e.g., `jsonwebtoken` for Node.js, `pyjwt` for Python, `golang-jwt/jwt` for Go).
- For HS256, sign with the shared secret.
- For RS256, sign with the private key.

**Example (HS256, using jwt.io):**
- Header: `{ "alg": "HS256", "typ": "JWT" }`
- Payload: `{ "sub": "user1", "exp": <timestamp> }`
- Sign with: `your_hs256_secret`

**Example (RS256, using jwt.io):**
- Header: `{ "alg": "RS256", "typ": "JWT" }`
- Payload: `{ "sub": "user1", "exp": <timestamp> }`
- Sign with: your private key

---

## 4. Per-Route JWT

- In your `routes.yaml` or config, you can override JWT requirements per route:
  ```yaml
  routes:
    - path: "/public"
      requireJwt: false
    - path: "/private"
      requireJwt: true
  ```

---

**Summary:**  
- Set up JWT config in the gateway (`config.yaml`).
- For HS256: use a shared secret; for RS256: use a public/private key pair.
- Clients must send a valid JWT in the `Authorization: Bearer ...` header.
- Use a JWT library to generate tokens.

If you want a code example for generating a JWT in a specific language, let me know!


## Support

For issues and questions:
1. Check the logs: `docker-compose -f docker-compose.prod.yaml logs`
2. Verify configuration files
3. Test connectivity between services
4. Review environment variables 