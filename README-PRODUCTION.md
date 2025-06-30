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

## Support

For issues and questions:
1. Check the logs: `docker-compose -f docker-compose.prod.yaml logs`
2. Verify configuration files
3. Test connectivity between services
4. Review environment variables 