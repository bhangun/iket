# Iket API Gateway

Lighweight API gateway

## Features

- HTTP server with configurable port
- CLI client to interact with the server
- Optimized Docker multi-stage build
- Docker Compose setup
- Makefile for common tasks

## Quick Start

### Local Development

```sh
# Build binaries
make build

# Run server
./bin/server --port 8080

# In another terminal, run client
./bin/client --server http://localhost:8080


# Docker
# Build and run with Docker Compose
docker-compose up --build

# Test the client
docker-compose run client
curl -H "Authorization: Bearer $CHAT_TOKEN" http://localhost:8080/api/products



## How to Use

1. Clone this repository
2. Run `go mod tidy` to download dependencies
3. Build and run using either:
   - `make` commands for local development
   - `docker-compose up` for containerized deployment

The project is set up with:
- Multi-stage Docker build for minimal final image size (using scratch)
- Proper separation of server and client components
- CLI flags for configuration
- All necessary ignore files
- Basic documentation

You can easily extend this starter project by adding more endpoints, configuration options, or additional services.

