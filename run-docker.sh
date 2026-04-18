#!/bin/bash

# Automatically set version from git tags
export IKET_VERSION=$(git describe --tags --always 2>/dev/null || echo "dev")

echo "Building with version: $IKET_VERSION"

# Run docker-compose with all arguments passed through
docker-compose -f docker/docker-compose.yaml "$@"
 