#!/bin/bash

# Production Deployment Script for Iket Gateway
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if .env.prod exists
if [ ! -f ".env.prod" ]; then
    print_warning ".env.prod file not found. Creating from template..."
    if [ -f "env.prod.example" ]; then
        cp env.prod.example .env.prod
        print_status "Created .env.prod from template. Please edit it with your production values."
        exit 1
    else
        print_error "env.prod.example not found. Please create .env.prod manually."
        exit 1
    fi
fi

# Load environment variables
print_status "Loading environment variables..."
source .env.prod

# Validate required directories exist
print_status "Validating required directories..."
for dir in config certs plugins; do
    if [ ! -d "$dir" ]; then
        print_warning "Directory $dir not found. Creating..."
        mkdir -p "$dir"
    fi
done

# Check if config files exist
if [ ! -f "config/config.yaml" ]; then
    print_error "config/config.yaml not found. Please create it before deployment."
    exit 1
fi

if [ ! -f "config/routes.yaml" ]; then
    print_error "config/routes.yaml not found. Please create it before deployment."
    exit 1
fi

# Build and deploy
print_status "Building production image..."
docker-compose -f docker-compose.prod.yaml build

print_status "Starting production services..."
docker-compose -f docker-compose.prod.yaml up -d

# Wait for services to be healthy
print_status "Waiting for services to be healthy..."
sleep 10

# Check service health
print_status "Checking service health..."
for service in iket postgres redis keycloak; do
    if docker-compose -f docker-compose.prod.yaml ps | grep -q "$service.*Up"; then
        print_status "$service is running"
    else
        print_error "$service failed to start"
        docker-compose -f docker-compose.prod.yaml logs "$service"
        exit 1
    fi
done

# Test gateway health endpoint
print_status "Testing gateway health endpoint..."
if curl -f http://localhost:8080/health > /dev/null 2>&1; then
    print_status "Gateway health check passed"
else
    print_error "Gateway health check failed"
    exit 1
fi

print_status "Production deployment completed successfully!"
print_status "Gateway is available at: http://localhost:8080"
print_status "Keycloak is available at: http://localhost:8180"

# Show running services
print_status "Running services:"
docker-compose -f docker-compose.prod.yaml ps 