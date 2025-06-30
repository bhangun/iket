# Iket Gateway - Improved Makefile
# Provides comprehensive build, test, and development targets

.PHONY: help build build-basic build-prod test test-coverage clean lint format docker-build docker-run docker-stop dev setup

# Default target
help: ## Show this help message
	@echo "Iket Gateway - Available targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

# Build targets
build: ## Build the main gateway binary
	@echo "Building Iket Gateway..."
	go build -ldflags="-w -s" -o bin/iket ./pkg/main.go
	@echo "Build complete: bin/iket"

build-basic: ## Build with basic tags (no storage dependencies)
	@echo "Building Iket Gateway (basic mode)..."
	go build -tags="basic" -ldflags="-w -s" -o bin/iket-basic ./pkg/main.go
	@echo "Build complete: bin/iket-basic"

build-prod: ## Build production binary with optimizations
	@echo "Building Iket Gateway (production)..."
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
		-ldflags="-w -s -extldflags=-static" \
		-o bin/iket-prod ./pkg/main.go
	@echo "Build complete: bin/iket-prod"

build-plugins: ## Build all plugins
	@echo "Building plugins..."
	@mkdir -p bin/plugins
	go build -buildmode=plugin -o bin/plugins/auth-keycloak.so plugins/auth/keycloak.go
	go build -buildmode=plugin -o bin/plugins/metrics-prometheus.so plugins/metrics/prometheus.go
	go build -buildmode=plugin -o bin/plugins/rate-limiter.so plugins/rate/rate-limiter.go
	go build -buildmode=plugin -o bin/plugins/storage-etcd.so plugins/storage/etcd.go
	@echo "Plugin build complete"

# Testing targets
test: ## Run all tests
	@echo "Running tests..."
	go test -v ./...

test-coverage: ## Run tests with coverage report
	@echo "Running tests with coverage..."
	go test -v -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

test-unit: ## Run unit tests only
	@echo "Running unit tests..."
	go test -v -short ./...

test-integration: ## Run integration tests
	@echo "Running integration tests..."
	go test -v -tags=integration ./...

test-benchmark: ## Run benchmark tests
	@echo "Running benchmarks..."
	go test -bench=. -benchmem ./...

# Code quality targets
lint: ## Run linter
	@echo "Running linter..."
	golangci-lint run

format: ## Format code
	@echo "Formatting code..."
	go fmt ./...
	gofmt -s -w .

vet: ## Run go vet
	@echo "Running go vet..."
	go vet ./...

# Docker targets
docker-build: ## Build Docker image
	@echo "Building Docker image..."
	docker build -f Dockerfile.prod -t iket:latest .

docker-build-basic: ## Build basic Docker image
	@echo "Building basic Docker image..."
	docker build -f Dockerfile.basic -t iket:basic .

docker-run: ## Run with docker-compose
	@echo "Starting services with docker-compose..."
	docker-compose -f docker-compose.prod.yaml up -d

docker-run-basic: ## Run basic setup with docker-compose
	@echo "Starting basic services..."
	docker-compose -f docker-compose.basic.yaml up -d

docker-stop: ## Stop docker-compose services
	@echo "Stopping services..."
	docker-compose -f docker-compose.prod.yaml down
	docker-compose -f docker-compose.basic.yaml down

docker-logs: ## Show docker-compose logs
	docker-compose -f docker-compose.prod.yaml logs -f

# Development targets
dev: ## Start development server
	@echo "Starting development server..."
	go run ./pkg/main.go --config ./config/config.yaml --routes ./config/routes.yaml

dev-basic: ## Start development server (basic mode)
	@echo "Starting development server (basic mode)..."
	go run -tags=basic ./pkg/main.go --config ./config/config.yaml --routes ./config/routes.yaml

setup: ## Setup development environment
	@echo "Setting up development environment..."
	@mkdir -p bin config certs plugins
	@if [ ! -f config/config.yaml ]; then \
		echo "Creating sample config..."; \
		cp config_sample.yaml config/config.yaml; \
	fi
	@if [ ! -f config/routes.yaml ]; then \
		echo "Creating sample routes..."; \
		cp config_sample_2.yaml config/routes.yaml; \
	fi
	@echo "Development environment ready!"

# Cleanup targets
clean: ## Clean build artifacts
	@echo "Cleaning build artifacts..."
	rm -rf bin/
	rm -f coverage.out coverage.html
	@echo "Clean complete"

clean-docker: ## Clean Docker images and containers
	@echo "Cleaning Docker artifacts..."
	docker-compose -f docker-compose.prod.yaml down -v --rmi all
	docker-compose -f docker-compose.basic.yaml down -v --rmi all
	docker system prune -f
	@echo "Docker cleanup complete"

# Security targets
security-scan: ## Run security scan
	@echo "Running security scan..."
	gosec ./...

# Documentation targets
docs: ## Generate documentation
	@echo "Generating documentation..."
	godoc -http=:6060 &
	@echo "Documentation available at http://localhost:6060"

# Release targets
release: ## Create release build
	@echo "Creating release build..."
	@mkdir -p releases
	@version=$$(git describe --tags --always --dirty); \
	echo "Building version: $$version"; \
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
		-ldflags="-w -s -X main.Version=$$version" \
		-o releases/iket-$$version-linux-amd64 ./pkg/main.go; \
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build \
		-ldflags="-w -s -X main.Version=$$version" \
		-o releases/iket-$$version-darwin-amd64 ./pkg/main.go; \
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build \
		-ldflags="-w -s -X main.Version=$$version" \
		-o releases/iket-$$version-windows-amd64.exe ./pkg/main.go; \
	echo "Release builds complete in releases/"

# Monitoring targets
monitor: ## Start monitoring tools
	@echo "Starting monitoring..."
	@echo "Prometheus: http://localhost:9090"
	@echo "Grafana: http://localhost:3000"
	docker-compose -f docker-compose.monitoring.yaml up -d

# Database targets
db-migrate: ## Run database migrations
	@echo "Running database migrations..."
	@# Add migration commands here

db-seed: ## Seed database with sample data
	@echo "Seeding database..."
	@# Add seed commands here

# Utility targets
check-deps: ## Check for outdated dependencies
	@echo "Checking dependencies..."
	go list -u -m all

update-deps: ## Update dependencies
	@echo "Updating dependencies..."
	go get -u ./...
	go mod tidy

generate: ## Generate code (protobuf, mocks, etc.)
	@echo "Generating code..."
	@# Add generation commands here

# Environment-specific targets
prod-deploy: ## Deploy to production
	@echo "Deploying to production..."
	@# Add production deployment commands here

staging-deploy: ## Deploy to staging
	@echo "Deploying to staging..."
	@# Add staging deployment commands here

# Health check targets
health: ## Check service health
	@echo "Checking service health..."
	@curl -f http://localhost:8080/health || echo "Service not responding"
	@curl -f http://localhost:8180/auth/health || echo "Keycloak not responding"

# Performance targets
bench: ## Run performance benchmarks
	@echo "Running performance benchmarks..."
	go test -bench=. -benchmem ./pkg/...

profile: ## Generate CPU profile
	@echo "Generating CPU profile..."
	go test -cpuprofile=cpu.prof -bench=. ./pkg/...
	go tool pprof cpu.prof

# Default target
.DEFAULT_GOAL := help