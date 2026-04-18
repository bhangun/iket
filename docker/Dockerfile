# Build stage
FROM golang:1.23.8-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git ca-certificates tzdata make

WORKDIR /app

# Download dependencies first (better layer caching)
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build binaries
ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux \
    go build -ldflags="-w -s -X github.com/bhangun/iket/pkg/app.Version=${VERSION}" \
    -o /bin/iket ./cmd/iket/main.go

RUN CGO_ENABLED=0 GOOS=linux \
    go build -ldflags="-w -s" \
    -o /bin/iket-cli ./cmd/iket-cli/*.go

# Runtime stage
FROM alpine:3.19

# Add basic security
RUN adduser -D -u 10001 iketuser

# Install runtime dependencies
RUN apk add --no-cache ca-certificates tzdata curl openssl

# Create necessary directories
RUN mkdir -p /app/config /app/certs /app/plugins /app/logs && \
    chown -R iketuser:iketuser /app

# Copy binaries to standard path
COPY --from=builder /bin/iket /usr/local/bin/iket
COPY --from=builder /bin/iket-cli /usr/local/bin/iket-cli

# Copy default config if exists (can be overridden by volumes)
COPY config /app/config/default

# Set permissions
RUN chmod 755 /usr/local/bin/iket /usr/local/bin/iket-cli && \
    chown iketuser:iketuser /usr/local/bin/iket /usr/local/bin/iket-cli

WORKDIR /app

# Use non-root user
USER iketuser

# Set environment variables
ENV TZ=UTC \
    IKET_CONFIG_DIR=/app/config \
    IKET_CERTS_DIR=/app/certs

# Expose HTTP and HTTPS/mTLS ports
EXPOSE 8080 8443

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Run the application
# Default command starts the gateway
ENTRYPOINT ["iket"]
CMD ["--config", "/app/config/config.yaml"]
