ARG TARGETPLATFORM
ARG BUILDPLATFORM
ARG TARGETOS
ARG TARGETARCH

# Build stage
FROM --platform=$TARGETPLATFORM golang:1.25.0-bookworm AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    ca-certificates \
    tzdata \
    make \
    build-essential \
    pkg-config \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Download dependencies first (better layer caching)
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build binaries
ARG VERSION=dev

RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} \
    go build -ldflags="-w -s -X github.com/bhangun/iket/pkg/app.Version=${VERSION}" \
    -o /bin/iket-server ./cmd/iket

RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} \
    go build -ldflags="-w -s" \
    -o /bin/iket ./cmd/iket-cli

# Runtime stage
FROM --platform=$TARGETPLATFORM debian:bookworm-slim

# Add basic security
RUN useradd --system --uid 10001 --create-home --home-dir /home/iketuser iketuser

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    tzdata \
    curl \
    openssl \
 && rm -rf /var/lib/apt/lists/*

# Create necessary directories
RUN mkdir -p /app/config /app/certs /app/plugins /app/logs && \
    chown -R iketuser:iketuser /app

# Copy binaries to standard path
COPY --from=builder /bin/iket-server /usr/local/bin/iket-server
COPY --from=builder /bin/iket /usr/local/bin/iket

# Copy default config if exists (can be overridden by volumes)
COPY config /app/config/default

# Set permissions
RUN cp /usr/local/bin/iket /usr/local/bin/iket-cli && \
    cp /usr/local/bin/iket-server /usr/local/bin/iket-gateway && \
    chmod 755 /usr/local/bin/iket-server /usr/local/bin/iket /usr/local/bin/iket-cli /usr/local/bin/iket-gateway && \
    chown iketuser:iketuser /usr/local/bin/iket-server /usr/local/bin/iket /usr/local/bin/iket-cli /usr/local/bin/iket-gateway

WORKDIR /app

# Use non-root user
USER iketuser

# Set environment variables
ENV TZ=UTC \
    IKET_CONFIG_DIR=/app/config \
    IKET_CERTS_DIR=/app/certs

# Expose HTTP, HTTPS/mTLS, and enrollment TLS ports
EXPOSE 8080 8443 9443

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Run the application
# Default command starts the gateway
ENTRYPOINT ["iket-server"]
CMD ["--config", "/app/config/config.yaml"]
