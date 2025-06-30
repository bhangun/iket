# Build stage
FROM golang:1.23.4-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git ca-certificates tzdata

WORKDIR /app

# Download dependencies first (better layer caching)
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the main application
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -ldflags="-w -s" \
    -o /bin/iket ./cmd/main.go

# Runtime stage
FROM alpine:3.19

# Add basic security
RUN adduser -D -u 10001 appuser

# Install runtime dependencies
RUN apk add --no-cache ca-certificates tzdata curl

# Create necessary directories
RUN mkdir -p /app/plugins /app/certs && \
    chown -R appuser:appuser /app

# Copy binary
COPY --from=builder /bin/iket /app/iket
# Copy config files
COPY config /app/config

# Set correct permissions for certificates
RUN chmod 600 /app/certs/*.key && \
    chmod 644 /app/certs/*.crt && \
    chown -R appuser:appuser /app/certs

WORKDIR /app

# Use non-root user
USER appuser

# Set environment variables
ENV TZ=UTC \
    CONFIG_PATH=/app/config

# Expose ports if needed (adjust as necessary)
EXPOSE 8080 8443

# Health check (adjust as necessary)
HEALTHCHECK --interval=30s --timeout=3s \
    CMD curl -k --fail https://localhost:8443/health || exit 1

# Run the application
ENTRYPOINT ["/app/iket"]