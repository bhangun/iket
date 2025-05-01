# Build stage
FROM golang:1.24-alpine AS builder

WORKDIR /app

# Download dependencies
COPY go.mod .
RUN go mod download

# Copy source
COPY config/ config/
COPY plugins/ plugins/
COPY . .

# Build server
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o /bin/server ./server

# Runtime stage
FROM scratch

# Copy binaries
COPY --from=builder /bin/server /bin/server

# Set default command
ENTRYPOINT ["/bin/server"]