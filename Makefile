.PHONY: build run test clean

build:
	go build -o bin/server ./server
	go build -buildmode=plugin -o plugins/auth/keycloak.so plugins/auth/keycloak.go
	go build -buildmode=plugin -o plugins/metrics/prometheus.so plugins/metrics/prometheus.go
	go build -buildmode=plugin -o plugins/rate/rate-limiter.so plugins/rate/rate-limiter.go
	go build -o bin/client ./cli

run-server:
	go run ./server --port 8080

run-client:
	go run ./cli --server http://localhost:8080

test:
	go test ./...

clean:
	rm -rf bin/