.PHONY: build run test clean

build:
	go build -o bin/pkg ./pkg
	go build -buildmode=plugin -o plugins/auth/keycloak.so plugins/auth/keycloak.go
	go build -buildmode=plugin -o plugins/metrics/prometheus.so plugins/metrics/prometheus.go
	go build -buildmode=plugin -o plugins/rate/rate-limiter.so plugins/rate/rate-limiter.go

run-server:
	go run ./pkg --port 8080

run-client:
	go run ./cli --pkg http://localhost:8080

test:
	go test ./...

clean:
	rm -rf bin/