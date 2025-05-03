#!/bin/bash

# Create directories for certificates
mkdir -p certs/{ca,server,client,saml}

# Generate CA private key and certificate
openssl genrsa -out certs/ca/ca.key 4096
openssl req -x509 -new -nodes -key certs/ca/ca.key -sha256 -days 3650 \
  -out certs/ca/ca.crt \
  -subj "/C=US/ST=CA/L=San Francisco/O=Iket/CN=Iket Root CA"

# Generate server private key and CSR
openssl genrsa -out certs/server/server.key 2048
openssl req -new -key certs/server/server.key \
  -out certs/server/server.csr \
  -subj "/C=US/ST=CA/L=San Francisco/O=Iket/CN=iket.local"

# Sign server certificate with CA
openssl x509 -req -in certs/server/server.csr \
  -CA certs/ca/ca.crt -CAkey certs/ca/ca.key -CAcreateserial \
  -out certs/server/server.crt -days 365 -sha256 \
  -extfile <(printf "subjectAltName=DNS:iket.local,DNS:localhost,IP:127.0.0.1")

# Generate client certificate for etcd
openssl genrsa -out certs/client/client.key 2048
openssl req -new -key certs/client/client.key \
  -out certs/client/client.csr \
  -subj "/C=US/ST=CA/L=San Francisco/O=Iket/CN=etcd-client"

# Sign client certificate with CA
openssl x509 -req -in certs/client/client.csr \
  -CA certs/ca/ca.crt -CAkey certs/ca/ca.key -CAcreateserial \
  -out certs/client/client.crt -days 365 -sha256

# Generate SAML signing key and certificate
openssl genrsa -out certs/saml/saml.key 2048
openssl req -new -key certs/saml/saml.key \
  -out certs/saml/saml.csr \
  -subj "/C=US/ST=CA/L=San Francisco/O=Iket/CN=iket-saml"

# Sign SAML certificate with CA
openssl x509 -req -in certs/saml/saml.csr \
  -CA certs/ca/ca.crt -CAkey certs/ca/ca.key -CAcreateserial \
  -out certs/saml/saml.crt -days 365 -sha256

# Clean up CSR files
rm certs/*/*.csr

# Set correct permissions
chmod 600 certs/*/*.key
chmod 644 certs/*/*.crt

echo "Certificates generated successfully in the certs directory"
