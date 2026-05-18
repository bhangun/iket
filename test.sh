rm -f certs/server.crt certs/server.key
docker-compose down
docker-compose pull
docker-compose up -d --force-recreate
openssl x509 -in certs/server.crt -noout -text | grep -A2 "Subject Alternative Name"