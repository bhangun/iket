# Example service.yaml

```yaml
version: 1
services:
  - name: "Example Service"
    host: "http://localhost:7112"
    routes:
      - path: "/{rest:.*}"
        method: GET
        requireAuth: false
      - path: "/swagger-ui/{rest:.*}"
        method: GET
        requireAuth: false
      - path: "/api/*"
        method: GET
        requireAuth: false
```