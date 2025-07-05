- path: "/{rest:.*}"
  destination: "http://localhost:7112"
  methods: ["GET"]
  requireAuth: false

- path: "/swagger-ui/{rest:.*}"
  destination: "http://localhost:7112/swagger-ui/{rest}"
  methods: ["GET"]
  requireAuth: false

- path: "/api/*"
  destination: "http://localhost:8000"
  methods: ["GET", "POST"]
  requireAuth: false