# Iket API Gateway Documentation

---

## 📖 Introduction

**Iket** is a lightweight, extensible, pluggable API Gateway written in Go. It supports modern gateway features such as rate-limiting, JWT authentication, WebSockets, middleware chaining, hot-reloadable plugins, and more.

## 🚀 Quickstart

### Installation

```bash
git clone https://github.com/your-org/iket
go build -o iket ./cmd/iket
```

### Run Example

```bash
./iket -config ./config.yaml
```

### Example config.yaml

```yaml
server:
  port: 8080
  enableLogging: true

routes:
  - path: "/api"
    destination: "http://localhost:3000"
    methods: ["GET"]
    requireJwt: true
```

---

## ⚙️ Configuration Reference

### Server

* `port`, `readTimeout`, `writeTimeout`, `pluginsDir`

### Security

* `enableBasicAuth`, `jwt.secret`, `tls.certFile`

### Routes

* `path`, `destination`, `methods`, `headers`, `rateLimit`, `timeout`

### Plugins

* Each plugin configuration under `plugins` map

---

## 🔌 Plugin System

### Interfaces

* `Plugin`, `TypedPlugin`, `MiddlewarePlugin`, `LifecyclePlugin`, `ReloadablePlugin`, `TaggedPlugin`

### Example MiddlewarePlugin

```go
type MyPlugin struct {}
func (p *MyPlugin) Name() string { return "myplugin" }
func (p *MyPlugin) Initialize(cfg map[string]interface{}) error { return nil }
func (p *MyPlugin) Middleware(next http.Handler) http.Handler { return next }
```

### Registering a Plugin

```go
registry.Register(&MyPlugin{})
```

---

## 🔄 Plugin Lifecycle

* `OnStart()`, `OnShutdown()`
* `Reload(config)`

---

## 🧪 Advanced Features

* Dynamic plugin reloading
* Middleware chain by tags
* Plugin introspection

---

## 📈 Observability

* Logging
* Planned: Metrics, Tracing

---

## 📦 Deployment

* Docker: `docker-compose.yaml`
* K8s: Helm (TBD)

---

## 📚 API & Admin Reference

* (future) `/admin/reload`, `/metrics`, etc.

---

## 👷 Contributing

* Add new plugin by implementing `Plugin` interface
* See `docs/plugins.md`
* Follow PR template and test coverage

---

## 🧭 Directory Structure

```bash
iket/
├── cmd/
├── internal/
│   ├── config/
│   ├── core/
│   ├── plugin/
│   └── logging/
├── plugins/
│   ├── auth/
│   ├── rate/
│   └── cors/
├── examples/
├── docs/
│   ├── index.md
│   ├── plugins.md
│   └── config.md
```
