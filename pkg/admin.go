package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/gorilla/mux"
)

// AdminAPI represents the administrative REST API for the gateway
type AdminAPI struct {
	gateway *Gateway
	router  *mux.Router
	openapi *OpenAPIPlugin
}

// NewAdminAPI creates a new AdminAPI instance
func NewAdminAPI(gateway *Gateway, openapi *OpenAPIPlugin) *AdminAPI {
	api := &AdminAPI{
		gateway: gateway,
		router:  mux.NewRouter(),
		openapi: openapi,
	}

	api.setupRoutes()
	return api
}

// setupRoutes configures the admin API routes
func (a *AdminAPI) setupRoutes() {
	// Route management endpoints
	a.router.HandleFunc("/api/admin/routes", a.listRoutes).Methods(http.MethodGet)
	a.router.HandleFunc("/api/admin/routes", a.addRoute).Methods(http.MethodPost)
	a.router.HandleFunc("/api/admin/routes/{id}", a.getRoute).Methods(http.MethodGet)
	a.router.HandleFunc("/api/admin/routes/{id}", a.updateRoute).Methods(http.MethodPut)
	a.router.HandleFunc("/api/admin/routes/{id}", a.deleteRoute).Methods(http.MethodDelete)

	// Plugin management endpoints
	a.router.HandleFunc("/api/admin/plugins", a.listPlugins).Methods(http.MethodGet)
	a.router.HandleFunc("/api/admin/plugins/{name}", a.getPlugin).Methods(http.MethodGet)
	a.router.HandleFunc("/api/admin/plugins/{name}/enable", a.enablePlugin).Methods(http.MethodPost)
	a.router.HandleFunc("/api/admin/plugins/{name}/disable", a.disablePlugin).Methods(http.MethodPost)
	a.router.HandleFunc("/api/admin/plugins/{name}/config", a.updatePluginConfig).Methods(http.MethodPut)

	// Configuration endpoints
	a.router.HandleFunc("/api/admin/config", a.getConfig).Methods(http.MethodGet)
	a.router.HandleFunc("/api/admin/config", a.updateConfig).Methods(http.MethodPut)
	a.router.HandleFunc("/api/admin/config/reload", a.reloadConfig).Methods(http.MethodPost)

	// Metrics and health endpoints
	a.router.HandleFunc("/api/admin/metrics", a.getMetrics).Methods(http.MethodGet)
	a.router.HandleFunc("/api/admin/health", a.getHealth).Methods(http.MethodGet)

	// Add OpenAPI spec endpoint
	a.router.HandleFunc("/api/admin/openapi.json", a.getOpenAPISpec).Methods(http.MethodGet)

	// Add Swagger UI endpoint (optional)
	a.router.PathPrefix("/api/admin/docs").Handler(http.StripPrefix("/api/admin/docs",
		http.FileServer(http.Dir("./swagger-ui"))))
}

// ServeHTTP implements the http.Handler interface
func (a *AdminAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Add security headers
	w.Header().Set("Content-Type", "application/json")

	// Apply authentication middleware
	if !a.authenticate(w, r) {
		return
	}

	a.router.ServeHTTP(w, r)
}

// authenticate checks if the request is authorized
func (a *AdminAPI) authenticate(w http.ResponseWriter, r *http.Request) bool {
	// Skip if basic auth is disabled
	if !a.gateway.config.Security.EnableBasicAuth {
		return true
	}

	username, password, ok := r.BasicAuth()
	if !ok {
		w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error":"Unauthorized","message":"Basic authentication required"}`))
		return false
	}

	expectedPassword, userExists := a.gateway.config.Security.BasicAuthUsers[username]
	if !userExists || expectedPassword != password {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error":"Unauthorized","message":"Invalid username or password"}`))
		return false
	}

	return true
}

// Route management handlers

func (a *AdminAPI) listRoutes(w http.ResponseWriter, r *http.Request) {
	a.gateway.logger.Info("Listing all routes")

	routes := make([]map[string]interface{}, len(a.gateway.config.Routes))
	for i, route := range a.gateway.config.Routes {
		routes[i] = map[string]interface{}{
			"path":           route.Path,
			"destination":    route.Destination,
			"methods":        route.Methods,
			"requireAuth":    route.RequireAuth,
			"rateLimit":      route.RateLimit,
			"timeout":        route.Timeout,
			"headers":        route.Headers,
			"stripPath":      route.StripPath,
			"validateSchema": route.ValidateSchema,
		}
	}

	json.NewEncoder(w).Encode(routes)
}

func (a *AdminAPI) addRoute(w http.ResponseWriter, r *http.Request) {
	var newRoute struct {
		Path           string            `json:"path"`
		Destination    string            `json:"destination"`
		Methods        []string          `json:"methods"`
		RequireAuth    bool              `json:"requireAuth"`
		RateLimit      *int              `json:"rateLimit"`
		Timeout        *time.Duration    `json:"timeout"`
		Headers        map[string]string `json:"headers"`
		StripPath      bool              `json:"stripPath"`
		ValidateSchema string            `json:"validateSchema"`
	}

	if err := json.NewDecoder(r.Body).Decode(&newRoute); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error":"Bad Request","message":"Invalid request body"}`))
		return
	}

	// Validate required fields
	if newRoute.Path == "" || newRoute.Destination == "" || len(newRoute.Methods) == 0 {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error":"Bad Request","message":"Path, destination, and methods are required"}`))
		return
	}

	// Add the new route to the configuration
	a.gateway.config.Routes = append(a.gateway.config.Routes, struct {
		Path           string            `yaml:"path"`
		Destination    string            `yaml:"destination"`
		Methods        []string          `yaml:"methods"`
		RequireAuth    bool              `yaml:"requireAuth"`
		RateLimit      *int              `yaml:"rateLimit"`
		Timeout        *time.Duration    `yaml:"timeout"`
		Headers        map[string]string `yaml:"headers"`
		StripPath      bool              `yaml:"stripPath"`
		ValidateSchema string            `yaml:"validateSchema"`
	}{
		Path:           newRoute.Path,
		Destination:    newRoute.Destination,
		Methods:        newRoute.Methods,
		RequireAuth:    newRoute.RequireAuth,
		RateLimit:      newRoute.RateLimit,
		Timeout:        newRoute.Timeout,
		Headers:        newRoute.Headers,
		StripPath:      newRoute.StripPath,
		ValidateSchema: newRoute.ValidateSchema,
	})

	// Rebuild the router with the new route
	a.gateway.setupRoutes()

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"message": "Route added successfully"})
}

func (a *AdminAPI) getRoute(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	path := vars["id"]

	for _, route := range a.gateway.config.Routes {
		if route.Path == path {
			json.NewEncoder(w).Encode(route)
			return
		}
	}

	w.WriteHeader(http.StatusNotFound)
	w.Write([]byte(`{"error":"Not Found","message":"Route not found"}`))
}

func (a *AdminAPI) updateRoute(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	path := vars["id"]

	var updatedRoute struct {
		Path           string            `json:"path"`
		Destination    string            `json:"destination"`
		Methods        []string          `json:"methods"`
		RequireAuth    bool              `json:"requireAuth"`
		RateLimit      *int              `json:"rateLimit"`
		Timeout        *time.Duration    `json:"timeout"`
		Headers        map[string]string `json:"headers"`
		StripPath      bool              `json:"stripPath"`
		ValidateSchema string            `json:"validateSchema"`
	}

	if err := json.NewDecoder(r.Body).Decode(&updatedRoute); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error":"Bad Request","message":"Invalid request body"}`))
		return
	}

	for i, route := range a.gateway.config.Routes {
		if route.Path == path {
			// Update the route
			if updatedRoute.Destination != "" {
				a.gateway.config.Routes[i].Destination = updatedRoute.Destination
			}
			if len(updatedRoute.Methods) > 0 {
				a.gateway.config.Routes[i].Methods = updatedRoute.Methods
			}
			a.gateway.config.Routes[i].RequireAuth = updatedRoute.RequireAuth
			a.gateway.config.Routes[i].RateLimit = updatedRoute.RateLimit
			a.gateway.config.Routes[i].Timeout = updatedRoute.Timeout
			if updatedRoute.Headers != nil {
				a.gateway.config.Routes[i].Headers = updatedRoute.Headers
			}
			a.gateway.config.Routes[i].StripPath = updatedRoute.StripPath
			a.gateway.config.Routes[i].ValidateSchema = updatedRoute.ValidateSchema

			// Rebuild the router with the updated route
			a.gateway.setupRoutes()

			json.NewEncoder(w).Encode(map[string]string{"message": "Route updated successfully"})
			return
		}
	}

	w.WriteHeader(http.StatusNotFound)
	w.Write([]byte(`{"error":"Not Found","message":"Route not found"}`))
}

func (a *AdminAPI) deleteRoute(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	path := vars["id"]

	for i, route := range a.gateway.config.Routes {
		if route.Path == path {
			// Remove the route
			a.gateway.config.Routes = append(a.gateway.config.Routes[:i], a.gateway.config.Routes[i+1:]...)

			// Rebuild the router without the deleted route
			a.gateway.setupRoutes()

			w.WriteHeader(http.StatusNoContent)
			return
		}
	}

	w.WriteHeader(http.StatusNotFound)
	w.Write([]byte(`{"error":"Not Found","message":"Route not found"}`))
}

// Plugin management handlers

func (a *AdminAPI) listPlugins(w http.ResponseWriter, r *http.Request) {
	plugins := make([]map[string]interface{}, len(a.gateway.config.Plugins))
	for i, plugin := range a.gateway.config.Plugins {
		plugins[i] = map[string]interface{}{
			"name":    plugin.Name,
			"path":    plugin.Path,
			"enabled": plugin.Enabled,
			"config":  plugin.Config,
		}
	}

	json.NewEncoder(w).Encode(plugins)
}

func (a *AdminAPI) getPlugin(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	name := vars["name"]

	for _, plugin := range a.gateway.config.Plugins {
		if plugin.Name == name {
			json.NewEncoder(w).Encode(plugin)
			return
		}
	}

	w.WriteHeader(http.StatusNotFound)
	w.Write([]byte(`{"error":"Not Found","message":"Plugin not found"}`))
}

func (a *AdminAPI) enablePlugin(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	name := vars["name"]

	for i, plugin := range a.gateway.config.Plugins {
		if plugin.Name == name {
			if plugin.Enabled {
				w.WriteHeader(http.StatusBadRequest)
				w.Write([]byte(`{"error":"Bad Request","message":"Plugin is already enabled"}`))
				return
			}

			a.gateway.config.Plugins[i].Enabled = true

			// Reload the plugin
			a.gateway.loadPlugins()

			json.NewEncoder(w).Encode(map[string]string{"message": "Plugin enabled successfully"})
			return
		}
	}

	w.WriteHeader(http.StatusNotFound)
	w.Write([]byte(`{"error":"Not Found","message":"Plugin not found"}`))
}

func (a *AdminAPI) disablePlugin(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	name := vars["name"]

	for i, plugin := range a.gateway.config.Plugins {
		if plugin.Name == name {
			if !plugin.Enabled {
				w.WriteHeader(http.StatusBadRequest)
				w.Write([]byte(`{"error":"Bad Request","message":"Plugin is already disabled"}`))
				return
			}

			a.gateway.config.Plugins[i].Enabled = false

			// Unload the plugin
			a.gateway.pluginsMu.Lock()
			for j, p := range a.gateway.plugins {
				if p.Name() == name {
					p.Shutdown()
					a.gateway.plugins = append(a.gateway.plugins[:j], a.gateway.plugins[j+1:]...)
					break
				}
			}
			a.gateway.pluginsMu.Unlock()

			json.NewEncoder(w).Encode(map[string]string{"message": "Plugin disabled successfully"})
			return
		}
	}

	w.WriteHeader(http.StatusNotFound)
	w.Write([]byte(`{"error":"Not Found","message":"Plugin not found"}`))
}

func (a *AdminAPI) updatePluginConfig(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	name := vars["name"]

	var newConfig map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&newConfig); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error":"Bad Request","message":"Invalid request body"}`))
		return
	}

	for i, plugin := range a.gateway.config.Plugins {
		if plugin.Name == name {
			a.gateway.config.Plugins[i].Config = newConfig

			// Reload the plugin with new config
			if plugin.Enabled {
				a.gateway.pluginsMu.Lock()
				for j, p := range a.gateway.plugins {
					if p.Name() == name {
						p.Shutdown()
						a.gateway.plugins = append(a.gateway.plugins[:j], a.gateway.plugins[j+1:]...)
						break
					}
				}
				a.gateway.pluginsMu.Unlock()

				// Load the plugin with new config
				/* plug, err := plugin.Open(plugin.Path)
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					w.Write([]byte(fmt.Sprintf(`{"error":"Internal Server Error","message":"Failed to open plugin: %v"}`, err)))
					return
				}

				symPlugin, err := plug.Lookup("Plugin")
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					w.Write([]byte(fmt.Sprintf(`{"error":"Internal Server Error","message":"Failed to lookup plugin symbol: %v"}`, err)))
					return
				}

				gatewayPlugin, ok := symPlugin.(GatewayPlugin)
				if !ok {
					w.WriteHeader(http.StatusInternalServerError)
					w.Write([]byte(`{"error":"Internal Server Error","message":"Plugin does not implement GatewayPlugin interface"}`))
					return
				}

				if err := gatewayPlugin.Initialize(newConfig); err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					w.Write([]byte(fmt.Sprintf(`{"error":"Internal Server Error","message":"Failed to initialize plugin: %v"}`, err)))
					return
				}

				a.gateway.pluginsMu.Lock()
				a.gateway.plugins = append(a.gateway.plugins, gatewayPlugin)
				middleware := gatewayPlugin.Middleware()
				if middleware != nil {
					a.gateway.middlewares = append(a.gateway.middlewares, middleware)
				}
				a.gateway.pluginsMu.Unlock()
				*/
			}

			json.NewEncoder(w).Encode(map[string]string{"message": "Plugin configuration updated successfully"})
			return
		}
	}

	w.WriteHeader(http.StatusNotFound)
	w.Write([]byte(`{"error":"Not Found","message":"Plugin not found"}`))
}

// Configuration handlers

func (a *AdminAPI) getConfig(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(a.gateway.config)
}

func (a *AdminAPI) updateConfig(w http.ResponseWriter, r *http.Request) {
	var newConfig Config
	if err := json.NewDecoder(r.Body).Decode(&newConfig); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error":"Bad Request","message":"Invalid request body"}`))
		return
	}

	// Validate the new config
	if newConfig.Server.Port <= 0 {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error":"Bad Request","message":"Invalid server port"}`))
		return
	}

	// Update the configuration
	a.gateway.config = &newConfig

	// Rebuild the router
	a.gateway.setupRoutes()

	json.NewEncoder(w).Encode(map[string]string{"message": "Configuration updated successfully"})
}

func (a *AdminAPI) reloadConfig(w http.ResponseWriter, r *http.Request) {
	config, err := loadConfig(a.gateway.configPath)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(fmt.Sprintf(`{"error":"Internal Server Error","message":"Failed to reload config: %v"}`, err)))
		return
	}

	a.gateway.config = config

	// Rebuild the router
	a.gateway.setupRoutes()

	// Reload plugins
	if err := a.gateway.loadPlugins(); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(fmt.Sprintf(`{"error":"Internal Server Error","message":"Failed to reload plugins: %v"}`, err)))
		return
	}

	json.NewEncoder(w).Encode(map[string]string{"message": "Configuration reloaded successfully"})
}

// Metrics and health handlers

func (a *AdminAPI) getMetrics(w http.ResponseWriter, r *http.Request) {
	// Get basic metrics
	metrics := map[string]interface{}{
		"active_connections": activeConnections,
	}

	json.NewEncoder(w).Encode(metrics)
}

func (a *AdminAPI) getHealth(w http.ResponseWriter, r *http.Request) {
	health := map[string]string{
		"status": "UP",
	}

	json.NewEncoder(w).Encode(health)
}

// OpenAPISpec generates the OpenAPI specification for the admin API
func (a *AdminAPI) OpenAPISpec() map[string]interface{} {
	return map[string]interface{}{
		"openapi": "3.0.0",
		"info": map[string]interface{}{
			"title":       "API Gateway Admin API",
			"description": "Administrative API for managing the API Gateway configuration",
			"version":     "1.0.0",
		},
		"servers": []map[string]interface{}{
			{
				"url":         "/admin",
				"description": "Gateway admin API",
			},
		},
		"paths": a.generatePaths(),
		"components": map[string]interface{}{
			"securitySchemes": map[string]interface{}{
				"basicAuth": map[string]interface{}{
					"type":   "http",
					"scheme": "basic",
				},
			},
			"schemas": a.generateSchemas(),
		},
		"security": []map[string]interface{}{
			{
				"basicAuth": []string{},
			},
		},
	}
}

func (a *AdminAPI) generatePaths() map[string]interface{} {
	return map[string]interface{}{
		"/api/admin/routes": map[string]interface{}{
			"get": map[string]interface{}{
				"summary":     "List all routes",
				"description": "Returns a list of all configured routes",
				"responses": map[string]interface{}{
					"200": map[string]interface{}{
						"description": "Successful operation",
						"content": map[string]interface{}{
							"application/json": map[string]interface{}{
								"schema": map[string]interface{}{
									"type": "array",
									"items": map[string]interface{}{
										"$ref": "#/components/schemas/Route",
									},
								},
							},
						},
					},
					"401": map[string]interface{}{
						"description": "Unauthorized",
					},
				},
			},
			"post": map[string]interface{}{
				"summary":     "Add a new route",
				"description": "Adds a new route to the gateway configuration",
				"requestBody": map[string]interface{}{
					"content": map[string]interface{}{
						"application/json": map[string]interface{}{
							"schema": map[string]interface{}{
								"$ref": "#/components/schemas/Route",
							},
						},
					},
					"required": true,
				},
				"responses": map[string]interface{}{
					"201": map[string]interface{}{
						"description": "Route created successfully",
					},
					"400": map[string]interface{}{
						"description": "Invalid input",
					},
					"401": map[string]interface{}{
						"description": "Unauthorized",
					},
				},
			},
		},
		"/api/admin/routes/{id}": map[string]interface{}{
			"get": map[string]interface{}{
				"summary":     "Get route details",
				"description": "Returns details for a specific route",
				"parameters": []map[string]interface{}{
					{
						"name":        "id",
						"in":          "path",
						"description": "Route path",
						"required":    true,
						"schema": map[string]interface{}{
							"type": "string",
						},
					},
				},
				"responses": map[string]interface{}{
					"200": map[string]interface{}{
						"description": "Successful operation",
						"content": map[string]interface{}{
							"application/json": map[string]interface{}{
								"schema": map[string]interface{}{
									"$ref": "#/components/schemas/Route",
								},
							},
						},
					},
					"401": map[string]interface{}{
						"description": "Unauthorized",
					},
					"404": map[string]interface{}{
						"description": "Route not found",
					},
				},
			},
			"put": map[string]interface{}{
				"summary":     "Update a route",
				"description": "Updates an existing route",
				"parameters": []map[string]interface{}{
					{
						"name":        "id",
						"in":          "path",
						"description": "Route path",
						"required":    true,
						"schema": map[string]interface{}{
							"type": "string",
						},
					},
				},
				"requestBody": map[string]interface{}{
					"content": map[string]interface{}{
						"application/json": map[string]interface{}{
							"schema": map[string]interface{}{
								"$ref": "#/components/schemas/Route",
							},
						},
					},
					"required": true,
				},
				"responses": map[string]interface{}{
					"200": map[string]interface{}{
						"description": "Route updated successfully",
					},
					"400": map[string]interface{}{
						"description": "Invalid input",
					},
					"401": map[string]interface{}{
						"description": "Unauthorized",
					},
					"404": map[string]interface{}{
						"description": "Route not found",
					},
				},
			},
			"delete": map[string]interface{}{
				"summary":     "Delete a route",
				"description": "Deletes an existing route",
				"parameters": []map[string]interface{}{
					{
						"name":        "id",
						"in":          "path",
						"description": "Route path",
						"required":    true,
						"schema": map[string]interface{}{
							"type": "string",
						},
					},
				},
				"responses": map[string]interface{}{
					"204": map[string]interface{}{
						"description": "Route deleted successfully",
					},
					"401": map[string]interface{}{
						"description": "Unauthorized",
					},
					"404": map[string]interface{}{
						"description": "Route not found",
					},
				},
			},
		},
		// Add similar documentation for other endpoints...
		"/api/admin/openapi.json": map[string]interface{}{
			"get": map[string]interface{}{
				"summary":     "Get OpenAPI specification",
				"description": "Returns the OpenAPI specification for this API",
				"responses": map[string]interface{}{
					"200": map[string]interface{}{
						"description": "Successful operation",
						"content": map[string]interface{}{
							"application/json": map[string]interface{}{
								"schema": map[string]interface{}{
									"type": "object",
								},
							},
						},
					},
				},
			},
		},
	}
}

func (a *AdminAPI) generateSchemas() map[string]interface{} {
	return map[string]interface{}{
		"Route": map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"path": map[string]interface{}{
					"type":        "string",
					"description": "The path pattern to match",
					"example":     "/api/users",
				},
				"destination": map[string]interface{}{
					"type":        "string",
					"description": "The destination URL to proxy to",
					"example":     "http://user-service:8080",
				},
				"methods": map[string]interface{}{
					"type": "array",
					"items": map[string]interface{}{
						"type": "string",
					},
					"description": "Allowed HTTP methods",
					"example":     []string{"GET", "POST"},
				},
				"requireAuth": map[string]interface{}{
					"type":        "boolean",
					"description": "Whether authentication is required",
					"default":     false,
				},
				"rateLimit": map[string]interface{}{
					"type":        "integer",
					"description": "Requests per interval (override global setting)",
					"nullable":    true,
				},
				"timeout": map[string]interface{}{
					"type":        "integer",
					"description": "Timeout in milliseconds",
					"nullable":    true,
				},
				"headers": map[string]interface{}{
					"type": "object",
					"additionalProperties": map[string]interface{}{
						"type": "string",
					},
					"description": "Additional headers to add to the request",
				},
				"stripPath": map[string]interface{}{
					"type":        "boolean",
					"description": "Whether to strip the path prefix before forwarding",
					"default":     false,
				},
				"validateSchema": map[string]interface{}{
					"type":        "string",
					"description": "Path to JSON schema for request validation",
					"nullable":    true,
				},
			},
			"required": []string{"path", "destination", "methods"},
		},
		"Plugin": map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"name": map[string]interface{}{
					"type":        "string",
					"description": "Plugin name",
				},
				"path": map[string]interface{}{
					"type":        "string",
					"description": "Path to plugin binary",
				},
				"enabled": map[string]interface{}{
					"type":        "boolean",
					"description": "Whether the plugin is enabled",
				},
				"config": map[string]interface{}{
					"type":        "object",
					"description": "Plugin configuration",
				},
			},
		},
		// Add more schemas as needed...
	}
}

func (a *AdminAPI) getOpenAPISpec(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(a.OpenAPISpec())
}
