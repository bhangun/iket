package main

import (
	"fmt"
	"net/http"

	"iket/pkg/plugin"
	"iket/plugins/auth"
	"iket/plugins/openapi"
)

func mainOpenAPI() {
	// Create a new plugin registry
	registry := plugin.NewRegistry()

	// Register the external OpenAPI plugin
	openAPIPlugin := openapi.NewOpenAPIPlugin()
	if err := registry.Register(openAPIPlugin); err != nil {
		panic(fmt.Sprintf("Failed to register OpenAPI plugin: %v", err))
	}

	// Register other plugins
	authPlugin := auth.NewAuthPlugin()
	if err := registry.Register(authPlugin); err != nil {
		panic(fmt.Sprintf("Failed to register auth plugin: %v", err))
	}

	// Initialize plugins with configuration
	configs := map[string]map[string]interface{}{
		"openapi": {
			"spec_path":  "openapi.yaml", // Path to your OpenAPI spec file
			"enabled":    true,
			"path":       "/openapi",
			"format":     "yaml",
			"swagger_ui": true, // Enable Swagger UI
		},
		"auth": {
			"api_key": "your-secret-api-key-here",
		},
	}

	if err := registry.Initialize(configs); err != nil {
		panic(fmt.Sprintf("Failed to initialize plugins: %v", err))
	}

	// Create a final handler
	finalHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Hello from your API!"))
	})

	// Build middleware chain with OpenAPI and auth
	middlewareChain, err := registry.BuildMiddlewareChain([]string{"openapi", "auth"}, finalHandler)
	if err != nil {
		panic(fmt.Sprintf("Failed to build middleware chain: %v", err))
	}

	// List all registered plugins
	fmt.Println("All plugins:", registry.List())
	fmt.Println("Middleware plugins:", registry.ListMiddlewarePlugins())

	// Start HTTP server
	fmt.Println("Starting server on :8080...")
	fmt.Println("OpenAPI spec available at: http://localhost:8080/openapi")
	fmt.Println("Swagger UI available at: http://localhost:8080/swagger-ui/")

	http.ListenAndServe(":8080", middlewareChain)
}
