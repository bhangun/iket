package main

import (
	"fmt"
	"net/http"

	"iket/pkg/plugin"
	"iket/plugins/auth"
	"iket/plugins/openapi"
)

func mainBridge() {
	// Create a registry adapter to work with both plugin systems
	adapter := plugin.NewRegistryAdapter()

	// Register all existing internal plugins (cors, rate_limit, ipwhitelist, etc.)
	if err := adapter.RegisterAllInternalPlugins(); err != nil {
		panic(fmt.Sprintf("Failed to register internal plugins: %v", err))
	}

	// Register new external plugins
	authPlugin := auth.NewAuthPlugin()
	if err := adapter.GetRegistry().Register(authPlugin); err != nil {
		panic(fmt.Sprintf("Failed to register auth plugin: %v", err))
	}

	openAPIPlugin := openapi.NewOpenAPIPlugin()
	if err := adapter.GetRegistry().Register(openAPIPlugin); err != nil {
		panic(fmt.Sprintf("Failed to register OpenAPI plugin: %v", err))
	}

	// Initialize plugins with configuration
	configs := map[string]map[string]interface{}{
		"cors": {
			"allow_origin":  "*",
			"allow_methods": "GET,POST,PUT,DELETE,OPTIONS",
		},
		"rate_limit": {
			"requests_per_second": 10,
			"burst":               20,
		},
		"auth": {
			"api_key": "your-secret-api-key-here",
		},
		"openapi": {
			"spec_path":  "openapi.yaml",
			"enabled":    true,
			"path":       "/openapi",
			"format":     "yaml",
			"swagger_ui": true,
		},
	}

	if err := adapter.GetRegistry().Initialize(configs); err != nil {
		panic(fmt.Sprintf("Failed to initialize plugins: %v", err))
	}

	// Create a final handler
	finalHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if user is authenticated
		if authenticated, ok := r.Context().Value("authenticated").(bool); ok && authenticated {
			w.Write([]byte("Hello, authenticated user!"))
		} else {
			w.Write([]byte("Hello, anonymous user!"))
		}
	})

	// Method 1: Use the new registry system with all plugins (internal + external)
	fmt.Println("Using new registry system with all plugins...")
	middlewareChain, err := adapter.GetRegistry().BuildMiddlewareChain([]string{"cors", "rate_limit", "openapi", "auth"}, finalHandler)
	if err != nil {
		panic(fmt.Sprintf("Failed to build middleware chain: %v", err))
	}

	// Method 2: Use the adapter to work with internal plugins directly
	fmt.Println("Using internal plugins directly...")
	_, err = adapter.BuildMiddlewareChainFromInternal([]string{"cors", "rate_limit"}, finalHandler)
	if err != nil {
		panic(fmt.Sprintf("Failed to build internal middleware chain: %v", err))
	}

	// List all available plugins
	fmt.Println("All plugins in new registry:", adapter.GetRegistry().List())
	fmt.Println("Middleware plugins:", adapter.GetRegistry().ListMiddlewarePlugins())

	// Start HTTP server with the new middleware chain
	fmt.Println("Starting server on :8080...")
	fmt.Println("OpenAPI spec available at: http://localhost:8080/openapi")
	fmt.Println("Swagger UI available at: http://localhost:8080/swagger-ui/")
	http.ListenAndServe(":8080", middlewareChain)

	// Or use the internal chain
	// http.ListenAndServe(":8080", internalChain)
}
