package main

import (
	"fmt"
	"net/http"

	"iket/pkg/plugin"
	"iket/plugins/auth"
)

func main() {
	// Create a new plugin registry
	registry := plugin.NewRegistry()

	// Register middleware plugins
	authPlugin := auth.NewAuthPlugin()
	if err := registry.Register(authPlugin); err != nil {
		panic(fmt.Sprintf("Failed to register auth plugin: %v", err))
	}

	// Initialize plugins with configuration
	configs := map[string]map[string]interface{}{
		"auth": {
			"api_key": "your-secret-api-key-here",
		},
	}

	if err := registry.Initialize(configs); err != nil {
		panic(fmt.Sprintf("Failed to initialize plugins: %v", err))
	}

	// Create a final handler (your actual application logic)
	finalHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if user is authenticated
		if authenticated, ok := r.Context().Value("authenticated").(bool); ok && authenticated {
			w.Write([]byte("Hello, authenticated user!"))
		} else {
			w.Write([]byte("Hello, anonymous user!"))
		}
	})

	// Build middleware chain using explicit plugin names
	middlewareChain, err := registry.BuildMiddlewareChain([]string{"auth"}, finalHandler)
	if err != nil {
		panic(fmt.Sprintf("Failed to build middleware chain: %v", err))
	}

	// Alternative: Build middleware chain using tag-based discovery
	// This would find all plugins with the "security" tag set to "authentication"
	_, err = registry.BuildMiddlewareChainFromTags("security", "authentication", finalHandler)
	if err != nil {
		panic(fmt.Sprintf("Failed to build tagged middleware chain: %v", err))
	}

	// List all registered plugins
	fmt.Println("All plugins:", registry.List())

	// List only middleware plugins
	fmt.Println("Middleware plugins:", registry.ListMiddlewarePlugins())

	// Check if a specific plugin is a middleware plugin
	if registry.IsMiddlewarePlugin("auth") {
		fmt.Println("Auth plugin implements MiddlewarePlugin interface")
	}

	// Demonstrate new plugin type features
	authPlugins := registry.GetByType(plugin.AuthPlugin)
	fmt.Printf("Found %d auth plugins\n", len(authPlugins))

	// Get plugin tags
	if authP, err := registry.Get("auth"); err == nil {
		if tagged, ok := authP.(plugin.TaggedPlugin); ok {
			fmt.Printf("Auth plugin tags: %v\n", tagged.Tags())
		}
	}

	// Start HTTP server with middleware chain
	fmt.Println("Starting server on :8080...")
	http.ListenAndServe(":8080", middlewareChain)

	// Or use the tagged chain
	// http.ListenAndServe(":8080", taggedChain)
}
