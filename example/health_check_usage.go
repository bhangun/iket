package main

import (
	"fmt"
	"net/http"
	"time"

	"iket/pkg/plugin"
	"iket/plugins/auth"
	"iket/plugins/openapi"
)

func mainHealthCheck() {
	// Create a new plugin registry
	registry := plugin.NewRegistry()

	// Register plugins
	authPlugin := auth.NewAuthPlugin()
	openAPIPlugin := openapi.NewOpenAPIPlugin()

	registry.Register(authPlugin)
	registry.Register(openAPIPlugin)

	// Initialize plugins with configuration
	configs := map[string]map[string]interface{}{
		"auth": {
			"api_key": "your-secret-api-key-here",
		},
		"openapi": {
			"spec_path":  "openapi.yaml",
			"enabled":    true,
			"swagger_ui": true,
		},
	}

	if err := registry.Initialize(configs); err != nil {
		panic(fmt.Sprintf("Failed to initialize plugins: %v", err))
	}

	// Start all lifecycle plugins
	if err := registry.StartAll(); err != nil {
		panic(fmt.Sprintf("Failed to start plugins: %v", err))
	}

	// Create a final handler
	finalHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Hello from your API!"))
	})

	// Build middleware chain
	middlewareChain, err := registry.BuildMiddlewareChain([]string{"openapi", "auth"}, finalHandler)
	if err != nil {
		panic(fmt.Sprintf("Failed to build middleware chain: %v", err))
	}

	// Add health check endpoint
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		healthResults := registry.HealthCheck()
		statuses := registry.PluginStatuses()

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		response := map[string]interface{}{
			"timestamp": time.Now().Format(time.RFC3339),
			"overall":   "healthy",
			"plugins":   make(map[string]interface{}),
		}

		hasErrors := false
		for name, err := range healthResults {
			pluginInfo := map[string]interface{}{
				"status": statuses[name],
			}
			if err != nil {
				pluginInfo["error"] = err.Error()
				hasErrors = true
			}
			response["plugins"].(map[string]interface{})[name] = pluginInfo
		}

		if hasErrors {
			response["overall"] = "unhealthy"
			w.WriteHeader(http.StatusServiceUnavailable)
		}

		// Simple JSON encoding (in production, use proper JSON encoder)
		fmt.Fprintf(w, `{"timestamp":"%s","overall":"%s","plugins":{`,
			response["timestamp"], response["overall"])

		first := true
		for name, info := range response["plugins"].(map[string]interface{}) {
			if !first {
				fmt.Fprint(w, ",")
			}
			first = false
			fmt.Fprintf(w, `"%s":{"status":"%s"`, name, info.(map[string]interface{})["status"])
			if err, ok := info.(map[string]interface{})["error"]; ok {
				fmt.Fprintf(w, `,"error":"%s"`, err)
			}
			fmt.Fprint(w, "}")
		}
		fmt.Fprint(w, "}}")
	})

	// Add plugin status endpoint
	http.HandleFunc("/plugin-status", func(w http.ResponseWriter, r *http.Request) {
		statuses := registry.PluginStatuses()

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		fmt.Fprint(w, `{"plugin_statuses":{`)
		first := true
		for name, status := range statuses {
			if !first {
				fmt.Fprint(w, ",")
			}
			first = false
			fmt.Fprintf(w, `"%s":"%s"`, name, status)
		}
		fmt.Fprint(w, "}}")
	})

	// Start HTTP server
	fmt.Println("Starting server on :8080...")
	fmt.Println("Health check available at: http://localhost:8080/health")
	fmt.Println("Plugin status available at: http://localhost:8080/plugin-status")

	go func() {
		// Periodic health checks
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()

		for range ticker.C {
			healthResults := registry.HealthCheck()
			statuses := registry.PluginStatuses()

			fmt.Println("=== Health Check Results ===")
			for name, err := range healthResults {
				status := statuses[name]
				if err != nil {
					fmt.Printf("❌ %s: %s - %v\n", name, status, err)
				} else {
					fmt.Printf("✅ %s: %s\n", name, status)
				}
			}
			fmt.Println("============================")
		}
	}()

	http.ListenAndServe(":8080", middlewareChain)
}
