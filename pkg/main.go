package main

import (
	"flag"
	"log"
)

// main is the entry point for the API gateway
func main() {
	// Parse command line flags
	configPath := flag.String("config", "config/config.yaml", "Path to the configuration file")
	routesPath := flag.String("routes", "config/routes.yaml", "Path to the routes configuration file")
	flag.Parse()

	// Initialize the gateway
	gateway, err := NewGateway(*configPath, *routesPath)
	if err != nil {
		log.Fatalf("Failed to initialize gateway: %v", err)
	}

	// Start the gateway server
	if err := gateway.Serve(); err != nil {
		log.Fatalf("Gateway server failed: %v", err)
	}
}
