package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// APIClient represents a client for the Iket management API
type APIClient struct {
	baseURL  string
	username string
	password string
	client   *http.Client
}

// NewAPIClient creates a new API client
func NewAPIClient(baseURL, username, password string) *APIClient {
	return &APIClient{
		baseURL:  baseURL,
		username: username,
		password: password,
		client:   &http.Client{Timeout: 30 * time.Second},
	}
}

// GatewayStatus represents the gateway status response
type GatewayStatus struct {
	Status            string    `json:"status"`
	Uptime            string    `json:"uptime"`
	Version           string    `json:"version"`
	StartTime         time.Time `json:"start_time"`
	ConfigLoaded      bool      `json:"config_loaded"`
	LastReload        time.Time `json:"last_reload"`
	ActiveConnections int       `json:"active_connections"`
	TotalRequests     int64     `json:"total_requests"`
	ErrorCount        int       `json:"error_count"`
}

// PluginInfo represents plugin information
type PluginInfo struct {
	Name    string            `json:"name"`
	Type    string            `json:"type"`
	Enabled bool              `json:"enabled"`
	Status  string            `json:"status"`
	Tags    map[string]string `json:"tags"`
}

// RouteInfo represents route information
type RouteInfo struct {
	ID          string                 `json:"id"`
	Path        string                 `json:"path"`
	Destination string                 `json:"destination"`
	Methods     []string               `json:"methods"`
	RequireAuth bool                   `json:"require_auth"`
	Timeout     int                    `json:"timeout"`
	StripPath   bool                   `json:"strip_path"`
	Active      bool                   `json:"active"`
	Stats       map[string]interface{} `json:"stats"`
}

// LogEntry represents a log entry
type LogEntry struct {
	Timestamp time.Time `json:"timestamp"`
	Level     string    `json:"level"`
	Message   string    `json:"message"`
	RouteID   string    `json:"route_id,omitempty"`
	ClientIP  string    `json:"client_ip,omitempty"`
	RequestID string    `json:"request_id,omitempty"`
}

// APIResponse represents a generic API response
type APIResponse struct {
	Success bool        `json:"success"`
	Message string      `json:"message,omitempty"`
	Data    interface{} `json:"data,omitempty"`
}

// ErrorResponse represents an error response
type ErrorResponse struct {
	Error struct {
		Code    string                 `json:"code"`
		Message string                 `json:"message"`
		Details map[string]interface{} `json:"details,omitempty"`
	} `json:"error"`
}

// getAuthHeaders returns the authentication headers
func (c *APIClient) getAuthHeaders() map[string]string {
	credentials := c.username + ":" + c.password
	encoded := base64.StdEncoding.EncodeToString([]byte(credentials))
	return map[string]string{
		"Authorization": "Basic " + encoded,
		"Content-Type":  "application/json",
	}
}

// doRequest performs an HTTP request with authentication
func (c *APIClient) doRequest(method, endpoint string, body io.Reader) (*http.Response, error) {
	url := c.baseURL + endpoint
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}

	headers := c.getAuthHeaders()
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	return c.client.Do(req)
}

// GetGatewayStatus retrieves the gateway status
func (c *APIClient) GetGatewayStatus() (*GatewayStatus, error) {
	resp, err := c.doRequest("GET", "/gateway/status", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var errorResp ErrorResponse
		if err := json.NewDecoder(resp.Body).Decode(&errorResp); err != nil {
			return nil, fmt.Errorf("HTTP %d: failed to decode error response", resp.StatusCode)
		}
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, errorResp.Error.Message)
	}

	var status GatewayStatus
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		return nil, err
	}

	return &status, nil
}

// GetPlugins retrieves all plugins
func (c *APIClient) GetPlugins() ([]PluginInfo, error) {
	resp, err := c.doRequest("GET", "/plugins", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var errorResp ErrorResponse
		if err := json.NewDecoder(resp.Body).Decode(&errorResp); err != nil {
			return nil, fmt.Errorf("HTTP %d: failed to decode error response", resp.StatusCode)
		}
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, errorResp.Error.Message)
	}

	var response struct {
		Plugins []PluginInfo `json:"plugins"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}

	return response.Plugins, nil
}

// GetRoutes retrieves all routes
func (c *APIClient) GetRoutes() ([]RouteInfo, error) {
	resp, err := c.doRequest("GET", "/routes", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var errorResp ErrorResponse
		if err := json.NewDecoder(resp.Body).Decode(&errorResp); err != nil {
			return nil, fmt.Errorf("HTTP %d: failed to decode error response", resp.StatusCode)
		}
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, errorResp.Error.Message)
	}

	var response struct {
		Routes []RouteInfo `json:"routes"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}

	return response.Routes, nil
}

// GetLogs retrieves recent logs
func (c *APIClient) GetLogs(limit int) ([]LogEntry, error) {
	endpoint := fmt.Sprintf("/logs?limit=%d", limit)
	resp, err := c.doRequest("GET", endpoint, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var errorResp ErrorResponse
		if err := json.NewDecoder(resp.Body).Decode(&errorResp); err != nil {
			return nil, fmt.Errorf("HTTP %d: failed to decode error response", resp.StatusCode)
		}
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, errorResp.Error.Message)
	}

	var response struct {
		Logs []LogEntry `json:"logs"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}

	return response.Logs, nil
}

// UpdatePluginConfig updates a plugin's configuration
func (c *APIClient) UpdatePluginConfig(pluginName string, config map[string]interface{}) error {
	body, err := json.Marshal(config)
	if err != nil {
		return err
	}

	endpoint := fmt.Sprintf("/plugins/%s/config", pluginName)
	resp, err := c.doRequest("PUT", endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var errorResp ErrorResponse
		if err := json.NewDecoder(resp.Body).Decode(&errorResp); err != nil {
			return fmt.Errorf("HTTP %d: failed to decode error response", resp.StatusCode)
		}
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, errorResp.Error.Message)
	}

	return nil
}

// EnablePlugin enables a plugin
func (c *APIClient) EnablePlugin(pluginName string) error {
	endpoint := fmt.Sprintf("/plugins/%s/enable", pluginName)
	resp, err := c.doRequest("POST", endpoint, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var errorResp ErrorResponse
		if err := json.NewDecoder(resp.Body).Decode(&errorResp); err != nil {
			return fmt.Errorf("HTTP %d: failed to decode error response", resp.StatusCode)
		}
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, errorResp.Error.Message)
	}

	return nil
}

// DisablePlugin disables a plugin
func (c *APIClient) DisablePlugin(pluginName string) error {
	endpoint := fmt.Sprintf("/plugins/%s/disable", pluginName)
	resp, err := c.doRequest("POST", endpoint, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var errorResp ErrorResponse
		if err := json.NewDecoder(resp.Body).Decode(&errorResp); err != nil {
			return fmt.Errorf("HTTP %d: failed to decode error response", resp.StatusCode)
		}
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, errorResp.Error.Message)
	}

	return nil
}

// CreateRoute creates a new route
func (c *APIClient) CreateRoute(route RouteInfo) error {
	body, err := json.Marshal(route)
	if err != nil {
		return err
	}

	resp, err := c.doRequest("POST", "/routes", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var errorResp ErrorResponse
		if err := json.NewDecoder(resp.Body).Decode(&errorResp); err != nil {
			return fmt.Errorf("HTTP %d: failed to decode error response", resp.StatusCode)
		}
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, errorResp.Error.Message)
	}

	return nil
}

// DeleteRoute deletes a route
func (c *APIClient) DeleteRoute(routeID string) error {
	endpoint := fmt.Sprintf("/routes/%s", routeID)
	resp, err := c.doRequest("DELETE", endpoint, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var errorResp ErrorResponse
		if err := json.NewDecoder(resp.Body).Decode(&errorResp); err != nil {
			return fmt.Errorf("HTTP %d: failed to decode error response", resp.StatusCode)
		}
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, errorResp.Error.Message)
	}

	return nil
}

func main() {
	// Create API client
	client := NewAPIClient("http://localhost:8080/api/v1", "admin", "admin123")

	fmt.Println("=== Iket Management API Client Example ===\n")

	// Get gateway status
	fmt.Println("1. Getting gateway status...")
	status, err := client.GetGatewayStatus()
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	fmt.Printf("Gateway Status: %s (Version: %s, Uptime: %s)\n", status.Status, status.Version, status.Uptime)
	fmt.Printf("Active Connections: %d, Total Requests: %d\n\n", status.ActiveConnections, status.TotalRequests)

	// Get plugins
	fmt.Println("2. Getting plugins...")
	plugins, err := client.GetPlugins()
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	fmt.Printf("Found %d plugins:\n", len(plugins))
	for _, plugin := range plugins {
		fmt.Printf("  - %s (%s): %s\n", plugin.Name, plugin.Type, plugin.Status)
	}
	fmt.Println()

	// Get routes
	fmt.Println("3. Getting routes...")
	routes, err := client.GetRoutes()
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	fmt.Printf("Found %d routes:\n", len(routes))
	for _, route := range routes {
		fmt.Printf("  - %s: %s -> %s\n", route.ID, route.Path, route.Destination)
	}
	fmt.Println()

	// Get logs
	fmt.Println("4. Getting recent logs...")
	logs, err := client.GetLogs(10)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	fmt.Printf("Found %d log entries:\n", len(logs))
	for _, log := range logs {
		fmt.Printf("  [%s] %s: %s\n", log.Level, log.Timestamp.Format("15:04:05"), log.Message)
	}
	fmt.Println()

	// Example: Update plugin configuration
	fmt.Println("5. Example: Updating rate limiter plugin configuration...")
	config := map[string]interface{}{
		"enabled":             true,
		"requests_per_second": 200,
		"burst_size":          20,
	}
	err = client.UpdatePluginConfig("rate_limiter", config)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
	} else {
		fmt.Println("Rate limiter configuration updated successfully")
	}
	fmt.Println()

	// Example: Create a new route
	fmt.Println("6. Example: Creating a new route...")
	newRoute := RouteInfo{
		Path:        "/api/v2/*",
		Destination: "http://backend-v2:3001",
		Methods:     []string{"GET", "POST"},
		RequireAuth: true,
		Timeout:     60,
		StripPath:   true,
		Active:      true,
	}
	err = client.CreateRoute(newRoute)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
	} else {
		fmt.Println("New route created successfully")
	}
	fmt.Println()

	fmt.Println("=== Example completed ===")
}
