package plugins

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"

	"iket/pkg/plugin"
)

// IPWhitelistPlugin implements an IP whitelist plugin
type IPWhitelistPlugin struct {
	*plugin.BasePlugin
	allowedIPs      map[string]bool
	allowedSubnets  []*net.IPNet
	deniedIPs       map[string]bool
	deniedSubnets   []*net.IPNet
	defaultAction   string // "allow" or "deny"
	mutex           sync.RWMutex
}

// NewIPWhitelistPlugin creates a new IP whitelist plugin
func NewIPWhitelistPlugin() *IPWhitelistPlugin {
	p := &IPWhitelistPlugin{
		BasePlugin: plugin.NewBasePlugin("ip-whitelist", "1.0.0", "IP whitelist/blacklist plugin for API gateway"),
		allowedIPs: make(map[string]bool),
		deniedIPs:  make(map[string]bool),
	}
	return p
}

// Type returns the plugin type
func (p *IPWhitelistPlugin) Type() plugin.PluginType {
	return plugin.MiddlewarePlugin
}

// Validate validates the plugin configuration
func (p *IPWhitelistPlugin) Validate(config map[string]interface{}) error {
	// Check for required fields if any
	requiredFields := []string{} // No required fields for this plugin
	return p.BasePlugin.ValidateRequiredFields(requiredFields)
}

// GetConfigSchema returns the JSON schema for plugin configuration
func (p *IPWhitelistPlugin) GetConfigSchema() map[string]interface{} {
	return map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"allowedIPs": map[string]interface{}{
				"type": "array",
				"items": map[string]interface{}{
					"type": "string",
				},
				"description": "List of allowed IP addresses",
			},
			"allowedSubnets": map[string]interface{}{
				"type": "array",
				"items": map[string]interface{}{
					"type": "string",
				},
				"description": "List of allowed IP subnets in CIDR format",
			},
			"deniedIPs": map[string]interface{}{
				"type": "array",
				"items": map[string]interface{}{
					"type": "string",
				},
				"description": "List of denied IP addresses",
			},
			"deniedSubnets": map[string]interface{}{
				"type": "array",
				"items": map[string]interface{}{
					"type": "string",
				},
				"description": "List of denied IP subnets in CIDR format",
			},
			"defaultAction": map[string]interface{}{
				"type":    "string",
				"enum":    []string{"allow", "deny"},
				"default": "allow",
				"description": "Default action when no rules match (allow or deny)",
			},
		},
	}
}

// Initialize sets up the IP whitelist with the provided configuration
func (p *IPWhitelistPlugin) Initialize(config map[string]interface{}) error {
	if err := p.Validate(config); err != nil {
		return err
	}

	// Initialize collections
	p.allowedIPs = make(map[string]bool)
	p.deniedIPs = make(map[string]bool)
	p.allowedSubnets = []*net.IPNet{}
	p.deniedSubnets = []*net.IPNet{}

	// Process allowed IPs
	if allowedIPs, ok := config["allowedIPs"].([]interface{}); ok {
		for _, ip := range allowedIPs {
			if ipStr, ok := ip.(string); ok {
				p.allowedIPs[ipStr] = true
			}
		}
	}

	// Process allowed subnets
	if allowedSubnets, ok := config["allowedSubnets"].([]interface{}); ok {
		for _, subnet := range allowedSubnets {
			if subnetStr, ok := subnet.(string); ok {
				if _, ipNet, err := net.ParseCIDR(subnetStr); err == nil {
					p.allowedSubnets = append(p.allowedSubnets, ipNet)
				}
			}
		}
	}

	// Process denied IPs
	if deniedIPs, ok := config["deniedIPs"].([]interface{}); ok {
		for _, ip := range deniedIPs {
			if ipStr, ok := ip.(string); ok {
				p.deniedIPs[ipStr] = true
			}
		}
	}

	// Process denied subnets
	if deniedSubnets, ok := config["deniedSubnets"].([]interface{}); ok {
		for _, subnet := range deniedSubnets {
			if subnetStr, ok := subnet.(string); ok {
				if _, ipNet, err := net.ParseCIDR(subnetStr); err == nil {
					p.deniedSubnets = append(p.deniedSubnets, ipNet)
				}
			}
		}
	}

	// Set default action
	p.defaultAction = p.GetConfigValueAsString("defaultAction", "allow")

	return p.BasePlugin.Initialize(config)
}

// Start starts the IP whitelist plugin
func (p *IPWhitelistPlugin) Start(ctx context.Context) error {
	return p.BasePlugin.Start(ctx)
}

// Stop stops the IP whitelist plugin
func (p *IPWhitelistPlugin) Stop(ctx context.Context) error {
	return p.BasePlugin.Stop(ctx)
}

// Middleware returns a middleware function that implements IP filtering
func (p *IPWhitelistPlugin) Middleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			clientIP := getClientIPFromRequest(r)

			// Check if IP is explicitly denied
			if p.isIPDenied(clientIP) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusForbidden)
				w.Write([]byte(`{"error":"Forbidden","message":"IP address is blocked"}`))
				return
			}

			// Check if IP is allowed
			if p.isIPAllowed(clientIP) {
				next.ServeHTTP(w, r)
				return
			}

			// Apply default action
			if p.defaultAction == "allow" {
				next.ServeHTTP(w, r)
			} else {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusForbidden)
				w.Write([]byte(`{"error":"Forbidden","message":"IP address not in whitelist"}`))
				return
			}
		})
	}
}

// isIPDenied checks if an IP is in the denied list
func (p *IPWhitelistPlugin) isIPDenied(ip string) bool {
	p.mutex.RLock()
	defer p.mutex.RUnlock()

	// Check exact IP match
	if p.deniedIPs[ip] {
		return true
	}

	// Check subnet matches
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}

	for _, subnet := range p.deniedSubnets {
		if subnet.Contains(parsedIP) {
			return true
		}
	}

	return false
}

// isIPAllowed checks if an IP is in the allowed list
func (p *IPWhitelistPlugin) isIPAllowed(ip string) bool {
	p.mutex.RLock()
	defer p.mutex.RUnlock()

	// Check exact IP match
	if p.allowedIPs[ip] {
		return true
	}

	// Check subnet matches
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}

	for _, subnet := range p.allowedSubnets {
		if subnet.Contains(parsedIP) {
			return true
		}
	}

	return false
}

// getClientIPFromRequest extracts the client IP from the request
func getClientIPFromRequest(r *http.Request) string {
	// Try X-Forwarded-For header first
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		if len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}

	// Try X-Real-IP header
	if xrip := r.Header.Get("X-Real-IP"); xrip != "" {
		return xrip
	}

	// Fall back to RemoteAddr
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	return host
}

// Plugin is the exported symbol for the plugin system to load
var Plugin plugin.Plugin = NewIPWhitelistPlugin()