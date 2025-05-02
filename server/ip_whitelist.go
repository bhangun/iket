package main

// IPWhitelist manages whitelisted IP addresses
type IPWhitelist struct {
	enabled        bool
	whitelistedIPs []string
}

// NewIPWhitelist creates a new IP whitelist
func NewIPWhitelist(enabled bool, ips []string) *IPWhitelist {
	return &IPWhitelist{
		enabled:        enabled,
		whitelistedIPs: ips,
	}
}

// IsAllowed checks if an IP is allowed
func (ip *IPWhitelist) IsAllowed(addr string) bool {
	if !ip.enabled {
		return true
	}

	for _, whitelisted := range ip.whitelistedIPs {
		if whitelisted == addr || whitelisted == "*" {
			return true
		}
	}

	return false
}
