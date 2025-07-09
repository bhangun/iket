package plugin

import (
	"fmt"
	"net"
	"net/http"
	"strings"
)

type IPWhitelistPlugin struct {
	allowedNets []*net.IPNet
}

func (p *IPWhitelistPlugin) Name() string { return "ip_whitelist" }

func (p *IPWhitelistPlugin) Init(config map[string]interface{}) error {
	p.allowedNets = nil
	list, ok := config["list"]
	if !ok {
		return fmt.Errorf("ip_whitelist: missing 'list' in config")
	}

	var entries []string
	switch v := list.(type) {
	case []interface{}:
		for _, entry := range v {
			if s, ok := entry.(string); ok {
				entries = append(entries, s)
			}
		}
	case []string:
		entries = v
	case string:
		entries = strings.Split(v, ",")
	default:
		return fmt.Errorf("ip_whitelist: invalid 'list' type")
	}

	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if !strings.Contains(entry, "/") {
			entry += "/32"
		}
		_, ipnet, err := net.ParseCIDR(entry)
		if err != nil {
			return fmt.Errorf("ip_whitelist: invalid CIDR or IP: %s", entry)
		}
		p.allowedNets = append(p.allowedNets, ipnet)
	}
	return nil
}

func (p *IPWhitelistPlugin) Middleware() func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			remoteIP, _, err := net.SplitHostPort(r.RemoteAddr)
			if err != nil {
				w.WriteHeader(http.StatusForbidden)
				w.Write([]byte(`{"error":"Forbidden","message":"Invalid remote address"}`))
				return
			}
			ip := net.ParseIP(remoteIP)
			if ip == nil {
				w.WriteHeader(http.StatusForbidden)
				w.Write([]byte(`{"error":"Forbidden","message":"Invalid IP address"}`))
				return
			}
			allowed := false
			for _, net := range p.allowedNets {
				if net.Contains(ip) {
					allowed = true
					break
				}
			}
			if !allowed {
				w.WriteHeader(http.StatusForbidden)
				w.Write([]byte(`{"error":"Forbidden","message":"Your IP is not allowed"}`))
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
