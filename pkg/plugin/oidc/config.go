package oidc

import "fmt"

type OIDCConfig struct {
	IssuerURL       string   `json:"issuer_url" yaml:"issuer_url"`
	ClientID        string   `json:"client_id" yaml:"client_id"`
	RequiredRoles   []string `json:"required_roles" yaml:"required_roles"`
	AllowIssuerAny  bool     `json:"allow_issuer_any" yaml:"allow_issuer_any"`
	CacheTTLSeconds int      `json:"cache_ttl_seconds" yaml:"cache_ttl_seconds"`
}

func loadConfig(config map[string]interface{}) (OIDCConfig, error) {
	var cfg OIDCConfig
	if v, ok := config["issuer_url"].(string); ok {
		cfg.IssuerURL = v
	} else {
		return cfg, fmt.Errorf("issuer_url is required")
	}
	if v, ok := config["cache_ttl_seconds"].(int); ok {
		cfg.CacheTTLSeconds = v
	} else if v, ok := config["cache_ttl_seconds"].(float64); ok {
		cfg.CacheTTLSeconds = int(v)
	} else {
		cfg.CacheTTLSeconds = 300 // default 5 min
	}
	if v, ok := config["allow_issuer_any"].(bool); ok {
		cfg.AllowIssuerAny = v
	}
	if v, ok := config["required_roles"].([]interface{}); ok {
		for _, role := range v {
			if s, ok := role.(string); ok {
				cfg.RequiredRoles = append(cfg.RequiredRoles, s)
			}
		}
	}
	return cfg, nil
}
