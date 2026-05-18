package config

import (
	"strings"
	"testing"
)

func TestServicesConfigRuleRejectsInvalidRouteProtocol(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Services: []ServiceConfig{{
			Version: 1,
			Services: []Service{{
				Name: "identity",
				Host: "http://identity:8080",
				Routes: []RouterConfig{{
					Path:     "/chat",
					Methods:  []string{"POST"},
					Protocol: "udp",
					Backends: []Backend{
						{URLPattern: "/chat"},
					},
				}},
			}},
		}},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), ".protocol") {
		t.Fatalf("expected protocol validation error, got %v", err)
	}
}

func TestServicesConfigRuleRejectsEmptyRequiredRequestHeaderValue(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Services: []ServiceConfig{{
			Version: 1,
			Services: []Service{{
				Name: "identity",
				Host: "http://identity:8080",
				Routes: []RouterConfig{{
					Path:                   "/chat",
					Methods:                []string{"POST"},
					RequiredRequestHeaders: []string{"Authorization", ""},
					Backends: []Backend{
						{URLPattern: "/chat"},
					},
				}},
			}},
		}},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), ".requiredRequestHeaders") {
		t.Fatalf("expected requiredRequestHeaders validation error, got %v", err)
	}
}

func TestServicesConfigRuleRejectsInvalidRequiredRequestHeaderRegex(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Services: []ServiceConfig{{
			Version: 1,
			Services: []Service{{
				Name: "identity",
				Host: "http://identity:8080",
				Routes: []RouterConfig{{
					Path:    "/chat",
					Methods: []string{"POST"},
					RequiredRequestHeaderRegex: map[string]string{
						"Authorization": "[",
					},
					Backends: []Backend{
						{URLPattern: "/chat"},
					},
				}},
			}},
		}},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), ".requiredRequestHeaderRegex") {
		t.Fatalf("expected requiredRequestHeaderRegex validation error, got %v", err)
	}
}

func TestServicesConfigRuleRejectsSSEBufferedResponsePolicies(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Services: []ServiceConfig{{
			Version: 1,
			Services: []Service{{
				Name: "agent",
				Host: "http://agent:8080",
				Routes: []RouterConfig{{
					Path:     "/stream",
					Methods:  []string{"GET"},
					Protocol: "sse",
					ResponseJSONFields: map[string]string{
						"meta.status": "ok",
					},
					Backends: []Backend{
						{URLPattern: "/"},
					},
				}},
			}},
		}},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "responseJSONFields") {
		t.Fatalf("expected sse response transform validation error, got %v", err)
	}
}

func TestServicesConfigRuleAllowsSSEProtocol(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Services: []ServiceConfig{{
			Version: 1,
			Services: []Service{{
				Name: "agent",
				Host: "http://agent:8080",
				Routes: []RouterConfig{{
					Path:     "/stream",
					Methods:  []string{"GET"},
					Protocol: "sse",
					ResponseHeaders: map[string]string{
						"Cache-Control": "no-cache",
					},
					Backends: []Backend{
						{URLPattern: "/"},
					},
				}},
			}},
		}},
	}

	if err := NewConfigValidator().Validate(cfg); err != nil {
		t.Fatalf("expected sse route to validate, got %v", err)
	}
}

func TestServicesConfigRuleAllowsGRPCWebProtocol(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Services: []ServiceConfig{{
			Version: 1,
			Services: []Service{{
				Name: "agent",
				Host: "http://agent:8080",
				Routes: []RouterConfig{{
					Path:     "/rpc.AgentService/Chat",
					Methods:  []string{"POST"},
					Protocol: "grpc-web",
					Backends: []Backend{
						{URLPattern: "/rpc.AgentService/Chat"},
					},
				}},
			}},
		}},
	}

	if err := NewConfigValidator().Validate(cfg); err != nil {
		t.Fatalf("expected grpc-web route to validate, got %v", err)
	}
}
