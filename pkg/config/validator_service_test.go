package config

import (
	"strings"
	"testing"
)

func TestServicesConfigRuleRejectsInvalidHost(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Services: []ServiceConfig{{
			Version: 1,
			Services: []Service{{
				Name: "identity",
				Host: "http://identity:prod:8080",
				Routes: []RouterConfig{{
					Path:    "/auth/{rest:.*}",
					Method:  "GET",
					Enabled: NewBool(true),
					Backends: []Backend{
						{URLPattern: "/api/{rest:.*}"},
					},
				}},
			}},
		}},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "host") {
		t.Fatalf("expected invalid host error, got %v", err)
	}
}

func TestServicesConfigRuleRejectsRestPatternWithoutRouteVar(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Services: []ServiceConfig{{
			Version: 1,
			Services: []Service{{
				Name: "identity",
				Host: "http://identity:8080",
				Routes: []RouterConfig{{
					Path:      "/auth/profile",
					Method:    "GET",
					StripPath: true,
					Enabled:   NewBool(true),
					Backends: []Backend{
						{URLPattern: "/api/{rest:.*}"},
					},
				}},
			}},
		}},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "{rest}") {
		t.Fatalf("expected rest variable validation error, got %v", err)
	}
}

func TestGetAllRoutesFromServicesAppliesBasePath(t *testing.T) {
	cfg := &Config{
		Services: []ServiceConfig{{
			Version: 1,
			Services: []Service{{
				Name:     "identity",
				Host:     "http://identity:8080",
				BasePath: "/{realm}/auth",
				Routes: []RouterConfig{{
					Path:   "/login",
					Method: "POST",
				}},
			}},
		}},
	}

	routes := cfg.GetAllRoutesFromServices(nil)
	if len(routes) != 1 {
		t.Fatalf("expected 1 route, got %d", len(routes))
	}
	if routes[0].Path != "/{realm}/auth/login" {
		t.Fatalf("expected prefixed route path, got %s", routes[0].Path)
	}
	if len(routes[0].Methods) != 1 || routes[0].Methods[0] != "POST" {
		t.Fatalf("expected normalized POST methods, got %#v", routes[0].Methods)
	}
}

func TestGetAllRoutesFromServicesMergesGlobalServiceAndRouteAIPresets(t *testing.T) {
	cfg := &Config{
		AIPolicyPresets: map[string]AIPolicyPreset{
			"shared": {AllowedModels: []string{"gpt-4.1-mini"}},
		},
		Services: []ServiceConfig{{
			Version: 1,
			Services: []Service{{
				Name: "identity",
				Host: "http://identity:8080",
				AIPolicyPresets: map[string]AIPolicyPreset{
					"shared": {AllowedModels: []string{"gpt-4.1"}},
					"svc":    {AllowedToolNames: []string{"web_search"}},
				},
				Routes: []RouterConfig{{
					Path:   "/login",
					Method: "POST",
					AIPolicyPresets: map[string]AIPolicyPreset{
						"shared": {RequiredRequestHeaders: []string{"X-Agent-Session"}},
					},
				}},
			}},
		}},
	}

	routes := cfg.GetAllRoutesFromServices(nil)
	if len(routes) != 1 {
		t.Fatalf("expected 1 route, got %d", len(routes))
	}
	if len(routes[0].AIPolicyPresets) != 2 {
		t.Fatalf("expected merged preset catalog, got %#v", routes[0].AIPolicyPresets)
	}
	if got := routes[0].AIPolicyPresets["shared"].RequiredRequestHeaders; len(got) != 1 || got[0] != "X-Agent-Session" {
		t.Fatalf("expected route-level preset to win, got %#v", routes[0].AIPolicyPresets["shared"])
	}
	if got := routes[0].AIPolicyPresets["svc"].AllowedToolNames; len(got) != 1 || got[0] != "web_search" {
		t.Fatalf("expected service-level preset to remain available, got %#v", routes[0].AIPolicyPresets["svc"])
	}
}

func TestServicesConfigRuleRejectsInvalidBackendHost(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Services: []ServiceConfig{{
			Version: 1,
			Services: []Service{{
				Name: "identity",
				Host: "http://identity:8080",
				Routes: []RouterConfig{{
					Path:    "/auth/{rest:.*}",
					Methods: []string{"GET"},
					Backends: []Backend{
						{URLPattern: "/api/{rest:.*}", Host: "ftp://bad.example.com"},
					},
				}},
			}},
		}},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), ".backend[0].host") {
		t.Fatalf("expected backend host validation error, got %v", err)
	}
}
