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

func TestStorageConfigRuleRejectsInvalidMode(t *testing.T) {
	cfg := &Config{
		Server:  ServerConfig{Port: 8080},
		Storage: StorageConfig{Mode: "oracle"},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "storage mode") {
		t.Fatalf("expected storage mode validation error, got %v", err)
	}
}

func TestStorageConfigRuleAllowsFileMode(t *testing.T) {
	cfg := &Config{
		Server:  ServerConfig{Port: 8080},
		Storage: StorageConfig{Mode: "file"},
	}

	if err := NewConfigValidator().Validate(cfg); err != nil {
		t.Fatalf("expected file storage mode to validate, got %v", err)
	}
}

func TestStorageConfigRuleRequiresPostgresURL(t *testing.T) {
	cfg := &Config{
		Server:  ServerConfig{Port: 8080},
		Storage: StorageConfig{Mode: "postgres"},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "postgres_url") {
		t.Fatalf("expected postgres_url validation error, got %v", err)
	}
}

func TestSecurityConfigRuleRejectsNegativeEnrollmentMaxActive(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Security: SecurityConfig{
			TLS: TLSConfig{
				Enabled:             true,
				CertFile:            "server.crt",
				KeyFile:             "server.key",
				EnrollmentMaxActive: -1,
			},
		},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "enrollmentMaxActive") {
		t.Fatalf("expected enrollmentMaxActive validation error, got %v", err)
	}
}
