package config

import (
	"strings"
	"testing"
)

func TestServicesConfigRuleRejectsNegativeBackendWeight(t *testing.T) {
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
						{URLPattern: "/api/{rest:.*}", Weight: -1},
					},
				}},
			}},
		}},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), ".backend[0].weight") {
		t.Fatalf("expected backend weight validation error, got %v", err)
	}
}

func TestServicesConfigRuleRejectsNegativeBackendFailureThreshold(t *testing.T) {
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
						{URLPattern: "/api/{rest:.*}", FailureThreshold: -1},
					},
				}},
			}},
		}},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), ".backend[0].failureThreshold") {
		t.Fatalf("expected backend failureThreshold validation error, got %v", err)
	}
}

func TestServicesConfigRuleRejectsInvalidBackendCooldown(t *testing.T) {
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
						{URLPattern: "/api/{rest:.*}", Cooldown: "later"},
					},
				}},
			}},
		}},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), ".backend[0].cooldown") {
		t.Fatalf("expected backend cooldown validation error, got %v", err)
	}
}

func TestServicesConfigRuleRejectsInvalidBackendHealthCheckPath(t *testing.T) {
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
						{URLPattern: "/api/{rest:.*}", HealthCheckPath: "health"},
					},
				}},
			}},
		}},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), ".backend[0].healthCheckPath") {
		t.Fatalf("expected backend healthCheckPath validation error, got %v", err)
	}
}

func TestServicesConfigRuleRejectsInvalidBackendHealthInterval(t *testing.T) {
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
						{URLPattern: "/api/{rest:.*}", HealthCheckPath: "/health", HealthInterval: "later"},
					},
				}},
			}},
		}},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), ".backend[0].healthInterval") {
		t.Fatalf("expected backend healthInterval validation error, got %v", err)
	}
}

func TestServicesConfigRuleRejectsInvalidBackendHealthTimeout(t *testing.T) {
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
						{URLPattern: "/api/{rest:.*}", HealthCheckPath: "/health", HealthTimeout: "later"},
					},
				}},
			}},
		}},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), ".backend[0].healthTimeout") {
		t.Fatalf("expected backend healthTimeout validation error, got %v", err)
	}
}

func TestServicesConfigRuleRejectsNegativeRouteRetryCount(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Services: []ServiceConfig{{
			Version: 1,
			Services: []Service{{
				Name: "api",
				Host: "http://localhost:9000",
				Routes: []RouterConfig{{
					Path:        "/hello",
					Method:      "GET",
					RetryCount:  -1,
					Backends:    []Backend{{URLPattern: "/hello"}},
					ServiceHost: "http://localhost:9000",
				}},
			}},
		}},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), ".routes[0].retryCount") {
		t.Fatalf("expected retryCount validation error, got %v", err)
	}
}

func TestServicesConfigRuleRejectsInvalidRouteRetryBackoff(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Services: []ServiceConfig{{
			Version: 1,
			Services: []Service{{
				Name: "api",
				Host: "http://localhost:9000",
				Routes: []RouterConfig{{
					Path:         "/hello",
					Method:       "GET",
					RetryCount:   1,
					RetryBackoff: "later",
					Backends:     []Backend{{URLPattern: "/hello"}},
				}},
			}},
		}},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), ".routes[0].retryBackoff") {
		t.Fatalf("expected retryBackoff validation error, got %v", err)
	}
}

func TestServicesConfigRuleRejectsInvalidRouteRetryJitter(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Services: []ServiceConfig{{
			Version: 1,
			Services: []Service{{
				Name: "api",
				Host: "http://localhost:9000",
				Routes: []RouterConfig{{
					Path:         "/hello",
					Method:       "GET",
					RetryCount:   1,
					RetryBackoff: "100ms",
					RetryJitter:  "later",
					Backends:     []Backend{{URLPattern: "/hello"}},
				}},
			}},
		}},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), ".routes[0].retryJitter") {
		t.Fatalf("expected retryJitter validation error, got %v", err)
	}
}

func TestServicesConfigRuleRejectsInvalidRouteHedgeDelay(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Services: []ServiceConfig{{
			Version: 1,
			Services: []Service{{
				Name: "api",
				Host: "http://localhost:9000",
				Routes: []RouterConfig{{
					Path:       "/hello",
					Method:     "GET",
					HedgeDelay: "soon",
					Backends:   []Backend{{URLPattern: "/hello"}},
				}},
			}},
		}},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), ".routes[0].hedgeDelay") {
		t.Fatalf("expected hedgeDelay validation error, got %v", err)
	}
}

func TestServicesConfigRuleRejectsInvalidShadowTrafficPercent(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Services: []ServiceConfig{{
			Version: 1,
			Services: []Service{{
				Name: "api",
				Host: "http://localhost:9000",
				Routes: []RouterConfig{{
					Path:                 "/hello",
					Method:               "GET",
					ShadowTrafficPercent: 101,
					Backends:             []Backend{{URLPattern: "/hello"}},
				}},
			}},
		}},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), ".routes[0].shadowTrafficPercent") {
		t.Fatalf("expected shadowTrafficPercent validation error, got %v", err)
	}
}

func TestServicesConfigRuleRejectsInvalidShadowMaxLatencyDelta(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Services: []ServiceConfig{{
			Version: 1,
			Services: []Service{{
				Name: "api",
				Host: "http://localhost:9000",
				Routes: []RouterConfig{{
					Path:                  "/hello",
					Method:                "GET",
					ShadowTrafficPercent:  10,
					ShadowMaxLatencyDelta: "fast",
					Backends:              []Backend{{URLPattern: "/hello"}},
				}},
			}},
		}},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), ".routes[0].shadowMaxLatencyDelta") {
		t.Fatalf("expected shadowMaxLatencyDelta validation error, got %v", err)
	}
}

func TestServicesConfigRuleRejectsInvalidRouteRetryStatusCode(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Services: []ServiceConfig{{
			Version: 1,
			Services: []Service{{
				Name: "api",
				Host: "http://localhost:9000",
				Routes: []RouterConfig{{
					Path:          "/hello",
					Method:        "GET",
					RetryStatuses: []int{99},
					Backends:      []Backend{{URLPattern: "/hello"}},
				}},
			}},
		}},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), ".routes[0].retryStatusCodes[0]") {
		t.Fatalf("expected retryStatusCodes validation error, got %v", err)
	}
}

func TestServicesConfigRuleRejectsInvalidBackendTimeout(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Services: []ServiceConfig{{
			Version: 1,
			Services: []Service{{
				Name: "api",
				Host: "http://localhost:9000",
				Routes: []RouterConfig{{
					Path:   "/hello",
					Method: "GET",
					Backends: []Backend{{
						URLPattern: "/hello",
						Timeout:    "soon",
					}},
				}},
			}},
		}},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), ".backend[0].timeout") {
		t.Fatalf("expected backend timeout validation error, got %v", err)
	}
}

func TestServicesConfigRuleRejectsNegativeBackendHalfOpenMaxRequests(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Services: []ServiceConfig{{
			Version: 1,
			Services: []Service{{
				Name: "api",
				Host: "http://localhost:9000",
				Routes: []RouterConfig{{
					Path:   "/hello",
					Method: "GET",
					Backends: []Backend{{
						URLPattern:          "/hello",
						HalfOpenMaxRequests: -1,
					}},
				}},
			}},
		}},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), ".backend[0].halfOpenMaxRequests") {
		t.Fatalf("expected backend halfOpenMaxRequests validation error, got %v", err)
	}
}

func TestServicesConfigRuleRejectsNegativeBackendRecoverySuccessThreshold(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Services: []ServiceConfig{{
			Version: 1,
			Services: []Service{{
				Name: "api",
				Host: "http://localhost:9000",
				Routes: []RouterConfig{{
					Path:   "/hello",
					Method: "GET",
					Backends: []Backend{{
						URLPattern:               "/hello",
						RecoverySuccessThreshold: -1,
					}},
				}},
			}},
		}},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), ".backend[0].recoverySuccessThreshold") {
		t.Fatalf("expected backend recoverySuccessThreshold validation error, got %v", err)
	}
}

func TestServicesConfigRuleRejectsInvalidBackendOutlierLatencyThreshold(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Services: []ServiceConfig{{
			Version: 1,
			Services: []Service{{
				Name: "api",
				Host: "http://localhost:9000",
				Routes: []RouterConfig{{
					Path:   "/hello",
					Method: "GET",
					Backends: []Backend{{
						URLPattern:              "/hello",
						OutlierLatencyThreshold: "later",
					}},
				}},
			}},
		}},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), ".backend[0].outlierLatencyThreshold") {
		t.Fatalf("expected backend outlierLatencyThreshold validation error, got %v", err)
	}
}

func TestServicesConfigRuleRejectsNegativeBackendOutlierConsecutiveSlowResponses(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Services: []ServiceConfig{{
			Version: 1,
			Services: []Service{{
				Name: "api",
				Host: "http://localhost:9000",
				Routes: []RouterConfig{{
					Path:   "/hello",
					Method: "GET",
					Backends: []Backend{{
						URLPattern:                      "/hello",
						OutlierConsecutiveSlowResponses: -1,
					}},
				}},
			}},
		}},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), ".backend[0].outlierConsecutiveSlowResponses") {
		t.Fatalf("expected backend outlierConsecutiveSlowResponses validation error, got %v", err)
	}
}
