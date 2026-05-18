package config

import (
	"strings"
	"testing"
)

func TestServicesConfigRuleRejectsInvalidGraphQLPersistedQueryField(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Services: []ServiceConfig{{
			Version: 1,
			Services: []Service{{
				Name: "agent",
				Host: "http://agent:8080",
				Routes: []RouterConfig{{
					Path:                       "/graphql",
					Methods:                    []string{"POST"},
					Protocol:                   "graphql",
					GraphQLPersistedQueryField: "extensions..persistedQuery",
					Backends: []Backend{
						{URLPattern: "/graphql"},
					},
				}},
			}},
		}},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "graphqlPersistedQueryField") {
		t.Fatalf("expected graphqlPersistedQueryField validation error, got %v", err)
	}
}

func TestServicesConfigRuleRejectsEmptyGraphQLAllowedPersistedQuery(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Services: []ServiceConfig{{
			Version: 1,
			Services: []Service{{
				Name: "agent",
				Host: "http://agent:8080",
				Routes: []RouterConfig{{
					Path:                           "/graphql",
					Methods:                        []string{"POST"},
					Protocol:                       "graphql",
					GraphQLAllowedPersistedQueries: []string{"abc123", ""},
					Backends: []Backend{
						{URLPattern: "/graphql"},
					},
				}},
			}},
		}},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "graphqlAllowedPersistedQueries") {
		t.Fatalf("expected graphqlAllowedPersistedQueries validation error, got %v", err)
	}
}

func TestServicesConfigRuleRejectsEmptyGraphQLAllowedOperation(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Services: []ServiceConfig{{
			Version: 1,
			Services: []Service{{
				Name: "agent",
				Host: "http://agent:8080",
				Routes: []RouterConfig{{
					Path:                     "/graphql",
					Methods:                  []string{"POST"},
					Protocol:                 "graphql",
					GraphQLAllowedOperations: []string{"ChatQuery", ""},
					Backends: []Backend{
						{URLPattern: "/graphql"},
					},
				}},
			}},
		}},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "graphqlAllowedOperations") {
		t.Fatalf("expected graphqlAllowedOperations validation error, got %v", err)
	}
}

func TestServicesConfigRuleRejectsNegativeGraphQLLimits(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Services: []ServiceConfig{{
			Version: 1,
			Services: []Service{{
				Name: "agent",
				Host: "http://agent:8080",
				Routes: []RouterConfig{{
					Path:            "/graphql",
					Methods:         []string{"POST"},
					Protocol:        "graphql",
					GraphQLMaxDepth: -1,
					Backends: []Backend{
						{URLPattern: "/graphql"},
					},
				}},
			}},
		}},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "graphqlMaxDepth") {
		t.Fatalf("expected graphqlMaxDepth validation error, got %v", err)
	}
}

func TestServicesConfigRuleRejectsEmptyAllowedGraphQLVariableValue(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Services: []ServiceConfig{{
			Version: 1,
			Services: []Service{{
				Name: "agent",
				Host: "http://agent:8080",
				Routes: []RouterConfig{{
					Path:                    "/graphql",
					Methods:                 []string{"POST"},
					Protocol:                "graphql",
					GraphQLAllowedVariables: []string{"tenantId", ""},
					Backends: []Backend{
						{URLPattern: "/graphql"},
					},
				}},
			}},
		}},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "graphqlAllowedVariables") {
		t.Fatalf("expected graphqlAllowedVariables validation error, got %v", err)
	}
}

func TestServicesConfigRuleRejectsEmptyRequiredGraphQLVariableValue(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Services: []ServiceConfig{{
			Version: 1,
			Services: []Service{{
				Name: "agent",
				Host: "http://agent:8080",
				Routes: []RouterConfig{{
					Path:                     "/graphql",
					Methods:                  []string{"POST"},
					Protocol:                 "graphql",
					GraphQLRequiredVariables: []string{"tenantId", ""},
					Backends: []Backend{
						{URLPattern: "/graphql"},
					},
				}},
			}},
		}},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "graphqlRequiredVariables") {
		t.Fatalf("expected graphqlRequiredVariables validation error, got %v", err)
	}
}

func TestServicesConfigRuleRejectsInvalidGraphQLVariableRegex(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Services: []ServiceConfig{{
			Version: 1,
			Services: []Service{{
				Name: "agent",
				Host: "http://agent:8080",
				Routes: []RouterConfig{{
					Path:                 "/graphql",
					Methods:              []string{"POST"},
					Protocol:             "graphql",
					GraphQLVariableRegex: map[string]string{"tenantId": "["},
					Backends: []Backend{
						{URLPattern: "/graphql"},
					},
				}},
			}},
		}},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "graphqlVariableRegex") {
		t.Fatalf("expected graphqlVariableRegex validation error, got %v", err)
	}
}

func TestServicesConfigRuleRejectsEmptyGraphQLVariableAllowedValues(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Services: []ServiceConfig{{
			Version: 1,
			Services: []Service{{
				Name: "agent",
				Host: "http://agent:8080",
				Routes: []RouterConfig{{
					Path:                         "/graphql",
					Methods:                      []string{"POST"},
					Protocol:                     "graphql",
					GraphQLVariableAllowedValues: map[string][]string{"mode": {"", "safe"}},
					Backends: []Backend{
						{URLPattern: "/graphql"},
					},
				}},
			}},
		}},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "graphqlVariableAllowedValues") {
		t.Fatalf("expected graphqlVariableAllowedValues validation error, got %v", err)
	}
}

func TestServicesConfigRuleRejectsInvalidGraphQLOperationPolicyRegex(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Services: []ServiceConfig{{
			Version: 1,
			Services: []Service{{
				Name: "agent",
				Host: "http://agent:8080",
				Routes: []RouterConfig{{
					Path:     "/graphql",
					Methods:  []string{"POST"},
					Protocol: "graphql",
					GraphQLOperationPolicies: map[string]GraphQLOperationPolicy{
						"ChatQuery": {VariableRegex: map[string]string{"tenantId": "["}},
					},
					Backends: []Backend{
						{URLPattern: "/graphql"},
					},
				}},
			}},
		}},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "graphqlOperationPolicies") {
		t.Fatalf("expected graphqlOperationPolicies validation error, got %v", err)
	}
}

func TestServicesConfigRuleRejectsInvalidGraphQLOperationPolicyResponseRegex(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Services: []ServiceConfig{{
			Version: 1,
			Services: []Service{{
				Name: "agent",
				Host: "http://agent:8080",
				Routes: []RouterConfig{{
					Path:     "/graphql",
					Methods:  []string{"POST"},
					Protocol: "graphql",
					GraphQLOperationPolicies: map[string]GraphQLOperationPolicy{
						"ChatQuery": {ResponseBodyBlockRegex: []string{"["}},
					},
					Backends: []Backend{
						{URLPattern: "/graphql"},
					},
				}},
			}},
		}},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "graphqlOperationPolicies") {
		t.Fatalf("expected graphqlOperationPolicies validation error, got %v", err)
	}
}

func TestServicesConfigRuleRejectsInvalidGraphQLOperationPolicyRequestRegex(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Services: []ServiceConfig{{
			Version: 1,
			Services: []Service{{
				Name: "agent",
				Host: "http://agent:8080",
				Routes: []RouterConfig{{
					Path:     "/graphql",
					Methods:  []string{"POST"},
					Protocol: "graphql",
					GraphQLOperationPolicies: map[string]GraphQLOperationPolicy{
						"ChatQuery": {RequestBodyBlockRegex: []string{"["}},
					},
					Backends: []Backend{
						{URLPattern: "/graphql"},
					},
				}},
			}},
		}},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "graphqlOperationPolicies") {
		t.Fatalf("expected graphqlOperationPolicies request regex validation error, got %v", err)
	}
}

func TestServicesConfigRuleRejectsInvalidGraphQLOperationPolicyRequiredHeaderRegex(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Services: []ServiceConfig{{
			Version: 1,
			Services: []Service{{
				Name: "agent",
				Host: "http://agent:8080",
				Routes: []RouterConfig{{
					Path:     "/graphql",
					Methods:  []string{"POST"},
					Protocol: "graphql",
					GraphQLOperationPolicies: map[string]GraphQLOperationPolicy{
						"ChatQuery": {RequiredRequestHeaderRegex: map[string]string{"X-Agent-Session": "["}},
					},
					Backends: []Backend{
						{URLPattern: "/graphql"},
					},
				}},
			}},
		}},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "graphqlOperationPolicies") {
		t.Fatalf("expected graphqlOperationPolicies required header regex validation error, got %v", err)
	}
}

func TestServicesConfigRuleRejectsInvalidGraphQLOperationPolicySuccessEnvelope(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Services: []ServiceConfig{{
			Version: 1,
			Services: []Service{{
				Name: "agent",
				Host: "http://agent:8080",
				Routes: []RouterConfig{{
					Path:     "/graphql",
					Methods:  []string{"POST"},
					Protocol: "graphql",
					GraphQLOperationPolicies: map[string]GraphQLOperationPolicy{
						"ChatQuery": {SuccessResponseFields: map[string]string{"": "ok"}},
					},
					Backends: []Backend{
						{URLPattern: "/graphql"},
					},
				}},
			}},
		}},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "graphqlOperationPolicies") {
		t.Fatalf("expected graphqlOperationPolicies validation error, got %v", err)
	}
}

func TestServicesConfigRuleRejectsInvalidGraphQLOperationPolicyResponseJSONField(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Services: []ServiceConfig{{
			Version: 1,
			Services: []Service{{
				Name: "agent",
				Host: "http://agent:8080",
				Routes: []RouterConfig{{
					Path:     "/graphql",
					Methods:  []string{"POST"},
					Protocol: "graphql",
					GraphQLOperationPolicies: map[string]GraphQLOperationPolicy{
						"ChatQuery": {ResponseJSONFields: map[string]string{"": "ok"}},
					},
					Backends: []Backend{
						{URLPattern: "/graphql"},
					},
				}},
			}},
		}},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "graphqlOperationPolicies") {
		t.Fatalf("expected graphqlOperationPolicies validation error, got %v", err)
	}
}

func TestServicesConfigRuleRejectsInvalidGraphQLOperationPolicyResponseHeader(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Services: []ServiceConfig{{
			Version: 1,
			Services: []Service{{
				Name: "agent",
				Host: "http://agent:8080",
				Routes: []RouterConfig{{
					Path:     "/graphql",
					Methods:  []string{"POST"},
					Protocol: "graphql",
					GraphQLOperationPolicies: map[string]GraphQLOperationPolicy{
						"ChatQuery": {ResponseHeaders: map[string]string{"": "bad"}},
					},
					Backends: []Backend{
						{URLPattern: "/graphql"},
					},
				}},
			}},
		}},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "graphqlOperationPolicies") {
		t.Fatalf("expected graphqlOperationPolicies validation error, got %v", err)
	}
}

func TestServicesConfigRuleRejectsInvalidGraphQLOperationPolicyResponseStatusClass(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Services: []ServiceConfig{{
			Version: 1,
			Services: []Service{{
				Name: "agent",
				Host: "http://agent:8080",
				Routes: []RouterConfig{{
					Path:     "/graphql",
					Methods:  []string{"POST"},
					Protocol: "graphql",
					GraphQLOperationPolicies: map[string]GraphQLOperationPolicy{
						"ChatQuery": {ResponseTransformStatusClasses: []string{"6xx"}},
					},
					Backends: []Backend{
						{URLPattern: "/graphql"},
					},
				}},
			}},
		}},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "graphqlOperationPolicies") {
		t.Fatalf("expected graphqlOperationPolicies validation error, got %v", err)
	}
}

func TestServicesConfigRuleRejectsInvalidGraphQLOperationPolicyRequestHeader(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Services: []ServiceConfig{{
			Version: 1,
			Services: []Service{{
				Name: "agent",
				Host: "http://agent:8080",
				Routes: []RouterConfig{{
					Path:     "/graphql",
					Methods:  []string{"POST"},
					Protocol: "graphql",
					GraphQLOperationPolicies: map[string]GraphQLOperationPolicy{
						"ChatQuery": {RequestHeaders: map[string]string{"": "bad"}},
					},
					Backends: []Backend{
						{URLPattern: "/graphql"},
					},
				}},
			}},
		}},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "graphqlOperationPolicies") {
		t.Fatalf("expected graphqlOperationPolicies validation error, got %v", err)
	}
}

func TestServicesConfigRuleRejectsEmptyGraphQLOperationPolicyPersistedQueryHash(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Services: []ServiceConfig{{
			Version: 1,
			Services: []Service{{
				Name: "agent",
				Host: "http://agent:8080",
				Routes: []RouterConfig{{
					Path:     "/graphql",
					Methods:  []string{"POST"},
					Protocol: "graphql",
					GraphQLOperationPolicies: map[string]GraphQLOperationPolicy{
						"ChatQuery": {AllowedPersistedQueries: []string{"abc123", ""}},
					},
					Backends: []Backend{
						{URLPattern: "/graphql"},
					},
				}},
			}},
		}},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "graphqlOperationPolicies") {
		t.Fatalf("expected graphqlOperationPolicies validation error, got %v", err)
	}
}

func TestServicesConfigRuleRejectsEmptyGraphQLOperationPolicyAllowedModel(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Services: []ServiceConfig{{
			Version: 1,
			Services: []Service{{
				Name: "agent",
				Host: "http://agent:8080",
				Routes: []RouterConfig{{
					Path:     "/graphql",
					Methods:  []string{"POST"},
					Protocol: "graphql",
					GraphQLOperationPolicies: map[string]GraphQLOperationPolicy{
						"ChatQuery": {AllowedModels: []string{"gpt-4.1-mini", ""}},
					},
					Backends: []Backend{
						{URLPattern: "/graphql"},
					},
				}},
			}},
		}},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "graphqlOperationPolicies") {
		t.Fatalf("expected graphqlOperationPolicies allowedModels validation error, got %v", err)
	}
}

func TestServicesConfigRuleRejectsNegativeGraphQLOperationPolicyMaxInputTokens(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Services: []ServiceConfig{{
			Version: 1,
			Services: []Service{{
				Name: "agent",
				Host: "http://agent:8080",
				Routes: []RouterConfig{{
					Path:     "/graphql",
					Methods:  []string{"POST"},
					Protocol: "graphql",
					GraphQLOperationPolicies: map[string]GraphQLOperationPolicy{
						"ChatQuery": {MaxInputTokens: -1},
					},
					Backends: []Backend{
						{URLPattern: "/graphql"},
					},
				}},
			}},
		}},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "graphqlOperationPolicies") {
		t.Fatalf("expected graphqlOperationPolicies maxInputTokens validation error, got %v", err)
	}
}

func TestServicesConfigRuleRejectsNegativeGraphQLOperationPolicyMaxMessages(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Services: []ServiceConfig{{
			Version: 1,
			Services: []Service{{
				Name: "agent",
				Host: "http://agent:8080",
				Routes: []RouterConfig{{
					Path:     "/graphql",
					Methods:  []string{"POST"},
					Protocol: "graphql",
					GraphQLOperationPolicies: map[string]GraphQLOperationPolicy{
						"ChatQuery": {MaxMessages: -1},
					},
					Backends: []Backend{
						{URLPattern: "/graphql"},
					},
				}},
			}},
		}},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "graphqlOperationPolicies") {
		t.Fatalf("expected graphqlOperationPolicies maxMessages validation error, got %v", err)
	}
}

func TestServicesConfigRuleRejectsEmptyGraphQLOperationPolicyAllowedUpstreamHost(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Services: []ServiceConfig{{
			Version: 1,
			Services: []Service{{
				Name: "agent",
				Host: "http://agent:8080",
				Routes: []RouterConfig{{
					Path:     "/graphql",
					Methods:  []string{"POST"},
					Protocol: "graphql",
					GraphQLOperationPolicies: map[string]GraphQLOperationPolicy{
						"ChatQuery": {AllowedUpstreamHosts: []string{"api.openai.com", ""}},
					},
					Backends: []Backend{
						{URLPattern: "/graphql"},
					},
				}},
			}},
		}},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "graphqlOperationPolicies") {
		t.Fatalf("expected graphqlOperationPolicies allowedUpstreamHosts validation error, got %v", err)
	}
}

func TestServicesConfigRuleRejectsUnknownGraphQLOperationPolicyPreset(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Services: []ServiceConfig{{
			Version: 1,
			Services: []Service{{
				Name: "agent",
				Host: "http://agent:8080",
				Routes: []RouterConfig{{
					Path:     "/graphql",
					Methods:  []string{"POST"},
					Protocol: "graphql",
					GraphQLOperationPolicies: map[string]GraphQLOperationPolicy{
						"ChatQuery": {Preset: "safe-chat"},
					},
					Backends: []Backend{
						{URLPattern: "/graphql"},
					},
				}},
			}},
		}},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), ".preset") {
		t.Fatalf("expected graphql operation preset validation error, got %v", err)
	}
}

func TestServicesConfigRuleRejectsUnknownAIPolicyPreset(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Services: []ServiceConfig{{
			Version: 1,
			Services: []Service{{
				Name: "agent",
				Host: "http://agent:8080",
				Routes: []RouterConfig{{
					Path:           "/chat",
					Methods:        []string{"POST"},
					AIPolicyPreset: "safe-agent",
					Backends: []Backend{
						{URLPattern: "/chat"},
					},
				}},
			}},
		}},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), ".aiPolicyPreset") {
		t.Fatalf("expected aiPolicyPreset validation error, got %v", err)
	}
}

func TestServicesConfigRuleRejectsUnknownAIPolicyPresetChainEntry(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Services: []ServiceConfig{{
			Version: 1,
			Services: []Service{{
				Name: "agent",
				Host: "http://agent:8080",
				Routes: []RouterConfig{{
					Path:                "/chat",
					Methods:             []string{"POST"},
					AIPolicyPresetChain: []string{"safe-agent", "missing"},
					AIPolicyPresets: map[string]AIPolicyPreset{
						"safe-agent": {AllowedModels: []string{"gpt-4.1"}},
					},
					Backends: []Backend{
						{URLPattern: "/chat"},
					},
				}},
			}},
		}},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), ".aiPolicyPresetChain") {
		t.Fatalf("expected aiPolicyPresetChain validation error, got %v", err)
	}
}

func TestServicesConfigRuleAllowsServiceLevelAIPolicyPresetReference(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Services: []ServiceConfig{{
			Version: 1,
			Services: []Service{{
				Name: "agent",
				Host: "http://agent:8080",
				AIPolicyPresets: map[string]AIPolicyPreset{
					"safe-agent": {
						AllowedModels: []string{"gpt-4.1"},
					},
				},
				Routes: []RouterConfig{{
					Path:           "/chat",
					Methods:        []string{"POST"},
					AIPolicyPreset: "safe-agent",
					Backends: []Backend{
						{URLPattern: "/chat"},
					},
				}},
			}},
		}},
	}

	if err := NewConfigValidator().Validate(cfg); err != nil {
		t.Fatalf("expected service-level aiPolicyPreset reference to validate, got %v", err)
	}
}

func TestServicesConfigRuleAllowsGlobalAIPolicyPresetReference(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		AIPolicyPresets: map[string]AIPolicyPreset{
			"safe-agent": {
				AllowedModels: []string{"gpt-4.1"},
			},
		},
		Services: []ServiceConfig{{
			Version: 1,
			Services: []Service{{
				Name: "agent",
				Host: "http://agent:8080",
				Routes: []RouterConfig{{
					Path:           "/chat",
					Methods:        []string{"POST"},
					AIPolicyPreset: "safe-agent",
					Backends: []Backend{
						{URLPattern: "/chat"},
					},
				}},
			}},
		}},
	}

	if err := NewConfigValidator().Validate(cfg); err != nil {
		t.Fatalf("expected global aiPolicyPreset reference to validate, got %v", err)
	}
}
