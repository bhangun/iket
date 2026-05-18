package config

import (
	"strings"
	"testing"
)

func TestServicesConfigRuleRejectsEmptyCORSOrigin(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Services: []ServiceConfig{{
			Version: 1,
			Services: []Service{{
				Name: "identity",
				Host: "http://identity:8080",
				Routes: []RouterConfig{{
					Path:    "/auth",
					Methods: []string{"GET"},
					CORS: &CORSConfig{
						AllowedOrigins: []string{"", "https://app.example.com"},
					},
					Backends: []Backend{
						{URLPattern: "/auth"},
					},
				}},
			}},
		}},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), ".cors.allowedOrigins") {
		t.Fatalf("expected CORS allowedOrigins validation error, got %v", err)
	}
}

func TestServicesConfigRuleRejectsInvalidCORSMethod(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Services: []ServiceConfig{{
			Version: 1,
			Services: []Service{{
				Name: "identity",
				Host: "http://identity:8080",
				Routes: []RouterConfig{{
					Path:    "/auth",
					Methods: []string{"GET"},
					CORS: &CORSConfig{
						AllowedOrigins: []string{"https://app.example.com"},
						AllowedMethods: []string{"FETCH"},
					},
					Backends: []Backend{
						{URLPattern: "/auth"},
					},
				}},
			}},
		}},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), ".cors.allowedMethods") {
		t.Fatalf("expected CORS allowedMethods validation error, got %v", err)
	}
}

func TestServicesConfigRuleRejectsEmptyRequestHeaderTransformName(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Services: []ServiceConfig{{
			Version: 1,
			Services: []Service{{
				Name: "identity",
				Host: "http://identity:8080",
				Routes: []RouterConfig{{
					Path:    "/auth",
					Methods: []string{"GET"},
					RequestHeaders: map[string]string{
						"": "bad",
					},
					Backends: []Backend{
						{URLPattern: "/auth"},
					},
				}},
			}},
		}},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), ".requestHeaders") {
		t.Fatalf("expected requestHeaders validation error, got %v", err)
	}
}

func TestServicesConfigRuleRejectsEmptyRemoveResponseHeaderValue(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Services: []ServiceConfig{{
			Version: 1,
			Services: []Service{{
				Name: "identity",
				Host: "http://identity:8080",
				Routes: []RouterConfig{{
					Path:                  "/auth",
					Methods:               []string{"GET"},
					RemoveResponseHeaders: []string{"", "X-Legacy"},
					Backends: []Backend{
						{URLPattern: "/auth"},
					},
				}},
			}},
		}},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), ".removeResponseHeaders") {
		t.Fatalf("expected removeResponseHeaders validation error, got %v", err)
	}
}

func TestServicesConfigRuleRejectsEmptyQueryParamTransformName(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Services: []ServiceConfig{{
			Version: 1,
			Services: []Service{{
				Name: "identity",
				Host: "http://identity:8080",
				Routes: []RouterConfig{{
					Path:    "/auth",
					Methods: []string{"GET"},
					QueryParams: map[string]string{
						"": "bad",
					},
					Backends: []Backend{
						{URLPattern: "/auth"},
					},
				}},
			}},
		}},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), ".queryParams") {
		t.Fatalf("expected queryParams validation error, got %v", err)
	}
}

func TestServicesConfigRuleRejectsEmptyRequestJSONFieldName(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Services: []ServiceConfig{{
			Version: 1,
			Services: []Service{{
				Name: "identity",
				Host: "http://identity:8080",
				Routes: []RouterConfig{{
					Path:    "/auth",
					Methods: []string{"POST"},
					RequestJSONFields: map[string]string{
						"": "bad",
					},
					Backends: []Backend{
						{URLPattern: "/auth"},
					},
				}},
			}},
		}},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), ".requestJSONFields") {
		t.Fatalf("expected requestJSONFields validation error, got %v", err)
	}
}

func TestServicesConfigRuleRejectsInvalidNestedRequestJSONFieldPath(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Services: []ServiceConfig{{
			Version: 1,
			Services: []Service{{
				Name: "identity",
				Host: "http://identity:8080",
				Routes: []RouterConfig{{
					Path:    "/auth",
					Methods: []string{"POST"},
					RequestJSONFields: map[string]string{
						"user..realm": "bad",
					},
					Backends: []Backend{
						{URLPattern: "/auth"},
					},
				}},
			}},
		}},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), ".requestJSONFields") {
		t.Fatalf("expected requestJSONFields path validation error, got %v", err)
	}
}

func TestServicesConfigRuleRejectsInvalidTypedRequestJSONLiteral(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Services: []ServiceConfig{{
			Version: 1,
			Services: []Service{{
				Name: "identity",
				Host: "http://identity:8080",
				Routes: []RouterConfig{{
					Path:    "/auth",
					Methods: []string{"POST"},
					RequestJSONFields: map[string]string{
						"meta.enabled": "json:{bad}",
					},
					Backends: []Backend{
						{URLPattern: "/auth"},
					},
				}},
			}},
		}},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), ".requestJSONFields") {
		t.Fatalf("expected requestJSONFields literal validation error, got %v", err)
	}
}

func TestServicesConfigRuleRejectsAppendSyntaxInRemoveRequestJSONFieldPath(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Services: []ServiceConfig{{
			Version: 1,
			Services: []Service{{
				Name: "identity",
				Host: "http://identity:8080",
				Routes: []RouterConfig{{
					Path:                    "/auth",
					Methods:                 []string{"POST"},
					RemoveRequestJSONFields: []string{"users[]"},
					Backends: []Backend{
						{URLPattern: "/auth"},
					},
				}},
			}},
		}},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), ".removeRequestJSONFields") {
		t.Fatalf("expected removeRequestJSONFields path validation error, got %v", err)
	}
}

func TestServicesConfigRuleRejectsEmptyRemoveRequestJSONFieldValue(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Services: []ServiceConfig{{
			Version: 1,
			Services: []Service{{
				Name: "identity",
				Host: "http://identity:8080",
				Routes: []RouterConfig{{
					Path:                    "/auth",
					Methods:                 []string{"POST"},
					RemoveRequestJSONFields: []string{"", "legacy"},
					Backends: []Backend{
						{URLPattern: "/auth"},
					},
				}},
			}},
		}},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), ".removeRequestJSONFields") {
		t.Fatalf("expected removeRequestJSONFields validation error, got %v", err)
	}
}

func TestServicesConfigRuleRejectsEmptyRemoveQueryParamValue(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Services: []ServiceConfig{{
			Version: 1,
			Services: []Service{{
				Name: "identity",
				Host: "http://identity:8080",
				Routes: []RouterConfig{{
					Path:              "/auth",
					Methods:           []string{"GET"},
					RemoveQueryParams: []string{"", "legacy"},
					Backends: []Backend{
						{URLPattern: "/auth"},
					},
				}},
			}},
		}},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), ".removeQueryParams") {
		t.Fatalf("expected removeQueryParams validation error, got %v", err)
	}
}

func TestServicesConfigRuleRejectsEmptyTransformWhenHeaderName(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Services: []ServiceConfig{{
			Version: 1,
			Services: []Service{{
				Name: "identity",
				Host: "http://identity:8080",
				Routes: []RouterConfig{{
					Path:    "/auth",
					Methods: []string{"GET"},
					TransformWhenHeaders: map[string]string{
						"": "beta",
					},
					Backends: []Backend{
						{URLPattern: "/auth"},
					},
				}},
			}},
		}},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), ".transformWhenHeaders") {
		t.Fatalf("expected transformWhenHeaders validation error, got %v", err)
	}
}

func TestServicesConfigRuleRejectsEmptyTransformWhenQueryParamName(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Services: []ServiceConfig{{
			Version: 1,
			Services: []Service{{
				Name: "identity",
				Host: "http://identity:8080",
				Routes: []RouterConfig{{
					Path:    "/auth",
					Methods: []string{"GET"},
					TransformWhenQueryParams: map[string]string{
						"": "preview",
					},
					Backends: []Backend{
						{URLPattern: "/auth"},
					},
				}},
			}},
		}},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), ".transformWhenQueryParams") {
		t.Fatalf("expected transformWhenQueryParams validation error, got %v", err)
	}
}

func TestServicesConfigRuleRejectsInvalidTransformWhenHeaderRegex(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Services: []ServiceConfig{{
			Version: 1,
			Services: []Service{{
				Name: "identity",
				Host: "http://identity:8080",
				Routes: []RouterConfig{{
					Path:    "/auth",
					Methods: []string{"GET"},
					TransformWhenHeaderRegex: map[string]string{
						"X-Mode": "[",
					},
					Backends: []Backend{
						{URLPattern: "/auth"},
					},
				}},
			}},
		}},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), ".transformWhenHeaderRegex") {
		t.Fatalf("expected transformWhenHeaderRegex validation error, got %v", err)
	}
}

func TestServicesConfigRuleRejectsInvalidTransformWhenQueryRegex(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Services: []ServiceConfig{{
			Version: 1,
			Services: []Service{{
				Name: "identity",
				Host: "http://identity:8080",
				Routes: []RouterConfig{{
					Path:    "/auth",
					Methods: []string{"GET"},
					TransformWhenQueryRegex: map[string]string{
						"mode": "(",
					},
					Backends: []Backend{
						{URLPattern: "/auth"},
					},
				}},
			}},
		}},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), ".transformWhenQueryRegex") {
		t.Fatalf("expected transformWhenQueryRegex validation error, got %v", err)
	}
}

func TestServicesConfigRuleRejectsInvalidTransformScope(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Services: []ServiceConfig{{
			Version: 1,
			Services: []Service{{
				Name: "identity",
				Host: "http://identity:8080",
				Routes: []RouterConfig{{
					Path:            "/auth",
					Methods:         []string{"GET"},
					TransformScopes: []string{"request_json", "all"},
					Backends: []Backend{
						{URLPattern: "/auth"},
					},
				}},
			}},
		}},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), ".transformScopes") {
		t.Fatalf("expected transformScopes validation error, got %v", err)
	}
}

func TestServicesConfigRuleRejectsInvalidResponseTransformStatusClass(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Services: []ServiceConfig{{
			Version: 1,
			Services: []Service{{
				Name: "identity",
				Host: "http://identity:8080",
				Routes: []RouterConfig{{
					Path:                           "/auth",
					Methods:                        []string{"GET"},
					ResponseTransformStatusClasses: []string{"success"},
					Backends: []Backend{
						{URLPattern: "/auth"},
					},
				}},
			}},
		}},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), ".responseTransformStatusClasses") {
		t.Fatalf("expected responseTransformStatusClasses validation error, got %v", err)
	}
}

func TestServicesConfigRuleRejectsInvalidTransformMethod(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Services: []ServiceConfig{{
			Version: 1,
			Services: []Service{{
				Name: "identity",
				Host: "http://identity:8080",
				Routes: []RouterConfig{{
					Path:             "/auth",
					Methods:          []string{"GET"},
					TransformMethods: []string{"FETCH"},
					Backends: []Backend{
						{URLPattern: "/auth"},
					},
				}},
			}},
		}},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), ".transformMethods") {
		t.Fatalf("expected transformMethods validation error, got %v", err)
	}
}

func TestServicesConfigRuleRejectsInvalidResponseTransformHeaderRegex(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Services: []ServiceConfig{{
			Version: 1,
			Services: []Service{{
				Name: "identity",
				Host: "http://identity:8080",
				Routes: []RouterConfig{{
					Path:    "/auth",
					Methods: []string{"GET"},
					ResponseTransformHeaderRegex: map[string]string{
						"Content-Type": "(",
					},
					Backends: []Backend{
						{URLPattern: "/auth"},
					},
				}},
			}},
		}},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), ".responseTransformHeaderRegex") {
		t.Fatalf("expected responseTransformHeaderRegex validation error, got %v", err)
	}
}

func TestServicesConfigRuleRejectsEmptyErrorResponseFieldName(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Services: []ServiceConfig{{
			Version: 1,
			Services: []Service{{
				Name: "identity",
				Host: "http://identity:8080",
				Routes: []RouterConfig{{
					Path:    "/auth",
					Methods: []string{"GET"},
					ErrorResponseFields: map[string]string{
						"": "bad",
					},
					Backends: []Backend{
						{URLPattern: "/auth"},
					},
				}},
			}},
		}},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), ".errorResponseFields") {
		t.Fatalf("expected errorResponseFields validation error, got %v", err)
	}
}

func TestServicesConfigRuleRejectsEmptySuccessResponseFieldName(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Services: []ServiceConfig{{
			Version: 1,
			Services: []Service{{
				Name: "identity",
				Host: "http://identity:8080",
				Routes: []RouterConfig{{
					Path:    "/auth",
					Methods: []string{"GET"},
					SuccessResponseFields: map[string]string{
						"": "bad",
					},
					Backends: []Backend{
						{URLPattern: "/auth"},
					},
				}},
			}},
		}},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), ".successResponseFields") {
		t.Fatalf("expected successResponseFields validation error, got %v", err)
	}
}

func TestServicesConfigRuleRejectsEmptyResponseRedactHeaderValue(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Services: []ServiceConfig{{
			Version: 1,
			Services: []Service{{
				Name: "identity",
				Host: "http://identity:8080",
				Routes: []RouterConfig{{
					Path:                  "/auth",
					Methods:               []string{"GET"},
					ResponseRedactHeaders: []string{"Authorization", ""},
					Backends: []Backend{
						{URLPattern: "/auth"},
					},
				}},
			}},
		}},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), ".responseRedactHeaders") {
		t.Fatalf("expected responseRedactHeaders validation error, got %v", err)
	}
}

func TestServicesConfigRuleRejectsNegativeMaxRequestBodyBytes(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Services: []ServiceConfig{{
			Version: 1,
			Services: []Service{{
				Name: "identity",
				Host: "http://identity:8080",
				Routes: []RouterConfig{{
					Path:                "/auth",
					Methods:             []string{"POST"},
					MaxRequestBodyBytes: -1,
					Backends: []Backend{
						{URLPattern: "/auth"},
					},
				}},
			}},
		}},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), ".maxRequestBodyBytes") {
		t.Fatalf("expected maxRequestBodyBytes validation error, got %v", err)
	}
}

func TestServicesConfigRuleRejectsEmptyAllowedModelValue(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Services: []ServiceConfig{{
			Version: 1,
			Services: []Service{{
				Name: "identity",
				Host: "http://identity:8080",
				Routes: []RouterConfig{{
					Path:          "/chat",
					Methods:       []string{"POST"},
					AllowedModels: []string{"gpt-4.1", ""},
					Backends: []Backend{
						{URLPattern: "/chat"},
					},
				}},
			}},
		}},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), ".allowedModels") {
		t.Fatalf("expected allowedModels validation error, got %v", err)
	}
}

func TestServicesConfigRuleRejectsEmptyAllowedUpstreamHostValue(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Services: []ServiceConfig{{
			Version: 1,
			Services: []Service{{
				Name: "identity",
				Host: "http://identity:8080",
				Routes: []RouterConfig{{
					Path:                 "/chat",
					Methods:              []string{"POST"},
					AllowedUpstreamHosts: []string{"api.openai.com", ""},
					Backends: []Backend{
						{URLPattern: "/chat"},
					},
				}},
			}},
		}},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), ".allowedUpstreamHosts") {
		t.Fatalf("expected allowedUpstreamHosts validation error, got %v", err)
	}
}

func TestServicesConfigRuleRejectsEmptyAllowedToolNameValue(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Services: []ServiceConfig{{
			Version: 1,
			Services: []Service{{
				Name: "identity",
				Host: "http://identity:8080",
				Routes: []RouterConfig{{
					Path:             "/chat",
					Methods:          []string{"POST"},
					AllowedToolNames: []string{"web_search", ""},
					Backends: []Backend{
						{URLPattern: "/chat"},
					},
				}},
			}},
		}},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), ".allowedToolNames") {
		t.Fatalf("expected allowedToolNames validation error, got %v", err)
	}
}

func TestServicesConfigRuleRejectsInvalidToolField(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Services: []ServiceConfig{{
			Version: 1,
			Services: []Service{{
				Name: "identity",
				Host: "http://identity:8080",
				Routes: []RouterConfig{{
					Path:      "/chat",
					Methods:   []string{"POST"},
					ToolField: "tools..name",
					Backends: []Backend{
						{URLPattern: "/chat"},
					},
				}},
			}},
		}},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), ".toolField") {
		t.Fatalf("expected toolField validation error, got %v", err)
	}
}

func TestServicesConfigRuleRejectsNegativeMaxInputTokens(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Services: []ServiceConfig{{
			Version: 1,
			Services: []Service{{
				Name: "identity",
				Host: "http://identity:8080",
				Routes: []RouterConfig{{
					Path:           "/chat",
					Methods:        []string{"POST"},
					MaxInputTokens: -1,
					Backends: []Backend{
						{URLPattern: "/chat"},
					},
				}},
			}},
		}},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), ".maxInputTokens") {
		t.Fatalf("expected maxInputTokens validation error, got %v", err)
	}
}

func TestServicesConfigRuleRejectsInvalidOutputTokensField(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Services: []ServiceConfig{{
			Version: 1,
			Services: []Service{{
				Name: "identity",
				Host: "http://identity:8080",
				Routes: []RouterConfig{{
					Path:              "/chat",
					Methods:           []string{"POST"},
					MaxOutputTokens:   512,
					OutputTokensField: "usage..max",
					Backends: []Backend{
						{URLPattern: "/chat"},
					},
				}},
			}},
		}},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), ".outputTokensField") {
		t.Fatalf("expected outputTokensField validation error, got %v", err)
	}
}

func TestServicesConfigRuleRejectsNegativeMaxMessages(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Services: []ServiceConfig{{
			Version: 1,
			Services: []Service{{
				Name: "identity",
				Host: "http://identity:8080",
				Routes: []RouterConfig{{
					Path:        "/chat",
					Methods:     []string{"POST"},
					MaxMessages: -1,
					Backends: []Backend{
						{URLPattern: "/chat"},
					},
				}},
			}},
		}},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), ".maxMessages") {
		t.Fatalf("expected maxMessages validation error, got %v", err)
	}
}

func TestServicesConfigRuleRejectsInvalidToolCallsField(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Services: []ServiceConfig{{
			Version: 1,
			Services: []Service{{
				Name: "identity",
				Host: "http://identity:8080",
				Routes: []RouterConfig{{
					Path:           "/chat",
					Methods:        []string{"POST"},
					MaxToolCalls:   4,
					ToolCallsField: "tools..items",
					Backends: []Backend{
						{URLPattern: "/chat"},
					},
				}},
			}},
		}},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), ".toolCallsField") {
		t.Fatalf("expected toolCallsField validation error, got %v", err)
	}
}

func TestServicesConfigRuleRejectsEmptyRequestRedactHeaderValue(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Services: []ServiceConfig{{
			Version: 1,
			Services: []Service{{
				Name: "identity",
				Host: "http://identity:8080",
				Routes: []RouterConfig{{
					Path:                 "/chat",
					Methods:              []string{"POST"},
					RequestRedactHeaders: []string{"Authorization", ""},
					Backends: []Backend{
						{URLPattern: "/chat"},
					},
				}},
			}},
		}},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), ".requestRedactHeaders") {
		t.Fatalf("expected requestRedactHeaders validation error, got %v", err)
	}
}

func TestServicesConfigRuleRejectsEmptyRequestRedactJSONFieldValue(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Services: []ServiceConfig{{
			Version: 1,
			Services: []Service{{
				Name: "identity",
				Host: "http://identity:8080",
				Routes: []RouterConfig{{
					Path:                    "/chat",
					Methods:                 []string{"POST"},
					RequestRedactJSONFields: []string{"messages[0].content", ""},
					Backends: []Backend{
						{URLPattern: "/chat"},
					},
				}},
			}},
		}},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), ".requestRedactJSONFields") {
		t.Fatalf("expected requestRedactJSONFields validation error, got %v", err)
	}
}

func TestServicesConfigRuleRejectsInvalidRequestBodyBlockRegex(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Services: []ServiceConfig{{
			Version: 1,
			Services: []Service{{
				Name: "identity",
				Host: "http://identity:8080",
				Routes: []RouterConfig{{
					Path:                  "/chat",
					Methods:               []string{"POST"},
					RequestBodyBlockRegex: []string{"["},
					Backends: []Backend{
						{URLPattern: "/chat"},
					},
				}},
			}},
		}},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), ".requestBodyBlockRegex") {
		t.Fatalf("expected requestBodyBlockRegex validation error, got %v", err)
	}
}

func TestServicesConfigRuleRejectsEmptyRequestBodyRequireRegexValue(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Services: []ServiceConfig{{
			Version: 1,
			Services: []Service{{
				Name: "identity",
				Host: "http://identity:8080",
				Routes: []RouterConfig{{
					Path:                    "/chat",
					Methods:                 []string{"POST"},
					RequestBodyRequireRegex: []string{"(?i)safe_system", ""},
					Backends: []Backend{
						{URLPattern: "/chat"},
					},
				}},
			}},
		}},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), ".requestBodyRequireRegex") {
		t.Fatalf("expected requestBodyRequireRegex validation error, got %v", err)
	}
}

func TestServicesConfigRuleRejectsInvalidResponseBodyBlockRegex(t *testing.T) {
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
					ResponseBodyBlockRegex: []string{"["},
					Backends: []Backend{
						{URLPattern: "/chat"},
					},
				}},
			}},
		}},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), ".responseBodyBlockRegex") {
		t.Fatalf("expected responseBodyBlockRegex validation error, got %v", err)
	}
}

func TestServicesConfigRuleRejectsEmptyResponseBodyRequireRegexValue(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Services: []ServiceConfig{{
			Version: 1,
			Services: []Service{{
				Name: "identity",
				Host: "http://identity:8080",
				Routes: []RouterConfig{{
					Path:                     "/chat",
					Methods:                  []string{"POST"},
					ResponseBodyRequireRegex: []string{"SAFE_OUTPUT", ""},
					Backends: []Backend{
						{URLPattern: "/chat"},
					},
				}},
			}},
		}},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), ".responseBodyRequireRegex") {
		t.Fatalf("expected responseBodyRequireRegex validation error, got %v", err)
	}
}

func TestServicesConfigRuleRejectsInvalidRequestPIIBlockType(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Services: []ServiceConfig{{
			Version: 1,
			Services: []Service{{
				Name: "identity",
				Host: "http://identity:8080",
				Routes: []RouterConfig{{
					Path:                 "/chat",
					Methods:              []string{"POST"},
					RequestPIIBlockTypes: []string{"email", "ssn"},
					Backends: []Backend{
						{URLPattern: "/chat"},
					},
				}},
			}},
		}},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), ".requestPIIBlockTypes") {
		t.Fatalf("expected requestPIIBlockTypes validation error, got %v", err)
	}
}

func TestServicesConfigRuleRejectsInvalidResponsePIIBlockType(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Services: []ServiceConfig{{
			Version: 1,
			Services: []Service{{
				Name: "identity",
				Host: "http://identity:8080",
				Routes: []RouterConfig{{
					Path:                  "/chat",
					Methods:               []string{"POST"},
					ResponsePIIBlockTypes: []string{"api_key", "ssn"},
					Backends: []Backend{
						{URLPattern: "/chat"},
					},
				}},
			}},
		}},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), ".responsePIIBlockTypes") {
		t.Fatalf("expected responsePIIBlockTypes validation error, got %v", err)
	}
}

func TestServicesConfigRuleRejectsEmptyResponseJSONFieldName(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Services: []ServiceConfig{{
			Version: 1,
			Services: []Service{{
				Name: "identity",
				Host: "http://identity:8080",
				Routes: []RouterConfig{{
					Path:    "/auth",
					Methods: []string{"GET"},
					ResponseJSONFields: map[string]string{
						"": "bad",
					},
					Backends: []Backend{
						{URLPattern: "/auth"},
					},
				}},
			}},
		}},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), ".responseJSONFields") {
		t.Fatalf("expected responseJSONFields validation error, got %v", err)
	}
}

func TestServicesConfigRuleRejectsEmptyRemoveResponseJSONFieldValue(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Services: []ServiceConfig{{
			Version: 1,
			Services: []Service{{
				Name: "identity",
				Host: "http://identity:8080",
				Routes: []RouterConfig{{
					Path:                     "/auth",
					Methods:                  []string{"GET"},
					RemoveResponseJSONFields: []string{"", "legacy"},
					Backends: []Backend{
						{URLPattern: "/auth"},
					},
				}},
			}},
		}},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), ".removeResponseJSONFields") {
		t.Fatalf("expected removeResponseJSONFields validation error, got %v", err)
	}
}
