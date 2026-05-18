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

func TestSecurityConfigRuleRejectsHTTP3WithoutTLS(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Security: SecurityConfig{
			TLS: TLSConfig{
				Enabled:      false,
				HTTP3Enabled: true,
			},
		},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "http3Enabled") {
		t.Fatalf("expected http3Enabled validation error, got %v", err)
	}
}

func TestSecurityConfigRuleAllowsHTTP3WithTLS(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Security: SecurityConfig{
			TLS: TLSConfig{
				Enabled:      true,
				Port:         8443,
				HTTP3Enabled: true,
				HTTP3Port:    8443,
				CertFile:     "server.crt",
				KeyFile:      "server.key",
			},
		},
	}

	if err := NewConfigValidator().Validate(cfg); err != nil {
		t.Fatalf("expected http3 tls config to validate, got %v", err)
	}
}

func TestSecurityConfigRuleRejectsDisabledMutationPolicyRequirements(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Security: SecurityConfig{
			MutationPolicy: MutationPolicy{
				Enabled:                  false,
				RequireNoteForHighImpact: true,
			},
		},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "mutationPolicy.enabled") {
		t.Fatalf("expected mutationPolicy.enabled validation error, got %v", err)
	}
}

func TestSecurityConfigRuleRejectsInvalidMutationPolicyScope(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Security: SecurityConfig{
			MutationPolicy: MutationPolicy{
				Enabled:        true,
				EnforcedScopes: []string{"banana"},
			},
		},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "mutationPolicy.enforcedScopes") {
		t.Fatalf("expected mutationPolicy.enforcedScopes validation error, got %v", err)
	}
}

func TestSecurityConfigRuleAllowsKnownMutationPolicyScopes(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Security: SecurityConfig{
			MutationPolicy: MutationPolicy{
				Enabled:        true,
				EnforcedScopes: []string{"services", "high_impact"},
			},
		},
	}

	if err := NewConfigValidator().Validate(cfg); err != nil {
		t.Fatalf("expected known mutation policy scopes to validate, got %v", err)
	}
}

func TestSecurityConfigRuleRejectsInvalidProposalQueueUrgencyThreshold(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Security: SecurityConfig{
			MutationPolicy: MutationPolicy{
				ProposalQueue: ProposalQueuePolicy{
					DefaultUrgency: ProposalQueueUrgencyThresholds{
						ReadyAgingAfter: "later",
					},
				},
			},
		},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "proposalQueue.defaultUrgency.readyAgingAfter") {
		t.Fatalf("expected proposal queue urgency validation error, got %v", err)
	}
}

func TestSecurityConfigRuleRejectsInvalidProposalQueueUrgencyOrdering(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Security: SecurityConfig{
			MutationPolicy: MutationPolicy{
				ProposalQueue: ProposalQueuePolicy{
					EnvironmentUrgency: map[string]ProposalQueueUrgencyThresholds{
						"prod": {
							BlockedAgingAfter:   "4h",
							BlockedOverdueAfter: "1h",
						},
					},
				},
			},
		},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "proposalQueue.environmentUrgency.prod") {
		t.Fatalf("expected proposal queue urgency ordering validation error, got %v", err)
	}
}

func TestSecurityConfigRuleRejectsInvalidPolicyAlertNotificationSeverity(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Security: SecurityConfig{
			MutationPolicy: MutationPolicy{
				PolicyAlertNotifications: PolicyAlertNotificationPolicy{
					Enabled:     true,
					MinSeverity: "banana",
				},
			},
		},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "policyAlertNotifications.minSeverity") {
		t.Fatalf("expected policy alert notification severity validation error, got %v", err)
	}
}

func TestSecurityConfigRuleRejectsInvalidProposalQueueNotificationInterval(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Security: SecurityConfig{
			MutationPolicy: MutationPolicy{
				ProposalQueue: ProposalQueuePolicy{
					Notifications: ProposalQueueNotificationPolicy{
						Enabled:  true,
						Interval: "whenever",
					},
				},
			},
		},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "proposalQueue.notifications.interval") {
		t.Fatalf("expected proposal queue notification interval validation error, got %v", err)
	}
}

func TestSecurityConfigRuleRejectsInvalidNotificationWebhookURL(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Security: SecurityConfig{
			NotificationWebhooks: []NotificationWebhook{
				{URL: "ftp://example.com/hook"},
			},
		},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "notificationWebhooks[0].url") {
		t.Fatalf("expected notification webhook url validation error, got %v", err)
	}
}

func TestSecurityConfigRuleRejectsInvalidNotificationWebhookFormat(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Security: SecurityConfig{
			NotificationWebhooks: []NotificationWebhook{
				{URL: "https://example.com/hook", Format: "discord"},
			},
		},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "notificationWebhooks[0].format") {
		t.Fatalf("expected notification webhook format validation error, got %v", err)
	}
}

func TestSecurityConfigRuleRejectsSignatureHeaderWithoutSecret(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Security: SecurityConfig{
			NotificationWebhooks: []NotificationWebhook{
				{
					URL:             "https://example.com/hook",
					SignatureHeader: "X-Iket-Signature",
				},
			},
		},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "notificationWebhooks[0].signingSecret") {
		t.Fatalf("expected notification webhook signing secret validation error, got %v", err)
	}
}

func TestSecurityConfigRuleRejectsNegativeNotificationWebhookRetryCount(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Security: SecurityConfig{
			NotificationWebhooks: []NotificationWebhook{
				{URL: "https://example.com/hook", RetryCount: -1},
			},
		},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "notificationWebhooks[0].retryCount") {
		t.Fatalf("expected notification webhook retryCount validation error, got %v", err)
	}
}

func TestSecurityConfigRuleRejectsInvalidNotificationWebhookRetryBackoff(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Security: SecurityConfig{
			NotificationWebhooks: []NotificationWebhook{
				{URL: "https://example.com/hook", RetryBackoff: "later"},
			},
		},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "notificationWebhooks[0].retryBackoff") {
		t.Fatalf("expected notification webhook retryBackoff validation error, got %v", err)
	}
}

func TestSecurityConfigRuleRejectsNegativeNotificationWebhookSLABreachThreshold(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Security: SecurityConfig{
			NotificationWebhooks: []NotificationWebhook{
				{URL: "https://example.com/hook", MinSLABreachCount: -1},
			},
		},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "notificationWebhooks[0].minSLABreachCount") {
		t.Fatalf("expected notification webhook minSLABreachCount validation error, got %v", err)
	}
}

func TestSecurityConfigRuleRejectsNegativeNotificationWebhookConsecutiveSLABreachThreshold(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Security: SecurityConfig{
			NotificationWebhooks: []NotificationWebhook{
				{URL: "https://example.com/hook", MinConsecutiveSLABreaches: -1},
			},
		},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "notificationWebhooks[0].minConsecutiveSLABreaches") {
		t.Fatalf("expected notification webhook minConsecutiveSLABreaches validation error, got %v", err)
	}
}

func TestSecurityConfigRuleRejectsInvalidNotificationWebhookSLABreachDuration(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Security: SecurityConfig{
			NotificationWebhooks: []NotificationWebhook{
				{URL: "https://example.com/hook", MinSLABreachDuration: "later"},
			},
		},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "notificationWebhooks[0].minSLABreachDuration") {
		t.Fatalf("expected notification webhook minSLABreachDuration validation error, got %v", err)
	}
}

func TestSecurityConfigRuleRejectsInvalidNotificationWebhookSLABreachTier(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Security: SecurityConfig{
			NotificationWebhooks: []NotificationWebhook{
				{URL: "https://example.com/hook", MinSLABreachTier: "urgent"},
			},
		},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "notificationWebhooks[0].minSLABreachTier") {
		t.Fatalf("expected notification webhook minSLABreachTier validation error, got %v", err)
	}
}

func TestSecurityConfigRuleRejectsInvalidNotificationWebhookSLABreachCooldown(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Security: SecurityConfig{
			NotificationWebhooks: []NotificationWebhook{
				{URL: "https://example.com/hook", SLABreachCooldown: "soon"},
			},
		},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "notificationWebhooks[0].slaBreachCooldown") {
		t.Fatalf("expected notification webhook slaBreachCooldown validation error, got %v", err)
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

func TestSecurityConfigRuleRejectsDisabledDifferentReviewerPolicy(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Security: SecurityConfig{
			MutationPolicy: MutationPolicy{
				Enabled:                              false,
				RequireDifferentReviewerForProposals: true,
			},
		},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "mutationPolicy.enabled") {
		t.Fatalf("expected mutationPolicy.enabled validation error, got %v", err)
	}
}

func TestSecurityConfigRuleRejectsNegativeProposalApproverRequirement(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Security: SecurityConfig{
			MutationPolicy: MutationPolicy{
				Enabled:                            true,
				MinApproversForHighImpactProposals: -1,
			},
		},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "minApproversForHighImpactProposals") {
		t.Fatalf("expected min approvers validation error, got %v", err)
	}
}

func TestSecurityConfigRuleRejectsDisabledProposalScheduleRequirement(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Security: SecurityConfig{
			MutationPolicy: MutationPolicy{
				Enabled:                                false,
				RequireNotBeforeForHighImpactProposals: true,
			},
		},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "mutationPolicy.enabled") {
		t.Fatalf("expected mutationPolicy.enabled validation error, got %v", err)
	}
}

func TestSecurityConfigRuleRejectsDisabledPromotedProposalVerificationRequirement(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Security: SecurityConfig{
			MutationPolicy: MutationPolicy{
				Enabled: false,
				RequireVerificationForPromotedHighImpactProposals: true,
			},
		},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "mutationPolicy.enabled") {
		t.Fatalf("expected mutationPolicy.enabled validation error, got %v", err)
	}
}

func TestSecurityConfigRuleRejectsDisabledPromotedProposalShadowEvaluationRequirement(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Security: SecurityConfig{
			MutationPolicy: MutationPolicy{
				Enabled: false,
				RequireShadowEvaluationForPromotedHighImpactProposals: true,
			},
		},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "mutationPolicy.enabled") {
		t.Fatalf("expected mutationPolicy.enabled validation error, got %v", err)
	}
}

func TestSecurityConfigRuleRejectsDisabledShadowVerificationStreakRequirement(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Security: SecurityConfig{
			MutationPolicy: MutationPolicy{
				Enabled: false,
				MinShadowHealthyVerificationsForPromotedHighImpactProposals: 2,
			},
		},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "mutationPolicy.enabled") {
		t.Fatalf("expected mutationPolicy.enabled validation error, got %v", err)
	}
}

func TestSecurityConfigRuleRejectsDisabledBlockedApplyWindows(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Security: SecurityConfig{
			MutationPolicy: MutationPolicy{
				Enabled: false,
				BlockedApplyWindows: []MutationApplyWindow{
					{Name: "freeze", Start: "22:00", End: "23:00"},
				},
			},
		},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "mutationPolicy.enabled") {
		t.Fatalf("expected mutationPolicy.enabled validation error, got %v", err)
	}
}

func TestSecurityConfigRuleRejectsDisabledProposalAgeLimits(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Security: SecurityConfig{
			MutationPolicy: MutationPolicy{
				Enabled:        false,
				MaxProposalAge: "24h",
			},
		},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "mutationPolicy.enabled") {
		t.Fatalf("expected mutationPolicy.enabled validation error, got %v", err)
	}
}

func TestSecurityConfigRuleRejectsInvalidProposalAgeLimits(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Security: SecurityConfig{
			MutationPolicy: MutationPolicy{
				Enabled:        true,
				MaxProposalAge: "tomorrow",
			},
		},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "maxProposalAge") {
		t.Fatalf("expected maxProposalAge validation error, got %v", err)
	}
}

func TestSecurityConfigRuleAllowsValidProposalAgeLimits(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Security: SecurityConfig{
			MutationPolicy: MutationPolicy{
				Enabled:        true,
				MaxProposalAge: "72h",
				MaxApprovalAge: "12h",
			},
		},
	}

	if err := NewConfigValidator().Validate(cfg); err != nil {
		t.Fatalf("expected valid proposal age limits to validate, got %v", err)
	}
}

func TestSecurityConfigRuleRejectsInvalidBlockedApplyWindow(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Security: SecurityConfig{
			MutationPolicy: MutationPolicy{
				Enabled: true,
				BlockedApplyWindows: []MutationApplyWindow{
					{Name: "freeze", Days: []string{"noday"}, Start: "22:00", End: "22:00", Timezone: "Mars/Phobos"},
				},
			},
		},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "blockedApplyWindows") {
		t.Fatalf("expected blocked apply window validation error, got %v", err)
	}
}

func TestSecurityConfigRuleAllowsValidBlockedApplyWindow(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Security: SecurityConfig{
			MutationPolicy: MutationPolicy{
				Enabled: true,
				BlockedApplyWindows: []MutationApplyWindow{
					{
						Name:     "weekend-freeze",
						Days:     []string{"sat", "sun"},
						Start:    "00:00",
						End:      "06:00",
						Timezone: "UTC",
						Scopes:   []string{"high_impact"},
					},
				},
			},
		},
	}

	if err := NewConfigValidator().Validate(cfg); err != nil {
		t.Fatalf("expected valid blocked apply window to validate, got %v", err)
	}
}
