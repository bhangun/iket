package config

import (
	"strings"
	"testing"
)

func TestServicesConfigRuleRejectsInvalidRouteRateLimitPolicyKeyBy(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Services: []ServiceConfig{{
			Version: 1,
			Services: []Service{{
				Name: "agent",
				Host: "http://agent:8080",
				Routes: []RouterConfig{{
					Path:    "/ai/chat",
					Methods: []string{"POST"},
					RateLimitPolicy: &RateLimitPolicyConfig{
						RequestsPerSecond: 5,
						Burst:             10,
						KeyBy:             "tenant",
					},
					Backends: []Backend{{URLPattern: "/"}},
				}},
			}},
		}},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "rateLimitPolicy.keyBy") {
		t.Fatalf("expected rateLimitPolicy.keyBy validation error, got %v", err)
	}
}

func TestServicesConfigRuleAcceptsPrincipalLimitKeyByWithClassPolicies(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Security: SecurityConfig{
			LimitAlertBucketClasses: map[string]LimitAlertBucketClassConfig{
				"enterprise-client": {
					KeyType:     "principal",
					BucketRegex: "^client:",
				},
			},
		},
		Services: []ServiceConfig{{
			Version: 1,
			Services: []Service{{
				Name: "agent",
				Host: "http://agent:8080",
				Routes: []RouterConfig{{
					Path:    "/ai/chat",
					Methods: []string{"POST"},
					RateLimitPolicy: &RateLimitPolicyConfig{
						RequestsPerSecond: 5,
						Burst:             10,
						KeyBy:             "principal",
						ClassPolicies: []LimiterClassRatePolicyConfig{{
							BucketClass:       "enterprise-client",
							RequestsPerSecond: 2,
							Burst:             4,
						}},
					},
					ConcurrencyLimitPolicy: &ConcurrencyLimitPolicyConfig{
						MaxInFlight: 4,
						KeyBy:       "principal",
						ClassPolicies: []LimiterClassConcurrencyPolicyConfig{{
							BucketClass: "enterprise-client",
							MaxInFlight: 2,
						}},
					},
					LimitAlertPolicy: &RouteLimitAlertPolicyConfig{
						BucketPolicies: []LimitAlertBucketPolicyConfig{{
							KeyType:     "principal",
							BucketRegex: "^client:",
							MinCount:    2,
						}},
					},
					Backends: []Backend{{URLPattern: "/"}},
				}},
			}},
		}},
	}

	if err := NewConfigValidator().Validate(cfg); err != nil {
		t.Fatalf("expected principal limiter key config to validate, got %v", err)
	}
}

func TestServicesConfigRuleRejectsHeaderRateLimitPolicyWithoutKeyHeader(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Services: []ServiceConfig{{
			Version: 1,
			Services: []Service{{
				Name: "agent",
				Host: "http://agent:8080",
				Routes: []RouterConfig{{
					Path:    "/ai/chat",
					Methods: []string{"POST"},
					RateLimitPolicy: &RateLimitPolicyConfig{
						RequestsPerSecond: 5,
						Burst:             10,
						KeyBy:             "header",
					},
					Backends: []Backend{{URLPattern: "/"}},
				}},
			}},
		}},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "rateLimitPolicy.keyHeader") {
		t.Fatalf("expected rateLimitPolicy.keyHeader validation error, got %v", err)
	}
}

func TestServicesConfigRuleRejectsUnknownRateLimitClassPolicyBucketClass(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Services: []ServiceConfig{{
			Version: 1,
			Services: []Service{{
				Name: "agent",
				Host: "http://agent:8080",
				Routes: []RouterConfig{{
					Path:    "/ai/chat",
					Methods: []string{"POST"},
					RateLimitPolicy: &RateLimitPolicyConfig{
						RequestsPerSecond: 5,
						Burst:             10,
						KeyBy:             "jwt_sub",
						ClassPolicies: []LimiterClassRatePolicyConfig{{
							BucketClass:       "missing",
							RequestsPerSecond: 2,
							Burst:             4,
						}},
					},
					Backends: []Backend{{URLPattern: "/"}},
				}},
			}},
		}},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "rateLimitPolicy.classPolicies[0].bucketClass") {
		t.Fatalf("expected rateLimitPolicy.classPolicies bucketClass validation error, got %v", err)
	}
}

func TestServicesConfigRuleRejectsRateLimitClassPolicyWithGlobalKeyBy(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Security: SecurityConfig{
			LimitAlertBucketClasses: map[string]LimitAlertBucketClassConfig{
				"vip-jwt": {KeyType: "jwt_sub", BucketRegex: "^vip-"},
			},
		},
		Services: []ServiceConfig{{
			Version: 1,
			Services: []Service{{
				Name: "agent",
				Host: "http://agent:8080",
				Routes: []RouterConfig{{
					Path:    "/ai/chat",
					Methods: []string{"POST"},
					RateLimitPolicy: &RateLimitPolicyConfig{
						RequestsPerSecond: 5,
						Burst:             10,
						KeyBy:             "global",
						ClassPolicies: []LimiterClassRatePolicyConfig{{
							BucketClass:       "vip-jwt",
							RequestsPerSecond: 2,
							Burst:             4,
						}},
					},
					Backends: []Backend{{URLPattern: "/"}},
				}},
			}},
		}},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "rateLimitPolicy.classPolicies") {
		t.Fatalf("expected rateLimitPolicy.classPolicies validation error, got %v", err)
	}
}

func TestServicesConfigRuleRejectsUnknownRateLimitClassPolicyPreset(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Services: []ServiceConfig{{
			Version: 1,
			Services: []Service{{
				Name: "agent",
				Host: "http://agent:8080",
				Routes: []RouterConfig{{
					Path:    "/ai/chat",
					Methods: []string{"POST"},
					RateLimitPolicy: &RateLimitPolicyConfig{
						RequestsPerSecond: 5,
						Burst:             10,
						KeyBy:             "jwt_sub",
						ClassPolicies: []LimiterClassRatePolicyConfig{{
							Preset: "missing",
						}},
					},
					Backends: []Backend{{URLPattern: "/"}},
				}},
			}},
		}},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "rateLimitPolicy.classPolicies[0].preset") {
		t.Fatalf("expected rateLimitPolicy.classPolicies preset validation error, got %v", err)
	}
}

func TestServicesConfigRuleRejectsInvalidConcurrentCalls(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Services: []ServiceConfig{{
			Version: 1,
			Services: []Service{{
				Name: "agent",
				Host: "http://agent:8080",
				Routes: []RouterConfig{{
					Path:            "/ai/chat",
					Methods:         []string{"POST"},
					ConcurrentCalls: "zero",
					Backends:        []Backend{{URLPattern: "/"}},
				}},
			}},
		}},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "concurrent_calls") {
		t.Fatalf("expected concurrent_calls validation error, got %v", err)
	}
}

func TestServicesConfigRuleRejectsHeaderConcurrencyLimitPolicyWithoutKeyHeader(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Services: []ServiceConfig{{
			Version: 1,
			Services: []Service{{
				Name: "agent",
				Host: "http://agent:8080",
				Routes: []RouterConfig{{
					Path:    "/ai/chat",
					Methods: []string{"POST"},
					ConcurrencyLimitPolicy: &ConcurrencyLimitPolicyConfig{
						MaxInFlight: 4,
						KeyBy:       "header",
					},
					Backends: []Backend{{URLPattern: "/"}},
				}},
			}},
		}},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "concurrencyLimitPolicy.keyHeader") {
		t.Fatalf("expected concurrencyLimitPolicy.keyHeader validation error, got %v", err)
	}
}

func TestServicesConfigRuleRejectsInvalidConcurrencyLimitQueueTimeout(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Services: []ServiceConfig{{
			Version: 1,
			Services: []Service{{
				Name: "agent",
				Host: "http://agent:8080",
				Routes: []RouterConfig{{
					Path:    "/ai/chat",
					Methods: []string{"POST"},
					ConcurrencyLimitPolicy: &ConcurrencyLimitPolicyConfig{
						MaxInFlight:  4,
						KeyBy:        "global",
						QueueTimeout: "later",
					},
					Backends: []Backend{{URLPattern: "/"}},
				}},
			}},
		}},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "concurrencyLimitPolicy.queueTimeout") {
		t.Fatalf("expected concurrencyLimitPolicy.queueTimeout validation error, got %v", err)
	}
}

func TestServicesConfigRuleRejectsUnknownConcurrencyLimitClassPolicyBucketClass(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Services: []ServiceConfig{{
			Version: 1,
			Services: []Service{{
				Name: "agent",
				Host: "http://agent:8080",
				Routes: []RouterConfig{{
					Path:    "/ai/chat",
					Methods: []string{"POST"},
					ConcurrencyLimitPolicy: &ConcurrencyLimitPolicyConfig{
						MaxInFlight: 4,
						KeyBy:       "jwt_sub",
						ClassPolicies: []LimiterClassConcurrencyPolicyConfig{{
							BucketClass: "missing",
							MaxInFlight: 2,
						}},
					},
					Backends: []Backend{{URLPattern: "/"}},
				}},
			}},
		}},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "concurrencyLimitPolicy.classPolicies[0].bucketClass") {
		t.Fatalf("expected concurrencyLimitPolicy.classPolicies bucketClass validation error, got %v", err)
	}
}

func TestServicesConfigRuleRejectsUnknownConcurrencyLimitClassPolicyPreset(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Services: []ServiceConfig{{
			Version: 1,
			Services: []Service{{
				Name: "agent",
				Host: "http://agent:8080",
				Routes: []RouterConfig{{
					Path:    "/ai/chat",
					Methods: []string{"POST"},
					ConcurrencyLimitPolicy: &ConcurrencyLimitPolicyConfig{
						MaxInFlight: 4,
						KeyBy:       "jwt_sub",
						ClassPolicies: []LimiterClassConcurrencyPolicyConfig{{
							Preset: "missing",
						}},
					},
					Backends: []Backend{{URLPattern: "/"}},
				}},
			}},
		}},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "concurrencyLimitPolicy.classPolicies[0].preset") {
		t.Fatalf("expected concurrencyLimitPolicy.classPolicies preset validation error, got %v", err)
	}
}

func TestServicesConfigRuleRejectsNegativeConcurrencyLimitQueueDepth(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Services: []ServiceConfig{{
			Version: 1,
			Services: []Service{{
				Name: "agent",
				Host: "http://agent:8080",
				Routes: []RouterConfig{{
					Path:    "/ai/chat",
					Methods: []string{"POST"},
					ConcurrencyLimitPolicy: &ConcurrencyLimitPolicyConfig{
						MaxInFlight:   4,
						KeyBy:         "global",
						MaxQueueDepth: -1,
					},
					Backends: []Backend{{URLPattern: "/"}},
				}},
			}},
		}},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "concurrencyLimitPolicy.maxQueueDepth") {
		t.Fatalf("expected concurrencyLimitPolicy.maxQueueDepth validation error, got %v", err)
	}
}

func TestServicesConfigRuleRejectsInvalidRouteLimitAlertPolicyOrdering(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Services: []ServiceConfig{{
			Version: 1,
			Services: []Service{{
				Name: "agent",
				Host: "http://agent:8080",
				Routes: []RouterConfig{{
					Path:    "/ai/chat",
					Methods: []string{"POST"},
					ConcurrencyLimitPolicy: &ConcurrencyLimitPolicyConfig{
						MaxInFlight: 4,
						KeyBy:       "global",
					},
					LimitAlertPolicy: &RouteLimitAlertPolicyConfig{
						LimitTypePolicies: map[string]LimitAlertTypePolicy{
							"concurrency_queue_full": {
								WarningCount:  3,
								ElevatedCount: 2,
							},
						},
					},
					Backends: []Backend{{URLPattern: "/"}},
				}},
			}},
		}},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "limitAlertPolicy.limitTypePolicies") {
		t.Fatalf("expected route limit alert policy validation error, got %v", err)
	}
}

func TestServicesConfigRuleRejectsInvalidRouteLimitAlertPolicyGroupBy(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Services: []ServiceConfig{{
			Version: 1,
			Services: []Service{{
				Name: "agent",
				Host: "http://agent:8080",
				Routes: []RouterConfig{{
					Path:    "/ai/chat",
					Methods: []string{"POST"},
					ConcurrencyLimitPolicy: &ConcurrencyLimitPolicyConfig{
						MaxInFlight: 4,
						KeyBy:       "jwt_sub",
					},
					LimitAlertPolicy: &RouteLimitAlertPolicyConfig{
						GroupBy: "tenant",
					},
					Backends: []Backend{{URLPattern: "/"}},
				}},
			}},
		}},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "limitAlertPolicy.groupBy") {
		t.Fatalf("expected route limit alert policy groupBy validation error, got %v", err)
	}
}

func TestServicesConfigRuleRejectsInvalidRouteLimitAlertBucketPolicy(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Services: []ServiceConfig{{
			Version: 1,
			Services: []Service{{
				Name: "agent",
				Host: "http://agent:8080",
				Routes: []RouterConfig{{
					Path:    "/ai/chat",
					Methods: []string{"POST"},
					ConcurrencyLimitPolicy: &ConcurrencyLimitPolicyConfig{
						MaxInFlight: 4,
						KeyBy:       "jwt_sub",
					},
					LimitAlertPolicy: &RouteLimitAlertPolicyConfig{
						BucketPolicies: []LimitAlertBucketPolicyConfig{{
							KeyType:     "global",
							BucketRegex: "[",
						}},
					},
					Backends: []Backend{{URLPattern: "/"}},
				}},
			}},
		}},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "limitAlertPolicy.bucketPolicies.keyType") {
		t.Fatalf("expected route limit alert bucket policy validation error, got %v", err)
	}
}

func TestServicesConfigRuleRejectsUnknownRouteLimitAlertBucketClass(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Security: SecurityConfig{
			LimitAlertBucketClasses: map[string]LimitAlertBucketClassConfig{
				"known": {
					KeyType:     "jwt_sub",
					BucketRegex: "^vip-",
				},
			},
		},
		Services: []ServiceConfig{{
			Version: 1,
			Services: []Service{{
				Name: "agent",
				Host: "http://agent:8080",
				Routes: []RouterConfig{{
					Path:    "/ai/chat",
					Methods: []string{"POST"},
					LimitAlertPolicy: &RouteLimitAlertPolicyConfig{
						BucketPolicies: []LimitAlertBucketPolicyConfig{{
							BucketClass: "missing",
						}},
					},
					Backends: []Backend{{URLPattern: "/"}},
				}},
			}},
		}},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "bucketClass") {
		t.Fatalf("expected route limit alert bucketClass validation error, got %v", err)
	}
}
