package config

import (
	"net/http"
	"testing"
)

func TestBFFRouteCanOmitBackend(t *testing.T) {
	cfg := validBFFConfig(RouterConfig{
		Path:   "/app/{user_id}",
		Method: "GET",
		BFF: &BFFConfig{
			Steps: []BFFStepConfig{{
				Name: "profile",
				URL:  "http://profile.local/users/{{var.user_id}}",
			}},
			ResponseFields: map[string]string{
				"user": "json:{{step.profile.body}}",
			},
		},
	})

	if err := NewConfigValidator().Validate(cfg); err != nil {
		t.Fatalf("expected BFF route without backend to validate, got %v", err)
	}
}

func TestBFFRouteRejectsMissingStepURL(t *testing.T) {
	cfg := validBFFConfig(RouterConfig{
		Path:   "/app",
		Method: "GET",
		BFF: &BFFConfig{
			Steps: []BFFStepConfig{{Name: "profile"}},
		},
	})

	if err := NewConfigValidator().Validate(cfg); err == nil {
		t.Fatal("expected missing BFF step URL to be rejected")
	}
}

func TestBFFRouteRejectsNegativeStepRetryCount(t *testing.T) {
	cfg := validBFFConfig(RouterConfig{
		Path:   "/app",
		Method: "GET",
		BFF: &BFFConfig{
			Steps: []BFFStepConfig{{
				Name:       "profile",
				URL:        "http://profile.local/users/me",
				RetryCount: -1,
			}},
		},
	})

	if err := NewConfigValidator().Validate(cfg); err == nil {
		t.Fatal("expected negative BFF step retryCount to be rejected")
	}
}

func TestBFFRouteRejectsInvalidStepRetryStatusCode(t *testing.T) {
	cfg := validBFFConfig(RouterConfig{
		Path:   "/app",
		Method: "GET",
		BFF: &BFFConfig{
			Steps: []BFFStepConfig{{
				Name:          "profile",
				URL:           "http://profile.local/users/me",
				RetryStatuses: []int{99},
			}},
		},
	})

	if err := NewConfigValidator().Validate(cfg); err == nil {
		t.Fatal("expected invalid BFF step retryStatusCodes entry to be rejected")
	}
}

func TestBFFRouteRejectsInvalidStepSuccessStatusCode(t *testing.T) {
	cfg := validBFFConfig(RouterConfig{
		Path:   "/app",
		Method: "GET",
		BFF: &BFFConfig{
			Steps: []BFFStepConfig{{
				Name:            "profile",
				URL:             "http://profile.local/users/me",
				SuccessStatuses: []int{700},
			}},
		},
	})

	if err := NewConfigValidator().Validate(cfg); err == nil {
		t.Fatal("expected invalid BFF step successStatusCodes entry to be rejected")
	}
}

func TestBFFRouteRejectsInvalidStepRequiredJSONPath(t *testing.T) {
	cfg := validBFFConfig(RouterConfig{
		Path:   "/app",
		Method: "GET",
		BFF: &BFFConfig{
			Steps: []BFFStepConfig{{
				Name:              "profile",
				URL:               "http://profile.local/users/me",
				RequiredJSONPaths: []string{"items[]"},
			}},
		},
	})

	if err := NewConfigValidator().Validate(cfg); err == nil {
		t.Fatal("expected invalid BFF step requiredJSONPaths entry to be rejected")
	}
}

func TestBFFRouteRejectsInvalidRequiredRequestJSONPath(t *testing.T) {
	cfg := validBFFConfig(RouterConfig{
		Path:   "/app",
		Method: "POST",
		BFF: &BFFConfig{
			RequiredRequestJSONPaths: []string{"items[]"},
			Steps: []BFFStepConfig{{
				Name: "profile",
				URL:  "http://profile.local/users/me",
			}},
		},
	})

	if err := NewConfigValidator().Validate(cfg); err == nil {
		t.Fatal("expected invalid BFF requiredRequestJSONPaths entry to be rejected")
	}
}

func TestBFFRouteRejectsInvalidStepCacheTTL(t *testing.T) {
	cfg := validBFFConfig(RouterConfig{
		Path:   "/app",
		Method: "GET",
		BFF: &BFFConfig{
			Steps: []BFFStepConfig{{
				Name:     "profile",
				URL:      "http://profile.local/users/me",
				CacheTTL: "later",
			}},
		},
	})

	if err := NewConfigValidator().Validate(cfg); err == nil {
		t.Fatal("expected invalid BFF step cacheTTL to be rejected")
	}
}

func TestBFFRouteRejectsInvalidStepStaleIfError(t *testing.T) {
	cfg := validBFFConfig(RouterConfig{
		Path:   "/app",
		Method: "GET",
		BFF: &BFFConfig{
			Steps: []BFFStepConfig{{
				Name:         "profile",
				URL:          "http://profile.local/users/me",
				StaleIfError: "later",
			}},
		},
	})

	if err := NewConfigValidator().Validate(cfg); err == nil {
		t.Fatal("expected invalid BFF step staleIfError to be rejected")
	}
}

func TestBFFRouteRejectsInvalidStepCacheStatusCode(t *testing.T) {
	cfg := validBFFConfig(RouterConfig{
		Path:   "/app",
		Method: "GET",
		BFF: &BFFConfig{
			Steps: []BFFStepConfig{{
				Name:          "profile",
				URL:           "http://profile.local/users/me",
				CacheStatuses: []int{700},
			}},
		},
	})

	if err := NewConfigValidator().Validate(cfg); err == nil {
		t.Fatal("expected invalid BFF step cacheStatusCodes entry to be rejected")
	}
}

func TestBFFRouteRejectsNegativeMaxStepResponseBodyBytes(t *testing.T) {
	cfg := validBFFConfig(RouterConfig{
		Path:   "/app",
		Method: "GET",
		BFF: &BFFConfig{
			MaxStepResponseBodyBytes: -1,
			Steps: []BFFStepConfig{{
				Name: "profile",
				URL:  "http://profile.local/users/me",
			}},
		},
	})

	if err := NewConfigValidator().Validate(cfg); err == nil {
		t.Fatal("expected negative BFF maxStepResponseBodyBytes to be rejected")
	}
}

func TestBFFRouteRejectsNegativeStepMaxResponseBodyBytes(t *testing.T) {
	cfg := validBFFConfig(RouterConfig{
		Path:   "/app",
		Method: "GET",
		BFF: &BFFConfig{
			Steps: []BFFStepConfig{{
				Name:                 "profile",
				URL:                  "http://profile.local/users/me",
				MaxResponseBodyBytes: -1,
			}},
		},
	})

	if err := NewConfigValidator().Validate(cfg); err == nil {
		t.Fatal("expected negative BFF step maxResponseBodyBytes to be rejected")
	}
}

func TestBFFRouteRejectsInvalidStepFallbackStatusCode(t *testing.T) {
	cfg := validBFFConfig(RouterConfig{
		Path:   "/app",
		Method: "GET",
		BFF: &BFFConfig{
			Steps: []BFFStepConfig{{
				Name: "profile",
				URL:  "http://profile.local/users/me",
				Fallback: &BFFStepFallback{
					Status: 700,
					Body:   `json:{"name":"Guest"}`,
				},
			}},
		},
	})

	if err := NewConfigValidator().Validate(cfg); err == nil {
		t.Fatal("expected invalid BFF step fallback status to be rejected")
	}
}

func TestBFFRouteRejectsEmptyResponseHeaderName(t *testing.T) {
	cfg := validBFFConfig(RouterConfig{
		Path:   "/app",
		Method: "GET",
		BFF: &BFFConfig{
			Steps: []BFFStepConfig{{
				Name: "profile",
				URL:  "http://profile.local/users/me",
			}},
			ResponseHeaders: map[string]string{"": "value"},
		},
	})

	if err := NewConfigValidator().Validate(cfg); err == nil {
		t.Fatal("expected empty BFF responseHeaders name to be rejected")
	}
}

func TestBFFRouteRejectsInvalidStaticResponseStatus(t *testing.T) {
	cfg := validBFFConfig(RouterConfig{
		Path:   "/app",
		Method: "GET",
		BFF: &BFFConfig{
			ResponseStatus: "99",
			Steps: []BFFStepConfig{{
				Name: "profile",
				URL:  "http://profile.local/users/me",
			}},
		},
	})

	if err := NewConfigValidator().Validate(cfg); err == nil {
		t.Fatal("expected invalid static BFF responseStatus to be rejected")
	}
}

func TestBFFRouteRejectsInvalidPartialResponseStatus(t *testing.T) {
	cfg := validBFFConfig(RouterConfig{
		Path:   "/app",
		Method: "GET",
		BFF: &BFFConfig{
			PartialResponseStatus: 99,
			Steps: []BFFStepConfig{{
				Name: "profile",
				URL:  "http://profile.local/users/me",
			}},
		},
	})

	if err := NewConfigValidator().Validate(cfg); err == nil {
		t.Fatal("expected invalid BFF partialResponseStatus to be rejected")
	}
}

func TestBFFRouteRejectsUnknownStepDependency(t *testing.T) {
	cfg := validBFFConfig(RouterConfig{
		Path:   "/app",
		Method: "GET",
		BFF: &BFFConfig{
			Steps: []BFFStepConfig{{
				Name:      "recommendations",
				URL:       "http://recommendation.local/users/me",
				DependsOn: []string{"profile"},
			}},
		},
	})

	if err := NewConfigValidator().Validate(cfg); err == nil {
		t.Fatal("expected unknown BFF step dependency to be rejected")
	}
}

func TestBFFRouteRejectsCyclicStepDependencies(t *testing.T) {
	cfg := validBFFConfig(RouterConfig{
		Path:   "/app",
		Method: "GET",
		BFF: &BFFConfig{
			Steps: []BFFStepConfig{
				{Name: "profile", URL: "http://profile.local/users/me", DependsOn: []string{"recommendations"}},
				{Name: "recommendations", URL: "http://recommendation.local/users/me", DependsOn: []string{"profile"}},
			},
		},
	})

	if err := NewConfigValidator().Validate(cfg); err == nil {
		t.Fatal("expected cyclic BFF step dependencies to be rejected")
	}
}

func TestBFFRouteRejectsUnknownStepTemplateReference(t *testing.T) {
	cfg := validBFFConfig(RouterConfig{
		Path:   "/app",
		Method: "GET",
		BFF: &BFFConfig{
			Steps: []BFFStepConfig{{
				Name: "profile",
				URL:  "http://profile.local/users/me",
			}},
			ResponseFields: map[string]string{
				"user_id": "{{step.proifle.json.id}}",
			},
		},
	})

	if err := NewConfigValidator().Validate(cfg); err == nil {
		t.Fatal("expected unknown BFF step template reference to be rejected")
	}
}

func TestBFFRouteAllowsImplicitStepTemplateDependency(t *testing.T) {
	cfg := validBFFConfig(RouterConfig{
		Path:   "/app",
		Method: "GET",
		BFF: &BFFConfig{
			Steps: []BFFStepConfig{
				{Name: "profile", URL: "http://profile.local/users/me"},
				{Name: "recommendations", URL: "http://recommendation.local/users/{{step.profile.json.id}}"},
			},
		},
	})

	if err := NewConfigValidator().Validate(cfg); err != nil {
		t.Fatalf("expected BFF step template reference to infer dependency, got %v", err)
	}
}

func TestBFFRouteRejectsImplicitStepTemplateDependencyCycle(t *testing.T) {
	cfg := validBFFConfig(RouterConfig{
		Path:   "/app",
		Method: "GET",
		BFF: &BFFConfig{
			Steps: []BFFStepConfig{
				{Name: "profile", URL: "http://profile.local/users/{{step.recommendations.json.user_id}}"},
				{Name: "recommendations", URL: "http://recommendation.local/users/{{step.profile.json.id}}"},
			},
		},
	})

	if err := NewConfigValidator().Validate(cfg); err == nil {
		t.Fatal("expected implicit BFF step template dependency cycle to be rejected")
	}
}

func TestBFFRouteAllowsStepTemplateReferenceWithDependency(t *testing.T) {
	cfg := validBFFConfig(RouterConfig{
		Path:   "/app",
		Method: "GET",
		BFF: &BFFConfig{
			Steps: []BFFStepConfig{
				{Name: "profile", URL: "http://profile.local/users/me"},
				{Name: "recommendations", URL: "http://recommendation.local/users/{{step.profile.json.id}}", DependsOn: []string{"profile"}},
			},
		},
	})

	if err := NewConfigValidator().Validate(cfg); err != nil {
		t.Fatalf("expected BFF step template reference with dependsOn to validate, got %v", err)
	}
}

func TestBFFRouteRejectsEmptyStepFallbackHeaderName(t *testing.T) {
	cfg := validBFFConfig(RouterConfig{
		Path:   "/app",
		Method: "GET",
		BFF: &BFFConfig{
			Steps: []BFFStepConfig{{
				Name: "profile",
				URL:  "http://profile.local/users/me",
				Fallback: &BFFStepFallback{
					Status:  http.StatusOK,
					Headers: map[string]string{"": "value"},
				},
			}},
		},
	})

	if err := NewConfigValidator().Validate(cfg); err == nil {
		t.Fatal("expected empty BFF step fallback header name to be rejected")
	}
}

func TestBFFRouteRejectsEmptyStepWhenHeaderName(t *testing.T) {
	cfg := validBFFConfig(RouterConfig{
		Path:   "/app",
		Method: "GET",
		BFF: &BFFConfig{
			Steps: []BFFStepConfig{{
				Name:        "profile",
				URL:         "http://profile.local/users/me",
				WhenHeaders: map[string]string{"": "full"},
			}},
		},
	})

	if err := NewConfigValidator().Validate(cfg); err == nil {
		t.Fatal("expected empty BFF step whenHeaders name to be rejected")
	}
}

func TestBFFRouteRejectsEmptyStepWhenQueryParamName(t *testing.T) {
	cfg := validBFFConfig(RouterConfig{
		Path:   "/app",
		Method: "GET",
		BFF: &BFFConfig{
			Steps: []BFFStepConfig{{
				Name:            "profile",
				URL:             "http://profile.local/users/me",
				WhenQueryParams: map[string]string{"": "true"},
			}},
		},
	})

	if err := NewConfigValidator().Validate(cfg); err == nil {
		t.Fatal("expected empty BFF step whenQueryParams name to be rejected")
	}
}

func validBFFConfig(route RouterConfig) *Config {
	return &Config{
		Server: ServerConfig{Port: 8080},
		Services: []ServiceConfig{{
			Version: 1,
			Services: []Service{{
				Name:   "bff",
				Host:   "http://gateway.local",
				Routes: []RouterConfig{route},
			}},
		}},
	}
}
