package gateway

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/bhangun/iket/pkg/config"
)

func TestComputeProxiedPath(t *testing.T) {
	t.Run("strip path true preserves rest", func(t *testing.T) {
		service := &config.Service{Host: "http://identity:8080"}
		route := config.RouterConfig{
			Path:      "/auth/{rest:.*}",
			StripPath: true,
		}

		got, err := ComputeProxiedPath(service, route, "/auth/profile", map[string]string{"rest": "profile"})
		if err != nil {
			t.Fatalf("ComputeProxiedPath returned error: %v", err)
		}
		if got != "/profile" {
			t.Fatalf("expected /profile, got %s", got)
		}
	})

	t.Run("strip path false preserves full incoming path", func(t *testing.T) {
		service := &config.Service{Host: "http://identity:8080"}
		route := config.RouterConfig{
			Path:      "/auth/{rest:.*}",
			StripPath: false,
		}

		got, err := ComputeProxiedPath(service, route, "/auth/profile", map[string]string{"rest": "profile"})
		if err != nil {
			t.Fatalf("ComputeProxiedPath returned error: %v", err)
		}
		if got != "/auth/profile" {
			t.Fatalf("expected /auth/profile, got %s", got)
		}
	})

	t.Run("url pattern rewrites rest without api in request", func(t *testing.T) {
		service := &config.Service{Host: "http://identity:8080"}
		route := config.RouterConfig{
			Path: "/auth/{rest:.*}",
			Backends: []config.Backend{
				{URLPattern: "/api/{rest:.*}"},
			},
		}

		got, err := ComputeProxiedPath(service, route, "/auth/profile", map[string]string{"rest": "profile"})
		if err != nil {
			t.Fatalf("ComputeProxiedPath returned error: %v", err)
		}
		if got != "/api/profile" {
			t.Fatalf("expected /api/profile, got %s", got)
		}
	})

	t.Run("url pattern rewrites rest with api in request", func(t *testing.T) {
		service := &config.Service{Host: "http://identity:8080"}
		route := config.RouterConfig{
			Path: "/auth/{rest:.*}",
			Backends: []config.Backend{
				{URLPattern: "/api/{rest:.*}"},
			},
		}

		got, err := ComputeProxiedPath(service, route, "/auth/api/profile", map[string]string{"rest": "api/profile"})
		if err != nil {
			t.Fatalf("ComputeProxiedPath returned error: %v", err)
		}
		if got != "/api/api/profile" {
			t.Fatalf("expected /api/api/profile, got %s", got)
		}
	})

	t.Run("host path prefix joins without double slashes", func(t *testing.T) {
		service := &config.Service{Host: "http://identity:8080/root/"}
		route := config.RouterConfig{
			Path: "/auth/{rest:.*}",
			Backends: []config.Backend{
				{URLPattern: "/api/{rest:.*}"},
			},
		}

		got, err := ComputeProxiedPath(service, route, "/auth/profile", map[string]string{"rest": "profile"})
		if err != nil {
			t.Fatalf("ComputeProxiedPath returned error: %v", err)
		}
		if got != "/root/api/profile" {
			t.Fatalf("expected /root/api/profile, got %s", got)
		}
	})

	t.Run("selected backend can override url pattern", func(t *testing.T) {
		service := &config.Service{Host: "http://identity:8080"}
		route := config.RouterConfig{
			Path: "/auth/{rest:.*}",
			Backends: []config.Backend{
				{URLPattern: "/api/{rest:.*}", Weight: 1},
				{URLPattern: "/v2/{rest:.*}", Weight: 2},
			},
		}

		got, err := ComputeProxiedPathForBackend(service, route, route.Backends[1], "/auth/profile", map[string]string{"rest": "profile"})
		if err != nil {
			t.Fatalf("ComputeProxiedPathForBackend returned error: %v", err)
		}
		if got != "/v2/profile" {
			t.Fatalf("expected /v2/profile, got %s", got)
		}
	})
}

func TestMatchRouteTemplate(t *testing.T) {
	route := config.RouterConfig{
		Path:    "/{realm}/auth/{rest:.*}",
		Methods: []string{"GET"},
	}

	vars, matched := MatchRouteTemplate(route, "GET", "/jahsy/auth/profile", nil)
	if !matched {
		t.Fatalf("expected route to match")
	}
	if vars["realm"] != "jahsy" {
		t.Fatalf("expected realm jahsy, got %q", vars["realm"])
	}
	if vars["rest"] != "profile" {
		t.Fatalf("expected rest profile, got %q", vars["rest"])
	}
}

func TestResolveRouteMatchPrefersMoreSpecificRoute(t *testing.T) {
	routes := []config.RouterConfig{
		{
			Path:    "/{realm}/auth/{rest:.*}",
			Methods: []string{"GET"},
			Name:    "wildcard",
		},
		{
			Path:    "/{realm}/auth/login",
			Methods: []string{"GET"},
			Name:    "login",
		},
	}

	match := ResolveRouteMatch(routes, "GET", "/jahsy/auth/login", nil, "")
	if !match.Matched {
		t.Fatalf("expected route to match")
	}
	if match.Route.Name != "login" {
		t.Fatalf("expected login route, got %q", match.Route.Name)
	}
	if match.Vars["realm"] != "jahsy" {
		t.Fatalf("expected realm jahsy, got %q", match.Vars["realm"])
	}
}

func TestSelectRouteBackendUsesWeightsDeterministically(t *testing.T) {
	route := config.RouterConfig{
		Path: "/auth/{rest:.*}",
		Backends: []config.Backend{
			{URLPattern: "/v1/{rest:.*}", Host: "http://identity-v1:8080", Weight: 1},
			{URLPattern: "/v2/{rest:.*}", Host: "http://identity-v2:8080", Weight: 3},
		},
	}

	counts := map[string]int{}
	for i := 0; i < 400; i++ {
		backend := SelectRouteBackend(route, fmt.Sprintf("client-%d", i))
		counts[backend.Host]++
	}
	if counts["http://identity-v2:8080"] <= counts["http://identity-v1:8080"] {
		t.Fatalf("expected weighted backend selection to prefer v2, got counts %#v", counts)
	}

	first := SelectRouteBackend(route, "sticky-client")
	second := SelectRouteBackend(route, "sticky-client")
	if first.Host != second.Host || first.URLPattern != second.URLPattern {
		t.Fatalf("expected deterministic backend selection, got %+v and %+v", first, second)
	}
}

func TestResolveRouteMatchPrefersHeaderScopedRoute(t *testing.T) {
	routes := []config.RouterConfig{
		{
			Path:    "/auth/profile",
			Methods: []string{"GET"},
			Name:    "stable",
		},
		{
			Path:         "/auth/profile",
			Methods:      []string{"GET"},
			Name:         "canary",
			MatchHeaders: map[string]string{"X-Iket-Canary": "identity-v2"},
		},
	}

	headers := http.Header{}
	headers.Set("X-Iket-Canary", "identity-v2")
	match := ResolveRouteMatch(routes, "GET", "/auth/profile", headers, "client-a")
	if !match.Matched {
		t.Fatalf("expected route to match")
	}
	if match.Route.Name != "canary" {
		t.Fatalf("expected canary route, got %q", match.Route.Name)
	}
}

func TestResolveRouteMatchPrefersPercentageScopedRouteForMatchingBucket(t *testing.T) {
	routes := []config.RouterConfig{
		{
			Path:    "/auth/profile",
			Methods: []string{"GET"},
			Name:    "stable",
		},
		{
			Path:         "/auth/profile",
			Methods:      []string{"GET"},
			Name:         "canary",
			MatchPercent: 30,
		},
	}

	var matchingKey string
	for i := 0; i < 1000; i++ {
		key := fmt.Sprintf("client-%d", i)
		if percentageBucketForKey(key) < 30 {
			matchingKey = key
			break
		}
	}
	if matchingKey == "" {
		t.Fatalf("expected to find a matching bucket key")
	}

	match := ResolveRouteMatch(routes, "GET", "/auth/profile", nil, matchingKey)
	if !match.Matched {
		t.Fatalf("expected route to match")
	}
	if match.Route.Name != "canary" {
		t.Fatalf("expected canary route, got %q", match.Route.Name)
	}
}

func TestNormalizeForwardedHeaders(t *testing.T) {
	req := httptest.NewRequest("GET", "http://gateway.local/jahsy/auth/profile", nil)
	req.RemoteAddr = "10.0.0.8:1234"
	req.Host = "gateway.example"
	req.Header.Set("X-Forwarded-For", "1.1.1.1")

	normalizeForwardedHeaders(req)

	if got := req.Header.Get("X-Forwarded-For"); got != "1.1.1.1, 10.0.0.8" {
		t.Fatalf("expected appended forwarded for, got %q", got)
	}
	if got := req.Header.Get("X-Forwarded-Proto"); got != "http" {
		t.Fatalf("expected forwarded proto http, got %q", got)
	}
	if got := req.Header.Get("X-Forwarded-Host"); got != "gateway.example" {
		t.Fatalf("expected forwarded host gateway.example, got %q", got)
	}
	if got := req.Header.Get("X-Request-Id"); got == "" {
		t.Fatalf("expected request id to be set")
	}
}
