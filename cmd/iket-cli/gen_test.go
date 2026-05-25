package main

import (
	"bufio"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestRenderGeneratedDockerComposeUsesCustomNames(t *testing.T) {
	answers := newDefaultDockerWizardAnswers()
	answers.DeploymentName = "team-gateway"
	answers.ImageName = "example/iket:test"
	answers.HTTPPort = "8088"
	answers.HTTPSPort = "9444"

	compose := renderGeneratedDockerCompose(answers)
	if !strings.Contains(compose, "container_name: team-gateway") {
		t.Fatalf("expected compose to include custom iket container name, got:\n%s", compose)
	}
	if !strings.Contains(compose, "container_name: team-gateway-postgres") {
		t.Fatalf("expected compose to include custom postgres container name, got:\n%s", compose)
	}
	if !strings.Contains(compose, "\"${IKET_HTTP_PORT:-8088}:8080\"") {
		t.Fatalf("expected compose to include custom http port, got:\n%s", compose)
	}
}

func TestBuildGeneratedDockerConfigYAMLIncludesSelectedFeatures(t *testing.T) {
	answers := newDefaultDockerWizardAnswers()
	answers.EnableBasicAuth = false
	answers.AuthMode = "apikey"
	answers.APIKeyHeaderName = "X-Custom-Key"
	answers.APIKeyClientID = "partner-a"
	answers.APIKeyClientName = "Partner A"
	answers.APIKeyClientKey = "super-secret"
	answers.APIKeyClientGroup = "partners"
	answers.APIKeyScopes = []string{"orders:read"}
	answers.GovernancePreset = "strict"
	answers.ServerNames = []string{"gw.internal", "localhost"}
	answers.ServerIPs = []string{"10.0.0.5"}

	text, err := buildGeneratedDockerConfigYAML(answers)
	if err != nil {
		t.Fatalf("buildGeneratedDockerConfigYAML returned error: %v", err)
	}

	var cfg map[string]interface{}
	if err := yaml.Unmarshal([]byte(text), &cfg); err != nil {
		t.Fatalf("failed to unmarshal generated config: %v", err)
	}

	security := cfg["security"].(map[string]interface{})
	if security["enableBasicAuth"] != false {
		t.Fatalf("expected basic auth to be disabled")
	}

	plugins := cfg["plugins"].(map[string]interface{})
	apikey := plugins["apikey"].(map[string]interface{})
	if apikey["header_name"] != "X-Custom-Key" {
		t.Fatalf("expected custom api key header name, got %#v", apikey["header_name"])
	}

	clients := apikey["clients"].([]interface{})
	client := clients[0].(map[string]interface{})
	if client["id"] != "partner-a" || client["group"] != "partners" {
		t.Fatalf("unexpected generated api key client: %#v", client)
	}

	policy := security["mutationPolicy"].(map[string]interface{})
	if policy["enabled"] != true {
		t.Fatalf("expected strict governance to enable mutation policy")
	}
	if policy["requireDifferentReviewerForProposals"] != true {
		t.Fatalf("expected strict governance to require different reviewer")
	}
}

func TestBuildGeneratedDockerConfigYAMLIncludesJWTPluginConfig(t *testing.T) {
	answers := newDefaultDockerWizardAnswers()
	answers.AuthMode = "jwt"
	answers.JWTAlgorithm = "HS256"
	answers.JWTSecret = "jwt-shared-secret"
	answers.APIKeyScopes = []string{"profile:read"}

	text, err := buildGeneratedDockerConfigYAML(answers)
	if err != nil {
		t.Fatalf("buildGeneratedDockerConfigYAML returned error: %v", err)
	}

	var cfg map[string]interface{}
	if err := yaml.Unmarshal([]byte(text), &cfg); err != nil {
		t.Fatalf("failed to unmarshal generated config: %v", err)
	}

	plugins := cfg["plugins"].(map[string]interface{})
	jwtPlugin := plugins["jwt"].(map[string]interface{})
	if jwtPlugin["secret"] != "jwt-shared-secret" {
		t.Fatalf("expected jwt plugin secret, got %#v", jwtPlugin["secret"])
	}

	security := cfg["security"].(map[string]interface{})
	jwtSecurity := security["jwt"].(map[string]interface{})
	if jwtSecurity["enabled"] != true {
		t.Fatalf("expected security.jwt enabled")
	}
}

func TestBuildGeneratedDockerConfigYAMLIncludesOAuth2PluginConfig(t *testing.T) {
	answers := newDefaultDockerWizardAnswers()
	answers.AuthMode = "oauth2"
	answers.OAuth2IntrospectURL = "https://auth.example.com/introspect"
	answers.OAuth2ClientID = "gateway"
	answers.OAuth2ClientSecret = "oauth-secret"

	text, err := buildGeneratedDockerConfigYAML(answers)
	if err != nil {
		t.Fatalf("buildGeneratedDockerConfigYAML returned error: %v", err)
	}

	var cfg map[string]interface{}
	if err := yaml.Unmarshal([]byte(text), &cfg); err != nil {
		t.Fatalf("failed to unmarshal generated config: %v", err)
	}

	plugins := cfg["plugins"].(map[string]interface{})
	oauth2Plugin := plugins["oauth2"].(map[string]interface{})
	if oauth2Plugin["introspect_url"] != "https://auth.example.com/introspect" {
		t.Fatalf("expected oauth2 introspect url, got %#v", oauth2Plugin["introspect_url"])
	}
	if oauth2Plugin["client_id"] != "gateway" {
		t.Fatalf("expected oauth2 client id, got %#v", oauth2Plugin["client_id"])
	}
}

func TestBuildGeneratedServiceYAMLIncludesRoutePolicies(t *testing.T) {
	answers := newDefaultDockerWizardAnswers()
	answers.AuthMode = "apikey"
	answers.APIKeyClientGroup = "ops"
	answers.APIKeyScopes = []string{"metrics:read"}
	answers.EnableCORS = true
	answers.CORSOrigins = []string{"https://console.example.com"}
	answers.EnableRateLimit = true
	answers.RateLimitRPS = 25
	answers.RateLimitBurst = 50

	text, err := buildGeneratedServiceYAML(answers)
	if err != nil {
		t.Fatalf("buildGeneratedServiceYAML returned error: %v", err)
	}

	var cfg map[string]interface{}
	if err := yaml.Unmarshal([]byte(text), &cfg); err != nil {
		t.Fatalf("failed to unmarshal generated service config: %v", err)
	}

	services := cfg["services"].([]interface{})
	service := services[0].(map[string]interface{})
	if service["group"] != "ops" {
		t.Fatalf("expected service group to match api key client group, got %#v", service["group"])
	}

	routes := service["routes"].([]interface{})
	route := routes[0].(map[string]interface{})
	if route["auth_plugin"] != "apikey" {
		t.Fatalf("expected auth_plugin apikey, got %#v", route["auth_plugin"])
	}
	if _, ok := route["cors"].(map[string]interface{}); !ok {
		t.Fatalf("expected cors configuration to be present")
	}
	rateLimit := route["rateLimitPolicy"].(map[string]interface{})
	if rateLimit["burst"] != 50 {
		t.Fatalf("expected rate limit burst to be 50, got %#v", rateLimit["burst"])
	}
}

func TestBuildGeneratedServiceYAMLSupportsMultipleServicesAndRoutes(t *testing.T) {
	answers := newDefaultDockerWizardAnswers()
	answers.AuthMode = "apikey"
	answers.APIKeyHeaderName = "X-API-Key"
	answers.Services = []generatedServiceAnswers{
		{
			Name:     "Orders",
			Host:     "http://orders:8080",
			BasePath: "/orders",
			Group:    "partners",
			Scopes:   []string{"orders:read"},
			AuthMode: "apikey",
			Routes: []generatedRouteAnswers{
				{
					Path:            "/list",
					Methods:         []string{"GET"},
					RequireAuth:     true,
					AuthPlugin:      "apikey",
					Scopes:          []string{"orders:read"},
					EnableRateLimit: true,
					RateLimitRPS:    15,
					RateLimitBurst:  30,
				},
				{
					Path:        "/health",
					Methods:     []string{"GET"},
					RequireAuth: false,
				},
			},
		},
		{
			Name:     "Public Info",
			Host:     "http://info:8080",
			BasePath: "/info",
			AuthMode: "public",
			Routes: []generatedRouteAnswers{
				{
					Path:        "/status",
					Methods:     []string{"GET"},
					RequireAuth: false,
					EnableCORS:  true,
					CORSOrigins: []string{"https://app.example.com"},
				},
			},
		},
	}

	text, err := buildGeneratedServiceYAML(answers)
	if err != nil {
		t.Fatalf("buildGeneratedServiceYAML returned error: %v", err)
	}

	var cfg map[string]interface{}
	if err := yaml.Unmarshal([]byte(text), &cfg); err != nil {
		t.Fatalf("failed to unmarshal generated service config: %v", err)
	}

	services := cfg["services"].([]interface{})
	if len(services) != 2 {
		t.Fatalf("expected 2 generated services, got %d", len(services))
	}

	first := services[0].(map[string]interface{})
	routes := first["routes"].([]interface{})
	if len(routes) != 2 {
		t.Fatalf("expected first service to have 2 routes, got %d", len(routes))
	}
	firstRoute := routes[0].(map[string]interface{})
	if firstRoute["auth_plugin"] != "apikey" {
		t.Fatalf("expected first route auth_plugin apikey, got %#v", firstRoute["auth_plugin"])
	}
	secondRoute := routes[1].(map[string]interface{})
	if secondRoute["requireAuth"] != false {
		t.Fatalf("expected second route to be public, got %#v", secondRoute["requireAuth"])
	}

	secondService := services[1].(map[string]interface{})
	secondRoutes := secondService["routes"].([]interface{})
	secondServiceRoute := secondRoutes[0].(map[string]interface{})
	if _, ok := secondServiceRoute["cors"].(map[string]interface{}); !ok {
		t.Fatalf("expected cors config on public info route")
	}
}

func TestBuildGeneratedServiceYAMLIncludesProtocolTimeoutAndConcurrencyPolicies(t *testing.T) {
	answers := newDefaultDockerWizardAnswers()
	answers.Services = []generatedServiceAnswers{
		{
			Name:     "Graph API",
			Host:     "http://graphql:8080",
			BasePath: "/graphql",
			AuthMode: "public",
			Routes: []generatedRouteAnswers{
				{
					Path:                     "/query",
					Methods:                  []string{"POST"},
					Protocol:                 "graphql",
					RequireAuth:              false,
					Timeout:                  "30s",
					StripPath:                true,
					EnableConcurrencyLimit:   true,
					ConcurrencyMaxInFlight:   12,
					ConcurrencyQueueTimeout:  "500ms",
					ConcurrencyMaxQueueDepth: 40,
				},
			},
		},
	}

	text, err := buildGeneratedServiceYAML(answers)
	if err != nil {
		t.Fatalf("buildGeneratedServiceYAML returned error: %v", err)
	}

	var cfg map[string]interface{}
	if err := yaml.Unmarshal([]byte(text), &cfg); err != nil {
		t.Fatalf("failed to unmarshal generated service config: %v", err)
	}

	services := cfg["services"].([]interface{})
	route := services[0].(map[string]interface{})["routes"].([]interface{})[0].(map[string]interface{})
	if route["protocol"] != "graphql" {
		t.Fatalf("expected protocol graphql, got %#v", route["protocol"])
	}
	if route["timeout"] != "30s" {
		t.Fatalf("expected timeout 30s, got %#v", route["timeout"])
	}
	if route["stripPath"] != true {
		t.Fatalf("expected stripPath true, got %#v", route["stripPath"])
	}
	concurrency := route["concurrencyLimitPolicy"].(map[string]interface{})
	if concurrency["maxInFlight"] != 12 {
		t.Fatalf("expected concurrency maxInFlight 12, got %#v", concurrency["maxInFlight"])
	}
	if concurrency["queueTimeout"] != "500ms" {
		t.Fatalf("expected concurrency queueTimeout 500ms, got %#v", concurrency["queueTimeout"])
	}
}

func TestBuildGeneratedServiceYAMLIncludesJWTAndOAuth2RoutePlugins(t *testing.T) {
	cases := []struct {
		name       string
		authMode   string
		authPlugin string
	}{
		{name: "jwt", authMode: "jwt", authPlugin: "jwt"},
		{name: "oauth2", authMode: "oauth2", authPlugin: "oauth2"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			answers := newDefaultDockerWizardAnswers()
			answers.AuthMode = tc.authMode
			answers.APIKeyScopes = []string{"read"}

			text, err := buildGeneratedServiceYAML(answers)
			if err != nil {
				t.Fatalf("buildGeneratedServiceYAML returned error: %v", err)
			}

			var cfg map[string]interface{}
			if err := yaml.Unmarshal([]byte(text), &cfg); err != nil {
				t.Fatalf("failed to unmarshal generated service config: %v", err)
			}

			route := cfg["services"].([]interface{})[0].(map[string]interface{})["routes"].([]interface{})[0].(map[string]interface{})
			if route["auth_plugin"] != tc.authPlugin {
				t.Fatalf("expected auth plugin %s, got %#v", tc.authPlugin, route["auth_plugin"])
			}
			if route["requireAuth"] != true {
				t.Fatalf("expected requireAuth true, got %#v", route["requireAuth"])
			}
		})
	}
}

func TestNormalizeOutputMode(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{name: "default empty", in: "", want: "write"},
		{name: "write explicit", in: "write", want: "write"},
		{name: "preview keeps mode", in: " preview ", want: "preview"},
		{name: "stdout keeps mode", in: "STDOUT", want: "stdout"},
		{name: "unknown falls back", in: "json", want: "write"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := normalizeOutputMode(tc.in); got != tc.want {
				t.Fatalf("normalizeOutputMode(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestBuildBasicDockerBundleIncludesExpectedFiles(t *testing.T) {
	rootDir := filepath.Join(t.TempDir(), "iket-docker")
	layout := newServerScaffoldLayout(rootDir, "iket-docker.service")

	bundle := buildBasicDockerBundle(layout)
	if bundle.RootDir != rootDir {
		t.Fatalf("expected bundle root %q, got %q", rootDir, bundle.RootDir)
	}
	if len(bundle.Files) != 4 {
		t.Fatalf("expected 4 generated files, got %d", len(bundle.Files))
	}

	expectedPaths := []string{
		layout.composePath,
		layout.configPath,
		layout.servicesPath,
		layout.envPath,
	}
	for _, path := range expectedPaths {
		if _, ok := bundle.Files[path]; !ok {
			t.Fatalf("expected bundle to include %s", path)
		}
	}

	if bundleHasPath(bundle, layout.systemdPath) {
		t.Fatalf("did not expect basic bundle to include a systemd unit")
	}
}

func TestFormatAdvancedDockerSummaryIncludesKeySelections(t *testing.T) {
	answers := newDefaultDockerWizardAnswers()
	answers.OutputMode = "preview"
	answers.OutputDir = "./deployments/team-a"
	answers.DeploymentName = "team-a"
	answers.ImageName = "example/iket:v2"
	answers.HTTPPort = "8080"
	answers.HTTPSPort = "9443"
	answers.EnrollmentPort = "9555"
	answers.WithEnv = true
	answers.WithSystemd = true
	answers.SystemdName = "team-a-gateway.service"
	answers.GovernancePreset = "strict"
	answers.AuthMode = "jwt"
	answers.JWTAlgorithm = "RS256"
	answers.JWTPublicKeyFile = "/app/certs/public.pem"
	answers.ServerNames = []string{"gw.internal", "localhost"}
	answers.ServerIPs = []string{"10.0.0.10"}
	answers.Services = []generatedServiceAnswers{
		{
			Name:     "Orders",
			Host:     "http://orders:8080",
			BasePath: "/orders",
			Group:    "partners",
			Scopes:   []string{"orders:read"},
			AuthMode: "jwt",
			Routes: []generatedRouteAnswers{
				{
					Path:                   "/query",
					Methods:                []string{"POST"},
					Protocol:               "graphql",
					RequireAuth:            true,
					AuthPlugin:             "jwt",
					EnableCORS:             true,
					EnableRateLimit:        true,
					RateLimitRPS:           25,
					RateLimitBurst:         50,
					EnableConcurrencyLimit: true,
					ConcurrencyMaxInFlight: 12,
				},
			},
		},
	}

	summary := formatAdvancedDockerSummary(answers)
	expectedSnippets := []string{
		"Output\n",
		"mode: preview",
		"directory: ./deployments/team-a",
		"Deployment\n",
		"name: team-a",
		"ports: http=8080 https=9443 enrollment=9555",
		"systemd file: team-a-gateway.service",
		"Security\n",
		"auth mode: jwt",
		"governance: strict",
		"jwt public key file: /app/certs/public.pem",
		"tls names: gw.internal, localhost",
		"Services (1)",
		"1. Orders -> http://orders:8080/orders",
		"route 1: POST /query [graphql] auth=jwt ratelimit=25rps/50 concurrency=12 cors",
	}
	for _, snippet := range expectedSnippets {
		if !strings.Contains(summary, snippet) {
			t.Fatalf("expected summary to contain %q, got:\n%s", snippet, summary)
		}
	}
}

func TestLoadDockerWizardPresetMergesDefaultsAndNormalizes(t *testing.T) {
	presetPath := filepath.Join(t.TempDir(), "advanced-preset.yaml")
	content := `
outputdir: ./team-a
deploymentname: Team A
outputmode: STDOUT
authmode: jwt
jwtalgorithm: RS256
jwtpublickeyfile: /app/certs/team-a.pem
services:
  - name: Orders
    host: http://orders:8080
    basepath: /orders/
`
	if err := os.WriteFile(presetPath, []byte(content), 0644); err != nil {
		t.Fatalf("write preset: %v", err)
	}

	answers, err := loadDockerWizardPreset(presetPath)
	if err != nil {
		t.Fatalf("loadDockerWizardPreset returned error: %v", err)
	}

	if answers.OutputMode != "stdout" {
		t.Fatalf("expected normalized output mode stdout, got %q", answers.OutputMode)
	}
	if answers.DeploymentName != "team-a" {
		t.Fatalf("expected normalized deployment name team-a, got %q", answers.DeploymentName)
	}
	if answers.JWTAlgorithm != "RS256" {
		t.Fatalf("expected jwt algorithm preserved, got %q", answers.JWTAlgorithm)
	}
	if answers.JWTPublicKeyFile != "/app/certs/team-a.pem" {
		t.Fatalf("expected jwt public key file preserved, got %q", answers.JWTPublicKeyFile)
	}
	if answers.HTTPPort != "7100" {
		t.Fatalf("expected default HTTP port to remain when absent, got %q", answers.HTTPPort)
	}
	if len(answers.Services) != 1 {
		t.Fatalf("expected 1 service from preset, got %d", len(answers.Services))
	}
	if answers.Services[0].BasePath != "/orders/" {
		t.Fatalf("expected preset base path to be preserved for prompting, got %q", answers.Services[0].BasePath)
	}
}

func TestSaveDockerWizardPresetWritesNormalizedYAML(t *testing.T) {
	presetPath := filepath.Join(t.TempDir(), "saved", "docker-preset.yaml")
	answers := newDefaultDockerWizardAnswers()
	answers.OutputMode = "Preview"
	answers.DeploymentName = "Team A"
	answers.SystemdName = "team-a"
	answers.AuthMode = "oauth2"
	answers.OAuth2IntrospectURL = "https://auth.example.com/introspect"
	answers.Services = []generatedServiceAnswers{
		{
			Name:     "Orders",
			Host:     "http://orders:8080",
			BasePath: "/orders",
			AuthMode: "oauth2",
		},
	}

	if err := saveDockerWizardPreset(presetPath, answers); err != nil {
		t.Fatalf("saveDockerWizardPreset returned error: %v", err)
	}

	savedAnswers, err := loadDockerWizardPreset(presetPath)
	if err != nil {
		t.Fatalf("loadDockerWizardPreset returned error: %v", err)
	}

	if savedAnswers.OutputMode != "preview" {
		t.Fatalf("expected saved output mode preview, got %q", savedAnswers.OutputMode)
	}
	if savedAnswers.DeploymentName != "team-a" {
		t.Fatalf("expected saved deployment name team-a, got %q", savedAnswers.DeploymentName)
	}
	if savedAnswers.SystemdName != "team-a" {
		t.Fatalf("expected saved systemd name team-a, got %q", savedAnswers.SystemdName)
	}
	if savedAnswers.AuthMode != "oauth2" {
		t.Fatalf("expected auth mode oauth2, got %q", savedAnswers.AuthMode)
	}
	if len(savedAnswers.Services) != 1 || savedAnswers.Services[0].Name != "Orders" {
		t.Fatalf("expected saved service payload, got %#v", savedAnswers.Services)
	}
}

func TestRunDockerGenerationWizardRejectsYesWithoutPreset(t *testing.T) {
	err := runDockerGenerationWizard(genWizardOptions{AutoApprove: true})
	if err == nil {
		t.Fatalf("expected error when --yes is used without --preset")
	}
	if !strings.Contains(err.Error(), "--yes requires --preset") {
		t.Fatalf("expected preset requirement error, got %v", err)
	}
}

func TestFinalizeAdvancedDockerGenerationAutoApproveSavesPreset(t *testing.T) {
	presetPath := filepath.Join(t.TempDir(), "saved", "team-a.yaml")
	answers := newDefaultDockerWizardAnswers()
	answers.OutputMode = "preview"
	answers.OutputDir = "./team-a"
	answers.DeploymentName = "Team A"
	answers.AuthMode = "apikey"
	answers.APIKeyHeaderName = "X-Team-Key"
	answers.APIKeyClientID = "team-a-client"
	answers.APIKeyClientGroup = "team-a"
	answers.Services = []generatedServiceAnswers{
		{
			Name:     "Orders",
			Host:     "http://orders:8080",
			BasePath: "/orders",
			Group:    "team-a",
			Scopes:   []string{"orders:read"},
			AuthMode: "apikey",
			Routes: []generatedRouteAnswers{
				{
					Path:        "/list",
					Methods:     []string{"GET"},
					RequireAuth: true,
					AuthPlugin:  "apikey",
				},
			},
		},
	}

	err := finalizeAdvancedDockerGeneration(
		bufio.NewReader(strings.NewReader("")),
		genWizardOptions{AutoApprove: true, SavePresetPath: presetPath},
		answers,
	)
	if err != nil {
		t.Fatalf("finalizeAdvancedDockerGeneration returned error: %v", err)
	}

	savedAnswers, err := loadDockerWizardPreset(presetPath)
	if err != nil {
		t.Fatalf("loadDockerWizardPreset returned error: %v", err)
	}
	if savedAnswers.OutputMode != "preview" {
		t.Fatalf("expected preview output mode, got %q", savedAnswers.OutputMode)
	}
	if savedAnswers.DeploymentName != "team-a" {
		t.Fatalf("expected normalized deployment name team-a, got %q", savedAnswers.DeploymentName)
	}
	if savedAnswers.APIKeyClientID != "team-a-client" {
		t.Fatalf("expected saved api key client id, got %q", savedAnswers.APIKeyClientID)
	}
	if len(savedAnswers.Services) != 1 || savedAnswers.Services[0].Name != "Orders" {
		t.Fatalf("expected saved service payload, got %#v", savedAnswers.Services)
	}
}

func TestFormatDockerWizardPresetYAMLIncludesNormalizedDefaults(t *testing.T) {
	answers := newDefaultDockerWizardAnswers()
	answers.DeploymentName = "Team A"
	answers.OutputMode = "STDOUT"

	text, err := formatDockerWizardPresetYAML(answers)
	if err != nil {
		t.Fatalf("formatDockerWizardPresetYAML returned error: %v", err)
	}
	if !strings.Contains(text, "deploymentname: team-a") {
		t.Fatalf("expected normalized deployment name in yaml, got:\n%s", text)
	}
	if !strings.Contains(text, "outputmode: stdout") {
		t.Fatalf("expected normalized output mode in yaml, got:\n%s", text)
	}
	if !strings.Contains(text, "withenv: true") {
		t.Fatalf("expected default env flag in yaml, got:\n%s", text)
	}
}

func TestBuildDockerWizardPresetTemplateSupportsAuthModes(t *testing.T) {
	cases := []struct {
		name        string
		authMode    string
		authPlugin  string
		requireAuth bool
	}{
		{name: "public", authMode: "public", authPlugin: "", requireAuth: false},
		{name: "apikey", authMode: "apikey", authPlugin: "apikey", requireAuth: true},
		{name: "jwt", authMode: "jwt", authPlugin: "jwt", requireAuth: true},
		{name: "oauth2", authMode: "oauth2", authPlugin: "oauth2", requireAuth: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			answers, err := buildDockerWizardPresetTemplate(tc.authMode, true)
			if err != nil {
				t.Fatalf("buildDockerWizardPresetTemplate returned error: %v", err)
			}
			if answers.AuthMode != tc.authMode {
				t.Fatalf("expected auth mode %q, got %q", tc.authMode, answers.AuthMode)
			}
			if len(answers.Services) != 1 || len(answers.Services[0].Routes) != 1 {
				t.Fatalf("expected one default service and route, got %#v", answers.Services)
			}
			route := answers.Services[0].Routes[0]
			if route.RequireAuth != tc.requireAuth {
				t.Fatalf("expected requireAuth %t, got %t", tc.requireAuth, route.RequireAuth)
			}
			if route.AuthPlugin != tc.authPlugin {
				t.Fatalf("expected auth plugin %q, got %q", tc.authPlugin, route.AuthPlugin)
			}
		})
	}
}

func TestBuildDockerWizardPresetTemplateRejectsUnknownAuthMode(t *testing.T) {
	_, err := buildDockerWizardPresetTemplate("saml", true)
	if err == nil {
		t.Fatalf("expected error for unsupported auth mode")
	}
	if !strings.Contains(err.Error(), "unsupported auth mode") {
		t.Fatalf("expected unsupported auth mode error, got %v", err)
	}
}

func TestBuildDockerWizardPresetTemplateSupportsEmptyServices(t *testing.T) {
	answers, err := buildDockerWizardPresetTemplate("oauth2", false)
	if err != nil {
		t.Fatalf("buildDockerWizardPresetTemplate returned error: %v", err)
	}
	if answers.AuthMode != "oauth2" {
		t.Fatalf("expected oauth2 auth mode, got %q", answers.AuthMode)
	}
	if answers.Services != nil {
		t.Fatalf("expected empty services skeleton, got %#v", answers.Services)
	}
}

func TestApplyDockerPresetOverridesSupportsCommonFields(t *testing.T) {
	answers := newDefaultDockerWizardAnswers()
	err := applyDockerPresetOverrides(&answers, []string{
		"deployment-name=Team A",
		"http-port=8088",
		"https-port=9444",
		"timezone=Asia/Jakarta",
		"with-systemd=true",
		"server-names=gw.internal,localhost",
		"api-key-scopes=orders:read,orders:write",
		"route-methods=get,post",
		"service-base-path=orders",
	})
	if err != nil {
		t.Fatalf("applyDockerPresetOverrides returned error: %v", err)
	}

	if answers.DeploymentName != "team-a" {
		t.Fatalf("expected normalized deployment name team-a, got %q", answers.DeploymentName)
	}
	if answers.HTTPPort != "8088" || answers.HTTPSPort != "9444" {
		t.Fatalf("expected overridden ports, got http=%q https=%q", answers.HTTPPort, answers.HTTPSPort)
	}
	if answers.Timezone != "Asia/Jakarta" {
		t.Fatalf("expected timezone override, got %q", answers.Timezone)
	}
	if !answers.WithSystemd {
		t.Fatalf("expected withSystemd true")
	}
	if len(answers.ServerNames) != 2 || answers.ServerNames[0] != "gw.internal" {
		t.Fatalf("expected server names override, got %#v", answers.ServerNames)
	}
	if len(answers.APIKeyScopes) != 2 || answers.APIKeyScopes[1] != "orders:write" {
		t.Fatalf("expected api key scopes override, got %#v", answers.APIKeyScopes)
	}
	if len(answers.RouteMethods) != 2 || answers.RouteMethods[0] != "GET" || answers.RouteMethods[1] != "POST" {
		t.Fatalf("expected uppercase route methods override, got %#v", answers.RouteMethods)
	}
	if answers.ServiceBasePath != "/orders" {
		t.Fatalf("expected normalized service base path /orders, got %q", answers.ServiceBasePath)
	}
}

func TestApplyDockerPresetOverridesRejectsInvalidEntries(t *testing.T) {
	answers := newDefaultDockerWizardAnswers()

	err := applyDockerPresetOverrides(&answers, []string{"broken"})
	if err == nil || !strings.Contains(err.Error(), "expected key=value") {
		t.Fatalf("expected key=value validation error, got %v", err)
	}

	err = applyDockerPresetOverrides(&answers, []string{"unknown-key=value"})
	if err == nil || !strings.Contains(err.Error(), "unsupported preset override key") {
		t.Fatalf("expected unsupported key error, got %v", err)
	}

	err = applyDockerPresetOverrides(&answers, []string{"with-env=maybe"})
	if err == nil || !strings.Contains(err.Error(), "expected boolean value") {
		t.Fatalf("expected boolean validation error, got %v", err)
	}
}

func TestCollectDockerPresetEnvOverrides(t *testing.T) {
	t.Setenv("IKET_PRESET_DEPLOYMENT_NAME", "Team A")
	t.Setenv("IKET_PRESET_HTTP_PORT", "8088")
	t.Setenv("IKET_PRESET_ROUTE_METHODS", "get,post")

	overrides, err := collectDockerPresetEnvOverrides("IKET_PRESET_")
	if err != nil {
		t.Fatalf("collectDockerPresetEnvOverrides returned error: %v", err)
	}
	joined := strings.Join(overrides, "\n")
	for _, expected := range []string{
		"deployment-name=Team A",
		"http-port=8088",
		"route-methods=get,post",
	} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("expected env override %q, got %#v", expected, overrides)
		}
	}
}

func TestGeneratedOverrideHelpMentionsKeysAndExamples(t *testing.T) {
	genHelp := buildGenCommandLongHelp()
	presetHelp := buildGenPresetCommandLongHelp()

	for _, snippet := range []string{
		"Supported override keys for `--set` and `--from-env`",
		"deployment-name",
		"http-port",
		"oauth2-introspect-url",
		"--from-env IKET_GEN_",
		"--fail-on-warning security --warning-report ./warnings.json --warning-report-format json --yes",
		"Auth requirements:",
		"jwt-secret for HS256",
		"Preflight checks:",
		"http-port, https-port, and enrollment-port must be numeric and unique",
		"Warning policy:",
		"`--warning-report ./warnings.md` writes a review artifact",
		"`--warning-report-format json` emits machine-readable warnings",
		"`--print-warning-summary json` prints the warning payload to stdout",
		"categories: security, deployment, local-dev",
	} {
		if !strings.Contains(genHelp, snippet) {
			t.Fatalf("expected gen help to contain %q, got:\n%s", snippet, genHelp)
		}
	}

	for _, snippet := range []string{
		"Supported override keys for `--set` and `--from-env`",
		"api-key-client-id",
		"route-methods",
		"--from-env IKET_PRESET_",
		"iket gen preset --inspect",
		"oauth2-client-secret",
		"each route needs at least one method",
	} {
		if !strings.Contains(presetHelp, snippet) {
			t.Fatalf("expected preset help to contain %q, got:\n%s", snippet, presetHelp)
		}
	}
}

func TestDockerAuthRequirementSummary(t *testing.T) {
	cases := []struct {
		authMode string
		want     string
	}{
		{authMode: "public", want: "no extra auth fields required"},
		{authMode: "apikey", want: "api-key-header-name"},
		{authMode: "jwt", want: "jwt-secret for HS256"},
		{authMode: "oauth2", want: "oauth2-introspect-url"},
	}
	for _, tc := range cases {
		got := dockerAuthRequirementSummary(tc.authMode)
		if !strings.Contains(got, tc.want) {
			t.Fatalf("dockerAuthRequirementSummary(%q) = %q, want substring %q", tc.authMode, got, tc.want)
		}
	}
}

func TestValidateDockerWizardAnswersRejectsInvalidAuthCombinations(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*dockerWizardAnswers)
		wantErr string
	}{
		{
			name: "jwt hs256 missing secret",
			mutate: func(a *dockerWizardAnswers) {
				a.AuthMode = "jwt"
				a.JWTAlgorithm = "HS256"
				a.JWTSecret = ""
			},
			wantErr: "jwt HS256 auth requires jwt-secret",
		},
		{
			name: "jwt rs256 missing public key",
			mutate: func(a *dockerWizardAnswers) {
				a.AuthMode = "jwt"
				a.JWTAlgorithm = "RS256"
				a.JWTPublicKeyFile = ""
			},
			wantErr: "jwt RS256 auth requires jwt-public-key-file",
		},
		{
			name: "oauth2 missing secret",
			mutate: func(a *dockerWizardAnswers) {
				a.AuthMode = "oauth2"
				a.OAuth2ClientSecret = ""
			},
			wantErr: "oauth2 auth requires oauth2-introspect-url, oauth2-client-id, and oauth2-client-secret",
		},
		{
			name: "apikey missing header",
			mutate: func(a *dockerWizardAnswers) {
				a.AuthMode = "apikey"
				a.APIKeyHeaderName = ""
			},
			wantErr: "api key auth requires api-key-header-name",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			answers := newDefaultDockerWizardAnswers()
			tc.mutate(&answers)
			err := validateDockerWizardAnswers(answers)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("expected error containing %q, got %v", tc.wantErr, err)
			}
		})
	}
}

func TestFormatAdvancedDockerSummaryIncludesAuthRequirements(t *testing.T) {
	answers := newDefaultDockerWizardAnswers()
	answers.AuthMode = "oauth2"
	answers.OAuth2IntrospectURL = "https://auth.example.com/introspect"

	summary := formatAdvancedDockerSummary(answers)
	if !strings.Contains(summary, "requirements: requires oauth2-introspect-url, oauth2-client-id, and oauth2-client-secret") {
		t.Fatalf("expected auth requirement hint in summary, got:\n%s", summary)
	}
	if !strings.Contains(summary, "port requirements: http/https/enrollment ports must be numeric and unique") {
		t.Fatalf("expected port requirement hint in summary, got:\n%s", summary)
	}
	if !strings.Contains(summary, "each service needs a name and host; each route needs methods; protected routes need auth_plugin") {
		t.Fatalf("expected service/route requirement hint in summary, got:\n%s", summary)
	}
}

func TestCollectDockerWizardWarningsFlagsRiskyDefaults(t *testing.T) {
	answers := newDefaultDockerWizardAnswers()
	answers.AuthMode = "oauth2"
	answers.Services = []generatedServiceAnswers{
		{
			Name:     "Orders",
			Host:     "http://localhost:8080",
			BasePath: "/orders",
			AuthMode: "oauth2",
		},
	}

	warnings := collectDockerWizardWarnings(answers)
	joined := ""
	for _, warning := range warnings {
		joined += warning.Category + ":" + warning.Message + "\n"
	}
	for _, expected := range []string{
		"`latest` tag",
		"default placeholder",
		"default UTC",
		"oauth2 client secret still uses a placeholder value",
		`service "Orders" still points to a localhost upstream`,
	} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("expected warning containing %q, got %#v", expected, warnings)
		}
	}
	if !strings.Contains(joined, "security:") || !strings.Contains(joined, "deployment:") || !strings.Contains(joined, "local-dev:") {
		t.Fatalf("expected categorized warnings, got %#v", warnings)
	}
}

func TestFormatAdvancedDockerSummaryIncludesWarnings(t *testing.T) {
	answers := newDefaultDockerWizardAnswers()
	answers.AuthMode = "apikey"
	answers.Services = []generatedServiceAnswers{
		{
			Name:     "Orders",
			Host:     "http://127.0.0.1:8080",
			BasePath: "/orders",
			AuthMode: "apikey",
		},
	}

	summary := formatAdvancedDockerSummary(answers)
	if !strings.Contains(summary, "Warnings (") {
		t.Fatalf("expected warnings section in summary, got:\n%s", summary)
	}
	if !strings.Contains(summary, "security (") || !strings.Contains(summary, "deployment (") || !strings.Contains(summary, "local-dev (") {
		t.Fatalf("expected grouped warning categories in summary, got:\n%s", summary)
	}
	if !strings.Contains(summary, "image uses a `latest` tag") {
		t.Fatalf("expected image warning in summary, got:\n%s", summary)
	}
	if !strings.Contains(summary, "service \"Orders\" still points to a localhost upstream") {
		t.Fatalf("expected localhost upstream warning in summary, got:\n%s", summary)
	}
}

func TestMatchDockerWarningsForPolicyRejectsUnknownCategory(t *testing.T) {
	warnings := []dockerWizardWarning{{Category: "security", Message: "placeholder secret"}}

	_, err := matchDockerWarningsForPolicy(warnings, []string{"unknown"})
	if err == nil || !strings.Contains(err.Error(), "unsupported warning category") {
		t.Fatalf("expected unsupported warning category error, got %v", err)
	}
}

func TestFinalizeAdvancedDockerGenerationFailsOnMatchingWarnings(t *testing.T) {
	answers := newDefaultDockerWizardAnswers()
	answers.OutputMode = "preview"
	answers.OutputDir = t.TempDir()
	reportPath := filepath.Join(t.TempDir(), "warnings.md")

	err := finalizeAdvancedDockerGeneration(
		bufio.NewReader(strings.NewReader("")),
		genWizardOptions{AutoApprove: true, FailOnWarnings: []string{"security"}, WarningReport: reportPath},
		answers,
	)
	if err == nil || !strings.Contains(err.Error(), "warning policy blocked generation") {
		t.Fatalf("expected warning policy failure, got %v", err)
	}
	if !strings.Contains(err.Error(), "security:") {
		t.Fatalf("expected security warning detail, got %v", err)
	}
	reportBytes, readErr := os.ReadFile(reportPath)
	if readErr != nil {
		t.Fatalf("expected warning report to be written before failure, got %v", readErr)
	}
	report := string(reportBytes)
	if !strings.Contains(report, "# Iket Docker Generator Warning Report") {
		t.Fatalf("expected warning report header, got:\n%s", report)
	}
	if !strings.Contains(report, "## Blocking Matches") {
		t.Fatalf("expected blocking matches section, got:\n%s", report)
	}
}

func TestFinalizeAdvancedDockerGenerationAllowsNonMatchingWarningCategories(t *testing.T) {
	answers := newDefaultDockerWizardAnswers()
	answers.OutputMode = "preview"
	answers.OutputDir = t.TempDir()
	answers.ImageName = "bhangun/iket:1.2.3"
	answers.AdminPassword = "super-secret"
	answers.Timezone = "Asia/Jakarta"
	answers.Services = []generatedServiceAnswers{
		{
			Name:     "Orders",
			Host:     "http://orders:8080",
			BasePath: "/orders",
			AuthMode: "public",
			Routes: []generatedRouteAnswers{
				{
					Path:    "/list",
					Methods: []string{"GET"},
				},
			},
		},
	}

	err := finalizeAdvancedDockerGeneration(
		bufio.NewReader(strings.NewReader("")),
		genWizardOptions{AutoApprove: true, FailOnWarnings: []string{"local-dev"}},
		answers,
	)
	if err != nil {
		t.Fatalf("expected non-matching warning policy to allow generation, got %v", err)
	}
}

func TestFinalizeAdvancedDockerGenerationWritesWarningReport(t *testing.T) {
	answers := newDefaultDockerWizardAnswers()
	answers.OutputMode = "preview"
	answers.OutputDir = t.TempDir()
	answers.ImageName = "bhangun/iket:1.2.3"
	answers.AdminPassword = "super-secret"
	answers.Timezone = "Asia/Jakarta"
	answers.Services = []generatedServiceAnswers{
		{
			Name:     "Orders",
			Host:     "http://localhost:8080",
			BasePath: "/orders",
			AuthMode: "public",
			Routes: []generatedRouteAnswers{
				{
					Path:    "/list",
					Methods: []string{"GET"},
				},
			},
		},
	}
	reportPath := filepath.Join(t.TempDir(), "warnings", "report.md")

	err := finalizeAdvancedDockerGeneration(
		bufio.NewReader(strings.NewReader("")),
		genWizardOptions{AutoApprove: true, WarningReport: reportPath},
		answers,
	)
	if err != nil {
		t.Fatalf("expected warning report generation to succeed, got %v", err)
	}

	reportBytes, readErr := os.ReadFile(reportPath)
	if readErr != nil {
		t.Fatalf("expected warning report file, got %v", readErr)
	}
	report := string(reportBytes)
	for _, snippet := range []string{
		"# Iket Docker Generator Warning Report",
		"- fail_on_warning: none",
		"## Warnings (1)",
		"### local-dev (1)",
		`service "Orders" still points to a localhost upstream`,
	} {
		if !strings.Contains(report, snippet) {
			t.Fatalf("expected warning report to contain %q, got:\n%s", snippet, report)
		}
	}
}

func TestFinalizeAdvancedDockerGenerationWritesJSONWarningReport(t *testing.T) {
	answers := newDefaultDockerWizardAnswers()
	answers.OutputMode = "preview"
	answers.OutputDir = t.TempDir()
	reportPath := filepath.Join(t.TempDir(), "warnings.json")

	err := finalizeAdvancedDockerGeneration(
		bufio.NewReader(strings.NewReader("")),
		genWizardOptions{
			AutoApprove:         true,
			WarningReport:       reportPath,
			WarningReportFormat: "json",
			FailOnWarnings:      []string{"security"},
		},
		answers,
	)
	if err == nil || !strings.Contains(err.Error(), "warning policy blocked generation") {
		t.Fatalf("expected warning policy failure, got %v", err)
	}

	reportBytes, readErr := os.ReadFile(reportPath)
	if readErr != nil {
		t.Fatalf("expected json warning report file, got %v", readErr)
	}

	var report struct {
		Deployment      string                `json:"deployment"`
		OutputMode      string                `json:"output_mode"`
		FailOnWarning   []string              `json:"fail_on_warning"`
		BlockingMatches []dockerWizardWarning `json:"blocking_matches"`
		Warnings        []dockerWizardWarning `json:"warnings"`
	}
	if unmarshalErr := json.Unmarshal(reportBytes, &report); unmarshalErr != nil {
		t.Fatalf("expected valid json warning report, got %v\n%s", unmarshalErr, string(reportBytes))
	}
	if report.Deployment != "iket" {
		t.Fatalf("expected deployment name iket, got %q", report.Deployment)
	}
	if report.OutputMode != "preview" {
		t.Fatalf("expected preview output mode, got %q", report.OutputMode)
	}
	if len(report.FailOnWarning) != 1 || report.FailOnWarning[0] != "security" {
		t.Fatalf("expected fail_on_warning selector, got %#v", report.FailOnWarning)
	}
	if len(report.BlockingMatches) == 0 {
		t.Fatalf("expected blocking matches in json report, got %#v", report)
	}
	if len(report.Warnings) == 0 {
		t.Fatalf("expected warnings in json report, got %#v", report)
	}
}

func TestFinalizeAdvancedDockerGenerationRejectsUnsupportedWarningReportFormat(t *testing.T) {
	answers := newDefaultDockerWizardAnswers()
	answers.OutputMode = "preview"
	answers.OutputDir = t.TempDir()

	err := finalizeAdvancedDockerGeneration(
		bufio.NewReader(strings.NewReader("")),
		genWizardOptions{
			AutoApprove:         true,
			WarningReport:       filepath.Join(t.TempDir(), "warnings.out"),
			WarningReportFormat: "yaml",
		},
		answers,
	)
	if err == nil || !strings.Contains(err.Error(), "unsupported warning report format") {
		t.Fatalf("expected unsupported warning report format error, got %v", err)
	}
}

func TestFinalizeAdvancedDockerGenerationPrintsJSONWarningSummary(t *testing.T) {
	answers := newDefaultDockerWizardAnswers()
	answers.OutputMode = "preview"
	answers.OutputDir = t.TempDir()

	output := captureStdout(t, func() {
		err := finalizeAdvancedDockerGeneration(
			bufio.NewReader(strings.NewReader("")),
			genWizardOptions{
				AutoApprove:         true,
				PrintWarningSummary: "json",
				FailOnWarnings:      []string{"security"},
			},
			answers,
		)
		if err == nil || !strings.Contains(err.Error(), "warning policy blocked generation") {
			t.Fatalf("expected warning policy failure, got %v", err)
		}
	})

	start := strings.Index(output, "{")
	if start == -1 {
		t.Fatalf("expected json warning summary in stdout, got:\n%s", output)
	}

	var report struct {
		Deployment      string                `json:"deployment"`
		FailOnWarning   []string              `json:"fail_on_warning"`
		BlockingMatches []dockerWizardWarning `json:"blocking_matches"`
	}
	if err := json.Unmarshal([]byte(output[start:]), &report); err != nil {
		t.Fatalf("expected valid json warning summary, got %v\n%s", err, output)
	}
	if report.Deployment != "iket" {
		t.Fatalf("expected deployment iket, got %q", report.Deployment)
	}
	if len(report.FailOnWarning) != 1 || report.FailOnWarning[0] != "security" {
		t.Fatalf("expected fail_on_warning selector, got %#v", report.FailOnWarning)
	}
	if len(report.BlockingMatches) == 0 {
		t.Fatalf("expected blocking matches in printed summary, got %#v", report)
	}
}

func TestFinalizeAdvancedDockerGenerationRejectsUnsupportedPrintedWarningSummaryFormat(t *testing.T) {
	answers := newDefaultDockerWizardAnswers()
	answers.OutputMode = "preview"
	answers.OutputDir = t.TempDir()

	err := finalizeAdvancedDockerGeneration(
		bufio.NewReader(strings.NewReader("")),
		genWizardOptions{
			AutoApprove:         true,
			PrintWarningSummary: "yaml",
		},
		answers,
	)
	if err == nil || !strings.Contains(err.Error(), "unsupported warning report format") {
		t.Fatalf("expected unsupported printed warning summary format error, got %v", err)
	}
}

func TestValidateDockerWizardAnswersRejectsInvalidPorts(t *testing.T) {
	answers := newDefaultDockerWizardAnswers()
	answers.HTTPPort = "8443"
	answers.HTTPSPort = "8443"

	err := validateDockerWizardAnswers(answers)
	if err == nil || !strings.Contains(err.Error(), "ports must be unique") {
		t.Fatalf("expected duplicate port validation error, got %v", err)
	}

	answers = newDefaultDockerWizardAnswers()
	answers.HTTPPort = "not-a-port"
	err = validateDockerWizardAnswers(answers)
	if err == nil || !strings.Contains(err.Error(), "must be numeric") {
		t.Fatalf("expected numeric port validation error, got %v", err)
	}
}

func TestWriteDockerWizardPresetTemplateWritesLoadableFile(t *testing.T) {
	presetPath := filepath.Join(t.TempDir(), "presets", "docker-template.yaml")
	if err := writeDockerWizardPresetTemplate(presetPath, false, "", true, nil, ""); err != nil {
		t.Fatalf("writeDockerWizardPresetTemplate returned error: %v", err)
	}

	answers, err := loadDockerWizardPreset(presetPath)
	if err != nil {
		t.Fatalf("loadDockerWizardPreset returned error: %v", err)
	}
	if answers.DeploymentName != "iket" {
		t.Fatalf("expected default deployment name iket, got %q", answers.DeploymentName)
	}
	if answers.OutputMode != "write" {
		t.Fatalf("expected default output mode write, got %q", answers.OutputMode)
	}
}

func TestWriteDockerWizardPresetTemplateSupportsAuthMode(t *testing.T) {
	presetPath := filepath.Join(t.TempDir(), "presets", "jwt-template.yaml")
	if err := writeDockerWizardPresetTemplate(presetPath, false, "jwt", true, nil, ""); err != nil {
		t.Fatalf("writeDockerWizardPresetTemplate returned error: %v", err)
	}

	answers, err := loadDockerWizardPreset(presetPath)
	if err != nil {
		t.Fatalf("loadDockerWizardPreset returned error: %v", err)
	}
	if answers.AuthMode != "jwt" {
		t.Fatalf("expected jwt auth mode, got %q", answers.AuthMode)
	}
	if len(answers.Services) != 1 || len(answers.Services[0].Routes) != 1 {
		t.Fatalf("expected one starter service/route, got %#v", answers.Services)
	}
	if answers.Services[0].Routes[0].AuthPlugin != "jwt" {
		t.Fatalf("expected jwt route auth plugin, got %q", answers.Services[0].Routes[0].AuthPlugin)
	}
}

func TestWriteDockerWizardPresetTemplateSupportsEmptyServices(t *testing.T) {
	presetPath := filepath.Join(t.TempDir(), "presets", "blank-template.yaml")
	if err := writeDockerWizardPresetTemplate(presetPath, false, "apikey", false, nil, ""); err != nil {
		t.Fatalf("writeDockerWizardPresetTemplate returned error: %v", err)
	}

	answers, err := loadDockerWizardPreset(presetPath)
	if err != nil {
		t.Fatalf("loadDockerWizardPreset returned error: %v", err)
	}
	if answers.AuthMode != "apikey" {
		t.Fatalf("expected apikey auth mode, got %q", answers.AuthMode)
	}
	if len(answers.Services) != 0 {
		t.Fatalf("expected saved preset without starter services, got %#v", answers.Services)
	}
}

func TestWriteDockerWizardPresetTemplateAppliesOverrides(t *testing.T) {
	presetPath := filepath.Join(t.TempDir(), "presets", "custom-template.yaml")
	err := writeDockerWizardPresetTemplate(presetPath, false, "oauth2", true, []string{
		"deployment-name=Team A",
		"http-port=8088",
		"oauth2-introspect-url=https://auth.example.com/introspect",
		"service-name=Orders API",
	}, "")
	if err != nil {
		t.Fatalf("writeDockerWizardPresetTemplate returned error: %v", err)
	}

	answers, err := loadDockerWizardPreset(presetPath)
	if err != nil {
		t.Fatalf("loadDockerWizardPreset returned error: %v", err)
	}
	if answers.DeploymentName != "team-a" {
		t.Fatalf("expected normalized deployment name team-a, got %q", answers.DeploymentName)
	}
	if answers.HTTPPort != "8088" {
		t.Fatalf("expected overridden http port 8088, got %q", answers.HTTPPort)
	}
	if answers.OAuth2IntrospectURL != "https://auth.example.com/introspect" {
		t.Fatalf("expected oauth2 introspection override, got %q", answers.OAuth2IntrospectURL)
	}
	if len(answers.Services) != 1 || answers.Services[0].Name != "Orders API" {
		t.Fatalf("expected overridden service name, got %#v", answers.Services)
	}
}

func TestWriteDockerWizardPresetTemplateAppliesEnvOverrides(t *testing.T) {
	presetPath := filepath.Join(t.TempDir(), "presets", "env-template.yaml")
	t.Setenv("IKET_PRESET_DEPLOYMENT_NAME", "Env Team")
	t.Setenv("IKET_PRESET_HTTP_PORT", "9090")

	err := writeDockerWizardPresetTemplate(presetPath, false, "public", true, nil, "IKET_PRESET_")
	if err != nil {
		t.Fatalf("writeDockerWizardPresetTemplate returned error: %v", err)
	}

	answers, err := loadDockerWizardPreset(presetPath)
	if err != nil {
		t.Fatalf("loadDockerWizardPreset returned error: %v", err)
	}
	if answers.DeploymentName != "env-team" {
		t.Fatalf("expected env-overridden deployment name env-team, got %q", answers.DeploymentName)
	}
	if answers.HTTPPort != "9090" {
		t.Fatalf("expected env-overridden http port 9090, got %q", answers.HTTPPort)
	}
}

func TestRunDockerGenerationWizardAppliesSetOverridesToPreset(t *testing.T) {
	presetPath := filepath.Join(t.TempDir(), "base-preset.yaml")
	savedPath := filepath.Join(t.TempDir(), "saved-preset.yaml")

	base := newDefaultDockerWizardAnswers()
	base.OutputMode = "preview"
	base.DeploymentName = "base-team"
	base.HTTPPort = "7100"
	base.AuthMode = "oauth2"
	base.OAuth2IntrospectURL = "https://base.example.com/introspect"
	if err := saveDockerWizardPreset(presetPath, base); err != nil {
		t.Fatalf("saveDockerWizardPreset returned error: %v", err)
	}

	err := runDockerGenerationWizard(genWizardOptions{
		PresetPath:      presetPath,
		SavePresetPath:  savedPath,
		AutoApprove:     true,
		PresetOverrides: []string{"deployment-name=Team A", "http-port=8088", "oauth2-introspect-url=https://auth.example.com/introspect"},
	})
	if err != nil {
		t.Fatalf("runDockerGenerationWizard returned error: %v", err)
	}

	saved, err := loadDockerWizardPreset(savedPath)
	if err != nil {
		t.Fatalf("loadDockerWizardPreset returned error: %v", err)
	}
	if saved.DeploymentName != "team-a" {
		t.Fatalf("expected overridden deployment name team-a, got %q", saved.DeploymentName)
	}
	if saved.HTTPPort != "8088" {
		t.Fatalf("expected overridden http port 8088, got %q", saved.HTTPPort)
	}
	if saved.OAuth2IntrospectURL != "https://auth.example.com/introspect" {
		t.Fatalf("expected overridden oauth2 introspection url, got %q", saved.OAuth2IntrospectURL)
	}
}

func TestRunDockerGenerationWizardAppliesEnvOverridesToPreset(t *testing.T) {
	presetPath := filepath.Join(t.TempDir(), "base-preset.yaml")
	savedPath := filepath.Join(t.TempDir(), "saved-preset.yaml")

	base := newDefaultDockerWizardAnswers()
	base.OutputMode = "preview"
	base.DeploymentName = "base-team"
	if err := saveDockerWizardPreset(presetPath, base); err != nil {
		t.Fatalf("saveDockerWizardPreset returned error: %v", err)
	}

	t.Setenv("IKET_GEN_DEPLOYMENT_NAME", "Env Team")
	t.Setenv("IKET_GEN_HTTP_PORT", "9090")

	err := runDockerGenerationWizard(genWizardOptions{
		PresetPath:     presetPath,
		SavePresetPath: savedPath,
		AutoApprove:    true,
		EnvPrefix:      "IKET_GEN_",
	})
	if err != nil {
		t.Fatalf("runDockerGenerationWizard returned error: %v", err)
	}

	saved, err := loadDockerWizardPreset(savedPath)
	if err != nil {
		t.Fatalf("loadDockerWizardPreset returned error: %v", err)
	}
	if saved.DeploymentName != "env-team" {
		t.Fatalf("expected env-overridden deployment name env-team, got %q", saved.DeploymentName)
	}
	if saved.HTTPPort != "9090" {
		t.Fatalf("expected env-overridden http port 9090, got %q", saved.HTTPPort)
	}
}

func TestRunDockerGenerationWizardRejectsInvalidPresetConfiguration(t *testing.T) {
	presetPath := filepath.Join(t.TempDir(), "invalid-preset.yaml")
	answers := newDefaultDockerWizardAnswers()
	answers.OutputMode = "preview"
	answers.AuthMode = "jwt"
	answers.JWTAlgorithm = "HS256"
	answers.JWTSecret = ""
	if err := saveDockerWizardPreset(presetPath, answers); err != nil {
		t.Fatalf("saveDockerWizardPreset returned error: %v", err)
	}

	err := runDockerGenerationWizard(genWizardOptions{
		PresetPath:  presetPath,
		AutoApprove: true,
	})
	if err == nil || !strings.Contains(err.Error(), "jwt HS256 auth requires jwt-secret") {
		t.Fatalf("expected jwt validation error, got %v", err)
	}
}

func TestInspectDockerWizardPresetPrintsSummary(t *testing.T) {
	presetPath := filepath.Join(t.TempDir(), "inspect.yaml")
	answers := newDefaultDockerWizardAnswers()
	answers.OutputDir = "./team-a"
	answers.DeploymentName = "Team A"
	answers.AuthMode = "oauth2"
	answers.OAuth2IntrospectURL = "https://auth.example.com/introspect"
	if err := saveDockerWizardPreset(presetPath, answers); err != nil {
		t.Fatalf("saveDockerWizardPreset returned error: %v", err)
	}

	output := captureStdout(t, func() {
		if err := inspectDockerWizardPreset(presetPath); err != nil {
			t.Fatalf("inspectDockerWizardPreset returned error: %v", err)
		}
	})
	if !strings.Contains(output, "Preset: "+presetPath) {
		t.Fatalf("expected preset path in inspect output, got:\n%s", output)
	}
	if !strings.Contains(output, "auth mode: oauth2") {
		t.Fatalf("expected auth mode in inspect output, got:\n%s", output)
	}
	if !strings.Contains(output, "oauth2 introspection: https://auth.example.com/introspect") {
		t.Fatalf("expected oauth2 details in inspect output, got:\n%s", output)
	}
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	original := os.Stdout
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stdout = writer
	defer func() {
		os.Stdout = original
	}()

	fn()

	if err := writer.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}
	data, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("read captured stdout: %v", err)
	}
	return string(data)
}
