package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

const generatedDockerComposeTemplate = `version: "3.8"

services:
  postgres:
    image: ${IKET_POSTGRES_IMAGE:-postgres:16-bookworm}
    container_name: %s
    restart: unless-stopped
    environment:
      - POSTGRES_DB=${IKET_DB_NAME:-iket}
      - POSTGRES_USER=${IKET_DB_USER:-iket}
      - POSTGRES_PASSWORD=${IKET_DB_PASSWORD:-iket}
    volumes:
      - %s:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U ${IKET_DB_USER:-iket} -d ${IKET_DB_NAME:-iket}"]
      interval: 10s
      timeout: 5s
      retries: 10

  iket:
    image: ${IKET_IMAGE:-%s}
    container_name: %s
    restart: unless-stopped
    user: "${IKET_UID:-1000}:${IKET_GID:-1000}"
    depends_on:
      postgres:
        condition: service_healthy
    ports:
      - "${IKET_HTTP_PORT:-%s}:8080"
      - "${IKET_HTTPS_PORT:-%s}:8443"
      - "${IKET_ENROLLMENT_PORT:-%s}:9443"
    environment:
      - TZ=${TZ:-%s}
      - IKET_CERTS_DIR=/app/certs
      - IKET_POSTGRES_URL=postgres://${IKET_DB_USER:-iket}:${IKET_DB_PASSWORD:-iket}@postgres:5432/${IKET_DB_NAME:-iket}?sslmode=disable
    command: ["--config", "/app/config/config.yaml", "--services", "/app/config/service.yaml"]
    volumes:
      - ./config:/app/config:ro
      - ./certs:/app/certs:rw
      - ./logs:/app/logs:rw

volumes:
  %s:
`

type dockerWizardAnswers struct {
	OutputDir           string
	DeploymentName      string
	ImageName           string
	AdminPassword       string
	HTTPPort            string
	HTTPSPort           string
	EnrollmentPort      string
	Timezone            string
	UID                 string
	GID                 string
	WithEnv             bool
	WithSystemd         bool
	Overwrite           bool
	SystemdName         string
	ServerNames         []string
	ServerIPs           []string
	EnableBasicAuth     bool
	GovernancePreset    string
	ServiceName         string
	ServiceHost         string
	ServiceBasePath     string
	RoutePath           string
	RouteMethods        []string
	AuthMode            string
	APIKeyHeaderName    string
	APIKeyClientID      string
	APIKeyClientName    string
	APIKeyClientKey     string
	APIKeyClientGroup   string
	APIKeyScopes        []string
	JWTAlgorithm        string
	JWTSecret           string
	JWTPublicKeyFile    string
	OAuth2IntrospectURL string
	OAuth2ClientID      string
	OAuth2ClientSecret  string
	EnableCORS          bool
	CORSOrigins         []string
	EnableRateLimit     bool
	RateLimitRPS        float64
	RateLimitBurst      int
	Services            []generatedServiceAnswers
	OutputMode          string
}

type generatedServiceAnswers struct {
	Name      string
	Host      string
	BasePath  string
	Group     string
	Scopes    []string
	Routes    []generatedRouteAnswers
	AuthMode  string
	AuthLabel string
}

type generatedRouteAnswers struct {
	Path                     string
	Methods                  []string
	Protocol                 string
	RequireAuth              bool
	AuthPlugin               string
	Scopes                   []string
	Timeout                  string
	StripPath                bool
	EnableCORS               bool
	CORSOrigins              []string
	EnableRateLimit          bool
	RateLimitRPS             float64
	RateLimitBurst           int
	EnableConcurrencyLimit   bool
	ConcurrencyMaxInFlight   int
	ConcurrencyQueueTimeout  string
	ConcurrencyMaxQueueDepth int
}

type generatedScaffoldBundle struct {
	RootDir string
	Files   map[string]string
}

type dockerWizardWarning struct {
	Category string
	Message  string
}

type genWizardOptions struct {
	PresetPath          string
	SavePresetPath      string
	AutoApprove         bool
	PresetOverrides     []string
	EnvPrefix           string
	FailOnWarnings      []string
	WarningReport       string
	WarningReportFormat string
	PrintWarningSummary string
}

var supportedDockerPresetOverrideKeys = []string{
	"output-dir",
	"deployment-name",
	"image-name",
	"admin-password",
	"http-port",
	"https-port",
	"enrollment-port",
	"timezone",
	"systemd-name",
	"with-env",
	"with-systemd",
	"enable-basic-auth",
	"governance-preset",
	"api-key-header-name",
	"api-key-client-id",
	"api-key-client-name",
	"api-key-client-key",
	"api-key-client-group",
	"api-key-scopes",
	"jwt-algorithm",
	"jwt-secret",
	"jwt-public-key-file",
	"oauth2-introspect-url",
	"oauth2-client-id",
	"oauth2-client-secret",
	"server-names",
	"server-ips",
	"service-name",
	"service-host",
	"service-base-path",
	"route-path",
	"route-methods",
	"output-mode",
}

var supportedDockerWarningCategories = []string{"security", "deployment", "local-dev"}

func initGenCmd(rootCmd *cobra.Command) {
	var (
		dockerMode bool
		hostMode   bool
		options    genWizardOptions
	)

	genCmd := &cobra.Command{
		Use:   "gen",
		Short: "Generate starter deployment scaffolds with a wizard",
		Long:  buildGenCommandLongHelp(),
		RunE: func(cmd *cobra.Command, args []string) error {
			if hostMode {
				return fmt.Errorf("host mode is not implemented yet; use --docker for the Docker wizard")
			}
			if !dockerMode {
				return fmt.Errorf("choose a generator target, for example: iket gen --docker")
			}
			return runDockerGenerationWizard(options)
		},
	}

	genCmd.Flags().BoolVar(&dockerMode, "docker", false, "Generate a Docker deployment scaffold with an interactive wizard")
	genCmd.Flags().BoolVar(&hostMode, "host", false, "Reserved for future host-mode generation")
	genCmd.Flags().StringVar(&options.PresetPath, "preset", "", "Load advanced Docker wizard defaults from a YAML preset file")
	genCmd.Flags().StringVar(&options.SavePresetPath, "save-preset", "", "Save the final advanced Docker wizard answers to a YAML preset file")
	genCmd.Flags().BoolVarP(&options.AutoApprove, "yes", "y", false, "Run non-interactively with a preset-backed advanced configuration")
	genCmd.Flags().StringArrayVar(&options.PresetOverrides, "set", nil, "Override common generator fields inline with key=value, for example --set deployment-name=team-a --set http-port=8080")
	genCmd.Flags().StringVar(&options.EnvPrefix, "from-env", "", "Load generator overrides from environment variables with the given prefix, for example --from-env IKET_GEN_")
	genCmd.Flags().StringArrayVar(&options.FailOnWarnings, "fail-on-warning", nil, "Fail generation when matching warnings are present. Use all or categories: security, deployment, local-dev")
	genCmd.Flags().StringVar(&options.WarningReport, "warning-report", "", "Write a warnings review report to a file before generation continues")
	genCmd.Flags().StringVar(&options.WarningReportFormat, "warning-report-format", "markdown", "Warning report format: markdown or json")
	genCmd.Flags().StringVar(&options.PrintWarningSummary, "print-warning-summary", "", "Print warning data to stdout in markdown or json before generation continues")
	initGenPresetCmd(genCmd)
	rootCmd.AddCommand(genCmd)
}

func initGenPresetCmd(genCmd *cobra.Command) {
	var (
		dockerTemplate bool
		outputPath     string
		stdoutMode     bool
		inspectPath    string
		authMode       string
		emptyServices  bool
		overrides      []string
		envPrefix      string
	)

	presetCmd := &cobra.Command{
		Use:   "preset",
		Short: "Create or inspect generator preset files",
		Long:  buildGenPresetCommandLongHelp(),
		RunE: func(cmd *cobra.Command, args []string) error {
			if strings.TrimSpace(inspectPath) != "" {
				return inspectDockerWizardPreset(inspectPath)
			}
			if !dockerTemplate {
				return fmt.Errorf("choose a preset action, for example: iket gen preset --docker")
			}
			return writeDockerWizardPresetTemplate(outputPath, stdoutMode, authMode, !emptyServices, overrides, envPrefix)
		},
	}

	presetCmd.Flags().BoolVar(&dockerTemplate, "docker", false, "Create a Docker generator preset template")
	presetCmd.Flags().StringVar(&outputPath, "output", "", "Write the preset template to a file")
	presetCmd.Flags().BoolVar(&stdoutMode, "stdout", false, "Print the preset template to stdout")
	presetCmd.Flags().StringVar(&inspectPath, "inspect", "", "Inspect an existing Docker generator preset file")
	presetCmd.Flags().StringVar(&authMode, "auth-mode", "", "Shape the Docker preset template for a specific auth mode: public, apikey, jwt, oauth2")
	presetCmd.Flags().BoolVar(&emptyServices, "empty-services", false, "Generate a cleaner preset without the starter example service and route")
	presetCmd.Flags().StringArrayVar(&overrides, "set", nil, "Override common preset fields inline with key=value, for example --set deployment-name=team-a --set http-port=8080")
	presetCmd.Flags().StringVar(&envPrefix, "from-env", "", "Load preset overrides from environment variables with the given prefix, for example --from-env IKET_PRESET_")
	genCmd.AddCommand(presetCmd)
}

func runDockerGenerationWizard(options genWizardOptions) error {
	reader := bufio.NewReader(os.Stdin)

	fmt.Println("Iket Docker Generator")
	fmt.Println("---------------------")

	profileDefault := "basic"
	answers := newDefaultDockerWizardAnswers()
	if strings.TrimSpace(options.PresetPath) != "" {
		loadedAnswers, err := loadDockerWizardPreset(options.PresetPath)
		if err != nil {
			return err
		}
		answers = loadedAnswers
		profileDefault = "advanced"
		fmt.Printf("Loaded preset defaults from %s\n", strings.TrimSpace(options.PresetPath))
	}
	envOverrides, err := collectDockerPresetEnvOverrides(options.EnvPrefix)
	if err != nil {
		return err
	}
	if err := applyDockerPresetOverrides(&answers, append(envOverrides, options.PresetOverrides...)); err != nil {
		return err
	}
	if options.AutoApprove {
		if strings.TrimSpace(options.PresetPath) == "" {
			return fmt.Errorf("--yes requires --preset for non-interactive Docker generation")
		}
		return finalizeAdvancedDockerGeneration(reader, options, answers)
	}

	profile := promptChoice(reader, "Iket profile configuration", []string{"basic", "advanced"}, profileDefault)
	if profile == "basic" {
		outputDir := promptString(reader, "Output directory", "./iket-docker")
		outputMode := promptChoice(reader, "Generator output mode", []string{"write", "preview", "stdout"}, "write")
		return generateBasicDockerScaffold(outputDir, outputMode)
	}

	answers.OutputDir = promptString(reader, "Output directory", answers.OutputDir)
	answers.OutputMode = promptChoice(reader, "Generator output mode", []string{"write", "preview", "stdout"}, answers.OutputMode)
	answers.DeploymentName = normalizeDeploymentName(promptString(reader, "Deployment name", answers.DeploymentName))
	answers.ImageName = promptString(reader, "Iket image", answers.ImageName)
	answers.Timezone = promptString(reader, "Timezone", answers.Timezone)
	answers.HTTPPort = promptString(reader, "Published HTTP port", answers.HTTPPort)
	answers.HTTPSPort = promptString(reader, "Published admin HTTPS port", answers.HTTPSPort)
	answers.EnrollmentPort = promptString(reader, "Published enrollment port", answers.EnrollmentPort)
	answers.AdminPassword = promptString(reader, "Initial admin password", answers.AdminPassword)
	answers.EnableBasicAuth = promptYesNo(reader, "Enable global basic auth for all gateway traffic", answers.EnableBasicAuth)
	answers.ServerNames = promptCSV(reader, "TLS server names", answers.ServerNames)
	answers.ServerIPs = promptCSV(reader, "TLS server IPs", answers.ServerIPs)
	featureSelection := promptChoice(reader, "Starter security mode", []string{"public", "apikey", "jwt", "oauth2"}, answers.AuthMode)
	answers.AuthMode = featureSelection
	if answers.AuthMode == "apikey" {
		answers.APIKeyHeaderName = promptString(reader, "API key header name", answers.APIKeyHeaderName)
		answers.APIKeyClientID = promptString(reader, "Bootstrap client ID", answers.APIKeyClientID)
		answers.APIKeyClientName = promptString(reader, "Bootstrap client name", answers.APIKeyClientName)
		answers.APIKeyClientKey = promptString(reader, "Bootstrap client key", answers.APIKeyClientKey)
		answers.APIKeyClientGroup = promptString(reader, "Client group", answers.APIKeyClientGroup)
		answers.APIKeyScopes = promptCSV(reader, "Client scopes", answers.APIKeyScopes)
	} else if answers.AuthMode == "jwt" {
		answers.JWTAlgorithm = promptChoice(reader, "JWT algorithm", []string{"HS256", "RS256"}, answers.JWTAlgorithm)
		if answers.JWTAlgorithm == "HS256" {
			answers.JWTSecret = promptString(reader, "JWT shared secret", answers.JWTSecret)
		} else {
			answers.JWTPublicKeyFile = promptString(reader, "JWT public key file inside container", answers.JWTPublicKeyFile)
		}
		answers.APIKeyScopes = promptCSV(reader, "JWT-required scopes", answers.APIKeyScopes)
	} else if answers.AuthMode == "oauth2" {
		answers.OAuth2IntrospectURL = promptString(reader, "OAuth2 introspection URL", answers.OAuth2IntrospectURL)
		answers.OAuth2ClientID = promptString(reader, "OAuth2 client ID", answers.OAuth2ClientID)
		answers.OAuth2ClientSecret = promptString(reader, "OAuth2 client secret", answers.OAuth2ClientSecret)
		answers.APIKeyScopes = promptCSV(reader, "OAuth2-required scopes", answers.APIKeyScopes)
	}
	answers.Services = promptServices(reader, answers)

	answers.GovernancePreset = promptChoice(reader, "Governance policy", []string{"none", "standard", "strict"}, answers.GovernancePreset)
	answers.WithEnv = promptYesNo(reader, "Generate .env overrides", answers.WithEnv)
	answers.WithSystemd = promptYesNo(reader, "Generate a systemd unit", answers.WithSystemd)
	if answers.WithSystemd {
		answers.SystemdName = promptString(reader, "Systemd filename", normalizeSystemdName(answers.SystemdName, "docker"))
	}
	answers.Overwrite = promptYesNo(reader, "Overwrite existing scaffold files if present", answers.Overwrite)
	return finalizeAdvancedDockerGeneration(reader, options, answers)
}

func newDefaultDockerWizardAnswers() dockerWizardAnswers {
	defaultTZ := "UTC"
	if tz := strings.TrimSpace(time.Now().Location().String()); tz != "" && tz != "Local" {
		defaultTZ = tz
	}

	return dockerWizardAnswers{
		OutputDir:           "./iket-docker",
		DeploymentName:      "iket",
		ImageName:           "bhangun/iket:latest",
		AdminPassword:       "change-this-password",
		HTTPPort:            "7100",
		HTTPSPort:           "8443",
		EnrollmentPort:      "9443",
		Timezone:            defaultTZ,
		UID:                 fmt.Sprintf("%d", os.Getuid()),
		GID:                 fmt.Sprintf("%d", os.Getgid()),
		WithEnv:             true,
		WithSystemd:         false,
		SystemdName:         "iket-docker.service",
		ServerNames:         []string{"localhost", "iket"},
		ServerIPs:           []string{"127.0.0.1"},
		EnableBasicAuth:     false,
		GovernancePreset:    "standard",
		ServiceName:         "Example Service",
		ServiceHost:         "http://localhost:9000/api",
		ServiceBasePath:     "/example",
		RoutePath:           "/hello",
		RouteMethods:        []string{"GET"},
		AuthMode:            "public",
		APIKeyHeaderName:    "X-API-Key",
		APIKeyClientID:      "starter-client",
		APIKeyClientName:    "Starter Client",
		APIKeyClientKey:     "replace-me-with-a-secret",
		APIKeyClientGroup:   "default",
		APIKeyScopes:        []string{"read"},
		JWTAlgorithm:        "HS256",
		JWTSecret:           "replace-me-jwt-secret",
		JWTPublicKeyFile:    "/app/certs/jwt-public.pem",
		OAuth2IntrospectURL: "https://auth.example.com/oauth2/introspect",
		OAuth2ClientID:      "iket-gateway",
		OAuth2ClientSecret:  "replace-me-oauth-secret",
		EnableCORS:          false,
		CORSOrigins:         []string{"*"},
		EnableRateLimit:     false,
		RateLimitRPS:        10,
		RateLimitBurst:      20,
		OutputMode:          "write",
	}
}

func generateBasicDockerScaffold(outputDir string, outputMode string) error {
	rootDir, err := filepath.Abs(strings.TrimSpace(outputDir))
	if err != nil {
		return err
	}
	layout := newServerScaffoldLayout(rootDir, normalizeSystemdName("", "docker"))
	bundle := buildBasicDockerBundle(layout)
	return emitScaffoldBundle(layout, bundle, normalizeOutputMode(outputMode), false)
}

func loadDockerWizardPreset(path string) (dockerWizardAnswers, error) {
	answers := newDefaultDockerWizardAnswers()
	resolvedPath, err := filepath.Abs(strings.TrimSpace(path))
	if err != nil {
		return dockerWizardAnswers{}, err
	}
	data, err := os.ReadFile(resolvedPath)
	if err != nil {
		return dockerWizardAnswers{}, err
	}
	if err := yaml.Unmarshal(data, &answers); err != nil {
		return dockerWizardAnswers{}, fmt.Errorf("parse preset %s: %w", resolvedPath, err)
	}
	answers.OutputMode = normalizeOutputMode(answers.OutputMode)
	answers.DeploymentName = normalizeDeploymentName(answers.DeploymentName)
	answers.SystemdName = normalizeSystemdName(answers.SystemdName, "docker")
	return answers, nil
}

func saveDockerWizardPreset(path string, answers dockerWizardAnswers) error {
	resolvedPath, err := filepath.Abs(strings.TrimSpace(path))
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(resolvedPath), 0755); err != nil {
		return err
	}
	payload := answers
	payload.OutputMode = normalizeOutputMode(payload.OutputMode)
	payload.DeploymentName = normalizeDeploymentName(payload.DeploymentName)
	payload.SystemdName = normalizeSystemdName(payload.SystemdName, "docker")
	data, err := yaml.Marshal(payload)
	if err != nil {
		return err
	}
	if err := os.WriteFile(resolvedPath, data, 0644); err != nil {
		return err
	}
	return nil
}

func formatDockerWizardPresetYAML(answers dockerWizardAnswers) (string, error) {
	payload := answers
	payload.OutputMode = normalizeOutputMode(payload.OutputMode)
	payload.DeploymentName = normalizeDeploymentName(payload.DeploymentName)
	payload.SystemdName = normalizeSystemdName(payload.SystemdName, "docker")
	data, err := yaml.Marshal(payload)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func buildDockerWizardPresetTemplate(authMode string, includeExampleService bool) (dockerWizardAnswers, error) {
	answers := newDefaultDockerWizardAnswers()
	mode := strings.ToLower(strings.TrimSpace(authMode))
	if mode == "" {
		mode = answers.AuthMode
	}
	switch mode {
	case "public", "apikey", "jwt", "oauth2":
		answers.AuthMode = mode
	default:
		return dockerWizardAnswers{}, fmt.Errorf("unsupported auth mode %q; choose public, apikey, jwt, or oauth2", authMode)
	}
	if includeExampleService {
		answers.Services = []generatedServiceAnswers{defaultGeneratedService(answers)}
		answers.Services[0].Routes = []generatedRouteAnswers{defaultGeneratedRoute(answers, answers.AuthMode)}
	} else {
		answers.Services = nil
	}
	return answers, nil
}

func writeDockerWizardPresetTemplate(path string, stdoutMode bool, authMode string, includeExampleService bool, overrides []string, envPrefix string) error {
	answers, err := buildDockerWizardPresetTemplate(authMode, includeExampleService)
	if err != nil {
		return err
	}
	envOverrides, err := collectDockerPresetEnvOverrides(envPrefix)
	if err != nil {
		return err
	}
	if err := applyDockerPresetOverrides(&answers, append(envOverrides, overrides...)); err != nil {
		return err
	}
	if includeExampleService {
		answers.Services = []generatedServiceAnswers{defaultGeneratedService(answers)}
		answers.Services[0].Routes = []generatedRouteAnswers{defaultGeneratedRoute(answers, answers.AuthMode)}
	}
	if err := validateDockerWizardAnswers(answers); err != nil {
		return err
	}
	if strings.TrimSpace(path) == "" || stdoutMode {
		text, err := formatDockerWizardPresetYAML(answers)
		if err != nil {
			return err
		}
		fmt.Print(text)
		return nil
	}
	if err := saveDockerWizardPreset(path, answers); err != nil {
		return err
	}
	fmt.Printf("Wrote Docker preset template to %s\n", strings.TrimSpace(path))
	return nil
}

func collectDockerPresetEnvOverrides(prefix string) ([]string, error) {
	prefix = strings.TrimSpace(prefix)
	if prefix == "" {
		return nil, nil
	}
	overrides := make([]string, 0, len(supportedDockerPresetOverrideKeys))
	for _, key := range supportedDockerPresetOverrideKeys {
		envName := prefix + strings.ToUpper(strings.NewReplacer("-", "_", ".", "_", " ", "_").Replace(key))
		if value, ok := os.LookupEnv(envName); ok {
			overrides = append(overrides, key+"="+value)
		}
	}
	return overrides, nil
}

func applyDockerPresetOverrides(answers *dockerWizardAnswers, overrides []string) error {
	for _, override := range overrides {
		key, value, ok := strings.Cut(strings.TrimSpace(override), "=")
		if !ok {
			return fmt.Errorf("invalid preset override %q; expected key=value", override)
		}
		if err := applyDockerPresetOverride(answers, key, value); err != nil {
			return err
		}
	}
	return nil
}

func applyDockerPresetOverride(answers *dockerWizardAnswers, key string, value string) error {
	normalizedKey := normalizePresetOverrideKey(key)
	trimmedValue := strings.TrimSpace(value)

	switch normalizedKey {
	case "outputdir":
		answers.OutputDir = trimmedValue
	case "deploymentname":
		answers.DeploymentName = normalizeDeploymentName(trimmedValue)
	case "imagename":
		answers.ImageName = trimmedValue
	case "adminpassword":
		answers.AdminPassword = trimmedValue
	case "httpport":
		answers.HTTPPort = trimmedValue
	case "httpsport":
		answers.HTTPSPort = trimmedValue
	case "enrollmentport":
		answers.EnrollmentPort = trimmedValue
	case "timezone":
		answers.Timezone = trimmedValue
	case "systemdname":
		answers.SystemdName = trimmedValue
	case "withenv":
		parsed, err := parseBoolOverride(trimmedValue)
		if err != nil {
			return fmt.Errorf("override %q: %w", key, err)
		}
		answers.WithEnv = parsed
	case "withsystemd":
		parsed, err := parseBoolOverride(trimmedValue)
		if err != nil {
			return fmt.Errorf("override %q: %w", key, err)
		}
		answers.WithSystemd = parsed
	case "enablebasicauth":
		parsed, err := parseBoolOverride(trimmedValue)
		if err != nil {
			return fmt.Errorf("override %q: %w", key, err)
		}
		answers.EnableBasicAuth = parsed
	case "governancepreset":
		answers.GovernancePreset = strings.ToLower(trimmedValue)
	case "apikeyheadername":
		answers.APIKeyHeaderName = trimmedValue
	case "apikeyclientid":
		answers.APIKeyClientID = trimmedValue
	case "apikeyclientname":
		answers.APIKeyClientName = trimmedValue
	case "apikeyclientkey":
		answers.APIKeyClientKey = trimmedValue
	case "apikeyclientgroup":
		answers.APIKeyClientGroup = trimmedValue
	case "apikeyscopes":
		answers.APIKeyScopes = splitCSVOverride(trimmedValue)
	case "jwtalgorithm":
		answers.JWTAlgorithm = strings.ToUpper(trimmedValue)
	case "jwtsecret":
		answers.JWTSecret = trimmedValue
	case "jwtpublickeyfile":
		answers.JWTPublicKeyFile = trimmedValue
	case "oauth2introspecturl":
		answers.OAuth2IntrospectURL = trimmedValue
	case "oauth2clientid":
		answers.OAuth2ClientID = trimmedValue
	case "oauth2clientsecret":
		answers.OAuth2ClientSecret = trimmedValue
	case "servernames":
		answers.ServerNames = splitCSVOverride(trimmedValue)
	case "serverips":
		answers.ServerIPs = splitCSVOverride(trimmedValue)
	case "servicename":
		answers.ServiceName = trimmedValue
	case "servicehost":
		answers.ServiceHost = trimmedValue
	case "servicebasepath":
		answers.ServiceBasePath = normalizePath(trimmedValue, true)
	case "routepath":
		answers.RoutePath = normalizePath(trimmedValue, true)
	case "routemethods":
		answers.RouteMethods = splitCSVOverrideUpper(trimmedValue)
	case "outputmode":
		answers.OutputMode = normalizeOutputMode(trimmedValue)
	default:
		return fmt.Errorf("unsupported preset override key %q", key)
	}
	return nil
}

func normalizePresetOverrideKey(key string) string {
	key = strings.ToLower(strings.TrimSpace(key))
	key = strings.NewReplacer("-", "", "_", "", ".", "", " ", "").Replace(key)
	return key
}

func parseBoolOverride(value string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "true", "1", "yes", "y", "on":
		return true, nil
	case "false", "0", "no", "n", "off":
		return false, nil
	default:
		return false, fmt.Errorf("expected boolean value, got %q", value)
	}
}

func splitCSVOverride(value string) []string {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func splitCSVOverrideUpper(value string) []string {
	parts := splitCSVOverride(value)
	for idx := range parts {
		parts[idx] = strings.ToUpper(parts[idx])
	}
	return parts
}

func buildGenCommandLongHelp() string {
	return "Launch an interactive generator for Docker-first Iket deployments, including config.yaml and service.yaml scaffolds.\n\n" +
		"Supported override keys for `--set` and `--from-env`:\n  - " + strings.Join(supportedDockerPresetOverrideKeys, "\n  - ") + "\n\n" +
		"Auth requirements:\n" + formatDockerAuthRequirementsBlock("  ") + "\n" +
		"Preflight checks:\n" + formatDockerPreflightChecksBlock("  ") + "\n" +
		"Warning policy:\n" +
		"  - `--fail-on-warning all` blocks generation on any warning\n" +
		"  - `--fail-on-warning security` blocks generation only on security warnings\n" +
		"  - `--warning-report ./warnings.md` writes a review artifact for local runs or CI\n" +
		"  - `--warning-report-format json` emits machine-readable warnings for CI parsing\n" +
		"  - `--print-warning-summary json` prints the warning payload to stdout\n" +
		"  - categories: " + strings.Join(supportedDockerWarningCategories, ", ") + "\n\n" +
		"Examples:\n" +
		"  iket gen --docker --preset ./presets/base.yaml --set deployment-name=team-a --set http-port=8088 --yes\n" +
		"  iket gen --docker --preset ./presets/base.yaml --from-env IKET_GEN_ --yes\n" +
		"  iket gen --docker --preset ./presets/base.yaml --fail-on-warning security --warning-report ./warnings.json --warning-report-format json --yes\n" +
		"  iket gen --docker --preset ./presets/base.yaml --print-warning-summary json --yes"
}

func buildGenPresetCommandLongHelp() string {
	return "Create or inspect Docker generator preset files.\n\n" +
		"Supported override keys for `--set` and `--from-env`:\n  - " + strings.Join(supportedDockerPresetOverrideKeys, "\n  - ") + "\n\n" +
		"Auth requirements:\n" + formatDockerAuthRequirementsBlock("  ") + "\n" +
		"Preflight checks:\n" + formatDockerPreflightChecksBlock("  ") + "\n" +
		"Examples:\n" +
		"  iket gen preset --docker --auth-mode jwt --set deployment-name=team-a --output ./presets/team-a.yaml\n" +
		"  iket gen preset --docker --from-env IKET_PRESET_ --stdout\n" +
		"  iket gen preset --inspect ./presets/team-a.yaml"
}

func inspectDockerWizardPreset(path string) error {
	answers, err := loadDockerWizardPreset(path)
	if err != nil {
		return err
	}
	fmt.Printf("Preset: %s\n", strings.TrimSpace(path))
	fmt.Println("------------------")
	fmt.Print(formatAdvancedDockerSummary(answers))
	return nil
}

func finalizeAdvancedDockerGeneration(reader *bufio.Reader, options genWizardOptions, answers dockerWizardAnswers) error {
	if err := validateDockerWizardAnswers(answers); err != nil {
		return err
	}
	printAdvancedDockerSummary(answers)
	warnings := collectDockerWizardWarnings(answers)
	matchingWarnings, err := matchDockerWarningsForPolicy(warnings, options.FailOnWarnings)
	if err != nil {
		return err
	}
	if strings.TrimSpace(options.PrintWarningSummary) != "" {
		reportText, err := formatDockerWarningReport(options.PrintWarningSummary, answers, warnings, options.FailOnWarnings, matchingWarnings)
		if err != nil {
			return err
		}
		fmt.Print(reportText)
	}
	if strings.TrimSpace(options.WarningReport) != "" {
		if err := writeDockerWarningReport(options.WarningReport, options.WarningReportFormat, answers, warnings, options.FailOnWarnings, matchingWarnings); err != nil {
			return err
		}
		fmt.Printf("Wrote warning report to %s\n", strings.TrimSpace(options.WarningReport))
	}
	if len(matchingWarnings) > 0 {
		messages := make([]string, 0, len(matchingWarnings))
		for _, warning := range matchingWarnings {
			messages = append(messages, fmt.Sprintf("%s: %s", warning.Category, warning.Message))
		}
		return fmt.Errorf("warning policy blocked generation: %s", strings.Join(messages, "; "))
	}
	if !options.AutoApprove {
		if !promptYesNo(reader, "Generate scaffold with this configuration", true) {
			return fmt.Errorf("generation cancelled")
		}
	} else {
		fmt.Println("Auto-approving generation from preset.")
	}
	if strings.TrimSpace(options.SavePresetPath) != "" {
		if err := saveDockerWizardPreset(options.SavePresetPath, answers); err != nil {
			return err
		}
		fmt.Printf("Saved wizard preset to %s\n", strings.TrimSpace(options.SavePresetPath))
	}
	return writeAdvancedDockerScaffold(answers)
}

func writeAdvancedDockerScaffold(answers dockerWizardAnswers) error {
	rootDir, err := filepath.Abs(strings.TrimSpace(answers.OutputDir))
	if err != nil {
		return err
	}
	layout := newServerScaffoldLayout(rootDir, normalizeSystemdName(answers.SystemdName, "docker"))
	bundle, err := buildAdvancedDockerBundle(layout, answers)
	if err != nil {
		return err
	}
	return emitScaffoldBundle(layout, bundle, normalizeOutputMode(answers.OutputMode), answers.Overwrite)
}

func buildBasicDockerBundle(layout serverScaffoldLayout) generatedScaffoldBundle {
	return generatedScaffoldBundle{
		RootDir: layout.rootDir,
		Files: map[string]string{
			layout.composePath:  fmt.Sprintf(prebuiltDockerComposeTemplate, "bhangun/iket:latest", "7100", "8443", "9443", "UTC"),
			layout.configPath:   fmt.Sprintf(prebuiltConfigTemplate, "change-this-password"),
			layout.servicesPath: serviceConfigTemplate,
			layout.envPath:      fmt.Sprintf(prebuiltEnvTemplate, "bhangun/iket:latest", fmt.Sprintf("%d", os.Getuid()), fmt.Sprintf("%d", os.Getgid()), "7100", "8443", "9443", "UTC"),
		},
	}
}

func buildAdvancedDockerBundle(layout serverScaffoldLayout, answers dockerWizardAnswers) (generatedScaffoldBundle, error) {
	composeContent := renderGeneratedDockerCompose(answers)
	configContent, err := buildGeneratedDockerConfigYAML(answers)
	if err != nil {
		return generatedScaffoldBundle{}, err
	}
	serviceContent, err := buildGeneratedServiceYAML(answers)
	if err != nil {
		return generatedScaffoldBundle{}, err
	}
	envContent := fmt.Sprintf(prebuiltEnvTemplate, answers.ImageName, answers.UID, answers.GID, answers.HTTPPort, answers.HTTPSPort, answers.EnrollmentPort, answers.Timezone)
	systemdContent := fmt.Sprintf(dockerSystemdTemplate, layout.rootDir)

	files := map[string]string{
		layout.composePath:  composeContent,
		layout.configPath:   configContent,
		layout.servicesPath: serviceContent,
	}
	if answers.WithEnv {
		files[layout.envPath] = envContent
	}
	if answers.WithSystemd {
		files[layout.systemdPath] = systemdContent
	}

	return generatedScaffoldBundle{
		RootDir: layout.rootDir,
		Files:   files,
	}, nil
}

func emitScaffoldBundle(layout serverScaffoldLayout, bundle generatedScaffoldBundle, mode string, overwrite bool) error {
	switch normalizeOutputMode(mode) {
	case "preview":
		printScaffoldBundle(bundle, false)
		return nil
	case "stdout":
		printScaffoldBundle(bundle, true)
		return nil
	default:
		return writeScaffoldBundle(layout, bundle, overwrite)
	}
}

func writeScaffoldBundle(layout serverScaffoldLayout, bundle generatedScaffoldBundle, overwrite bool) error {
	for _, dir := range []string{layout.rootDir, layout.configDir, layout.certsDir, layout.logsDir} {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return err
		}
	}
	withEnv := bundleHasPath(bundle, layout.envPath)
	withSystemd := bundleHasPath(bundle, layout.systemdPath)
	if err := ensureScaffoldTargets(layout, withEnv, withSystemd, overwrite); err != nil {
		return err
	}
	paths := sortedBundlePaths(bundle)
	for _, path := range paths {
		if err := os.WriteFile(path, []byte(bundle.Files[path]), 0644); err != nil {
			return err
		}
	}

	fmt.Printf("Generated Docker scaffold in %s\n", layout.rootDir)
	for _, path := range paths {
		fmt.Printf("  - %s\n", path)
	}
	if withEnv {
		fmt.Printf("  - %s\n", layout.envPath)
	}
	if withSystemd {
		fmt.Printf("  - %s\n", layout.systemdPath)
	}
	fmt.Printf("  - %s\n", layout.certsDir)
	fmt.Printf("  - %s\n", layout.logsDir)
	fmt.Println()
	fmt.Println("Next steps:")
	fmt.Printf("  1. Review %s for your generated security, governance, and plugin settings.\n", layout.configPath)
	fmt.Printf("  2. Review %s for the starter service and route policy scaffold.\n", layout.servicesPath)
	fmt.Printf("  3. Start Iket with: cd %s && docker compose up -d\n", layout.rootDir)
	fmt.Printf("  4. Wait for first boot to auto-generate TLS assets in %s.\n", layout.certsDir)
	fmt.Printf("  5. Bootstrap your first trusted admin context with: iket setup docker --cert-dir %s --url https://<server>:8443\n", layout.certsDir)
	return nil
}

func printScaffoldBundle(bundle generatedScaffoldBundle, stdoutOnly bool) {
	paths := sortedBundlePaths(bundle)
	if !stdoutOnly {
		fmt.Printf("Preview Docker scaffold for %s\n", bundle.RootDir)
		fmt.Println("----------------------------------------")
	}
	for _, path := range paths {
		rel := path
		if bundle.RootDir != "" {
			if short, err := filepath.Rel(bundle.RootDir, path); err == nil {
				rel = short
			}
		}
		fmt.Printf("=== %s ===\n%s\n", rel, strings.TrimRight(bundle.Files[path], "\n"))
		if !strings.HasSuffix(bundle.Files[path], "\n") {
			fmt.Println()
		}
	}
}

func sortedBundlePaths(bundle generatedScaffoldBundle) []string {
	paths := make([]string, 0, len(bundle.Files))
	for path := range bundle.Files {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	return paths
}

func bundleHasPath(bundle generatedScaffoldBundle, path string) bool {
	_, ok := bundle.Files[path]
	return ok
}

func normalizeOutputMode(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "preview", "stdout":
		return strings.ToLower(strings.TrimSpace(mode))
	default:
		return "write"
	}
}

func ensureScaffoldTargets(layout serverScaffoldLayout, withEnv, withSystemd, overwrite bool) error {
	if overwrite {
		return nil
	}
	paths := []string{layout.composePath, layout.configPath, layout.servicesPath}
	if withEnv {
		paths = append(paths, layout.envPath)
	}
	if withSystemd {
		paths = append(paths, layout.systemdPath)
	}
	for _, path := range paths {
		if _, err := os.Stat(path); err == nil {
			return fmt.Errorf("%s already exists; rerun the generator and allow overwrite or choose a different output directory", path)
		}
	}
	return nil
}

func renderGeneratedDockerCompose(answers dockerWizardAnswers) string {
	deploymentName := normalizeDeploymentName(answers.DeploymentName)
	postgresName := deploymentName + "-postgres"
	volumeName := deploymentName + "-postgres-data"
	return fmt.Sprintf(
		generatedDockerComposeTemplate,
		postgresName,
		volumeName,
		answers.ImageName,
		deploymentName,
		answers.HTTPPort,
		answers.HTTPSPort,
		answers.EnrollmentPort,
		answers.Timezone,
		volumeName,
	)
}

func buildGeneratedDockerConfigYAML(answers dockerWizardAnswers) (string, error) {
	configText := fmt.Sprintf(prebuiltConfigTemplate, answers.AdminPassword)
	var cfg map[string]interface{}
	if err := yaml.Unmarshal([]byte(configText), &cfg); err != nil {
		return "", err
	}

	security := ensureMap(cfg, "security")
	tls := ensureMap(security, "tls")
	tls["serverNames"] = answers.ServerNames
	tls["serverIPs"] = answers.ServerIPs

	if answers.EnableBasicAuth {
		security["enableBasicAuth"] = true
		security["basicAuthUsers"] = map[string]interface{}{"admin": answers.AdminPassword}
	} else {
		security["enableBasicAuth"] = false
		security["basicAuthUsers"] = map[string]interface{}{}
	}

	plugins := ensureMap(cfg, "plugins")
	for key := range plugins {
		delete(plugins, key)
	}

	if answers.AuthMode == "apikey" {
		plugins["apikey"] = map[string]interface{}{
			"enabled":     true,
			"header_name": answers.APIKeyHeaderName,
			"query_param": "api_key",
			"clients": []map[string]interface{}{{
				"id":     answers.APIKeyClientID,
				"name":   answers.APIKeyClientName,
				"key":    answers.APIKeyClientKey,
				"group":  answers.APIKeyClientGroup,
				"scopes": answers.APIKeyScopes,
			}},
		}
	} else if answers.AuthMode == "jwt" {
		algorithms := []string{answers.JWTAlgorithm}
		plugins["jwt"] = map[string]interface{}{
			"enabled":    true,
			"algorithms": algorithms,
		}
		if strings.EqualFold(strings.TrimSpace(answers.JWTAlgorithm), "HS256") {
			plugins["jwt"].(map[string]interface{})["secret"] = answers.JWTSecret
		} else {
			plugins["jwt"].(map[string]interface{})["public_key_file"] = answers.JWTPublicKeyFile
		}
		security["jwt"] = map[string]interface{}{
			"enabled":    true,
			"algorithms": algorithms,
			"required":   false,
		}
		if strings.EqualFold(strings.TrimSpace(answers.JWTAlgorithm), "HS256") {
			security["jwt"].(map[string]interface{})["secret"] = answers.JWTSecret
		} else {
			security["jwt"].(map[string]interface{})["publicKeyFile"] = answers.JWTPublicKeyFile
		}
	} else if answers.AuthMode == "oauth2" {
		plugins["oauth2"] = map[string]interface{}{
			"enabled":        true,
			"introspect_url": answers.OAuth2IntrospectURL,
			"client_id":      answers.OAuth2ClientID,
			"client_secret":  answers.OAuth2ClientSecret,
		}
	}

	applyGovernancePreset(ensureMap(security, "mutationPolicy"), answers.GovernancePreset)

	bytes, err := yaml.Marshal(cfg)
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}

func buildGeneratedServiceYAML(answers dockerWizardAnswers) (string, error) {
	services := buildGeneratedServices(answers)

	payload := map[string]interface{}{
		"version":  1,
		"services": services,
	}

	bytes, err := yaml.Marshal(payload)
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}

func validateDockerWizardAnswers(answers dockerWizardAnswers) error {
	if strings.TrimSpace(answers.ImageName) == "" {
		return fmt.Errorf("generator validation: image name is required")
	}
	ports := []string{
		strings.TrimSpace(answers.HTTPPort),
		strings.TrimSpace(answers.HTTPSPort),
		strings.TrimSpace(answers.EnrollmentPort),
	}
	seenPorts := map[string]struct{}{}
	for _, port := range ports {
		if port == "" {
			return fmt.Errorf("generator validation: http, https, and enrollment ports are required")
		}
		if _, err := strconv.Atoi(port); err != nil {
			return fmt.Errorf("generator validation: port %q must be numeric", port)
		}
		if _, exists := seenPorts[port]; exists {
			return fmt.Errorf("generator validation: ports must be unique; %s is duplicated", port)
		}
		seenPorts[port] = struct{}{}
	}

	switch strings.ToLower(strings.TrimSpace(answers.AuthMode)) {
	case "public":
	case "apikey":
		if strings.TrimSpace(answers.APIKeyHeaderName) == "" {
			return fmt.Errorf("generator validation: api key auth requires api-key-header-name")
		}
		if strings.TrimSpace(answers.APIKeyClientID) == "" || strings.TrimSpace(answers.APIKeyClientKey) == "" {
			return fmt.Errorf("generator validation: api key auth requires api-key-client-id and api-key-client-key")
		}
	case "jwt":
		algorithm := strings.ToUpper(strings.TrimSpace(answers.JWTAlgorithm))
		if algorithm != "HS256" && algorithm != "RS256" {
			return fmt.Errorf("generator validation: jwt auth requires jwt-algorithm to be HS256 or RS256")
		}
		if algorithm == "HS256" && strings.TrimSpace(answers.JWTSecret) == "" {
			return fmt.Errorf("generator validation: jwt HS256 auth requires jwt-secret")
		}
		if algorithm == "RS256" && strings.TrimSpace(answers.JWTPublicKeyFile) == "" {
			return fmt.Errorf("generator validation: jwt RS256 auth requires jwt-public-key-file")
		}
	case "oauth2":
		if strings.TrimSpace(answers.OAuth2IntrospectURL) == "" || strings.TrimSpace(answers.OAuth2ClientID) == "" || strings.TrimSpace(answers.OAuth2ClientSecret) == "" {
			return fmt.Errorf("generator validation: oauth2 auth requires oauth2-introspect-url, oauth2-client-id, and oauth2-client-secret")
		}
	default:
		return fmt.Errorf("generator validation: unsupported auth mode %q", answers.AuthMode)
	}

	services := answers.Services
	if len(services) == 0 {
		services = []generatedServiceAnswers{defaultGeneratedService(answers)}
	}
	for _, service := range services {
		if strings.TrimSpace(service.Name) == "" || strings.TrimSpace(service.Host) == "" {
			return fmt.Errorf("generator validation: each service requires a name and host")
		}
		routes := service.Routes
		if len(routes) == 0 {
			routes = []generatedRouteAnswers{defaultGeneratedRoute(answers, service.AuthMode)}
		}
		for _, route := range routes {
			if len(route.Methods) == 0 {
				return fmt.Errorf("generator validation: each route requires at least one method")
			}
			if route.RequireAuth && strings.TrimSpace(route.AuthPlugin) == "" {
				return fmt.Errorf("generator validation: protected routes require an auth plugin")
			}
		}
	}

	return nil
}

func buildGeneratedServices(answers dockerWizardAnswers) []map[string]interface{} {
	serviceAnswers := answers.Services
	if len(serviceAnswers) == 0 {
		serviceAnswers = []generatedServiceAnswers{defaultGeneratedService(answers)}
	}

	services := make([]map[string]interface{}, 0, len(serviceAnswers))
	for _, svc := range serviceAnswers {
		routeAnswers := svc.Routes
		if len(routeAnswers) == 0 {
			routeAnswers = []generatedRouteAnswers{defaultGeneratedRoute(answers, svc.AuthMode)}
		}

		routes := make([]map[string]interface{}, 0, len(routeAnswers))
		for _, routeAnswer := range routeAnswers {
			route := map[string]interface{}{
				"path":    normalizePath(routeAnswer.Path, true),
				"methods": routeAnswer.Methods,
			}
			if protocol := strings.TrimSpace(strings.ToLower(routeAnswer.Protocol)); protocol != "" && protocol != "http" {
				route["protocol"] = protocol
			}
			if timeout := strings.TrimSpace(routeAnswer.Timeout); timeout != "" {
				route["timeout"] = timeout
			}
			if routeAnswer.StripPath {
				route["stripPath"] = true
			}

			if routeAnswer.RequireAuth {
				route["requireAuth"] = true
				if strings.TrimSpace(routeAnswer.AuthPlugin) != "" {
					route["auth_plugin"] = routeAnswer.AuthPlugin
				}
				if len(routeAnswer.Scopes) > 0 {
					route["scopes"] = routeAnswer.Scopes
				}
			} else {
				route["requireAuth"] = false
			}

			if routeAnswer.EnableCORS {
				allowedHeaders := []string{"Content-Type", "Authorization"}
				if answers.AuthMode == "apikey" && strings.TrimSpace(answers.APIKeyHeaderName) != "" {
					allowedHeaders = append(allowedHeaders, answers.APIKeyHeaderName)
				}
				route["cors"] = map[string]interface{}{
					"allowedOrigins": routeAnswer.CORSOrigins,
					"allowedMethods": routeAnswer.Methods,
					"allowedHeaders": allowedHeaders,
					"maxAge":         600,
				}
			}

			if routeAnswer.EnableRateLimit {
				route["rateLimitPolicy"] = map[string]interface{}{
					"requestsPerSecond": routeAnswer.RateLimitRPS,
					"burst":             routeAnswer.RateLimitBurst,
				}
			}
			if routeAnswer.EnableConcurrencyLimit {
				route["concurrencyLimitPolicy"] = map[string]interface{}{
					"maxInFlight":   routeAnswer.ConcurrencyMaxInFlight,
					"queueTimeout":  routeAnswer.ConcurrencyQueueTimeout,
					"maxQueueDepth": routeAnswer.ConcurrencyMaxQueueDepth,
				}
			}

			routes = append(routes, route)
		}

		service := map[string]interface{}{
			"name":      svc.Name,
			"host":      svc.Host,
			"base_path": normalizePath(svc.BasePath, true),
			"routes":    routes,
		}

		if strings.TrimSpace(svc.Group) != "" {
			service["group"] = svc.Group
		}
		if len(svc.Scopes) > 0 {
			service["scopes"] = svc.Scopes
		}

		services = append(services, service)
	}

	return services
}

func applyGovernancePreset(policy map[string]interface{}, preset string) {
	switch strings.TrimSpace(strings.ToLower(preset)) {
	case "strict":
		policy["enabled"] = true
		policy["enforcedScopes"] = []string{"all"}
		policy["requireLabel"] = true
		policy["requireNoteForHighImpact"] = true
		policy["requireChangeRefForHighImpact"] = true
		policy["requireDifferentReviewerForProposals"] = true
		policy["minApproversForHighImpactProposals"] = 1
	case "standard":
		policy["enabled"] = true
		policy["enforcedScopes"] = []string{"all"}
		policy["requireLabel"] = true
		policy["requireNoteForHighImpact"] = false
		policy["requireChangeRefForHighImpact"] = false
		policy["requireDifferentReviewerForProposals"] = false
		policy["minApproversForHighImpactProposals"] = 0
	default:
		policy["enabled"] = false
	}
}

func ensureMap(root map[string]interface{}, key string) map[string]interface{} {
	if value, ok := root[key].(map[string]interface{}); ok {
		return value
	}
	next := map[string]interface{}{}
	root[key] = next
	return next
}

func promptString(reader *bufio.Reader, label, defaultValue string) string {
	fmt.Printf("%s [%s]: ", label, defaultValue)
	line, _ := reader.ReadString('\n')
	line = strings.TrimSpace(line)
	if line == "" {
		return defaultValue
	}
	return line
}

func promptChoice(reader *bufio.Reader, label string, options []string, defaultValue string) string {
	defaultValue = strings.ToLower(strings.TrimSpace(defaultValue))
	optionList := strings.Join(options, "/")
	for {
		answer := strings.ToLower(strings.TrimSpace(promptString(reader, label+" ("+optionList+")", defaultValue)))
		for _, option := range options {
			if answer == strings.ToLower(option) {
				return answer
			}
		}
		fmt.Printf("Please choose one of: %s\n", optionList)
	}
}

func promptYesNo(reader *bufio.Reader, label string, defaultValue bool) bool {
	defaultLabel := "n"
	if defaultValue {
		defaultLabel = "y"
	}
	for {
		answer := strings.ToLower(strings.TrimSpace(promptString(reader, label+" (y/n)", defaultLabel)))
		switch answer {
		case "y", "yes":
			return true
		case "n", "no":
			return false
		}
		fmt.Println("Please answer y or n.")
	}
}

func promptCSV(reader *bufio.Reader, label string, defaultValues []string) []string {
	defaultValue := strings.Join(defaultValues, ",")
	raw := promptString(reader, label, defaultValue)
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		value := strings.TrimSpace(part)
		if value != "" {
			out = append(out, value)
		}
	}
	if len(out) == 0 {
		return append([]string(nil), defaultValues...)
	}
	return out
}

func promptFloat(reader *bufio.Reader, label string, defaultValue float64) float64 {
	for {
		raw := promptString(reader, label, strconv.FormatFloat(defaultValue, 'f', -1, 64))
		value, err := strconv.ParseFloat(strings.TrimSpace(raw), 64)
		if err == nil && value > 0 {
			return value
		}
		fmt.Println("Please enter a positive number.")
	}
}

func promptInt(reader *bufio.Reader, label string, defaultValue int) int {
	for {
		raw := promptString(reader, label, strconv.Itoa(defaultValue))
		value, err := strconv.Atoi(strings.TrimSpace(raw))
		if err == nil && value > 0 {
			return value
		}
		fmt.Println("Please enter a positive integer.")
	}
}

func printAdvancedDockerSummary(answers dockerWizardAnswers) {
	fmt.Println()
	fmt.Println("Generation summary")
	fmt.Println("------------------")
	fmt.Print(formatAdvancedDockerSummary(answers))
	fmt.Println()
}

func formatAdvancedDockerSummary(answers dockerWizardAnswers) string {
	var builder strings.Builder

	fmt.Fprintf(&builder, "Output\n")
	fmt.Fprintf(&builder, "  mode: %s\n", normalizeOutputMode(answers.OutputMode))
	fmt.Fprintf(&builder, "  directory: %s\n", strings.TrimSpace(answers.OutputDir))
	fmt.Fprintf(&builder, "  overwrite: %t\n", answers.Overwrite)

	fmt.Fprintf(&builder, "Deployment\n")
	fmt.Fprintf(&builder, "  name: %s\n", normalizeDeploymentName(answers.DeploymentName))
	fmt.Fprintf(&builder, "  image: %s\n", strings.TrimSpace(answers.ImageName))
	fmt.Fprintf(&builder, "  timezone: %s\n", strings.TrimSpace(answers.Timezone))
	fmt.Fprintf(&builder, "  ports: http=%s https=%s enrollment=%s\n", strings.TrimSpace(answers.HTTPPort), strings.TrimSpace(answers.HTTPSPort), strings.TrimSpace(answers.EnrollmentPort))
	fmt.Fprintf(&builder, "  port requirements: http/https/enrollment ports must be numeric and unique\n")
	fmt.Fprintf(&builder, "  env file: %t\n", answers.WithEnv)
	fmt.Fprintf(&builder, "  systemd: %t\n", answers.WithSystemd)
	if answers.WithSystemd {
		fmt.Fprintf(&builder, "  systemd file: %s\n", normalizeSystemdName(answers.SystemdName, "docker"))
	}

	fmt.Fprintf(&builder, "Security\n")
	fmt.Fprintf(&builder, "  auth mode: %s\n", strings.TrimSpace(answers.AuthMode))
	fmt.Fprintf(&builder, "  global basic auth: %t\n", answers.EnableBasicAuth)
	fmt.Fprintf(&builder, "  governance: %s\n", strings.TrimSpace(answers.GovernancePreset))
	fmt.Fprintf(&builder, "  tls names: %s\n", strings.Join(answers.ServerNames, ", "))
	fmt.Fprintf(&builder, "  tls ips: %s\n", strings.Join(answers.ServerIPs, ", "))
	fmt.Fprintf(&builder, "  requirements: %s\n", dockerAuthRequirementSummary(strings.TrimSpace(answers.AuthMode)))

	switch strings.TrimSpace(answers.AuthMode) {
	case "apikey":
		fmt.Fprintf(&builder, "  api key header: %s\n", strings.TrimSpace(answers.APIKeyHeaderName))
		fmt.Fprintf(&builder, "  bootstrap client: %s (%s)\n", strings.TrimSpace(answers.APIKeyClientID), strings.TrimSpace(answers.APIKeyClientGroup))
		if len(answers.APIKeyScopes) > 0 {
			fmt.Fprintf(&builder, "  scopes: %s\n", strings.Join(answers.APIKeyScopes, ", "))
		}
	case "jwt":
		fmt.Fprintf(&builder, "  jwt algorithm: %s\n", strings.TrimSpace(answers.JWTAlgorithm))
		if strings.EqualFold(strings.TrimSpace(answers.JWTAlgorithm), "HS256") {
			fmt.Fprintf(&builder, "  jwt secret: configured\n")
		} else {
			fmt.Fprintf(&builder, "  jwt public key file: %s\n", strings.TrimSpace(answers.JWTPublicKeyFile))
		}
		if len(answers.APIKeyScopes) > 0 {
			fmt.Fprintf(&builder, "  scopes: %s\n", strings.Join(answers.APIKeyScopes, ", "))
		}
	case "oauth2":
		fmt.Fprintf(&builder, "  oauth2 introspection: %s\n", strings.TrimSpace(answers.OAuth2IntrospectURL))
		fmt.Fprintf(&builder, "  oauth2 client id: %s\n", strings.TrimSpace(answers.OAuth2ClientID))
		if len(answers.APIKeyScopes) > 0 {
			fmt.Fprintf(&builder, "  scopes: %s\n", strings.Join(answers.APIKeyScopes, ", "))
		}
	}

	services := answers.Services
	if len(services) == 0 {
		services = []generatedServiceAnswers{defaultGeneratedService(answers)}
	}
	fmt.Fprintf(&builder, "Services (%d)\n", len(services))
	fmt.Fprintf(&builder, "  requirements: each service needs a name and host; each route needs methods; protected routes need auth_plugin\n")
	for idx, service := range services {
		fmt.Fprintf(&builder, "  %d. %s -> %s%s\n", idx+1, strings.TrimSpace(service.Name), strings.TrimSpace(service.Host), normalizePath(service.BasePath, true))
		if strings.TrimSpace(service.Group) != "" {
			fmt.Fprintf(&builder, "     group: %s\n", strings.TrimSpace(service.Group))
		}
		if len(service.Scopes) > 0 {
			fmt.Fprintf(&builder, "     scopes: %s\n", strings.Join(service.Scopes, ", "))
		}

		routes := service.Routes
		if len(routes) == 0 {
			routes = []generatedRouteAnswers{defaultGeneratedRoute(answers, service.AuthMode)}
		}
		for routeIdx, route := range routes {
			fmt.Fprintf(&builder, "     route %d: %s %s", routeIdx+1, strings.Join(route.Methods, ","), normalizePath(route.Path, true))
			if protocol := strings.TrimSpace(route.Protocol); protocol != "" && protocol != "http" {
				fmt.Fprintf(&builder, " [%s]", protocol)
			}
			if route.RequireAuth && strings.TrimSpace(route.AuthPlugin) != "" {
				fmt.Fprintf(&builder, " auth=%s", strings.TrimSpace(route.AuthPlugin))
			}
			if route.EnableRateLimit {
				fmt.Fprintf(&builder, " ratelimit=%.0frps/%d", route.RateLimitRPS, route.RateLimitBurst)
			}
			if route.EnableConcurrencyLimit {
				fmt.Fprintf(&builder, " concurrency=%d", route.ConcurrencyMaxInFlight)
			}
			if route.EnableCORS {
				fmt.Fprintf(&builder, " cors")
			}
			fmt.Fprintf(&builder, "\n")
		}
	}

	warnings := collectDockerWizardWarnings(answers)
	if len(warnings) > 0 {
		fmt.Fprintf(&builder, "Warnings (%d)\n", len(warnings))
		grouped := groupDockerWizardWarnings(warnings)
		for _, category := range supportedDockerWarningCategories {
			items := grouped[category]
			if len(items) == 0 {
				continue
			}
			fmt.Fprintf(&builder, "  %s (%d)\n", category, len(items))
			for _, warning := range items {
				fmt.Fprintf(&builder, "    - %s\n", warning.Message)
			}
		}
	}

	return builder.String()
}

func dockerAuthRequirementSummary(authMode string) string {
	switch strings.ToLower(strings.TrimSpace(authMode)) {
	case "public":
		return "no extra auth fields required"
	case "apikey":
		return "requires api-key-header-name, api-key-client-id, and api-key-client-key"
	case "jwt":
		return "requires jwt-algorithm plus jwt-secret for HS256 or jwt-public-key-file for RS256"
	case "oauth2":
		return "requires oauth2-introspect-url, oauth2-client-id, and oauth2-client-secret"
	default:
		return "unsupported auth mode"
	}
}

func matchDockerWarningsForPolicy(warnings []dockerWizardWarning, selectors []string) ([]dockerWizardWarning, error) {
	if len(selectors) == 0 || len(warnings) == 0 {
		return nil, nil
	}

	supportedCategories := make(map[string]struct{}, len(supportedDockerWarningCategories))
	for _, category := range supportedDockerWarningCategories {
		supportedCategories[category] = struct{}{}
	}

	selectedCategories := make(map[string]struct{}, len(selectors))
	matchAll := false
	for _, selector := range selectors {
		normalized := strings.ToLower(strings.TrimSpace(selector))
		if normalized == "" {
			continue
		}
		if normalized == "all" {
			matchAll = true
			continue
		}
		if _, ok := supportedCategories[normalized]; !ok {
			return nil, fmt.Errorf("unsupported warning category %q; expected all or one of: %s", selector, strings.Join(supportedDockerWarningCategories, ", "))
		}
		selectedCategories[normalized] = struct{}{}
	}

	if !matchAll && len(selectedCategories) == 0 {
		return nil, nil
	}

	matching := make([]dockerWizardWarning, 0, len(warnings))
	for _, warning := range warnings {
		if matchAll {
			matching = append(matching, warning)
			continue
		}
		if _, ok := selectedCategories[warning.Category]; ok {
			matching = append(matching, warning)
		}
	}
	return matching, nil
}

func normalizeDockerWarningReportFormat(format string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "", "markdown", "md":
		return "markdown", nil
	case "json":
		return "json", nil
	default:
		return "", fmt.Errorf("unsupported warning report format %q; choose markdown or json", format)
	}
}

type dockerWarningReport struct {
	GeneratedAt     string                           `json:"generated_at"`
	Deployment      string                           `json:"deployment"`
	OutputMode      string                           `json:"output_mode"`
	OutputDirectory string                           `json:"output_directory"`
	FailOnWarning   []string                         `json:"fail_on_warning,omitempty"`
	BlockingMatches []dockerWizardWarning            `json:"blocking_matches,omitempty"`
	Warnings        []dockerWizardWarning            `json:"warnings,omitempty"`
	GroupedWarnings map[string][]dockerWizardWarning `json:"grouped_warnings,omitempty"`
}

func newDockerWarningReport(answers dockerWizardAnswers, warnings []dockerWizardWarning, selectors []string, matchingWarnings []dockerWizardWarning) dockerWarningReport {
	return dockerWarningReport{
		GeneratedAt:     time.Now().Format(time.RFC3339),
		Deployment:      normalizeDeploymentName(answers.DeploymentName),
		OutputMode:      normalizeOutputMode(answers.OutputMode),
		OutputDirectory: strings.TrimSpace(answers.OutputDir),
		FailOnWarning:   selectors,
		BlockingMatches: matchingWarnings,
		Warnings:        warnings,
		GroupedWarnings: groupDockerWizardWarnings(warnings),
	}
}

func formatDockerWarningReport(format string, answers dockerWizardAnswers, warnings []dockerWizardWarning, selectors []string, matchingWarnings []dockerWizardWarning) (string, error) {
	normalizedFormat, err := normalizeDockerWarningReportFormat(format)
	if err != nil {
		return "", err
	}
	report := newDockerWarningReport(answers, warnings, selectors, matchingWarnings)

	if normalizedFormat == "json" {
		data, marshalErr := json.MarshalIndent(report, "", "  ")
		if marshalErr != nil {
			return "", marshalErr
		}
		return string(append(data, '\n')), nil
	}

	var builder strings.Builder
	fmt.Fprintf(&builder, "# Iket Docker Generator Warning Report\n\n")
	fmt.Fprintf(&builder, "- generated_at: %s\n", report.GeneratedAt)
	fmt.Fprintf(&builder, "- deployment: %s\n", report.Deployment)
	fmt.Fprintf(&builder, "- output_mode: %s\n", report.OutputMode)
	fmt.Fprintf(&builder, "- output_directory: %s\n", report.OutputDirectory)
	if len(report.FailOnWarning) == 0 {
		fmt.Fprintf(&builder, "- fail_on_warning: none\n")
	} else {
		fmt.Fprintf(&builder, "- fail_on_warning: %s\n", strings.Join(report.FailOnWarning, ", "))
	}
	if len(report.BlockingMatches) == 0 {
		fmt.Fprintf(&builder, "- blocking_matches: none\n\n")
	} else {
		fmt.Fprintf(&builder, "- blocking_matches: %d\n\n", len(report.BlockingMatches))
	}

	if len(report.Warnings) == 0 {
		fmt.Fprintf(&builder, "## Warnings\n\nNo warnings detected.\n")
	} else {
		fmt.Fprintf(&builder, "## Warnings (%d)\n\n", len(report.Warnings))
		for _, category := range supportedDockerWarningCategories {
			items := report.GroupedWarnings[category]
			if len(items) == 0 {
				continue
			}
			fmt.Fprintf(&builder, "### %s (%d)\n\n", category, len(items))
			for _, warning := range items {
				fmt.Fprintf(&builder, "- %s\n", warning.Message)
			}
			fmt.Fprintf(&builder, "\n")
		}
	}

	if len(report.BlockingMatches) > 0 {
		fmt.Fprintf(&builder, "## Blocking Matches\n\n")
		for _, warning := range report.BlockingMatches {
			fmt.Fprintf(&builder, "- %s: %s\n", warning.Category, warning.Message)
		}
	}

	return builder.String(), nil
}

func writeDockerWarningReport(path string, format string, answers dockerWizardAnswers, warnings []dockerWizardWarning, selectors []string, matchingWarnings []dockerWizardWarning) error {
	resolvedPath, err := filepath.Abs(strings.TrimSpace(path))
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(resolvedPath), 0755); err != nil {
		return err
	}
	reportText, err := formatDockerWarningReport(format, answers, warnings, selectors, matchingWarnings)
	if err != nil {
		return err
	}
	return os.WriteFile(resolvedPath, []byte(reportText), 0644)
}

func formatDockerAuthRequirementsBlock(indent string) string {
	lines := []string{
		indent + "- public: no extra auth fields required",
		indent + "- apikey: requires api-key-header-name, api-key-client-id, and api-key-client-key",
		indent + "- jwt: requires jwt-algorithm plus jwt-secret for HS256 or jwt-public-key-file for RS256",
		indent + "- oauth2: requires oauth2-introspect-url, oauth2-client-id, and oauth2-client-secret",
	}
	return strings.Join(lines, "\n") + "\n"
}

func formatDockerPreflightChecksBlock(indent string) string {
	lines := []string{
		indent + "- image-name must be set",
		indent + "- http-port, https-port, and enrollment-port must be numeric and unique",
		indent + "- each service needs a name and host",
		indent + "- each route needs at least one method",
		indent + "- protected routes must declare an auth_plugin",
	}
	return strings.Join(lines, "\n") + "\n"
}

func collectDockerWizardWarnings(answers dockerWizardAnswers) []dockerWizardWarning {
	warnings := make([]dockerWizardWarning, 0, 8)

	if strings.Contains(strings.ToLower(strings.TrimSpace(answers.ImageName)), ":latest") {
		warnings = append(warnings, dockerWizardWarning{Category: "deployment", Message: "image uses a `latest` tag; pin a versioned image for repeatable deployments"})
	}
	if strings.Contains(strings.ToLower(strings.TrimSpace(answers.AdminPassword)), "change-this-password") {
		warnings = append(warnings, dockerWizardWarning{Category: "security", Message: "admin password is still the default placeholder"})
	}
	if strings.ToLower(strings.TrimSpace(answers.Timezone)) == "utc" {
		warnings = append(warnings, dockerWizardWarning{Category: "deployment", Message: "timezone is still the default UTC value"})
	}

	switch strings.ToLower(strings.TrimSpace(answers.AuthMode)) {
	case "apikey":
		if strings.Contains(strings.ToLower(strings.TrimSpace(answers.APIKeyClientKey)), "replace-me") {
			warnings = append(warnings, dockerWizardWarning{Category: "security", Message: "api key client key still uses a placeholder secret"})
		}
	case "jwt":
		if strings.EqualFold(strings.TrimSpace(answers.JWTAlgorithm), "HS256") &&
			strings.Contains(strings.ToLower(strings.TrimSpace(answers.JWTSecret)), "replace-me") {
			warnings = append(warnings, dockerWizardWarning{Category: "security", Message: "jwt shared secret still uses a placeholder value"})
		}
	case "oauth2":
		if strings.Contains(strings.ToLower(strings.TrimSpace(answers.OAuth2ClientSecret)), "replace-me") {
			warnings = append(warnings, dockerWizardWarning{Category: "security", Message: "oauth2 client secret still uses a placeholder value"})
		}
	}

	services := answers.Services
	if len(services) == 0 {
		services = []generatedServiceAnswers{defaultGeneratedService(answers)}
	}
	for _, service := range services {
		host := strings.ToLower(strings.TrimSpace(service.Host))
		if strings.Contains(host, "localhost") || strings.Contains(host, "127.0.0.1") {
			warnings = append(warnings, dockerWizardWarning{Category: "local-dev", Message: fmt.Sprintf("service %q still points to a localhost upstream", strings.TrimSpace(service.Name))})
		}
	}

	return warnings
}

func groupDockerWizardWarnings(warnings []dockerWizardWarning) map[string][]dockerWizardWarning {
	grouped := make(map[string][]dockerWizardWarning, 3)
	for _, warning := range warnings {
		grouped[warning.Category] = append(grouped[warning.Category], warning)
	}
	return grouped
}

func promptServices(reader *bufio.Reader, answers dockerWizardAnswers) []generatedServiceAnswers {
	fmt.Println()
	fmt.Println("Service wizard")
	fmt.Println("--------------")

	services := make([]generatedServiceAnswers, 0, 2)
	defaultService := defaultGeneratedService(answers)
	serviceIndex := 1
	for {
		fmt.Printf("\nService %d\n", serviceIndex)
		service := generatedServiceAnswers{
			Name:     promptString(reader, "Service name", defaultService.Name),
			Host:     promptString(reader, "Upstream host", defaultService.Host),
			BasePath: normalizePath(promptString(reader, "Base path", defaultService.BasePath), true),
			AuthMode: answers.AuthMode,
		}
		if authModeUsesServiceIdentity(answers.AuthMode) {
			service.Group = promptString(reader, "Service group", defaultService.Group)
			service.Scopes = promptCSV(reader, "Service scopes", defaultService.Scopes)
		}
		service.Routes = promptRoutes(reader, answers, service)
		services = append(services, service)
		serviceIndex++

		if !promptYesNo(reader, "Add another service", false) {
			break
		}
		defaultService = generatedServiceAnswers{
			Name:     fmt.Sprintf("Example Service %d", serviceIndex),
			Host:     "http://localhost:9000/api",
			BasePath: fmt.Sprintf("/service-%d", serviceIndex),
			Group:    defaultService.Group,
			Scopes:   append([]string(nil), defaultService.Scopes...),
			AuthMode: answers.AuthMode,
		}
	}

	return services
}

func promptRoutes(reader *bufio.Reader, answers dockerWizardAnswers, service generatedServiceAnswers) []generatedRouteAnswers {
	routes := make([]generatedRouteAnswers, 0, 2)
	defaultRoute := defaultGeneratedRoute(answers, service.AuthMode)
	routeIndex := 1
	for {
		fmt.Printf("  Route %d\n", routeIndex)
		route := generatedRouteAnswers{
			Path:        normalizePath(promptString(reader, "  Route path", defaultRoute.Path), true),
			Methods:     promptCSV(reader, "  Route methods", defaultRoute.Methods),
			Protocol:    promptChoice(reader, "  Route protocol", []string{"http", "graphql", "websocket"}, defaultRoute.Protocol),
			RequireAuth: authModeRequiresRouteAuth(service.AuthMode),
			AuthPlugin:  defaultRoute.AuthPlugin,
			Timeout:     promptString(reader, "  Route timeout", defaultRoute.Timeout),
			StripPath:   promptYesNo(reader, "  Strip base path before proxying", defaultRoute.StripPath),
		}
		if authModeUsesServiceIdentity(service.AuthMode) {
			route.Scopes = promptCSV(reader, "  Route scopes", defaultRoute.Scopes)
		}

		route.EnableCORS = promptYesNo(reader, "  Enable CORS on this route", defaultRoute.EnableCORS)
		if route.EnableCORS {
			route.CORSOrigins = promptCSV(reader, "  Allowed CORS origins", defaultRoute.CORSOrigins)
		}

		route.EnableRateLimit = promptYesNo(reader, "  Enable rate limiting on this route", defaultRoute.EnableRateLimit)
		if route.EnableRateLimit {
			route.RateLimitRPS = promptFloat(reader, "  Requests per second", defaultRoute.RateLimitRPS)
			route.RateLimitBurst = promptInt(reader, "  Burst", defaultRoute.RateLimitBurst)
		}
		route.EnableConcurrencyLimit = promptYesNo(reader, "  Enable concurrency limit on this route", defaultRoute.EnableConcurrencyLimit)
		if route.EnableConcurrencyLimit {
			route.ConcurrencyMaxInFlight = promptInt(reader, "  Max in-flight requests", defaultRoute.ConcurrencyMaxInFlight)
			route.ConcurrencyQueueTimeout = promptString(reader, "  Queue timeout", defaultRoute.ConcurrencyQueueTimeout)
			route.ConcurrencyMaxQueueDepth = promptInt(reader, "  Max queue depth", defaultRoute.ConcurrencyMaxQueueDepth)
		}

		routes = append(routes, route)
		routeIndex++
		if !promptYesNo(reader, "  Add another route to this service", false) {
			break
		}
		defaultRoute = generatedRouteAnswers{
			Path:                     fmt.Sprintf("/route-%d", routeIndex),
			Methods:                  []string{"GET"},
			Protocol:                 defaultRoute.Protocol,
			RequireAuth:              authModeRequiresRouteAuth(service.AuthMode),
			AuthPlugin:               defaultRoute.AuthPlugin,
			Scopes:                   append([]string(nil), defaultRoute.Scopes...),
			Timeout:                  defaultRoute.Timeout,
			StripPath:                defaultRoute.StripPath,
			EnableCORS:               defaultRoute.EnableCORS,
			CORSOrigins:              append([]string(nil), defaultRoute.CORSOrigins...),
			EnableRateLimit:          defaultRoute.EnableRateLimit,
			RateLimitRPS:             defaultRoute.RateLimitRPS,
			RateLimitBurst:           defaultRoute.RateLimitBurst,
			EnableConcurrencyLimit:   defaultRoute.EnableConcurrencyLimit,
			ConcurrencyMaxInFlight:   defaultRoute.ConcurrencyMaxInFlight,
			ConcurrencyQueueTimeout:  defaultRoute.ConcurrencyQueueTimeout,
			ConcurrencyMaxQueueDepth: defaultRoute.ConcurrencyMaxQueueDepth,
		}
	}

	return routes
}

func defaultGeneratedService(answers dockerWizardAnswers) generatedServiceAnswers {
	service := generatedServiceAnswers{
		Name:     answers.ServiceName,
		Host:     answers.ServiceHost,
		BasePath: answers.ServiceBasePath,
		AuthMode: answers.AuthMode,
	}
	if authModeUsesServiceIdentity(answers.AuthMode) {
		service.Group = answers.APIKeyClientGroup
		service.Scopes = append([]string(nil), answers.APIKeyScopes...)
	}
	return service
}

func defaultGeneratedRoute(answers dockerWizardAnswers, authMode string) generatedRouteAnswers {
	route := generatedRouteAnswers{
		Path:                     answers.RoutePath,
		Methods:                  append([]string(nil), answers.RouteMethods...),
		Protocol:                 "http",
		RequireAuth:              authModeRequiresRouteAuth(authMode),
		Timeout:                  "15s",
		StripPath:                false,
		EnableCORS:               answers.EnableCORS,
		CORSOrigins:              append([]string(nil), answers.CORSOrigins...),
		EnableRateLimit:          answers.EnableRateLimit,
		RateLimitRPS:             answers.RateLimitRPS,
		RateLimitBurst:           answers.RateLimitBurst,
		EnableConcurrencyLimit:   false,
		ConcurrencyMaxInFlight:   10,
		ConcurrencyQueueTimeout:  "250ms",
		ConcurrencyMaxQueueDepth: 20,
	}
	switch authMode {
	case "apikey":
		route.AuthPlugin = "apikey"
		route.Scopes = append([]string(nil), answers.APIKeyScopes...)
	case "jwt":
		route.AuthPlugin = "jwt"
		route.Scopes = append([]string(nil), answers.APIKeyScopes...)
	case "oauth2":
		route.AuthPlugin = "oauth2"
		route.Scopes = append([]string(nil), answers.APIKeyScopes...)
	}
	return route
}

func authModeRequiresRouteAuth(mode string) bool {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "apikey", "jwt", "oauth2":
		return true
	default:
		return false
	}
}

func authModeUsesServiceIdentity(mode string) bool {
	return authModeRequiresRouteAuth(mode)
}

func normalizePath(value string, allowRoot bool) string {
	value = strings.TrimSpace(value)
	if value == "" {
		if allowRoot {
			return "/"
		}
		return ""
	}
	if !strings.HasPrefix(value, "/") {
		value = "/" + value
	}
	if value != "/" {
		value = strings.TrimRight(value, "/")
	}
	return value
}

func normalizeDeploymentName(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return "iket"
	}
	replacer := strings.NewReplacer(" ", "-", "_", "-", "/", "-", "\\", "-", ".", "-")
	value = replacer.Replace(value)
	value = strings.Trim(value, "-")
	if value == "" {
		return "iket"
	}
	return value
}
