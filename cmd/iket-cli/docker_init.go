package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	iketconfig "github.com/bhangun/iket/pkg/config"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

const prebuiltDockerComposeTemplate = `version: "3.8"

services:
  postgres:
    image: ${IKET_POSTGRES_IMAGE:-postgres:16-bookworm}
    container_name: iket-postgres
    restart: unless-stopped
    environment:
      - POSTGRES_DB=${IKET_DB_NAME:-iket}
      - POSTGRES_USER=${IKET_DB_USER:-iket}
      - POSTGRES_PASSWORD=${IKET_DB_PASSWORD:-iket}
    volumes:
      - iket-postgres-data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U ${IKET_DB_USER:-iket} -d ${IKET_DB_NAME:-iket}"]
      interval: 10s
      timeout: 5s
      retries: 10

  iket:
    image: ${IKET_IMAGE:-%s}
    container_name: iket
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
  iket-postgres-data:
`

const prebuiltConfigTemplate = `server:
  port: 8080
  readTimeout: "10s"
  writeTimeout: "10s"
  idleTimeout: "60s"
  enableLogging: true

security:
  tls:
    enabled: true
    port: 8443
    http3Enabled: true
    http3Port: 8443
    http3Datagrams: true
    enrollmentPort: 9443
    enrollmentMaxActive: 10
    certFile: "/app/certs/server.crt"
    keyFile: "/app/certs/server.key"
    clientCAFile: "/app/certs/ca.crt"
    clientAuthType: "RequireAndVerifyClientCert"
    minVersion: "TLS1.3"
    serverNames: ["localhost", "iket"]
    serverIPs: ["127.0.0.1"]
    autoGenerate: true
    generateSharedClient: false
  enableBasicAuth: true
  basicAuthUsers:
    admin: "%s"
  mutationPolicy:
    enabled: false
    enforcedScopes: ["all"]
    requireLabel: true
    requireNoteForHighImpact: true
    requireChangeRefForHighImpact: true
    requireDifferentReviewerForProposals: false
    minApproversForHighImpactProposals: 0
    requireNotBeforeForHighImpactProposals: false
    requireVerificationForPromotedHighImpactProposals: false
    maxProposalAge: ""
    maxApprovalAge: ""
    blockedApplyWindows: []
    proposalQueue:
      defaultUrgency:
        readyAgingAfter: "1h"
        readyOverdueAfter: "4h"
        blockedAgingAfter: "4h"
        blockedOverdueAfter: "24h"
      environmentUrgency:
        prod:
          readyAgingAfter: "30m"
          readyOverdueAfter: "2h"
      notifications:
        enabled: false
        interval: "15m"
        minNotificationInterval: "5m"
        onlyOnSLABreach: true
        onlyOnChange: true
        environments: ["prod"]
    policyAlertNotifications:
      enabled: false
      interval: "5m"
      minNotificationInterval: "2m"
      onlyOnChange: true
      window: "5m"
      minCount: 3
      minSeverity: "warning"
  notificationWebhooks:
    - name: "ops-events"
      url: "https://ops.example.com/hooks/iket"
      format: "slack"
      events: ["proposal.applied", "proposal.canary_aborted", "proposal.digest", "proposal.sla_stage_changed", "proposal.sla_resolved", "gateway.policy_alert_digest", "gateway.policy_alert", "gateway.policy_alert_opened", "gateway.policy_alert_stage_changed", "gateway.policy_alert_resolved"]
      environments: ["prod", "staging"]
      timeout: "3s"
      retryCount: 2
      retryBackoff: "2s"
      signingSecret: "replace-me"
      signatureHeader: "X-Iket-Signature"
      timestampHeader: "X-Iket-Timestamp"
    - name: "ops-escalation"
      url: "https://pager.example.com/hooks/iket"
      events: ["proposal.sla_breach"]
      environments: ["prod"]
      minSLABreachTier: "critical"
      minSLABreachCount: 2
      minConsecutiveSLABreaches: 3
      minSLABreachDuration: "15m"
      slaBreachCooldown: "30m"
      timeout: "3s"
      retryCount: 2
      retryBackoff: "2s"

storage:
  mode: "postgres"
  postgres_url: "${IKET_POSTGRES_URL:-postgres://iket:iket@postgres:5432/iket?sslmode=disable}"
  mirror_files: true

plugins: {}
`

const serviceConfigTemplate = `version: 1
services:
  - name: "Example Service"
    host: "http://localhost:9000/api"
    base_path: "/example"
    routes:
      - path: /hello
        method: GET
        requireAuth: false
        stripPath: false
        backend:
          - url_pattern: /hello
`

const prebuiltEnvTemplate = `IKET_IMAGE=%s
IKET_POSTGRES_IMAGE=postgres:16-bookworm
IKET_UID=%s
IKET_GID=%s
IKET_HTTP_PORT=%s
IKET_HTTPS_PORT=%s
IKET_ENROLLMENT_PORT=%s
IKET_DB_NAME=iket
IKET_DB_USER=iket
IKET_DB_PASSWORD=iket
TZ=%s
`

const dockerSystemdTemplate = `[Unit]
Description=Iket Docker Stack
After=network-online.target docker.service
Requires=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=%s
ExecStart=/usr/bin/docker compose up -d
ExecStop=/usr/bin/docker compose down
TimeoutStartSec=0

[Install]
WantedBy=multi-user.target
`

const hostConfigTemplate = `server:
  port: %s
  readTimeout: "10s"
  writeTimeout: "10s"
  idleTimeout: "60s"
  enableLogging: true

security:
  tls:
    enabled: true
    port: %s
    http3Enabled: true
    http3Port: %s
    http3Datagrams: true
    enrollmentPort: %s
    enrollmentMaxActive: 10
    certFile: "%s"
    keyFile: "%s"
    clientCAFile: "%s"
    clientAuthType: "RequireAndVerifyClientCert"
    minVersion: "TLS1.3"
    serverNames: ["localhost"]
    serverIPs: ["127.0.0.1"]
    autoGenerate: true
    generateSharedClient: false
  enableBasicAuth: true
  basicAuthUsers:
    admin: "%s"
  mutationPolicy:
    enabled: false
    enforcedScopes: ["all"]
    requireLabel: true
    requireNoteForHighImpact: true
    requireChangeRefForHighImpact: true
    requireDifferentReviewerForProposals: false
    minApproversForHighImpactProposals: 0
    requireNotBeforeForHighImpactProposals: false
    requireVerificationForPromotedHighImpactProposals: false
    maxProposalAge: ""
    maxApprovalAge: ""
    blockedApplyWindows: []
    proposalQueue:
      defaultUrgency:
        readyAgingAfter: "1h"
        readyOverdueAfter: "4h"
        blockedAgingAfter: "4h"
        blockedOverdueAfter: "24h"
      environmentUrgency:
        prod:
          readyAgingAfter: "30m"
          readyOverdueAfter: "2h"
      notifications:
        enabled: false
        interval: "15m"
        minNotificationInterval: "5m"
        onlyOnSLABreach: true
        onlyOnChange: true
        environments: ["prod"]
    policyAlertNotifications:
      enabled: false
      interval: "5m"
      minNotificationInterval: "2m"
      onlyOnChange: true
      window: "5m"
      minCount: 3
      minSeverity: "warning"
  notificationWebhooks:
    - name: "ops-events"
      url: "https://ops.example.com/hooks/iket"
      format: "slack"
      events: ["proposal.applied", "proposal.canary_aborted", "proposal.digest", "proposal.sla_stage_changed", "proposal.sla_resolved", "gateway.policy_alert_digest", "gateway.policy_alert", "gateway.policy_alert_opened", "gateway.policy_alert_stage_changed", "gateway.policy_alert_resolved"]
      environments: ["prod", "staging"]
      timeout: "3s"
      retryCount: 2
      retryBackoff: "2s"
      signingSecret: "replace-me"
      signatureHeader: "X-Iket-Signature"
      timestampHeader: "X-Iket-Timestamp"
    - name: "ops-escalation"
      url: "https://pager.example.com/hooks/iket"
      events: ["proposal.sla_breach"]
      environments: ["prod"]
      minSLABreachTier: "critical"
      minSLABreachCount: 2
      minConsecutiveSLABreaches: 3
      minSLABreachDuration: "15m"
      slaBreachCooldown: "30m"
      timeout: "3s"
      retryCount: 2
      retryBackoff: "2s"

storage:
  mode: "postgres"
  postgres_url: "${IKET_POSTGRES_URL:-postgres://iket:iket@127.0.0.1:55432/iket?sslmode=disable}"
  mirror_files: true

plugins: {}
`

const hostEnvTemplate = `IKET_CONFIG=%s
IKET_SERVICES=%s
IKET_HTTP_PORT=%s
IKET_HTTPS_PORT=%s
IKET_ENROLLMENT_PORT=%s
IKET_POSTGRES_URL=postgres://iket:iket@127.0.0.1:55432/iket?sslmode=disable
TZ=%s
`

const hostSystemdTemplate = `[Unit]
Description=Iket Gateway
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=%s
EnvironmentFile=-%s
ExecStart=%s --config %s --services %s
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
`

type serverScaffoldLayout struct {
	rootDir      string
	configDir    string
	certsDir     string
	logsDir      string
	composePath  string
	configPath   string
	servicesPath string
	envPath      string
	systemdPath  string
	sqliteDir    string
	sqlitePath   string
}

func newServerScaffoldLayout(rootDir, systemdName string) serverScaffoldLayout {
	return serverScaffoldLayout{
		rootDir:      rootDir,
		configDir:    filepath.Join(rootDir, "config"),
		certsDir:     filepath.Join(rootDir, "certs"),
		logsDir:      filepath.Join(rootDir, "logs"),
		composePath:  filepath.Join(rootDir, "docker-compose.yaml"),
		configPath:   filepath.Join(rootDir, "config", "config.yaml"),
		servicesPath: filepath.Join(rootDir, "config", "service.yaml"),
		envPath:      filepath.Join(rootDir, ".env"),
		systemdPath:  filepath.Join(rootDir, systemdName),
		sqliteDir:    filepath.Join(rootDir, ".iket-admin", "sqlite"),
		sqlitePath:   filepath.Join(rootDir, ".iket-admin", "sqlite", "iket.db"),
	}
}

type doctorStatus struct {
	ok    int
	warn  int
	fail  int
	lines []string
}

type serverDoctorPorts struct {
	http       string
	https      string
	enrollment string
}

func (d *doctorStatus) addOK(format string, args ...interface{}) {
	d.ok++
	d.lines = append(d.lines, "OK   "+fmt.Sprintf(format, args...))
}

func (d *doctorStatus) addWarn(format string, args ...interface{}) {
	d.warn++
	d.lines = append(d.lines, "WARN "+fmt.Sprintf(format, args...))
}

func (d *doctorStatus) addFail(format string, args ...interface{}) {
	d.fail++
	d.lines = append(d.lines, "FAIL "+fmt.Sprintf(format, args...))
}

func initServerCmd(rootCmd *cobra.Command) {
	var (
		mode           string
		outputDir      string
		imageName      string
		adminPassword  string
		httpPort       string
		httpsPort      string
		enrollmentPort string
		timezone       string
		withEnv        bool
		withSystemd    bool
		systemdName    string
		forceOverwrite bool
		currentUID     string
		currentGID     string
	)

	serverCmd := &cobra.Command{
		Use:     "server",
		Aliases: []string{"docker"},
		Short:   "Server deployment helpers",
	}

	initCmd := &cobra.Command{
		Use:   "init",
		Short: "Generate a deployment scaffold",
		Long:  "Create a deployment scaffold for Iket in docker or host mode, including config, cert directories, and optional runtime helpers.",
		RunE: func(cmd *cobra.Command, args []string) error {
			if strings.TrimSpace(outputDir) == "" {
				outputDir = "."
			}
			rootDir, err := filepath.Abs(outputDir)
			if err != nil {
				return err
			}
			selectedMode, err := normalizeServerMode(mode)
			if err != nil {
				return err
			}
			selectedSystemdName := normalizeSystemdName(systemdName, selectedMode)
			layout := newServerScaffoldLayout(rootDir, selectedSystemdName)

			for _, dir := range []string{layout.rootDir, layout.configDir, layout.certsDir, layout.logsDir} {
				if err := os.MkdirAll(dir, 0755); err != nil {
					return err
				}
			}

			if !forceOverwrite {
				paths := []string{layout.configPath, layout.servicesPath}
				if selectedMode == "docker" {
					paths = append(paths, layout.composePath)
				}
				if withEnv {
					paths = append(paths, layout.envPath)
				}
				if withSystemd {
					paths = append(paths, layout.systemdPath)
				}
				for _, path := range paths {
					if _, err := os.Stat(path); err == nil {
						return fmt.Errorf("%s already exists; re-run with --force to overwrite", path)
					}
				}
			}

			switch selectedMode {
			case "docker":
				return writeDockerScaffold(layout, imageName, adminPassword, httpPort, httpsPort, enrollmentPort, timezone, currentUID, currentGID, withEnv, withSystemd)
			case "host":
				return writeHostScaffold(layout, adminPassword, httpPort, httpsPort, enrollmentPort, timezone, withEnv, withSystemd)
			default:
				return fmt.Errorf("unsupported server mode: %s", selectedMode)
			}
		},
	}

	var (
		doctorMode       string
		doctorDir        string
		doctorSystemd    string
		doctorContext    string
		doctorURL        string
		doctorSkipDocker bool
	)
	doctorCmd := &cobra.Command{
		Use:   "doctor",
		Short: "Inspect deployment scaffold and runtime state",
		RunE: func(cmd *cobra.Command, args []string) error {
			if strings.TrimSpace(doctorDir) == "" {
				doctorDir = "."
			}
			rootDir, err := filepath.Abs(doctorDir)
			if err != nil {
				return err
			}
			selectedMode, err := normalizeServerMode(doctorMode)
			if err != nil {
				return err
			}
			selectedSystemdName := normalizeSystemdName(doctorSystemd, selectedMode)
			layout := newServerScaffoldLayout(rootDir, selectedSystemdName)
			switch selectedMode {
			case "docker":
				return runDockerDoctor(layout, doctorContext, doctorURL, doctorSkipDocker)
			case "host":
				return runHostDoctor(layout, doctorContext, doctorURL)
			default:
				return fmt.Errorf("unsupported server mode: %s", selectedMode)
			}
		},
	}

	initCmd.Flags().StringVar(&mode, "mode", "docker", "Deployment mode: docker or host")
	initCmd.Flags().StringVar(&outputDir, "output", ".", "Directory to write scaffold files")
	initCmd.Flags().StringVar(&imageName, "image", "bhangun/iket:latest", "Prebuilt Iket image to deploy")
	initCmd.Flags().StringVar(&adminPassword, "admin-password", "change-this-password", "Initial admin basic-auth password")
	initCmd.Flags().StringVar(&httpPort, "http-port", "7100", "Published plain HTTP port")
	initCmd.Flags().StringVar(&httpsPort, "https-port", "8443", "Published mTLS admin port")
	initCmd.Flags().StringVar(&enrollmentPort, "enrollment-port", "9443", "Published enrollment TLS port")
	initCmd.Flags().StringVar(&timezone, "tz", "UTC", "Container timezone")
	initCmd.Flags().StringVar(&currentUID, "uid", fmt.Sprintf("%d", os.Getuid()), "Host UID to run the container as in docker mode")
	initCmd.Flags().StringVar(&currentGID, "gid", fmt.Sprintf("%d", os.Getgid()), "Host GID to run the container as in docker mode")
	initCmd.Flags().BoolVar(&withEnv, "with-env", true, "Generate a .env file for overrides and runtime hints")
	initCmd.Flags().BoolVar(&withSystemd, "with-systemd", false, "Generate a systemd unit for this deployment")
	initCmd.Flags().StringVar(&systemdName, "systemd-name", "", "Filename for the generated systemd unit")
	initCmd.Flags().BoolVar(&forceOverwrite, "force", false, "Overwrite existing scaffold files")

	doctorCmd.Flags().StringVar(&doctorMode, "mode", "docker", "Deployment mode: docker or host")
	doctorCmd.Flags().StringVar(&doctorDir, "output", ".", "Directory containing the deployment scaffold")
	doctorCmd.Flags().StringVar(&doctorSystemd, "systemd-name", "", "Expected filename for the generated systemd unit")
	doctorCmd.Flags().StringVar(&doctorContext, "context", "", "Optional CLI context name to verify against the running gateway")
	doctorCmd.Flags().StringVar(&doctorURL, "url", "", "Optional target admin URL to verify against the generated server certificate SANs")
	doctorCmd.Flags().BoolVar(&doctorSkipDocker, "skip-docker", false, "Skip docker/docker compose runtime checks")

	serverCmd.AddCommand(initCmd, doctorCmd)
	rootCmd.AddCommand(serverCmd)
}

func normalizeServerMode(mode string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "", "docker":
		return "docker", nil
	case "host":
		return "host", nil
	default:
		return "", fmt.Errorf("unsupported mode %q; expected docker or host", mode)
	}
}

func normalizeSystemdName(systemdName string, mode string) string {
	if strings.TrimSpace(systemdName) != "" {
		return systemdName
	}
	if mode == "host" {
		return "iket.service"
	}
	return "iket-docker.service"
}

func writeDockerScaffold(layout serverScaffoldLayout, imageName, adminPassword, httpPort, httpsPort, enrollmentPort, timezone, currentUID, currentGID string, withEnv, withSystemd bool) error {
	composeContent := fmt.Sprintf(prebuiltDockerComposeTemplate, imageName, httpPort, httpsPort, enrollmentPort, timezone)
	configContent := fmt.Sprintf(prebuiltConfigTemplate, adminPassword)
	envContent := fmt.Sprintf(prebuiltEnvTemplate, imageName, currentUID, currentGID, httpPort, httpsPort, enrollmentPort, timezone)
	systemdContent := fmt.Sprintf(dockerSystemdTemplate, layout.rootDir)

	if err := os.WriteFile(layout.composePath, []byte(composeContent), 0644); err != nil {
		return err
	}
	if err := os.WriteFile(layout.configPath, []byte(configContent), 0644); err != nil {
		return err
	}
	if err := os.WriteFile(layout.servicesPath, []byte(serviceConfigTemplate), 0644); err != nil {
		return err
	}
	if withEnv {
		if err := os.WriteFile(layout.envPath, []byte(envContent), 0644); err != nil {
			return err
		}
	}
	if withSystemd {
		if err := os.WriteFile(layout.systemdPath, []byte(systemdContent), 0644); err != nil {
			return err
		}
	}

	fmt.Printf("Generated Docker server scaffold in %s\n", layout.rootDir)
	fmt.Printf("  - %s\n", layout.composePath)
	fmt.Printf("  - %s\n", layout.configPath)
	fmt.Printf("  - %s\n", layout.servicesPath)
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
	fmt.Printf("  1. Review %s and change the admin password.\n", layout.configPath)
	fmt.Printf("  2. Review %s and replace the example upstream/service routes.\n", layout.servicesPath)
	if withEnv {
		fmt.Printf("  3. Adjust %s if you want different ports, image tags, database credentials, or UID/GID mapping.\n", layout.envPath)
	}
	fmt.Printf("  4. Start Iket with: cd %s && docker compose up -d\n", layout.rootDir)
	fmt.Printf("  5. Docker also starts an internal PostgreSQL service for Iket on the compose network only, so no host PostgreSQL port is used by default.\n")
	fmt.Printf("  6. Wait for first boot to auto-generate TLS assets in %s (ca.crt, ca.key, server.crt, server.key).\n", layout.certsDir)
	if withSystemd {
		fmt.Printf("  7. Install the service with: sudo cp %s /etc/systemd/system/%s && sudo systemctl daemon-reload && sudo systemctl enable --now %s\n", layout.systemdPath, filepath.Base(layout.systemdPath), strings.TrimSuffix(filepath.Base(layout.systemdPath), ".service"))
	}
	fmt.Printf("  8. On the trusted server host, bootstrap the first local admin context with: iket setup docker --cert-dir %s --url https://<server>:8443\n", layout.certsDir)
	fmt.Printf("  9. Use enrollment tokens later for additional remote admins: iket enroll create-token --name <admin-name> --out ./enroll.json\n")
	return nil
}

func writeHostScaffold(layout serverScaffoldLayout, adminPassword, httpPort, httpsPort, enrollmentPort, timezone string, withEnv, withSystemd bool) error {
	configContent := fmt.Sprintf(
		hostConfigTemplate,
		httpPort,
		httpsPort,
		httpsPort,
		enrollmentPort,
		filepath.Join(layout.certsDir, "server.crt"),
		filepath.Join(layout.certsDir, "server.key"),
		filepath.Join(layout.certsDir, "ca.crt"),
		adminPassword,
	)
	envContent := fmt.Sprintf(hostEnvTemplate, layout.configPath, layout.servicesPath, httpPort, httpsPort, enrollmentPort, timezone)
	systemdContent := fmt.Sprintf(hostSystemdTemplate, layout.rootDir, layout.envPath, "/usr/local/bin/iket-server", layout.configPath, layout.servicesPath)

	if err := os.WriteFile(layout.configPath, []byte(configContent), 0644); err != nil {
		return err
	}
	if err := os.WriteFile(layout.servicesPath, []byte(serviceConfigTemplate), 0644); err != nil {
		return err
	}
	if withEnv {
		if err := os.WriteFile(layout.envPath, []byte(envContent), 0644); err != nil {
			return err
		}
	}
	if withSystemd {
		if err := os.WriteFile(layout.systemdPath, []byte(systemdContent), 0644); err != nil {
			return err
		}
	}

	fmt.Printf("Generated host server scaffold in %s\n", layout.rootDir)
	fmt.Printf("  - %s\n", layout.configPath)
	fmt.Printf("  - %s\n", layout.servicesPath)
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
	fmt.Printf("  1. Review %s and change the admin password.\n", layout.configPath)
	fmt.Printf("  2. Review %s and replace the example upstream/service routes.\n", layout.servicesPath)
	if withEnv {
		fmt.Printf("  3. Adjust %s if you want different ports or PostgreSQL connection settings.\n", layout.envPath)
	}
	fmt.Printf("  4. Start Iket with: iket-server --config %s --services %s\n", layout.configPath, layout.servicesPath)
	fmt.Printf("  5. Wait for first boot to auto-generate TLS assets in %s (ca.crt, ca.key, server.crt, server.key).\n", layout.certsDir)
	if withSystemd {
		fmt.Printf("  6. Install the service with: sudo cp %s /etc/systemd/system/%s && sudo systemctl daemon-reload && sudo systemctl enable --now %s\n", layout.systemdPath, filepath.Base(layout.systemdPath), strings.TrimSuffix(filepath.Base(layout.systemdPath), ".service"))
	}
	fmt.Printf("  7. On the trusted server host, bootstrap the first local admin context with: iket setup docker --cert-dir %s --url https://<server>:8443\n", layout.certsDir)
	fmt.Printf("  8. Bootstrap remote admin machines later with enrollment: iket enroll create-token --name <admin-name> --out ./enroll.json\n")
	return nil
}

func runDockerDoctor(layout serverScaffoldLayout, doctorContext string, doctorURL string, doctorSkipDocker bool) error {
	status := &doctorStatus{}
	checkPath := doctorCheckPathFn(status)

	fmt.Printf("Inspecting Docker deployment in %s\n", layout.rootDir)
	checkPath(layout.rootDir, "root directory", true)
	composeExists := checkPath(layout.composePath, "docker-compose", false)
	checkPath(layout.configDir, "config directory", true)
	checkPath(layout.configPath, "gateway config", false)
	checkPath(layout.servicesPath, "service config", false)
	checkPath(layout.certsDir, "certs directory", true)
	checkPath(layout.logsDir, "logs directory", true)
	if _, err := os.Stat(layout.envPath); err == nil {
		status.addOK(".env present: %s", layout.envPath)
	} else {
		status.addWarn(".env not present: %s", layout.envPath)
	}
	if _, err := os.Stat(layout.systemdPath); err == nil {
		status.addOK("systemd unit present: %s", layout.systemdPath)
	} else {
		status.addWarn("systemd unit not present: %s", layout.systemdPath)
	}
	checkDockerOwnership(status, layout)
	checkCertFiles(status, layout.certsDir, readExpectedSharedClient(layout.configPath))
	checkTargetAdminURL(status, layout.certsDir, doctorContext, doctorURL)

	if !doctorSkipDocker {
		if _, err := exec.LookPath("docker"); err != nil {
			status.addFail("docker not found in PATH")
		} else {
			status.addOK("docker binary available")
			if out, err := runCommand("", "docker", "compose", "version"); err != nil {
				status.addFail("docker compose unavailable: %v", err)
			} else {
				status.addOK("docker compose available: %s", firstLine(out))
			}
			if composeExists {
				if out, err := runCommand(layout.rootDir, "docker", "compose", "-f", layout.composePath, "ps"); err != nil {
					status.addWarn("docker compose ps failed: %v", err)
				} else {
					status.addOK("docker compose ps succeeded")
					for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
						line = strings.TrimSpace(line)
						if line != "" {
							status.lines = append(status.lines, "INFO "+line)
						}
					}
				}
				if out, err := runCommand(layout.rootDir, "docker", "inspect", "--format", "{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}", "iket"); err != nil {
					status.addWarn("docker inspect for container health failed: %v", err)
				} else {
					health := strings.TrimSpace(out)
					if health == "healthy" || health == "running" {
						status.addOK("container health/status: %s", health)
					} else {
						status.addWarn("container health/status: %s", health)
					}
				}
				if out, err := runCommand(layout.rootDir, "docker", "inspect", "--format", "{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}", "iket-postgres"); err != nil {
					status.addWarn("docker inspect for postgres health failed: %v", err)
				} else {
					health := strings.TrimSpace(out)
					if health == "healthy" || health == "running" {
						status.addOK("postgres container health/status: %s", health)
					} else {
						status.addWarn("postgres container health/status: %s", health)
					}
				}
			}
		}
	}

	ports := resolveDockerDoctorPorts(layout)
	checkTCPPort(status, "http port", ports.http)
	checkTCPPort(status, "https admin port", ports.https)
	checkTCPPort(status, "https enrollment port", ports.enrollment)
	checkTLSPort(status, "https admin tls", ports.https, filepath.Join(layout.certsDir, "ca.crt"), "localhost")
	checkTLSPort(status, "https enrollment tls", ports.enrollment, filepath.Join(layout.certsDir, "ca.crt"), "localhost")
	checkDoctorContext(status, doctorContext)
	return finishDoctor(status, "server doctor")
}

func readEnvFileMap(path string) map[string]string {
	out := map[string]string{}
	data, err := os.ReadFile(path)
	if err != nil {
		return out
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || !strings.Contains(line, "=") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		out[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
	}
	return out
}

func checkDockerOwnership(status *doctorStatus, layout serverScaffoldLayout) {
	envMap := readEnvFileMap(layout.envPath)
	uid := strings.TrimSpace(envMap["IKET_UID"])
	gid := strings.TrimSpace(envMap["IKET_GID"])
	if uid == "" || gid == "" {
		status.addWarn("IKET_UID/IKET_GID not found in %s; ownership checks are limited", layout.envPath)
		return
	}

	uidNum, errUID := strconv.Atoi(uid)
	gidNum, errGID := strconv.Atoi(gid)
	if errUID != nil || errGID != nil {
		status.addWarn("IKET_UID/IKET_GID are not numeric in %s", layout.envPath)
		return
	}

	checkOwnershipPath(status, "certs directory", layout.certsDir, uidNum, gidNum)
	checkOwnershipPath(status, "logs directory", layout.logsDir, uidNum, gidNum)
}

func checkOwnershipPath(status *doctorStatus, label, path string, expectedUID, expectedGID int) {
	info, err := os.Stat(path)
	if err != nil {
		status.addWarn("%s not accessible for ownership check: %v", label, err)
		return
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		status.addWarn("%s ownership details unavailable on this platform", label)
		return
	}

	mode := info.Mode().Perm()
	actualUID := int(stat.Uid)
	actualGID := int(stat.Gid)
	if actualUID == expectedUID && actualGID == expectedGID {
		status.addOK("%s ownership matches IKET_UID/IKET_GID (%d:%d)", label, expectedUID, expectedGID)
	} else {
		status.addWarn("%s ownership is %d:%d but IKET_UID/IKET_GID expects %d:%d", label, actualUID, actualGID, expectedUID, expectedGID)
	}

	if mode&0200 == 0 {
		status.addWarn("%s owner write bit is not set (mode %o)", label, mode)
	}
}

func runHostDoctor(layout serverScaffoldLayout, doctorContext string, doctorURL string) error {
	status := &doctorStatus{}
	checkPath := doctorCheckPathFn(status)

	fmt.Printf("Inspecting host deployment in %s\n", layout.rootDir)
	checkPath(layout.rootDir, "root directory", true)
	checkPath(layout.configDir, "config directory", true)
	checkPath(layout.configPath, "gateway config", false)
	checkPath(layout.servicesPath, "service config", false)
	checkPath(layout.certsDir, "certs directory", true)
	checkPath(layout.logsDir, "logs directory", true)
	if _, err := os.Stat(layout.envPath); err == nil {
		status.addOK(".env present: %s", layout.envPath)
	} else {
		status.addWarn(".env not present: %s", layout.envPath)
	}
	if _, err := os.Stat(layout.systemdPath); err == nil {
		status.addOK("systemd unit present: %s", layout.systemdPath)
	} else {
		status.addWarn("systemd unit not present: %s", layout.systemdPath)
	}
	checkCertFiles(status, layout.certsDir, readExpectedSharedClient(layout.configPath))
	checkTargetAdminURL(status, layout.certsDir, doctorContext, doctorURL)

	if _, err := exec.LookPath("iket-server"); err != nil {
		status.addWarn("iket-server binary not found in PATH")
	} else {
		status.addOK("iket-server binary available in PATH")
	}

	ports := resolveHostDoctorPorts(layout.configPath)
	checkTCPPort(status, "http port", ports.http)
	checkTCPPort(status, "https admin port", ports.https)
	checkTCPPort(status, "https enrollment port", ports.enrollment)
	checkTLSPort(status, "https admin tls", ports.https, filepath.Join(layout.certsDir, "ca.crt"), "localhost")
	checkTLSPort(status, "https enrollment tls", ports.enrollment, filepath.Join(layout.certsDir, "ca.crt"), "localhost")
	checkDoctorContext(status, doctorContext)
	return finishDoctor(status, "server doctor")
}

func doctorCheckPathFn(status *doctorStatus) func(string, string, bool) bool {
	return func(path string, label string, dir bool) bool {
		info, err := os.Stat(path)
		if err != nil {
			status.addFail("%s missing: %s", label, path)
			return false
		}
		if dir && !info.IsDir() {
			status.addFail("%s is not a directory: %s", label, path)
			return false
		}
		if !dir && info.IsDir() {
			status.addFail("%s is a directory, expected file: %s", label, path)
			return false
		}
		status.addOK("%s present: %s", label, path)
		return true
	}
}

func checkCertFiles(status *doctorStatus, certsDir string, expectSharedClient bool) {
	required := []string{"ca.crt", "ca.key", "server.crt", "server.key"}
	for _, certName := range required {
		certPath := filepath.Join(certsDir, certName)
		if _, err := os.Stat(certPath); err == nil {
			status.addOK("certificate present: %s", certPath)
		} else {
			status.addWarn("certificate missing (may be auto-generated on first start): %s", certPath)
		}
	}
	for _, certName := range []string{"client.crt", "client.key"} {
		certPath := filepath.Join(certsDir, certName)
		if _, err := os.Stat(certPath); err == nil {
			status.addOK("shared client credential present: %s", certPath)
		} else if expectSharedClient {
			status.addWarn("shared client credential missing (expected by config): %s", certPath)
		} else {
			status.lines = append(status.lines, "INFO shared client credential not present (default hardened mode): "+certPath)
		}
	}

	checkServerCertSANs(status, certsDir)
}

func readExpectedSharedClient(configPath string) bool {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return false
	}
	var cfg struct {
		Security struct {
			TLS struct {
				GenerateSharedClient bool `yaml:"generateSharedClient"`
			} `yaml:"tls"`
		} `yaml:"security"`
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return false
	}
	return cfg.Security.TLS.GenerateSharedClient
}

func checkDoctorContext(status *doctorStatus, doctorContext string) {
	if strings.TrimSpace(doctorContext) == "" {
		return
	}
	cfg, err := loadCLIConfig()
	if err != nil {
		status.addFail("failed to load CLI config: %v", err)
		return
	}
	ctx, ok := cfg.Contexts[doctorContext]
	if !ok {
		status.addFail("CLI context %q not found", doctorContext)
		return
	}
	if err := verifyCLIContext(ctx); err != nil {
		status.addWarn("CLI context %q failed verification: %v", doctorContext, err)
		return
	}
	status.addOK("CLI context %q verified successfully", doctorContext)
}

func checkTargetAdminURL(status *doctorStatus, certsDir string, doctorContext string, doctorURL string) {
	target := strings.TrimSpace(doctorURL)
	if target == "" && strings.TrimSpace(doctorContext) != "" {
		cfg, err := loadCLIConfig()
		if err == nil {
			if ctx, ok := cfg.Contexts[doctorContext]; ok {
				target = strings.TrimSpace(ctx.ServerURL)
			}
		}
	}
	if target == "" {
		return
	}

	normalized, err := normalizeAdminURL(target)
	if err != nil {
		status.addWarn("target admin URL is invalid for SAN verification: %v", err)
		return
	}

	serverName, err := hostnameFromURL(normalized)
	if err != nil {
		status.addWarn("could not parse target admin URL %q for SAN verification: %v", normalized, err)
		return
	}

	certPath := filepath.Join(certsDir, "server.crt")
	pemBytes, err := os.ReadFile(certPath)
	if err != nil {
		status.addWarn("target URL SAN verification skipped; could not read %s: %v", certPath, err)
		return
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		status.addWarn("target URL SAN verification skipped; invalid PEM in %s", certPath)
		return
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		status.addWarn("target URL SAN verification skipped; parse failed for %s: %v", certPath, err)
		return
	}

	if err := cert.VerifyHostname(serverName); err != nil {
		status.addWarn("server certificate does not cover target admin URL %s (hostname/IP %s): %v", normalized, serverName, err)
		return
	}
	status.addOK("server certificate covers target admin URL %s", normalized)
}

func hostnameFromURL(raw string) (string, error) {
	parsed, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	host := strings.TrimSpace(parsed.Hostname())
	if host == "" {
		return "", fmt.Errorf("missing hostname")
	}
	return host, nil
}

func checkServerCertSANs(status *doctorStatus, certsDir string) {
	configPath := filepath.Join(filepath.Dir(certsDir), "config", "config.yaml")
	data, err := os.ReadFile(configPath)
	if err != nil {
		status.addWarn("could not read config for SAN verification: %v", err)
		return
	}

	var cfg struct {
		Security struct {
			TLS iketconfig.TLSConfig `yaml:"tls"`
		} `yaml:"security"`
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		status.addWarn("could not parse config for SAN verification: %v", err)
		return
	}

	expectedNames := iketconfig.EffectiveServerNames(cfg.Security.TLS)
	expectedIPs := iketconfig.EffectiveServerIPs(cfg.Security.TLS)

	certPath := filepath.Join(certsDir, "server.crt")
	pemBytes, err := os.ReadFile(certPath)
	if err != nil {
		status.addWarn("server certificate SAN verification skipped; could not read %s: %v", certPath, err)
		return
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		status.addWarn("server certificate SAN verification skipped; invalid PEM in %s", certPath)
		return
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		status.addWarn("server certificate SAN verification skipped; parse failed for %s: %v", certPath, err)
		return
	}

	missingNames := []string{}
	for _, name := range expectedNames {
		if err := cert.VerifyHostname(name); err != nil {
			missingNames = append(missingNames, name)
		}
	}
	missingIPs := []string{}
	for _, ip := range expectedIPs {
		if err := cert.VerifyHostname(ip.String()); err != nil {
			missingIPs = append(missingIPs, ip.String())
		}
	}

	if len(missingNames) == 0 && len(missingIPs) == 0 {
		status.addOK("server certificate SANs cover configured names=%v ips=%v", expectedNames, stringifyIPs(expectedIPs))
		return
	}

	status.addWarn("server certificate SAN mismatch: configured names=%v ips=%v, missing names=%v missing ips=%v. Regenerate server.crt or update security.tls.serverNames/serverIPs", expectedNames, stringifyIPs(expectedIPs), missingNames, missingIPs)
}

func stringifyIPs(ips []net.IP) []string {
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		out = append(out, ip.String())
	}
	return out
}

func finishDoctor(status *doctorStatus, commandName string) error {
	fmt.Println()
	for _, line := range status.lines {
		fmt.Println(line)
	}
	fmt.Println()
	fmt.Printf("Summary: %d ok, %d warnings, %d failures\n", status.ok, status.warn, status.fail)
	if status.fail > 0 {
		return fmt.Errorf("%s found %d failure(s)", commandName, status.fail)
	}
	return nil
}

func runCommand(workdir string, name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	if workdir != "" {
		cmd.Dir = workdir
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = strings.TrimSpace(stdout.String())
		}
		if msg == "" {
			msg = err.Error()
		}
		return stdout.String(), fmt.Errorf("%s", msg)
	}
	return stdout.String(), nil
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if idx := strings.IndexByte(s, '\n'); idx >= 0 {
		return s[:idx]
	}
	return s
}

func resolveDockerDoctorPorts(layout serverScaffoldLayout) serverDoctorPorts {
	ports := serverDoctorPorts{
		http:       "7100",
		https:      "8443",
		enrollment: "9443",
	}
	data, err := os.ReadFile(layout.envPath)
	if err != nil {
		return ports
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || !strings.Contains(line, "=") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		switch key {
		case "IKET_HTTP_PORT":
			if value != "" {
				ports.http = value
			}
		case "IKET_HTTPS_PORT":
			if value != "" {
				ports.https = value
			}
		case "IKET_ENROLLMENT_PORT":
			if value != "" {
				ports.enrollment = value
			}
		}
	}
	return ports
}

func resolveHostDoctorPorts(configPath string) serverDoctorPorts {
	ports := serverDoctorPorts{
		http:       "8080",
		https:      "8443",
		enrollment: "9443",
	}
	data, err := os.ReadFile(configPath)
	if err != nil {
		return ports
	}
	var cfg struct {
		Server struct {
			Port int `yaml:"port"`
		} `yaml:"server"`
		Security struct {
			TLS iketconfig.TLSConfig `yaml:"tls"`
		} `yaml:"security"`
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return ports
	}
	if cfg.Server.Port > 0 {
		ports.http = fmt.Sprintf("%d", cfg.Server.Port)
	}
	if cfg.Security.TLS.Port > 0 {
		ports.https = fmt.Sprintf("%d", cfg.Security.TLS.Port)
	}
	if cfg.Security.TLS.EnrollmentPort > 0 {
		ports.enrollment = fmt.Sprintf("%d", cfg.Security.TLS.EnrollmentPort)
	}
	return ports
}

func checkTCPPort(status *doctorStatus, label string, port string) {
	address := net.JoinHostPort("127.0.0.1", strings.TrimSpace(port))
	conn, err := net.DialTimeout("tcp", address, 1500*time.Millisecond)
	if err != nil {
		status.addWarn("%s not reachable on %s: %v", label, address, err)
		return
	}
	_ = conn.Close()
	status.addOK("%s reachable on %s", label, address)
}

func checkTLSPort(status *doctorStatus, label string, port string, caPath string, serverName string) {
	address := net.JoinHostPort("127.0.0.1", strings.TrimSpace(port))
	tlsConfig := &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: true,
	}
	if fileExists(caPath) {
		caPEM, err := os.ReadFile(caPath)
		if err == nil {
			pool := x509.NewCertPool()
			if pool.AppendCertsFromPEM(caPEM) {
				tlsConfig.RootCAs = pool
				tlsConfig.InsecureSkipVerify = false
			}
		}
	}
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 2 * time.Second}, "tcp", address, tlsConfig)
	if err != nil {
		status.addWarn("%s handshake failed on %s: %v", label, address, err)
		return
	}
	defer conn.Close()
	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		status.addWarn("%s connected but no peer certificate was presented", label)
		return
	}
	status.addOK("%s handshake succeeded on %s (subject=%s)", label, address, state.PeerCertificates[0].Subject.CommonName)
}
