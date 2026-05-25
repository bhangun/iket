package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
)

type runCommandOptions struct {
	ConfigPath    string
	ServicesPath  string
	UseDatabase   bool
	DatabaseUser  string
	DatabasePass  string
	DatabaseName  string
	DatabaseHost  string
	DatabasePort  string
	ServerPort    int
	PrintConfig   bool
	ServerBinary  string
	ResetDefaults bool
	InitOnly      bool
	Daemon        bool
	LogFile       string
	PIDFile       string
	LogDir        string
	PIDDir        string
	TailLines     int
	FollowLogs    bool
	BackupPath    string
	LatestBackup  bool
	BackupKind    string
	Preview       bool
	RestoreAll    bool
}

func initServerRunCmd(serverCmd *cobra.Command) {
	var options runCommandOptions

	runCmd := &cobra.Command{
		Use:   "run",
		Short: "Run the Iket server with first-run scaffold defaults",
		Long: "Start the Iket server. By default it auto-creates config/config.yaml, config/service.yaml, and docker-compose.yaml " +
			"and runs with file-based configuration storage. Use --database to switch to PostgreSQL-backed configuration.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runServerCommand(options)
		},
	}

	runCmd.Flags().StringVar(&options.ConfigPath, "config", "config/config.yaml", "Path to config.yaml")
	runCmd.Flags().StringVar(&options.ServicesPath, "services", "config/service.yaml", "Path to service-based config (service.yaml)")
	runCmd.Flags().BoolVar(&options.UseDatabase, "database", false, "Use PostgreSQL for configuration storage instead of file-based config")
	runCmd.Flags().StringVar(&options.DatabaseUser, "username", "", "Database username used when --database is enabled")
	runCmd.Flags().StringVar(&options.DatabasePass, "password", "", "Database password used when --database is enabled")
	runCmd.Flags().StringVar(&options.DatabaseName, "database-name", "", "Database name used when --database is enabled")
	runCmd.Flags().StringVar(&options.DatabaseHost, "database-host", "", "Database host used when --database is enabled")
	runCmd.Flags().StringVar(&options.DatabasePort, "database-port", "", "Database port used when --database is enabled")
	runCmd.Flags().IntVar(&options.ServerPort, "port", 0, "Port to run the gateway on")
	runCmd.Flags().BoolVar(&options.PrintConfig, "print-config", false, "Print the loaded server configuration and exit")
	runCmd.Flags().StringVar(&options.ServerBinary, "server-binary", "", "Optional explicit path to the iket-server binary")
	runCmd.Flags().BoolVar(&options.ResetDefaults, "reset-defaults", false, "Rewrite default config, service, and docker-compose files before starting")
	runCmd.Flags().BoolVar(&options.InitOnly, "init-only", false, "Generate or refresh scaffold files and exit without starting")
	runCmd.Flags().BoolVarP(&options.Daemon, "daemon", "d", false, "Run iket-server in the background and write a pid/log file")
	runCmd.Flags().StringVar(&options.LogFile, "log-file", "", "Log file used when --daemon is enabled")
	runCmd.Flags().StringVar(&options.PIDFile, "pid-file", "", "PID file used when --daemon is enabled")
	runCmd.Flags().StringVar(&options.LogDir, "log-dir", "", "Directory used for the daemon log when --log-file is not set")
	runCmd.Flags().StringVar(&options.PIDDir, "pid-dir", "", "Directory used for the daemon pid file when --pid-file is not set")

	serverCmd.AddCommand(runCmd)
	initServerStatusCmd(serverCmd)
	initServerStopCmd(serverCmd)
	initServerLogsCmd(serverCmd)
	initServerBackupsCmd(serverCmd)
	initServerRestoreCmd(serverCmd)
}

func initServerStatusCmd(serverCmd *cobra.Command) {
	var options runCommandOptions

	statusCmd := &cobra.Command{
		Use:   "status",
		Short: "Show local iket-server daemon status",
		RunE: func(cmd *cobra.Command, args []string) error {
			return printServerStatus(options)
		},
	}

	statusCmd.Flags().StringVar(&options.ConfigPath, "config", "config/config.yaml", "Path to config.yaml")
	statusCmd.Flags().StringVar(&options.LogFile, "log-file", "", "Log file used by daemon mode")
	statusCmd.Flags().StringVar(&options.PIDFile, "pid-file", "", "PID file used by daemon mode")
	statusCmd.Flags().StringVar(&options.LogDir, "log-dir", "", "Directory used for the daemon log when --log-file is not set")
	statusCmd.Flags().StringVar(&options.PIDDir, "pid-dir", "", "Directory used for the daemon pid file when --pid-file is not set")

	serverCmd.AddCommand(statusCmd)
}

func initServerStopCmd(serverCmd *cobra.Command) {
	var options runCommandOptions

	stopCmd := &cobra.Command{
		Use:   "stop",
		Short: "Stop a local iket-server daemon started with -d",
		RunE: func(cmd *cobra.Command, args []string) error {
			return stopServerProcess(options)
		},
	}

	stopCmd.Flags().StringVar(&options.ConfigPath, "config", "config/config.yaml", "Path to config.yaml")
	stopCmd.Flags().StringVar(&options.LogFile, "log-file", "", "Log file used by daemon mode")
	stopCmd.Flags().StringVar(&options.PIDFile, "pid-file", "", "PID file used by daemon mode")
	stopCmd.Flags().StringVar(&options.LogDir, "log-dir", "", "Directory used for the daemon log when --log-file is not set")
	stopCmd.Flags().StringVar(&options.PIDDir, "pid-dir", "", "Directory used for the daemon pid file when --pid-file is not set")

	serverCmd.AddCommand(stopCmd)
}

func initServerLogsCmd(serverCmd *cobra.Command) {
	var options runCommandOptions

	logsCmd := &cobra.Command{
		Use:   "logs",
		Short: "Print local iket-server daemon logs",
		RunE: func(cmd *cobra.Command, args []string) error {
			return printServerLogs(options)
		},
	}

	logsCmd.Flags().StringVar(&options.ConfigPath, "config", "config/config.yaml", "Path to config.yaml")
	logsCmd.Flags().StringVar(&options.LogFile, "log-file", "", "Log file used by daemon mode")
	logsCmd.Flags().StringVar(&options.LogDir, "log-dir", "", "Directory used for the daemon log when --log-file is not set")
	logsCmd.Flags().StringVar(&options.PIDDir, "pid-dir", "", "Directory used for the daemon pid file when --pid-file is not set")
	logsCmd.Flags().IntVar(&options.TailLines, "tail", 50, "How many recent log lines to print")
	logsCmd.Flags().BoolVar(&options.FollowLogs, "follow", false, "Follow the log file for new lines")

	serverCmd.AddCommand(logsCmd)
}

func initServerBackupsCmd(serverCmd *cobra.Command) {
	var options runCommandOptions

	backupsCmd := &cobra.Command{
		Use:   "backups",
		Short: "List local scaffold backup files",
		RunE: func(cmd *cobra.Command, args []string) error {
			return printServerBackups(options)
		},
	}

	backupsCmd.Flags().StringVar(&options.ConfigPath, "config", "config/config.yaml", "Path to config.yaml")
	backupsCmd.Flags().StringVar(&options.ServicesPath, "services", "config/service.yaml", "Path to service-based config (service.yaml)")

	serverCmd.AddCommand(backupsCmd)
}

func initServerRestoreCmd(serverCmd *cobra.Command) {
	var options runCommandOptions

	restoreCmd := &cobra.Command{
		Use:   "restore",
		Short: "Restore one scaffold file from a timestamped backup",
		RunE: func(cmd *cobra.Command, args []string) error {
			return restoreServerBackup(options)
		},
	}

	restoreCmd.Flags().StringVar(&options.ConfigPath, "config", "config/config.yaml", "Path to config.yaml")
	restoreCmd.Flags().StringVar(&options.ServicesPath, "services", "config/service.yaml", "Path to service-based config (service.yaml)")
	restoreCmd.Flags().StringVar(&options.BackupPath, "backup", "", "Path to a timestamped .bak scaffold file to restore")
	restoreCmd.Flags().BoolVar(&options.LatestBackup, "latest", false, "Restore the most recent scaffold backup for one kind")
	restoreCmd.Flags().StringVar(&options.BackupKind, "kind", "", "Scaffold kind to restore with --latest: config, service, or compose")
	restoreCmd.Flags().BoolVar(&options.Preview, "preview", false, "Show which scaffold file and backup would be used without restoring")
	restoreCmd.Flags().BoolVar(&options.RestoreAll, "all", false, "Restore the full scaffold set together (config, service, and compose) from one backup timestamp")

	serverCmd.AddCommand(restoreCmd)
}

func buildServerRunArgs(options runCommandOptions) []string {
	args := []string{
		"--config", strings.TrimSpace(options.ConfigPath),
		"--services", strings.TrimSpace(options.ServicesPath),
	}
	if options.UseDatabase {
		args = append(args, "--database")
	}
	if strings.TrimSpace(options.DatabaseUser) != "" {
		args = append(args, "--username", strings.TrimSpace(options.DatabaseUser))
	}
	if strings.TrimSpace(options.DatabasePass) != "" {
		args = append(args, "--password", strings.TrimSpace(options.DatabasePass))
	}
	if strings.TrimSpace(options.DatabaseName) != "" {
		args = append(args, "--database-name", strings.TrimSpace(options.DatabaseName))
	}
	if strings.TrimSpace(options.DatabaseHost) != "" {
		args = append(args, "--database-host", strings.TrimSpace(options.DatabaseHost))
	}
	if strings.TrimSpace(options.DatabasePort) != "" {
		args = append(args, "--database-port", strings.TrimSpace(options.DatabasePort))
	}
	if options.ServerPort > 0 {
		args = append(args, "--port", fmt.Sprintf("%d", options.ServerPort))
	}
	if options.PrintConfig {
		args = append(args, "--print-config")
	}
	if options.ResetDefaults {
		args = append(args, "--reset-defaults")
	}
	if options.InitOnly {
		args = append(args, "--init-only")
	}
	return args
}

func resolveServerBinary(explicitPath string) (string, error) {
	if strings.TrimSpace(explicitPath) != "" {
		return explicitPath, nil
	}
	executablePath, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("failed to locate iket-server: %w", err)
	}
	sibling := filepath.Join(filepath.Dir(executablePath), "iket-server")
	if _, err := os.Stat(sibling); err == nil {
		return sibling, nil
	}
	if path, err := exec.LookPath("iket-server"); err == nil {
		return path, nil
	}
	return "", fmt.Errorf("iket-server binary not found in PATH; install it or use --server-binary")
}

func buildServerRunArtifactPaths(configPath string, explicitLogFile string, explicitPIDFile string, explicitLogDir string, explicitPIDDir string) (string, string, error) {
	configPath = strings.TrimSpace(configPath)
	if configPath == "" {
		configPath = "config/config.yaml"
	}
	absConfigPath, err := filepath.Abs(configPath)
	if err != nil {
		return "", "", err
	}

	rootDir := filepath.Dir(absConfigPath)
	if filepath.Base(rootDir) == "config" {
		rootDir = filepath.Dir(rootDir)
	}
	logFile := strings.TrimSpace(explicitLogFile)
	pidFile := strings.TrimSpace(explicitPIDFile)
	logDir := strings.TrimSpace(explicitLogDir)
	pidDir := strings.TrimSpace(explicitPIDDir)
	if logFile == "" {
		if logDir == "" {
			logDir = filepath.Join(rootDir, "logs")
		}
		logFile = filepath.Join(logDir, "iket-server.log")
	}
	if pidFile == "" {
		if pidDir == "" {
			pidDir = filepath.Join(rootDir, "logs")
		}
		pidFile = filepath.Join(pidDir, "iket-server.pid")
	}
	logFile = expandHomePath(logFile)
	pidFile = expandHomePath(pidFile)
	logFile, err = filepath.Abs(logFile)
	if err != nil {
		return "", "", err
	}
	pidFile, err = filepath.Abs(pidFile)
	if err != nil {
		return "", "", err
	}
	return logFile, pidFile, nil
}

func expandHomePath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return path
	}
	if path == "~" {
		if home, err := os.UserHomeDir(); err == nil {
			return home
		}
		return path
	}
	if strings.HasPrefix(path, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, strings.TrimPrefix(path, "~/"))
		}
	}
	return path
}

func inferServerComposePath(configPath string) string {
	configDir := filepath.Dir(configPath)
	if filepath.Base(configDir) == "config" {
		return filepath.Join(filepath.Dir(configDir), "docker-compose.yaml")
	}
	return filepath.Join(configDir, "docker-compose.yaml")
}

func startDetachedServer(serverBinary string, args []string, logFile string, pidFile string) error {
	if err := os.MkdirAll(filepath.Dir(logFile), 0755); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(pidFile), 0755); err != nil {
		return err
	}

	logHandle, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return err
	}
	defer logHandle.Close()

	devNull, err := os.Open(os.DevNull)
	if err != nil {
		return err
	}
	defer devNull.Close()

	cmd := exec.Command(serverBinary, args...)
	cmd.Stdin = devNull
	cmd.Stdout = logHandle
	cmd.Stderr = logHandle
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}

	if err := cmd.Start(); err != nil {
		return err
	}
	pid := cmd.Process.Pid
	if err := os.WriteFile(pidFile, []byte(fmt.Sprintf("%d\n", pid)), 0644); err != nil {
		return err
	}
	if err := cmd.Process.Release(); err != nil {
		return err
	}

	fmt.Printf("Started iket-server in background\n")
	fmt.Printf("  pid: %d\n", pid)
	fmt.Printf("  pid file: %s\n", pidFile)
	fmt.Printf("  log file: %s\n", logFile)
	return nil
}

func readServerPID(pidFile string) (int, error) {
	data, err := os.ReadFile(pidFile)
	if err != nil {
		return 0, err
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return 0, fmt.Errorf("invalid pid file %s: %w", pidFile, err)
	}
	return pid, nil
}

func serverProcessRunning(pid int) bool {
	process, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	return process.Signal(syscall.Signal(0)) == nil
}

func printServerStatus(options runCommandOptions) error {
	logFile, pidFile, err := buildServerRunArtifactPaths(options.ConfigPath, options.LogFile, options.PIDFile, options.LogDir, options.PIDDir)
	if err != nil {
		return err
	}
	fmt.Printf("Iket server status\n")
	fmt.Printf("  config: %s\n", strings.TrimSpace(options.ConfigPath))
	fmt.Printf("  pid file: %s\n", pidFile)
	fmt.Printf("  log file: %s\n", logFile)

	pid, err := readServerPID(pidFile)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Printf("  state: not running (pid file missing)\n")
			return nil
		}
		return err
	}
	if serverProcessRunning(pid) {
		fmt.Printf("  state: running\n")
		fmt.Printf("  pid: %d\n", pid)
	} else {
		fmt.Printf("  state: stopped\n")
		fmt.Printf("  pid: %d (stale pid file)\n", pid)
	}
	return nil
}

func stopServerProcess(options runCommandOptions) error {
	_, pidFile, err := buildServerRunArtifactPaths(options.ConfigPath, options.LogFile, options.PIDFile, options.LogDir, options.PIDDir)
	if err != nil {
		return err
	}

	pid, err := readServerPID(pidFile)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Printf("Iket server is not running (pid file missing)\n")
			return nil
		}
		return err
	}

	process, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	if err := process.Signal(syscall.SIGTERM); err != nil {
		if err := os.Remove(pidFile); err == nil {
			fmt.Printf("Removed stale pid file %s\n", pidFile)
			return nil
		}
		return err
	}

	for i := 0; i < 20; i++ {
		if !serverProcessRunning(pid) {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	_ = os.Remove(pidFile)

	fmt.Printf("Stopped iket-server\n")
	fmt.Printf("  pid: %d\n", pid)
	fmt.Printf("  pid file: %s\n", pidFile)
	return nil
}

func readLastLogLines(path string, tail int) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	if tail <= 0 {
		tail = 50
	}

	lines := make([]string, 0, tail)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
		if len(lines) > tail {
			lines = lines[1:]
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return lines, nil
}

func followLogFile(path string, writer io.Writer) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	if _, err := file.Seek(0, io.SeekEnd); err != nil {
		return err
	}

	reader := bufio.NewReader(file)
	for {
		line, err := reader.ReadString('\n')
		if err == nil {
			fmt.Fprint(writer, line)
			continue
		}
		if err == io.EOF {
			time.Sleep(250 * time.Millisecond)
			continue
		}
		return err
	}
}

func printServerLogs(options runCommandOptions) error {
	logFile, _, err := buildServerRunArtifactPaths(options.ConfigPath, options.LogFile, options.PIDFile, options.LogDir, options.PIDDir)
	if err != nil {
		return err
	}

	lines, err := readLastLogLines(logFile, options.TailLines)
	if err != nil {
		return err
	}
	fmt.Printf("Iket server logs\n")
	fmt.Printf("  log file: %s\n", logFile)
	fmt.Printf("  tail lines: %d\n", len(lines))
	for _, line := range lines {
		fmt.Println(line)
	}
	if options.FollowLogs {
		fmt.Printf("Following log output...\n")
		return followLogFile(logFile, os.Stdout)
	}
	return nil
}

type scaffoldBackup struct {
	Kind       string
	ActivePath string
	BackupPath string
	Timestamp  string
}

func scaffoldTargetPaths(configPath string, servicesPath string) (map[string]string, error) {
	if strings.TrimSpace(configPath) == "" {
		configPath = "config/config.yaml"
	}
	if strings.TrimSpace(servicesPath) == "" {
		servicesPath = "config/service.yaml"
	}
	absConfigPath, err := filepath.Abs(strings.TrimSpace(configPath))
	if err != nil {
		return nil, err
	}
	absServicesPath, err := filepath.Abs(strings.TrimSpace(servicesPath))
	if err != nil {
		return nil, err
	}
	return map[string]string{
		"config":  absConfigPath,
		"service": absServicesPath,
		"compose": inferServerComposePath(absConfigPath),
	}, nil
}

func listScaffoldBackups(configPath string, servicesPath string) ([]scaffoldBackup, error) {
	targets, err := scaffoldTargetPaths(configPath, servicesPath)
	if err != nil {
		return nil, err
	}
	backups := make([]scaffoldBackup, 0)
	for kind, activePath := range targets {
		found, err := listBackupsForTarget(kind, activePath)
		if err != nil {
			return nil, err
		}
		backups = append(backups, found...)
	}
	sort.Slice(backups, func(i, j int) bool {
		if backups[i].Timestamp == backups[j].Timestamp {
			return backups[i].Kind < backups[j].Kind
		}
		return backups[i].Timestamp > backups[j].Timestamp
	})
	return backups, nil
}

func listBackupsForTarget(kind string, activePath string) ([]scaffoldBackup, error) {
	dir := filepath.Dir(activePath)
	base := filepath.Base(activePath)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	backups := make([]scaffoldBackup, 0)
	prefix := base + "."
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasPrefix(name, prefix) || !strings.HasSuffix(name, ".bak") {
			continue
		}
		timestamp := strings.TrimSuffix(strings.TrimPrefix(name, prefix), ".bak")
		if !isTimestampedBackupSuffix(timestamp) {
			continue
		}
		backups = append(backups, scaffoldBackup{
			Kind:       kind,
			ActivePath: activePath,
			BackupPath: filepath.Join(dir, name),
			Timestamp:  timestamp,
		})
	}
	sort.Slice(backups, func(i, j int) bool {
		return backups[i].Timestamp > backups[j].Timestamp
	})
	return backups, nil
}

func isTimestampedBackupSuffix(value string) bool {
	if len(value) != len("20060102-150405") {
		return false
	}
	_, err := time.Parse("20060102-150405", value)
	return err == nil
}

func printServerBackups(options runCommandOptions) error {
	backups, err := listScaffoldBackups(options.ConfigPath, options.ServicesPath)
	if err != nil {
		return err
	}
	fmt.Printf("Iket server scaffold backups\n")
	if len(backups) == 0 {
		fmt.Printf("  none found\n")
		return nil
	}
	for _, backup := range backups {
		fmt.Printf("- [%s] %s\n", backup.Kind, backup.BackupPath)
		fmt.Printf("    active: %s\n", backup.ActivePath)
		fmt.Printf("    timestamp: %s\n", backup.Timestamp)
	}
	return nil
}

func restoreServerBackup(options runCommandOptions) error {
	targets, err := scaffoldTargetPaths(options.ConfigPath, options.ServicesPath)
	if err != nil {
		return err
	}
	selected, err := resolveRequestedScaffoldBackups(targets, options)
	if err != nil {
		return err
	}
	if options.Preview {
		return printRestorePreview(selected)
	}
	if !force {
		confirmed, err := confirmRestoreSelection(os.Stdin, os.Stdout, selected)
		if err != nil {
			return err
		}
		if !confirmed {
			return fmt.Errorf("restore cancelled")
		}
	}
	for _, item := range selected {
		if err := createTimestampedBackup(item.ActivePath); err != nil {
			return err
		}
	}
	for _, item := range selected {
		data, err := os.ReadFile(item.BackupPath)
		if err != nil {
			return err
		}
		if err := os.WriteFile(item.ActivePath, data, 0644); err != nil {
			return err
		}
	}
	if len(selected) == 1 {
		fmt.Printf("Restored scaffold backup\n")
		fmt.Printf("  kind: %s\n", selected[0].Kind)
		fmt.Printf("  backup: %s\n", selected[0].BackupPath)
		fmt.Printf("  active: %s\n", selected[0].ActivePath)
		return nil
	}
	fmt.Printf("Restored scaffold backup set\n")
	for _, item := range selected {
		fmt.Printf("  [%s] %s -> %s\n", item.Kind, item.BackupPath, item.ActivePath)
	}
	return nil
}

func printRestorePreview(selected []scaffoldBackup) error {
	fmt.Printf("Iket server restore preview\n")
	if len(selected) == 1 {
		fmt.Printf("  kind: %s\n", selected[0].Kind)
		fmt.Printf("  backup: %s\n", selected[0].BackupPath)
		fmt.Printf("  active: %s\n", selected[0].ActivePath)
	} else {
		fmt.Printf("  set size: %d\n", len(selected))
		for _, item := range selected {
			fmt.Printf("  [%s] backup: %s\n", item.Kind, item.BackupPath)
			fmt.Printf("  [%s] active: %s\n", item.Kind, item.ActivePath)
		}
	}
	fmt.Printf("  action: would restore backup into active file and preserve the current active file as a new timestamped backup\n")
	return nil
}

func confirmRestoreSelection(reader io.Reader, writer io.Writer, selected []scaffoldBackup) (bool, error) {
	if len(selected) == 1 {
		if _, err := fmt.Fprintf(writer, "Restore scaffold backup for %s?\n", selected[0].Kind); err != nil {
			return false, err
		}
		if _, err := fmt.Fprintf(writer, "  backup: %s\n", selected[0].BackupPath); err != nil {
			return false, err
		}
		if _, err := fmt.Fprintf(writer, "  active: %s\n", selected[0].ActivePath); err != nil {
			return false, err
		}
	} else {
		if _, err := fmt.Fprintf(writer, "Restore scaffold backup set (%d files)?\n", len(selected)); err != nil {
			return false, err
		}
		for _, item := range selected {
			if _, err := fmt.Fprintf(writer, "  [%s] %s -> %s\n", item.Kind, item.BackupPath, item.ActivePath); err != nil {
				return false, err
			}
		}
	}
	if _, err := fmt.Fprint(writer, "Proceed? (y/N): "); err != nil {
		return false, err
	}
	line, err := bufio.NewReader(reader).ReadString('\n')
	if err != nil && err != io.EOF {
		return false, err
	}
	answer := strings.TrimSpace(strings.ToLower(line))
	return answer == "y" || answer == "yes", nil
}

func resolveRequestedScaffoldBackups(targets map[string]string, options runCommandOptions) ([]scaffoldBackup, error) {
	if options.RestoreAll {
		return resolveRequestedScaffoldBackupSet(targets, options)
	}
	selected, err := resolveRequestedScaffoldBackup(targets, options)
	if err != nil {
		return nil, err
	}
	return []scaffoldBackup{selected}, nil
}

func resolveRequestedScaffoldBackupSet(targets map[string]string, options runCommandOptions) ([]scaffoldBackup, error) {
	if strings.TrimSpace(options.BackupKind) != "" {
		return nil, fmt.Errorf("--kind cannot be combined with --all")
	}
	if options.LatestBackup {
		if strings.TrimSpace(options.BackupPath) != "" {
			return nil, fmt.Errorf("use either --backup or --latest with --all, not both")
		}
		return findLatestScaffoldBackupSet(targets)
	}
	backupPath := strings.TrimSpace(options.BackupPath)
	if backupPath == "" {
		return nil, fmt.Errorf("--all requires either --latest or --backup <path>")
	}
	absBackupPath, err := filepath.Abs(backupPath)
	if err != nil {
		return nil, err
	}
	selected, err := findScaffoldBackupByPath(targets, absBackupPath)
	if err != nil {
		return nil, err
	}
	return findScaffoldBackupSetByTimestamp(targets, selected.Timestamp)
}

func resolveRequestedScaffoldBackup(targets map[string]string, options runCommandOptions) (scaffoldBackup, error) {
	backupPath := strings.TrimSpace(options.BackupPath)
	kind := normalizeScaffoldBackupKind(options.BackupKind)
	if kind == "__invalid__" {
		return scaffoldBackup{}, fmt.Errorf("unsupported scaffold kind %q; use config, service, or compose", strings.TrimSpace(options.BackupKind))
	}
	if options.LatestBackup {
		if backupPath != "" {
			return scaffoldBackup{}, fmt.Errorf("use either --backup or --latest, not both")
		}
		if kind == "" {
			return scaffoldBackup{}, fmt.Errorf("--kind is required with --latest; use config, service, or compose")
		}
		return findLatestScaffoldBackup(targets, kind)
	}
	if backupPath == "" {
		return scaffoldBackup{}, fmt.Errorf("backup path is required; use --backup <path> or --latest --kind <config|service|compose>")
	}
	absBackupPath, err := filepath.Abs(backupPath)
	if err != nil {
		return scaffoldBackup{}, err
	}
	selected, err := findScaffoldBackupByPath(targets, absBackupPath)
	if err != nil {
		return scaffoldBackup{}, err
	}
	if kind != "" && selected.Kind != kind {
		return scaffoldBackup{}, fmt.Errorf("backup path %s is for kind %s, not %s", selected.BackupPath, selected.Kind, kind)
	}
	return selected, nil
}

func findScaffoldBackupByPath(targets map[string]string, backupPath string) (scaffoldBackup, error) {
	for kind, activePath := range targets {
		backups, err := listBackupsForTarget(kind, activePath)
		if err != nil {
			return scaffoldBackup{}, err
		}
		for _, backup := range backups {
			if backup.BackupPath == backupPath {
				return backup, nil
			}
		}
	}
	return scaffoldBackup{}, fmt.Errorf("backup path %s does not match the current scaffold targets", backupPath)
}

func findLatestScaffoldBackup(targets map[string]string, kind string) (scaffoldBackup, error) {
	activePath, ok := targets[kind]
	if !ok {
		return scaffoldBackup{}, fmt.Errorf("unsupported scaffold kind %q; use config, service, or compose", kind)
	}
	backups, err := listBackupsForTarget(kind, activePath)
	if err != nil {
		return scaffoldBackup{}, err
	}
	if len(backups) == 0 {
		return scaffoldBackup{}, fmt.Errorf("no backups found for scaffold kind %s", kind)
	}
	return backups[0], nil
}

func findScaffoldBackupSetByTimestamp(targets map[string]string, timestamp string) ([]scaffoldBackup, error) {
	selected := make([]scaffoldBackup, 0, len(targets))
	for _, kind := range []string{"config", "service", "compose"} {
		activePath, ok := targets[kind]
		if !ok {
			continue
		}
		backups, err := listBackupsForTarget(kind, activePath)
		if err != nil {
			return nil, err
		}
		matched := false
		for _, backup := range backups {
			if backup.Timestamp == timestamp {
				selected = append(selected, backup)
				matched = true
				break
			}
		}
		if !matched {
			return nil, fmt.Errorf("backup timestamp %s does not include scaffold kind %s", timestamp, kind)
		}
	}
	if len(selected) == 0 {
		return nil, fmt.Errorf("no scaffold backups found for timestamp %s", timestamp)
	}
	return selected, nil
}

func findLatestScaffoldBackupSet(targets map[string]string) ([]scaffoldBackup, error) {
	backups, err := listScaffoldBackups(targets["config"], targets["service"])
	if err != nil {
		return nil, err
	}
	timestampCounts := make(map[string]int)
	for _, backup := range backups {
		timestampCounts[backup.Timestamp]++
	}
	for _, backup := range backups {
		if timestampCounts[backup.Timestamp] >= 3 {
			return findScaffoldBackupSetByTimestamp(targets, backup.Timestamp)
		}
	}
	return nil, fmt.Errorf("no complete scaffold backup set found; restore individual files or choose a specific backup timestamp")
}

func normalizeScaffoldBackupKind(kind string) string {
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case "":
		return ""
	case "config", "service", "compose":
		return strings.ToLower(strings.TrimSpace(kind))
	default:
		return "__invalid__"
	}
}

func createTimestampedBackup(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	timestamp := time.Now().Format("20060102-150405")
	return os.WriteFile(path+"."+timestamp+".bak", data, 0644)
}

func runServerCommand(options runCommandOptions) error {
	serverBinary, err := resolveServerBinary(options.ServerBinary)
	if err != nil {
		return err
	}
	args := buildServerRunArgs(options)
	if options.Daemon {
		logFile, pidFile, err := buildServerRunArtifactPaths(options.ConfigPath, options.LogFile, options.PIDFile, options.LogDir, options.PIDDir)
		if err != nil {
			return err
		}
		return startDetachedServer(serverBinary, args, logFile, pidFile)
	}
	cmd := exec.Command(serverBinary, args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
