package main

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestBuildServerRunArgsDefaultsToConfigAndServices(t *testing.T) {
	args := buildServerRunArgs(runCommandOptions{
		ConfigPath:   "config/config.yaml",
		ServicesPath: "config/service.yaml",
	})

	want := []string{"--config", "config/config.yaml", "--services", "config/service.yaml"}
	if !reflect.DeepEqual(args, want) {
		t.Fatalf("buildServerRunArgs() = %#v, want %#v", args, want)
	}
}

func TestBuildServerRunArgsIncludesDatabaseFlags(t *testing.T) {
	args := buildServerRunArgs(runCommandOptions{
		ConfigPath:    "config/config.yaml",
		ServicesPath:  "config/service.yaml",
		UseDatabase:   true,
		DatabaseUser:  "foo",
		DatabasePass:  "secret",
		DatabaseName:  "mydb",
		DatabaseHost:  "db.internal",
		DatabasePort:  "55432",
		ServerPort:    9090,
		PrintConfig:   true,
		ResetDefaults: true,
		InitOnly:      true,
	})

	joined := strings.Join(args, " ")
	for _, expected := range []string{
		"--database",
		"--username foo",
		"--password secret",
		"--database-name mydb",
		"--database-host db.internal",
		"--database-port 55432",
		"--port 9090",
		"--print-config",
		"--reset-defaults",
		"--init-only",
	} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("expected args to contain %q, got %#v", expected, args)
		}
	}
}

func TestResolveServerBinaryUsesExplicitPath(t *testing.T) {
	path, err := resolveServerBinary("/tmp/iket-server")
	if err != nil {
		t.Fatalf("resolveServerBinary returned error: %v", err)
	}
	if path != "/tmp/iket-server" {
		t.Fatalf("expected explicit path to win, got %q", path)
	}
}

func TestResolveServerBinaryFallsBackToSiblingBinary(t *testing.T) {
	t.Setenv("PATH", "")
	executablePath, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable returned error: %v", err)
	}
	sibling := filepath.Join(filepath.Dir(executablePath), "iket-server")
	if err := os.WriteFile(sibling, []byte("#!/bin/sh\n"), 0755); err != nil {
		t.Fatalf("write sibling binary: %v", err)
	}
	t.Cleanup(func() {
		_ = os.Remove(sibling)
	})

	path, err := resolveServerBinary("")
	if err != nil {
		t.Fatalf("resolveServerBinary returned error: %v", err)
	}
	if path != sibling {
		t.Fatalf("expected sibling binary path %q, got %q", sibling, path)
	}
}

func TestBuildServerRunArtifactPathsUsesScaffoldDefaults(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "config", "config.yaml")

	logFile, pidFile, err := buildServerRunArtifactPaths(configPath, "", "", "", "")
	if err != nil {
		t.Fatalf("buildServerRunArtifactPaths returned error: %v", err)
	}
	if logFile != filepath.Join(root, "logs", "iket-server.log") {
		t.Fatalf("expected default log file under logs/, got %q", logFile)
	}
	if pidFile != filepath.Join(root, "logs", "iket-server.pid") {
		t.Fatalf("expected default pid file under logs/, got %q", pidFile)
	}
}

func TestBuildServerRunArtifactPathsHonorsExplicitPaths(t *testing.T) {
	logFile, pidFile, err := buildServerRunArtifactPaths("config/config.yaml", "./custom/server.log", "./custom/server.pid", "", "")
	if err != nil {
		t.Fatalf("buildServerRunArtifactPaths returned error: %v", err)
	}
	if !strings.HasSuffix(logFile, filepath.Join("custom", "server.log")) {
		t.Fatalf("expected custom log file path, got %q", logFile)
	}
	if !strings.HasSuffix(pidFile, filepath.Join("custom", "server.pid")) {
		t.Fatalf("expected custom pid file path, got %q", pidFile)
	}
}

func TestBuildServerRunArtifactPathsHonorsExplicitDirs(t *testing.T) {
	logFile, pidFile, err := buildServerRunArtifactPaths("config/config.yaml", "", "", "~/.iket/logs", "~/.iket/run")
	if err != nil {
		t.Fatalf("buildServerRunArtifactPaths returned error: %v", err)
	}
	homeDir, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("os.UserHomeDir returned error: %v", err)
	}
	if logFile != filepath.Join(homeDir, ".iket", "logs", "iket-server.log") {
		t.Fatalf("expected log-dir based log file, got %q", logFile)
	}
	if pidFile != filepath.Join(homeDir, ".iket", "run", "iket-server.pid") {
		t.Fatalf("expected pid-dir based pid file, got %q", pidFile)
	}
}

func TestReadServerPIDParsesPIDFile(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "iket-server.pid")
	if err := os.WriteFile(pidFile, []byte("4321\n"), 0644); err != nil {
		t.Fatalf("write pid file: %v", err)
	}
	pid, err := readServerPID(pidFile)
	if err != nil {
		t.Fatalf("readServerPID returned error: %v", err)
	}
	if pid != 4321 {
		t.Fatalf("expected pid 4321, got %d", pid)
	}
}

func TestPrintServerStatusHandlesMissingPIDFile(t *testing.T) {
	root := t.TempDir()
	output := captureStdout(t, func() {
		if err := printServerStatus(runCommandOptions{
			ConfigPath: filepath.Join(root, "config", "config.yaml"),
		}); err != nil {
			t.Fatalf("printServerStatus returned error: %v", err)
		}
	})
	if !strings.Contains(output, "state: not running (pid file missing)") {
		t.Fatalf("expected missing pid status, got:\n%s", output)
	}
}

func TestPrintServerStatusHandlesStalePIDFile(t *testing.T) {
	root := t.TempDir()
	pidFile := filepath.Join(root, "logs", "iket-server.pid")
	if err := os.MkdirAll(filepath.Dir(pidFile), 0755); err != nil {
		t.Fatalf("mkdir logs: %v", err)
	}
	if err := os.WriteFile(pidFile, []byte("999999\n"), 0644); err != nil {
		t.Fatalf("write pid file: %v", err)
	}
	output := captureStdout(t, func() {
		if err := printServerStatus(runCommandOptions{
			ConfigPath: filepath.Join(root, "config", "config.yaml"),
		}); err != nil {
			t.Fatalf("printServerStatus returned error: %v", err)
		}
	})
	if !strings.Contains(output, "state: stopped") {
		t.Fatalf("expected stopped status for stale pid file, got:\n%s", output)
	}
}

func TestStopServerProcessHandlesMissingPIDFile(t *testing.T) {
	root := t.TempDir()
	output := captureStdout(t, func() {
		if err := stopServerProcess(runCommandOptions{
			ConfigPath: filepath.Join(root, "config", "config.yaml"),
		}); err != nil {
			t.Fatalf("stopServerProcess returned error: %v", err)
		}
	})
	if !strings.Contains(output, "not running (pid file missing)") {
		t.Fatalf("expected missing pid message, got:\n%s", output)
	}
}

func TestStopServerProcessRemovesStalePIDFile(t *testing.T) {
	root := t.TempDir()
	pidFile := filepath.Join(root, "logs", "iket-server.pid")
	if err := os.MkdirAll(filepath.Dir(pidFile), 0755); err != nil {
		t.Fatalf("mkdir logs: %v", err)
	}
	if err := os.WriteFile(pidFile, []byte("999999\n"), 0644); err != nil {
		t.Fatalf("write pid file: %v", err)
	}

	output := captureStdout(t, func() {
		if err := stopServerProcess(runCommandOptions{
			ConfigPath: filepath.Join(root, "config", "config.yaml"),
		}); err != nil {
			t.Fatalf("stopServerProcess returned error: %v", err)
		}
	})
	if !strings.Contains(output, "Removed stale pid file") {
		t.Fatalf("expected stale pid cleanup message, got:\n%s", output)
	}
	if _, err := os.Stat(pidFile); !os.IsNotExist(err) {
		t.Fatalf("expected stale pid file to be removed, stat err=%v", err)
	}
}

func TestReadLastLogLinesReturnsTail(t *testing.T) {
	logFile := filepath.Join(t.TempDir(), "iket-server.log")
	content := "one\ntwo\nthree\nfour\n"
	if err := os.WriteFile(logFile, []byte(content), 0644); err != nil {
		t.Fatalf("write log file: %v", err)
	}

	lines, err := readLastLogLines(logFile, 2)
	if err != nil {
		t.Fatalf("readLastLogLines returned error: %v", err)
	}
	if !reflect.DeepEqual(lines, []string{"three", "four"}) {
		t.Fatalf("expected tail lines [three four], got %#v", lines)
	}
}

func TestPrintServerLogsPrintsTail(t *testing.T) {
	root := t.TempDir()
	logFile := filepath.Join(root, "logs", "iket-server.log")
	if err := os.MkdirAll(filepath.Dir(logFile), 0755); err != nil {
		t.Fatalf("mkdir logs: %v", err)
	}
	if err := os.WriteFile(logFile, []byte("alpha\nbeta\ngamma\n"), 0644); err != nil {
		t.Fatalf("write log file: %v", err)
	}

	output := captureStdout(t, func() {
		if err := printServerLogs(runCommandOptions{
			ConfigPath: filepath.Join(root, "config", "config.yaml"),
			TailLines:  2,
		}); err != nil {
			t.Fatalf("printServerLogs returned error: %v", err)
		}
	})
	if !strings.Contains(output, "beta") || !strings.Contains(output, "gamma") {
		t.Fatalf("expected tail log lines in output, got:\n%s", output)
	}
	if strings.Contains(output, "alpha") {
		t.Fatalf("did not expect trimmed log line alpha in output, got:\n%s", output)
	}
}

func TestListScaffoldBackupsFindsTimestampedFiles(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "config", "config.yaml")
	servicePath := filepath.Join(root, "config", "service.yaml")
	composePath := filepath.Join(root, "docker-compose.yaml")
	if err := os.MkdirAll(filepath.Dir(configPath), 0755); err != nil {
		t.Fatalf("mkdir config dir: %v", err)
	}
	for _, path := range []string{
		configPath + ".20260525-131000.bak",
		servicePath + ".20260525-131000.bak",
		composePath + ".20260525-131000.bak",
	} {
		if err := os.WriteFile(path, []byte("backup"), 0644); err != nil {
			t.Fatalf("write backup %s: %v", path, err)
		}
	}

	backups, err := listScaffoldBackups(configPath, servicePath)
	if err != nil {
		t.Fatalf("listScaffoldBackups returned error: %v", err)
	}
	if len(backups) != 3 {
		t.Fatalf("expected three backups, got %#v", backups)
	}
}

func TestPrintServerBackupsPrintsGroupedEntries(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "config", "config.yaml")
	servicePath := filepath.Join(root, "config", "service.yaml")
	if err := os.MkdirAll(filepath.Dir(configPath), 0755); err != nil {
		t.Fatalf("mkdir config dir: %v", err)
	}
	backupPath := configPath + ".20260525-131000.bak"
	if err := os.WriteFile(backupPath, []byte("backup"), 0644); err != nil {
		t.Fatalf("write backup: %v", err)
	}

	output := captureStdout(t, func() {
		if err := printServerBackups(runCommandOptions{ConfigPath: configPath, ServicesPath: servicePath}); err != nil {
			t.Fatalf("printServerBackups returned error: %v", err)
		}
	})
	if !strings.Contains(output, "[config] "+backupPath) {
		t.Fatalf("expected config backup in output, got:\n%s", output)
	}
}

func TestRestoreServerBackupRestoresSelectedFile(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "config", "config.yaml")
	servicePath := filepath.Join(root, "config", "service.yaml")
	if err := os.MkdirAll(filepath.Dir(configPath), 0755); err != nil {
		t.Fatalf("mkdir config dir: %v", err)
	}
	if err := os.WriteFile(configPath, []byte("current"), 0644); err != nil {
		t.Fatalf("write current config: %v", err)
	}
	backupPath := configPath + ".20260525-131000.bak"
	if err := os.WriteFile(backupPath, []byte("restored"), 0644); err != nil {
		t.Fatalf("write backup: %v", err)
	}

	originalForce := force
	force = true
	defer func() { force = originalForce }()

	output := captureStdout(t, func() {
		if err := restoreServerBackup(runCommandOptions{
			ConfigPath:   configPath,
			ServicesPath: servicePath,
			BackupPath:   backupPath,
		}); err != nil {
			t.Fatalf("restoreServerBackup returned error: %v", err)
		}
	})
	restoredBytes, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read restored config: %v", err)
	}
	if string(restoredBytes) != "restored" {
		t.Fatalf("expected restored contents, got %q", string(restoredBytes))
	}
	if !strings.Contains(output, "Restored scaffold backup") {
		t.Fatalf("expected restore confirmation, got:\n%s", output)
	}
	matches, err := filepath.Glob(configPath + ".????????-??????.bak")
	if err != nil {
		t.Fatalf("glob restore backups: %v", err)
	}
	if len(matches) < 2 {
		t.Fatalf("expected restore to preserve current file as new backup, got %#v", matches)
	}
}

func TestResolveRequestedScaffoldBackupSelectsLatestByKind(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "config", "config.yaml")
	servicePath := filepath.Join(root, "config", "service.yaml")
	if err := os.MkdirAll(filepath.Dir(configPath), 0755); err != nil {
		t.Fatalf("mkdir config dir: %v", err)
	}
	newer := configPath + ".20260525-141500.bak"
	older := configPath + ".20260525-131000.bak"
	for _, path := range []string{older, newer} {
		if err := os.WriteFile(path, []byte("backup"), 0644); err != nil {
			t.Fatalf("write backup %s: %v", path, err)
		}
	}
	targets, err := scaffoldTargetPaths(configPath, servicePath)
	if err != nil {
		t.Fatalf("scaffoldTargetPaths returned error: %v", err)
	}
	selected, err := resolveRequestedScaffoldBackup(targets, runCommandOptions{
		LatestBackup: true,
		BackupKind:   "config",
	})
	if err != nil {
		t.Fatalf("resolveRequestedScaffoldBackup returned error: %v", err)
	}
	if selected.BackupPath != newer {
		t.Fatalf("expected latest backup %q, got %q", newer, selected.BackupPath)
	}
}

func TestResolveRequestedScaffoldBackupRejectsInvalidSelectors(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "config", "config.yaml")
	servicePath := filepath.Join(root, "config", "service.yaml")
	targets, err := scaffoldTargetPaths(configPath, servicePath)
	if err != nil {
		t.Fatalf("scaffoldTargetPaths returned error: %v", err)
	}
	_, err = resolveRequestedScaffoldBackup(targets, runCommandOptions{
		LatestBackup: true,
		BackupKind:   "unknown",
	})
	if err == nil || !strings.Contains(err.Error(), "unsupported scaffold kind") {
		t.Fatalf("expected unsupported kind error, got %v", err)
	}

	_, err = resolveRequestedScaffoldBackup(targets, runCommandOptions{
		LatestBackup: true,
		BackupKind:   "config",
		BackupPath:   "./some/path.bak",
	})
	if err == nil || !strings.Contains(err.Error(), "either --backup or --latest") {
		t.Fatalf("expected mutually exclusive selector error, got %v", err)
	}

	_, err = resolveRequestedScaffoldBackups(targets, runCommandOptions{
		RestoreAll:   true,
		LatestBackup: true,
		BackupKind:   "config",
	})
	if err == nil || !strings.Contains(err.Error(), "--kind cannot be combined with --all") {
		t.Fatalf("expected --all kind validation error, got %v", err)
	}
}

func TestRestoreServerBackupSupportsLatestKind(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "config", "config.yaml")
	servicePath := filepath.Join(root, "config", "service.yaml")
	if err := os.MkdirAll(filepath.Dir(configPath), 0755); err != nil {
		t.Fatalf("mkdir config dir: %v", err)
	}
	if err := os.WriteFile(configPath, []byte("current"), 0644); err != nil {
		t.Fatalf("write current config: %v", err)
	}
	backupPath := configPath + ".20260525-141500.bak"
	if err := os.WriteFile(backupPath, []byte("latest"), 0644); err != nil {
		t.Fatalf("write backup: %v", err)
	}

	originalForce := force
	force = true
	defer func() { force = originalForce }()

	if err := restoreServerBackup(runCommandOptions{
		ConfigPath:   configPath,
		ServicesPath: servicePath,
		LatestBackup: true,
		BackupKind:   "config",
	}); err != nil {
		t.Fatalf("restoreServerBackup returned error: %v", err)
	}
	restoredBytes, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read restored config: %v", err)
	}
	if string(restoredBytes) != "latest" {
		t.Fatalf("expected latest backup contents, got %q", string(restoredBytes))
	}
}

func TestFindLatestScaffoldBackupSetReturnsCompleteSnapshot(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "config", "config.yaml")
	servicePath := filepath.Join(root, "config", "service.yaml")
	composePath := filepath.Join(root, "docker-compose.yaml")
	if err := os.MkdirAll(filepath.Dir(configPath), 0755); err != nil {
		t.Fatalf("mkdir config dir: %v", err)
	}
	for _, path := range []string{
		configPath + ".20260525-141500.bak",
		servicePath + ".20260525-141500.bak",
		composePath + ".20260525-141500.bak",
		configPath + ".20260525-131000.bak",
		servicePath + ".20260525-131000.bak",
		composePath + ".20260525-131000.bak",
	} {
		if err := os.WriteFile(path, []byte(path), 0644); err != nil {
			t.Fatalf("write backup %s: %v", path, err)
		}
	}
	targets, err := scaffoldTargetPaths(configPath, servicePath)
	if err != nil {
		t.Fatalf("scaffoldTargetPaths returned error: %v", err)
	}
	selected, err := findLatestScaffoldBackupSet(targets)
	if err != nil {
		t.Fatalf("findLatestScaffoldBackupSet returned error: %v", err)
	}
	if len(selected) != 3 {
		t.Fatalf("expected complete backup set, got %#v", selected)
	}
	for _, item := range selected {
		if item.Timestamp != "20260525-141500" {
			t.Fatalf("expected latest timestamp, got %#v", selected)
		}
	}
}

func TestRestoreServerBackupAllLatestRestoresFullSet(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "config", "config.yaml")
	servicePath := filepath.Join(root, "config", "service.yaml")
	composePath := filepath.Join(root, "docker-compose.yaml")
	if err := os.MkdirAll(filepath.Dir(configPath), 0755); err != nil {
		t.Fatalf("mkdir config dir: %v", err)
	}
	for path, value := range map[string]string{
		configPath:  "current-config",
		servicePath: "current-service",
		composePath: "current-compose",
	} {
		if err := os.WriteFile(path, []byte(value), 0644); err != nil {
			t.Fatalf("write current file %s: %v", path, err)
		}
	}
	for path, value := range map[string]string{
		configPath + ".20260525-141500.bak":  "restored-config",
		servicePath + ".20260525-141500.bak": "restored-service",
		composePath + ".20260525-141500.bak": "restored-compose",
	} {
		if err := os.WriteFile(path, []byte(value), 0644); err != nil {
			t.Fatalf("write backup file %s: %v", path, err)
		}
	}

	originalForce := force
	force = true
	defer func() { force = originalForce }()

	if err := restoreServerBackup(runCommandOptions{
		ConfigPath:   configPath,
		ServicesPath: servicePath,
		RestoreAll:   true,
		LatestBackup: true,
	}); err != nil {
		t.Fatalf("restoreServerBackup returned error: %v", err)
	}
	for path, want := range map[string]string{
		configPath:  "restored-config",
		servicePath: "restored-service",
		composePath: "restored-compose",
	} {
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read restored file %s: %v", path, err)
		}
		if string(got) != want {
			t.Fatalf("expected %s to be %q, got %q", path, want, string(got))
		}
	}
}

func TestRestoreServerBackupAllPreviewDoesNotModifyFiles(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "config", "config.yaml")
	servicePath := filepath.Join(root, "config", "service.yaml")
	composePath := filepath.Join(root, "docker-compose.yaml")
	if err := os.MkdirAll(filepath.Dir(configPath), 0755); err != nil {
		t.Fatalf("mkdir config dir: %v", err)
	}
	for path, value := range map[string]string{
		configPath:  "current-config",
		servicePath: "current-service",
		composePath: "current-compose",
	} {
		if err := os.WriteFile(path, []byte(value), 0644); err != nil {
			t.Fatalf("write current file %s: %v", path, err)
		}
	}
	for _, path := range []string{
		configPath + ".20260525-141500.bak",
		servicePath + ".20260525-141500.bak",
		composePath + ".20260525-141500.bak",
	} {
		if err := os.WriteFile(path, []byte("backup"), 0644); err != nil {
			t.Fatalf("write backup file %s: %v", path, err)
		}
	}
	output := captureStdout(t, func() {
		if err := restoreServerBackup(runCommandOptions{
			ConfigPath:   configPath,
			ServicesPath: servicePath,
			RestoreAll:   true,
			LatestBackup: true,
			Preview:      true,
		}); err != nil {
			t.Fatalf("restoreServerBackup returned error: %v", err)
		}
	})
	if !strings.Contains(output, "set size: 3") {
		t.Fatalf("expected full-set preview output, got:\n%s", output)
	}
	for path, want := range map[string]string{
		configPath:  "current-config",
		servicePath: "current-service",
		composePath: "current-compose",
	} {
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read current file %s: %v", path, err)
		}
		if string(got) != want {
			t.Fatalf("expected preview not to modify %s, got %q", path, string(got))
		}
	}
}

func TestRestoreServerBackupPreviewDoesNotModifyFiles(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "config", "config.yaml")
	servicePath := filepath.Join(root, "config", "service.yaml")
	if err := os.MkdirAll(filepath.Dir(configPath), 0755); err != nil {
		t.Fatalf("mkdir config dir: %v", err)
	}
	if err := os.WriteFile(configPath, []byte("current"), 0644); err != nil {
		t.Fatalf("write current config: %v", err)
	}
	backupPath := configPath + ".20260525-141500.bak"
	if err := os.WriteFile(backupPath, []byte("preview"), 0644); err != nil {
		t.Fatalf("write backup: %v", err)
	}

	output := captureStdout(t, func() {
		if err := restoreServerBackup(runCommandOptions{
			ConfigPath:   configPath,
			ServicesPath: servicePath,
			BackupPath:   backupPath,
			Preview:      true,
		}); err != nil {
			t.Fatalf("restoreServerBackup returned error: %v", err)
		}
	})
	currentBytes, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read current config: %v", err)
	}
	if string(currentBytes) != "current" {
		t.Fatalf("expected preview not to modify active file, got %q", string(currentBytes))
	}
	if !strings.Contains(output, "Iket server restore preview") {
		t.Fatalf("expected restore preview output, got:\n%s", output)
	}
	matches, err := filepath.Glob(configPath + ".????????-??????.bak")
	if err != nil {
		t.Fatalf("glob preview backups: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected preview not to create new backups, got %#v", matches)
	}
}

func TestPrintRestorePreviewPrintsSelection(t *testing.T) {
	output := captureStdout(t, func() {
		if err := printRestorePreview([]scaffoldBackup{{
			Kind:       "config",
			ActivePath: "/tmp/config/config.yaml",
			BackupPath: "/tmp/config/config.yaml.20260525-141500.bak",
			Timestamp:  "20260525-141500",
		}}); err != nil {
			t.Fatalf("printRestorePreview returned error: %v", err)
		}
	})
	for _, expected := range []string{
		"Iket server restore preview",
		"kind: config",
		"/tmp/config/config.yaml.20260525-141500.bak",
		"/tmp/config/config.yaml",
		"would restore backup into active file",
	} {
		if !strings.Contains(output, expected) {
			t.Fatalf("expected preview output to contain %q, got:\n%s", expected, output)
		}
	}
}

func TestConfirmRestoreSelectionAcceptsYes(t *testing.T) {
	var output bytes.Buffer
	confirmed, err := confirmRestoreSelection(strings.NewReader("yes\n"), &output, []scaffoldBackup{{
		Kind:       "config",
		ActivePath: "/tmp/config/config.yaml",
		BackupPath: "/tmp/config/config.yaml.20260525-141500.bak",
	}})
	if err != nil {
		t.Fatalf("confirmRestoreSelection returned error: %v", err)
	}
	if !confirmed {
		t.Fatalf("expected confirmation to succeed")
	}
	if !strings.Contains(output.String(), "Proceed? (y/N):") {
		t.Fatalf("expected prompt output, got:\n%s", output.String())
	}
}

func TestConfirmRestoreSelectionDefaultsToNo(t *testing.T) {
	var output bytes.Buffer
	confirmed, err := confirmRestoreSelection(strings.NewReader("\n"), &output, []scaffoldBackup{{
		Kind:       "config",
		ActivePath: "/tmp/config/config.yaml",
		BackupPath: "/tmp/config/config.yaml.20260525-141500.bak",
	}})
	if err != nil {
		t.Fatalf("confirmRestoreSelection returned error: %v", err)
	}
	if confirmed {
		t.Fatalf("expected empty confirmation to be treated as no")
	}
}

func TestRestoreServerBackupCancelledByPrompt(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "config", "config.yaml")
	servicePath := filepath.Join(root, "config", "service.yaml")
	if err := os.MkdirAll(filepath.Dir(configPath), 0755); err != nil {
		t.Fatalf("mkdir config dir: %v", err)
	}
	if err := os.WriteFile(configPath, []byte("current"), 0644); err != nil {
		t.Fatalf("write current config: %v", err)
	}
	backupPath := configPath + ".20260525-141500.bak"
	if err := os.WriteFile(backupPath, []byte("backup"), 0644); err != nil {
		t.Fatalf("write backup: %v", err)
	}

	originalForce := force
	originalStdin := os.Stdin
	force = false
	defer func() {
		force = originalForce
		os.Stdin = originalStdin
	}()

	promptFile, err := os.CreateTemp(t.TempDir(), "restore-prompt")
	if err != nil {
		t.Fatalf("create temp prompt file: %v", err)
	}
	if _, err := promptFile.WriteString("n\n"); err != nil {
		t.Fatalf("write prompt file: %v", err)
	}
	if _, err := promptFile.Seek(0, 0); err != nil {
		t.Fatalf("seek prompt file: %v", err)
	}
	os.Stdin = promptFile

	err = restoreServerBackup(runCommandOptions{
		ConfigPath:   configPath,
		ServicesPath: servicePath,
		BackupPath:   backupPath,
	})
	if err == nil || !strings.Contains(err.Error(), "restore cancelled") {
		t.Fatalf("expected restore cancelled error, got %v", err)
	}
	currentBytes, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read current config: %v", err)
	}
	if string(currentBytes) != "current" {
		t.Fatalf("expected cancelled restore not to modify active file, got %q", string(currentBytes))
	}
}

func TestCreateTimestampedBackupWritesBackupFile(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "config.yaml")
	if err := os.WriteFile(path, []byte("current"), 0644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	if err := createTimestampedBackup(path); err != nil {
		t.Fatalf("createTimestampedBackup returned error: %v", err)
	}

	matches, err := filepath.Glob(path + ".????????-??????.bak")
	if err != nil {
		t.Fatalf("glob backup files: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected one backup file, got %#v", matches)
	}
	backupBytes, err := os.ReadFile(matches[0])
	if err != nil {
		t.Fatalf("read backup file: %v", err)
	}
	if string(backupBytes) != "current" {
		t.Fatalf("expected backup contents to match, got %q", string(backupBytes))
	}
	timestamp := strings.TrimSuffix(strings.TrimPrefix(matches[0], path+"."), ".bak")
	if _, err := time.Parse("20060102-150405", timestamp); err != nil {
		t.Fatalf("parse backup timestamp: %v", err)
	}
}
