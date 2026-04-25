package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
)

func TestDiscoverCertBundleInDirs(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"ca.crt", "client.crt", "client.key"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(name), 0600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}

	bundle, err := discoverCertBundleInDirs([]string{filepath.Join(dir, "missing"), dir})
	if err != nil {
		t.Fatalf("discover bundle: %v", err)
	}

	if bundle.Dir != dir {
		t.Fatalf("expected dir %q, got %q", dir, bundle.Dir)
	}
	if bundle.CAFile != filepath.Join(dir, "ca.crt") {
		t.Fatalf("unexpected CA file: %s", bundle.CAFile)
	}
	if bundle.CertFile != filepath.Join(dir, "client.crt") {
		t.Fatalf("unexpected cert file: %s", bundle.CertFile)
	}
	if bundle.KeyFile != filepath.Join(dir, "client.key") {
		t.Fatalf("unexpected key file: %s", bundle.KeyFile)
	}
}

func TestInstallCertBundle(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	sourceDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(sourceDir, "ca.crt"), []byte("ca"), 0644); err != nil {
		t.Fatalf("write ca: %v", err)
	}
	if err := os.WriteFile(filepath.Join(sourceDir, "client.crt"), []byte("cert"), 0644); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(filepath.Join(sourceDir, "client.key"), []byte("key"), 0600); err != nil {
		t.Fatalf("write key: %v", err)
	}

	ctx, err := installCertBundle("Docker Prod", certBundle{
		Dir:      sourceDir,
		CAFile:   filepath.Join(sourceDir, "ca.crt"),
		CertFile: filepath.Join(sourceDir, "client.crt"),
		KeyFile:  filepath.Join(sourceDir, "client.key"),
	})
	if err != nil {
		t.Fatalf("install bundle: %v", err)
	}

	expectedDir := filepath.Join(home, ".iket", "certs", "contexts", "docker-prod")
	if ctx.CAFile != filepath.Join(expectedDir, "ca.crt") {
		t.Fatalf("unexpected installed CA path: %s", ctx.CAFile)
	}
	if ctx.CertFile != filepath.Join(expectedDir, "client.crt") {
		t.Fatalf("unexpected installed cert path: %s", ctx.CertFile)
	}
	if ctx.KeyFile != filepath.Join(expectedDir, "client.key") {
		t.Fatalf("unexpected installed key path: %s", ctx.KeyFile)
	}

	data, err := os.ReadFile(ctx.KeyFile)
	if err != nil {
		t.Fatalf("read installed key: %v", err)
	}
	if string(data) != "key" {
		t.Fatalf("unexpected key contents: %q", string(data))
	}
}

func TestTopLevelCommandName(t *testing.T) {
	root := &cobra.Command{Use: "iket"}
	setup := &cobra.Command{Use: "setup"}
	docker := &cobra.Command{Use: "docker"}
	root.AddCommand(setup)
	setup.AddCommand(docker)

	if got := topLevelCommandName(docker); got != "setup" {
		t.Fatalf("expected top-level command name setup, got %q", got)
	}
}
