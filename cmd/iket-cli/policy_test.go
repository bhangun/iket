package main

import (
	"testing"

	"github.com/spf13/cobra"
)

func TestIsDangerousCommandPath(t *testing.T) {
	if isDangerousCommandPath("iket revision diff", nil) {
		t.Fatalf("expected revision diff to be safe")
	}
	if !isDangerousCommandPath("iket service delete", []string{"identity"}) {
		t.Fatalf("expected service delete to be dangerous")
	}
	if isDangerousCommandPath("iket gateway config", nil) {
		t.Fatalf("expected gateway config without args to be safe")
	}
	if !isDangerousCommandPath("iket gateway config", []string{"config.yaml"}) {
		t.Fatalf("expected gateway config with file arg to be dangerous")
	}
}

func TestStrictRevisionMetadataRequirements(t *testing.T) {
	dryRun = false

	root := &cobra.Command{Use: "iket"}

	configCmd := &cobra.Command{Use: "config"}
	applyCmd := &cobra.Command{Use: "apply"}
	applyCmd.Flags().Bool("replace", false, "")
	if err := applyCmd.Flags().Set("replace", "true"); err != nil {
		t.Fatalf("set replace flag: %v", err)
	}
	root.AddCommand(configCmd)
	configCmd.AddCommand(applyCmd)

	requireLabel, requireNote, requireChangeRef := strictRevisionMetadataRequirements(applyCmd, []string{"config.yaml"})
	if !requireLabel || !requireNote || !requireChangeRef {
		t.Fatalf("expected config apply --replace to require label, note, and change reference")
	}

	revisionCmd := &cobra.Command{Use: "revision"}
	diffCmd := &cobra.Command{Use: "diff"}
	root.AddCommand(revisionCmd)
	revisionCmd.AddCommand(diffCmd)
	requireLabel, requireNote, requireChangeRef = strictRevisionMetadataRequirements(diffCmd, []string{"rev-a", "current"})
	if requireLabel || requireNote || requireChangeRef {
		t.Fatalf("expected revision diff to be exempt from revision metadata requirements")
	}

	serviceCmd := &cobra.Command{Use: "service"}
	deleteCmd := &cobra.Command{Use: "delete"}
	root.AddCommand(serviceCmd)
	serviceCmd.AddCommand(deleteCmd)
	requireLabel, requireNote, requireChangeRef = strictRevisionMetadataRequirements(deleteCmd, []string{"identity"})
	if !requireLabel || !requireNote || !requireChangeRef {
		t.Fatalf("expected service delete to require label, note, and change reference")
	}
}
