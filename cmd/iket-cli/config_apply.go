package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

func initConfigApplyCmd(rootCmd *cobra.Command) {
	var (
		applyReplace   bool
		applyMerge     bool
		proposeReplace bool
		proposeMerge   bool
		proposer       string
		environment    string
		notBefore      string
		diffReplace    bool
		diffMerge      bool
	)

	configCmd := &cobra.Command{
		Use:   "config",
		Short: "Gateway configuration workflows",
	}

	applyCmd := &cobra.Command{
		Use:   "apply [file]",
		Short: "Apply gateway config from a file to the remote gateway",
		Long:  "Apply a gateway config file to the remote gateway. Use --replace to replace the full remote config, or --merge to merge into the current state.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			strategy := "merge"
			if applyReplace && applyMerge {
				return fmt.Errorf("choose only one of --replace or --merge")
			}
			if applyReplace {
				strategy = "replace"
			}
			if applyMerge {
				strategy = "merge"
			}
			return runPush(args[0], "/api/v1/gateway/config", strategy)
		},
	}
	applyCmd.Flags().BoolVar(&applyReplace, "replace", false, "Replace the full remote gateway config with the file contents")
	applyCmd.Flags().BoolVar(&applyMerge, "merge", false, "Merge the file contents into the current remote gateway config")
	configCmd.AddCommand(applyCmd)

	proposeCmd := &cobra.Command{
		Use:   "propose [file]",
		Short: "Create a pending gateway config proposal from a file",
		Long:  "Create a pending proposal instead of applying the gateway config immediately. Use --replace to propose a full replacement, or --merge to propose a merge into the current state.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			strategy := "merge"
			if proposeReplace && proposeMerge {
				return fmt.Errorf("choose only one of --replace or --merge")
			}
			if proposeReplace {
				strategy = "replace"
			}
			if proposeMerge {
				strategy = "merge"
			}
			return runPushWithMode(args[0], "/api/v1/gateway/config", strategy, false, true, proposer, environment, notBefore, nil, nil, nil, 0, nil, 0, 0, "", false, "", "")
		},
	}
	proposeCmd.Flags().BoolVar(&proposeReplace, "replace", false, "Create a proposal for full remote gateway config replacement")
	proposeCmd.Flags().BoolVar(&proposeMerge, "merge", false, "Create a proposal for merging into the current remote gateway config")
	proposeCmd.Flags().StringVar(&proposer, "proposer", "", "Identity to record as the proposal creator")
	proposeCmd.Flags().StringVar(&environment, "env", "", "Environment name to record on the proposal, such as staging or prod")
	proposeCmd.Flags().StringVar(&notBefore, "not-before", "", "Do not allow proposal apply before this RFC3339 timestamp")
	configCmd.AddCommand(proposeCmd)

	diffCmd := &cobra.Command{
		Use:   "diff [file]",
		Short: "Preview gateway config changes without applying them",
		Long:  "Preview how a gateway config file would change the remote gateway. Use --replace to preview full replacement, or --merge to preview a merge into the current state.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			strategy := "merge"
			if diffReplace && diffMerge {
				return fmt.Errorf("choose only one of --replace or --merge")
			}
			if diffReplace {
				strategy = "replace"
			}
			if diffMerge {
				strategy = "merge"
			}
			return runPushWithOptions(args[0], "/api/v1/gateway/config", strategy, true)
		},
	}
	diffCmd.Flags().BoolVar(&diffReplace, "replace", false, "Preview a full remote gateway config replacement")
	diffCmd.Flags().BoolVar(&diffMerge, "merge", false, "Preview a merge into the current remote gateway config")
	configCmd.AddCommand(diffCmd)

	rootCmd.AddCommand(configCmd)
}
