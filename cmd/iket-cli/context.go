package main

import (
	"fmt"
	"os"
	"sort"
	"text/tabwriter"

	"github.com/spf13/cobra"
)

func initContextCmd(rootCmd *cobra.Command) {
	contextCmd := &cobra.Command{
		Use:     "context",
		Aliases: []string{"ctx"},
		Short:   "Manage CLI contexts (server profiles)",
	}

	// List contexts
	listCmd := &cobra.Command{
		Use:   "list",
		Short: "List all contexts",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadCLIConfig()
			if err != nil {
				return err
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
			fmt.Fprintln(w, "ACTIVE\tNAME\tURL\tSTRICT")

			// Sort keys for consistent output
			keys := make([]string, 0, len(cfg.Contexts))
			for k := range cfg.Contexts {
				keys = append(keys, k)
			}
			sort.Strings(keys)

			for _, name := range keys {
				active := ""
				if name == cfg.CurrentContext {
					active = "*"
				}
				ctx := cfg.Contexts[name]
				strict := ""
				if ctx.Strict {
					strict = "YES"
				}
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", active, name, ctx.ServerURL, strict)
			}
			return w.Flush()
		},
	}

	// Use context
	useCmd := &cobra.Command{
		Use:   "use [name]",
		Short: "Switch to a different context",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			cfg, err := loadCLIConfig()
			if err != nil {
				return err
			}

			if _, ok := cfg.Contexts[name]; !ok {
				return fmt.Errorf("context %q not found", name)
			}

			cfg.CurrentContext = name
			if err := saveCLIConfig(cfg); err != nil {
				return err
			}

			fmt.Printf("Switched to context %q\n", name)
			return nil
		},
	}

	// Add context
	var (
		addURL        string
		addCert       string
		addKey        string
		addCA         string
		addSkipVerify bool
		addStrict     bool
	)
	addCmd := &cobra.Command{
		Use:   "add [name]",
		Short: "Add a new context",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			cfg, err := loadCLIConfig()
			if err != nil {
				return err
			}

			if addURL == "" {
				return fmt.Errorf("server URL is required (use --url)")
			}

			cfg.Contexts[name] = Context{
				ServerURL:  addURL,
				CertFile:   addCert,
				KeyFile:    addKey,
				CAFile:     addCA,
				SkipVerify: addSkipVerify,
				Strict:     addStrict,
			}

			if len(cfg.Contexts) == 1 {
				cfg.CurrentContext = name
			}

			if err := saveCLIConfig(cfg); err != nil {
				return err
			}

			fmt.Printf("Added context %q\n", name)
			return nil
		},
	}
	addCmd.Flags().StringVar(&addURL, "url", "", "Server URL (e.g., http://localhost:8080)")
	addCmd.Flags().StringVar(&addCert, "cert", "", "Client certificate file")
	addCmd.Flags().StringVar(&addKey, "key", "", "Client key file")
	addCmd.Flags().StringVar(&addCA, "ca", "", "CA certificate file")
	addCmd.Flags().BoolVar(&addSkipVerify, "skip-verify", false, "Skip TLS verification")
	addCmd.Flags().BoolVar(&addStrict, "strict", false, "Enable strict mode (requires confirmation for state-changing commands)")

	// Delete context
	deleteCmd := &cobra.Command{
		Use:   "delete [name]",
		Short: "Delete a context",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			cfg, err := loadCLIConfig()
			if err != nil {
				return err
			}

			if _, ok := cfg.Contexts[name]; !ok {
				return fmt.Errorf("context %q not found", name)
			}

			delete(cfg.Contexts, name)
			if cfg.CurrentContext == name {
				cfg.CurrentContext = ""
				// Set to first available if any
				for k := range cfg.Contexts {
					cfg.CurrentContext = k
					break
				}
			}

			if err := saveCLIConfig(cfg); err != nil {
				return err
			}

			fmt.Printf("Deleted context %q\n", name)
			return nil
		},
	}

	contextCmd.AddCommand(listCmd, useCmd, addCmd, deleteCmd)
	rootCmd.AddCommand(contextCmd)
}
