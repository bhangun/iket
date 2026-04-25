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

	testCmd := &cobra.Command{
		Use:   "test [name]",
		Short: "Test connectivity and certificate readiness for a context",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadCLIConfig()
			if err != nil {
				return err
			}

			name := cfg.CurrentContext
			if len(args) == 1 {
				name = args[0]
			}

			ctx, ok := cfg.Contexts[name]
			if !ok {
				return fmt.Errorf("context %q not found", name)
			}

			fmt.Printf("Testing context %q\n", name)
			fmt.Printf("  URL: %s\n", ctx.ServerURL)
			if ctx.CAFile != "" {
				fmt.Printf("  CA: %s\n", ctx.CAFile)
			}
			if ctx.CertFile != "" {
				fmt.Printf("  Cert: %s\n", ctx.CertFile)
			}
			if ctx.KeyFile != "" {
				fmt.Printf("  Key: %s\n", ctx.KeyFile)
			}

			if ctx.CAFile != "" {
				if _, err := validateOptionalFile(ctx.CAFile, "CA certificate"); err != nil {
					return err
				}
			}
			if ctx.CertFile != "" {
				if _, err := validateOptionalFile(ctx.CertFile, "client certificate"); err != nil {
					return err
				}
			}
			if ctx.KeyFile != "" {
				if _, err := validateOptionalFile(ctx.KeyFile, "client key"); err != nil {
					return err
				}
			}

			if err := verifyCLIContext(ctx); err != nil {
				return fmt.Errorf("gateway verification failed: %w", err)
			}

			fmt.Println("Connection successful.")
			return nil
		},
	}

	// Add context
	var (
		addURL        string
		addCert       string
		addKey        string
		addCA         string
		addCertDir    string
		addSkipVerify bool
		addStrict     bool
		addActivate   bool
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

			if addCertDir != "" && (addCert != "" || addKey != "" || addCA != "") {
				return fmt.Errorf("--cert-dir cannot be combined with --cert, --key, or --ca")
			}

			ctx := Context{
				ServerURL:  addURL,
				SkipVerify: addSkipVerify,
				Strict:     addStrict,
			}

			if addCertDir != "" {
				bundle, err := discoverCertBundle(addCertDir)
				if err != nil {
					return err
				}
				installed, err := installCertBundle(name, bundle)
				if err != nil {
					return err
				}
				ctx.CAFile = installed.CAFile
				ctx.CertFile = installed.CertFile
				ctx.KeyFile = installed.KeyFile
			} else {
				ctx.CertFile, err = validateOptionalFile(addCert, "client certificate")
				if err != nil {
					return err
				}
				ctx.KeyFile, err = validateOptionalFile(addKey, "client key")
				if err != nil {
					return err
				}
				ctx.CAFile, err = validateOptionalFile(addCA, "CA certificate")
				if err != nil {
					return err
				}
			}

			cfg.Contexts[name] = ctx

			if addActivate || len(cfg.Contexts) == 1 {
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
	addCmd.Flags().StringVar(&addCertDir, "cert-dir", "", "Directory containing ca.crt, client.crt, and client.key")
	addCmd.Flags().BoolVar(&addSkipVerify, "skip-verify", false, "Skip TLS verification")
	addCmd.Flags().BoolVar(&addStrict, "strict", false, "Enable strict mode (requires confirmation for state-changing commands)")
	addCmd.Flags().BoolVar(&addActivate, "activate", false, "Set this context as the active context")

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

	contextCmd.AddCommand(listCmd, useCmd, testCmd, addCmd, deleteCmd)
	rootCmd.AddCommand(contextCmd)
}
