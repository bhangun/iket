package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

var (
	apiClient *APIClient
	cliConfig *CLIConfig
	force     bool
	dryRun    bool
)

var rootCmd = &cobra.Command{
	Use:   "iket-cli",
	Short: "Iket Gateway management CLI",
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		if cmd.Name() == "cert" || cmd.Name() == "gen" || cmd.Name() == "setup" || cmd.Name() == "context" {
			return nil
		}

		var err error
		cliConfig, err = loadCLIConfig()
		if err != nil {
			return fmt.Errorf("failed to load config: %w", err)
		}

		ctx := cliConfig.GetCurrentContext()

		// Strict mode protection
		if ctx.Strict && !force {
			isDangerous := true
			// List of safe (read-only) command paths
			safeCommandPaths := map[string]bool{
				"iket-cli gateway status": true,
				"iket-cli service list":   true,
				"iket-cli route list":     true,
				"iket-cli plugin list":    true,
				"iket-cli context list":   true,
				"iket-cli cert status":    true,
			}

			cmdPath := cmd.CommandPath()

			// Special handling for 'gateway config' (safe if no args)
			if cmdPath == "iket-cli gateway config" && len(args) == 0 {
				isDangerous = false
			} else if safeCommandPaths[cmdPath] {
				isDangerous = false
			}

			if isDangerous {
				fmt.Printf("⚠️  STRICT MODE ENABLED for context %q\n", cliConfig.CurrentContext)
				fmt.Printf("You are about to execute: %s %s\n", cmdPath, strings.Join(args, " "))
				fmt.Print("Are you sure you want to proceed? (y/N): ")
				var confirm string
				fmt.Scanln(&confirm)
				if strings.ToLower(confirm) != "y" {
					return fmt.Errorf("operation cancelled")
				}
			}
		}

		apiClient, err = NewAPIClient(
			ctx.ServerURL,
			ctx.SkipVerify,
			ctx.CAFile,
			ctx.CertFile,
			ctx.KeyFile,
		)
		if err != nil {
			return fmt.Errorf("failed to initialize API client: %w", err)
		}

		return nil
	},
}

func main() {
	rootCmd.PersistentFlags().BoolVarP(&force, "force", "f", false, "Force execution without confirmation")
	rootCmd.PersistentFlags().BoolVar(&dryRun, "dry-run", false, "Simulate the command without making changes")

	initCertCmd(rootCmd)
	initContextCmd(rootCmd)
	initSetupCmd(rootCmd)
	initPushCmd(rootCmd)
	initPullCmd(rootCmd)
	initGatewayCmd(rootCmd)
	initServiceCmd(rootCmd)
	initRouteCmd(rootCmd)
	initPluginCmd(rootCmd)
	initClientCmd(rootCmd)

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func initGatewayCmd(rootCmd *cobra.Command) {
	gatewayCmd := &cobra.Command{
		Use:   "gateway",
		Short: "Gateway management",
	}

	gatewayCmd.AddCommand(&cobra.Command{
		Use:   "status",
		Short: "Get gateway status",
		RunE: func(cmd *cobra.Command, args []string) error {
			resp, err := apiClient.Do("GET", "/api/v1/gateway/status", nil)
			if err != nil {
				return err
			}
			fmt.Println(string(resp))
			return nil
		},
	})

	gatewayCmd.AddCommand(&cobra.Command{
		Use:   "config",
		Short: "Get/Set gateway config",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				resp, err := apiClient.Do("GET", "/api/v1/gateway/config", nil)
				if err != nil {
					return err
				}
				fmt.Println(string(resp))
				return nil
			}

			// Set config from file
			data, err := os.ReadFile(args[0])
			if err != nil {
				return err
			}
			var cfg map[string]interface{}
			if err := json.Unmarshal(data, &cfg); err != nil {
				return err
			}

			path := "/api/v1/gateway/config"
			if dryRun {
				path += "?dry_run=true"
			}
			resp, err := apiClient.Do("PUT", path, cfg)
			if err != nil {
				return err
			}
			fmt.Println(string(resp))
			return nil
		},
	})

	gatewayCmd.AddCommand(&cobra.Command{
		Use:   "reload",
		Short: "Reload gateway",
		RunE: func(cmd *cobra.Command, args []string) error {
			resp, err := apiClient.Do("POST", "/api/v1/gateway/reload", nil)
			if err != nil {
				return err
			}
			fmt.Println(string(resp))
			return nil
		},
	})

	rootCmd.AddCommand(gatewayCmd)
}

func initServiceCmd(rootCmd *cobra.Command) {
	serviceCmd := &cobra.Command{
		Use:   "service",
		Short: "Service management",
	}

	serviceCmd.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List services",
		RunE: func(cmd *cobra.Command, args []string) error {
			resp, err := apiClient.Do("GET", "/api/v1/services", nil)
			if err != nil {
				return err
			}
			fmt.Println(string(resp))
			return nil
		},
	})

	// Add Wizard-based Create and Set
	initServiceWizard(serviceCmd)
	initServiceSet(serviceCmd)

	serviceCmd.AddCommand(&cobra.Command{
		Use:   "delete [name]",
		Short: "Delete a service",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			resp, err := apiClient.Do("DELETE", "/api/v1/services/"+args[0], nil)
			if err != nil {
				return err
			}
			fmt.Println(string(resp))
			return nil
		},
	})

	rootCmd.AddCommand(serviceCmd)
}

func initRouteCmd(rootCmd *cobra.Command) {
	routeCmd := &cobra.Command{
		Use:   "route",
		Short: "Route management",
	}

	routeCmd.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List routes",
		RunE: func(cmd *cobra.Command, args []string) error {
			resp, err := apiClient.Do("GET", "/api/v1/routes", nil)
			if err != nil {
				return err
			}
			fmt.Println(string(resp))
			return nil
		},
	})

	// Add Targeted Set capability
	initRouteSet(routeCmd)

	routeCmd.AddCommand(&cobra.Command{
		Use:   "enable [id]",
		Short: "Enable a route",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			resp, err := apiClient.Do("POST", "/api/v1/routes/"+args[0]+"/enable", nil)
			if err != nil {
				return err
			}
			fmt.Println(string(resp))
			return nil
		},
	})

	routeCmd.AddCommand(&cobra.Command{
		Use:   "disable [id]",
		Short: "Disable a route",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			resp, err := apiClient.Do("POST", "/api/v1/routes/"+args[0]+"/disable", nil)
			if err != nil {
				return err
			}
			fmt.Println(string(resp))
			return nil
		},
	})

	rootCmd.AddCommand(routeCmd)
}

func initPluginCmd(rootCmd *cobra.Command) {
	pluginCmd := &cobra.Command{
		Use:   "plugin",
		Short: "Plugin management",
	}

	pluginCmd.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List plugins",
		RunE: func(cmd *cobra.Command, args []string) error {
			resp, err := apiClient.Do("GET", "/api/v1/plugins", nil)
			if err != nil {
				return err
			}
			fmt.Println(string(resp))
			return nil
		},
	})

	pluginCmd.AddCommand(&cobra.Command{
		Use:   "enable [name]",
		Short: "Enable a plugin",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			resp, err := apiClient.Do("POST", "/api/v1/plugins/"+args[0]+"/enable", nil)
			if err != nil {
				return err
			}
			fmt.Println(string(resp))
			return nil
		},
	})

	pluginCmd.AddCommand(&cobra.Command{
		Use:   "disable [name]",
		Short: "Disable a plugin",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			resp, err := apiClient.Do("POST", "/api/v1/plugins/"+args[0]+"/disable", nil)
			if err != nil {
				return err
			}
			fmt.Println(string(resp))
			return nil
		},
	})

	rootCmd.AddCommand(pluginCmd)
}

func initClientCmd(rootCmd *cobra.Command) {
	clientCmd := &cobra.Command{
		Use:   "client",
		Short: "Client app management (API Keys)",
	}

	clientCmd.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List client apps",
		RunE: func(cmd *cobra.Command, args []string) error {
			resp, err := apiClient.Do("GET", "/api/v1/clients", nil)
			if err != nil {
				return err
			}
			fmt.Println(string(resp))
			return nil
		},
	})

	var (
		clientName   string
		clientKey    string
		clientGroup  string
		clientScopes []string
		clientTags   []string
	)

	addCmd := &cobra.Command{
		Use:   "add [id]",
		Short: "Add a client app",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id := args[0]
			payload := map[string]interface{}{
				"id":     id,
				"name":   clientName,
				"key":    clientKey,
				"group":  clientGroup,
				"scopes": clientScopes,
				"tags":   clientTags,
			}
			resp, err := apiClient.Do("POST", "/api/v1/clients", payload)
			if err != nil {
				return err
			}
			fmt.Println(string(resp))
			return nil
		},
	}
	addCmd.Flags().StringVar(&clientName, "name", "", "Display name of the client")
	addCmd.Flags().StringVar(&clientKey, "key", "", "API Key for the client")
	addCmd.Flags().StringVar(&clientGroup, "group", "", "Group for the client")
	addCmd.Flags().StringSliceVar(&clientScopes, "scopes", []string{}, "Scopes for the client (comma separated)")
	addCmd.Flags().StringSliceVar(&clientTags, "tags", []string{}, "Tags for the client (comma separated)")
	addCmd.MarkFlagRequired("key")

	clientCmd.AddCommand(addCmd)

	clientCmd.AddCommand(&cobra.Command{
		Use:   "delete [key]",
		Short: "Delete a client app by key",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			resp, err := apiClient.Do("DELETE", "/api/v1/clients/"+args[0], nil)
			if err != nil {
				return err
			}
			fmt.Println(string(resp))
			return nil
		},
	})

	rootCmd.AddCommand(clientCmd)
}
