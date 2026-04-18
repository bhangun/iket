package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	apiClient *APIClient
	config    *CLIConfig
)

var rootCmd = &cobra.Command{
	Use:   "iket-cli",
	Short: "Iket Gateway management CLI",
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		if cmd.Name() == "cert" || cmd.Name() == "gen" {
			return nil
		}

		var err error
		config, err = loadCLIConfig()
		if err != nil {
			return fmt.Errorf("failed to load config: %w", err)
		}

		apiClient, err = NewAPIClient(
			config.ServerURL,
			config.SkipVerify,
			config.CAFile,
			config.CertFile,
			config.KeyFile,
		)
		if err != nil {
			return fmt.Errorf("failed to initialize API client: %w", err)
		}

		return nil
	},
}

func main() {
	initCertCmd(rootCmd)
	initGatewayCmd(rootCmd)
	initServiceCmd(rootCmd)
	initRouteCmd(rootCmd)
	initPluginCmd(rootCmd)

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

			resp, err := apiClient.Do("PUT", "/api/v1/gateway/config", cfg)
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

	serviceCmd.AddCommand(&cobra.Command{
		Use:   "create [file]",
		Short: "Create a service",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := os.ReadFile(args[0])
			if err != nil {
				return err
			}
			var svc map[string]interface{}
			if err := json.Unmarshal(data, &svc); err != nil {
				return err
			}
			resp, err := apiClient.Do("POST", "/api/v1/services", svc)
			if err != nil {
				return err
			}
			fmt.Println(string(resp))
			return nil
		},
	})

	serviceCmd.AddCommand(&cobra.Command{
		Use:   "update [name] [file]",
		Short: "Update a service",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := os.ReadFile(args[1])
			if err != nil {
				return err
			}
			var svc map[string]interface{}
			if err := json.Unmarshal(data, &svc); err != nil {
				return err
			}
			resp, err := apiClient.Do("PUT", "/api/v1/services/"+args[0], svc)
			if err != nil {
				return err
			}
			fmt.Println(string(resp))
			return nil
		},
	})

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
