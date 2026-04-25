package main

import (
	"net/url"

	"github.com/spf13/cobra"
)

func initAdminCoverageCmds(rootCmd *cobra.Command) {
	initGatewayAdminCmds(rootCmd)
	initPluginAdminCmds(rootCmd)
	initRouteAdminCmds(rootCmd)
	initCertRemoteCmds(rootCmd)
	initBackupCmd(rootCmd)
}

func initGatewayAdminCmds(rootCmd *cobra.Command) {
	gatewayCmd, _, err := rootCmd.Find([]string{"gateway"})
	if err != nil || gatewayCmd == nil {
		return
	}

	gatewayCmd.AddCommand(&cobra.Command{
		Use:   "metrics",
		Short: "Get gateway metrics snapshot",
		RunE: func(cmd *cobra.Command, args []string) error {
			resp, err := apiClient.Do("GET", "/api/v1/gateway/metrics", nil)
			if err != nil {
				return err
			}
			printResponse(resp)
			return nil
		},
	})

	gatewayCmd.AddCommand(&cobra.Command{
		Use:   "system",
		Short: "Get system metrics snapshot",
		RunE: func(cmd *cobra.Command, args []string) error {
			resp, err := apiClient.Do("GET", "/api/v1/metrics/system", nil)
			if err != nil {
				return err
			}
			printResponse(resp)
			return nil
		},
	})
}

func initPluginAdminCmds(rootCmd *cobra.Command) {
	pluginCmd, _, err := rootCmd.Find([]string{"plugin"})
	if err != nil || pluginCmd == nil {
		return
	}

	pluginCmd.AddCommand(&cobra.Command{
		Use:   "get [name]",
		Short: "Get plugin details",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			resp, err := apiClient.Do("GET", "/api/v1/plugins/"+url.PathEscape(args[0]), nil)
			if err != nil {
				return err
			}
			printResponse(resp)
			return nil
		},
	})

	pluginCmd.AddCommand(&cobra.Command{
		Use:   "status [name]",
		Short: "Get plugin status",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			resp, err := apiClient.Do("GET", "/api/v1/plugins/"+url.PathEscape(args[0])+"/status", nil)
			if err != nil {
				return err
			}
			printResponse(resp)
			return nil
		},
	})

	pluginCmd.AddCommand(&cobra.Command{
		Use:   "health [name]",
		Short: "Get plugin health",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			resp, err := apiClient.Do("GET", "/api/v1/plugins/"+url.PathEscape(args[0])+"/health", nil)
			if err != nil {
				return err
			}
			printResponse(resp)
			return nil
		},
	})

	configSetCmd := &cobra.Command{
		Use:   "set-config [name] [file]",
		Short: "Update plugin config from a file",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			payload, err := loadStructuredFile(args[1])
			if err != nil {
				return err
			}
			resp, err := apiClient.Do("PUT", "/api/v1/plugins/"+url.PathEscape(args[0])+"/config", payload)
			if err != nil {
				return err
			}
			printResponse(resp)
			return nil
		},
	}
	pluginCmd.AddCommand(configSetCmd)
}

func initRouteAdminCmds(rootCmd *cobra.Command) {
	routeCmd, _, err := rootCmd.Find([]string{"route"})
	if err != nil || routeCmd == nil {
		return
	}

	routeCmd.AddCommand(&cobra.Command{
		Use:   "get [id]",
		Short: "Get route details",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			resp, err := apiClient.Do("GET", "/api/v1/routes/"+url.PathEscape(args[0]), nil)
			if err != nil {
				return err
			}
			printResponse(resp)
			return nil
		},
	})

	createCmd := &cobra.Command{
		Use:   "create [file]",
		Short: "Create a route from a file",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			payload, err := loadStructuredFile(args[0])
			if err != nil {
				return err
			}
			resp, err := apiClient.Do("POST", "/api/v1/routes", payload)
			if err != nil {
				return err
			}
			printResponse(resp)
			return nil
		},
	}
	routeCmd.AddCommand(createCmd)

	updateCmd := &cobra.Command{
		Use:   "update [id] [file]",
		Short: "Update a route from a file",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			payload, err := loadStructuredFile(args[1])
			if err != nil {
				return err
			}
			resp, err := apiClient.Do("PUT", "/api/v1/routes/"+url.PathEscape(args[0]), payload)
			if err != nil {
				return err
			}
			printResponse(resp)
			return nil
		},
	}
	routeCmd.AddCommand(updateCmd)

	routeCmd.AddCommand(&cobra.Command{
		Use:   "delete [id]",
		Short: "Delete a route",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			resp, err := apiClient.Do("DELETE", "/api/v1/routes/"+url.PathEscape(args[0]), nil)
			if err != nil {
				return err
			}
			printResponse(resp)
			return nil
		},
	})
}

func initCertRemoteCmds(rootCmd *cobra.Command) {
	certCmd, _, err := rootCmd.Find([]string{"cert"})
	if err != nil || certCmd == nil {
		return
	}

	certCmd.AddCommand(&cobra.Command{
		Use:   "list-remote",
		Short: "List certificates on the remote gateway",
		RunE: func(cmd *cobra.Command, args []string) error {
			resp, err := apiClient.Do("GET", "/api/v1/certificates", nil)
			if err != nil {
				return err
			}
			printResponse(resp)
			return nil
		},
	})

	uploadCmd := &cobra.Command{
		Use:   "upload [file]",
		Short: "Upload certificate metadata or payload to the remote gateway",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			payload, err := loadStructuredFile(args[0])
			if err != nil {
				return err
			}
			resp, err := apiClient.Do("POST", "/api/v1/certificates", payload)
			if err != nil {
				return err
			}
			printResponse(resp)
			return nil
		},
	}
	certCmd.AddCommand(uploadCmd)

	certCmd.AddCommand(&cobra.Command{
		Use:   "delete-remote [id]",
		Short: "Delete a remote certificate",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			resp, err := apiClient.Do("DELETE", "/api/v1/certificates/"+url.PathEscape(args[0]), nil)
			if err != nil {
				return err
			}
			printResponse(resp)
			return nil
		},
	})
}

func initBackupCmd(rootCmd *cobra.Command) {
	backupCmd := &cobra.Command{
		Use:   "backup",
		Short: "Backup and restore gateway state",
	}

	backupCmd.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List remote backups",
		RunE: func(cmd *cobra.Command, args []string) error {
			resp, err := apiClient.Do("GET", "/api/v1/backup", nil)
			if err != nil {
				return err
			}
			printResponse(resp)
			return nil
		},
	})

	backupCmd.AddCommand(&cobra.Command{
		Use:   "create",
		Short: "Create a remote backup",
		RunE: func(cmd *cobra.Command, args []string) error {
			resp, err := apiClient.Do("POST", "/api/v1/backup", nil)
			if err != nil {
				return err
			}
			printResponse(resp)
			return nil
		},
	})

	backupCmd.AddCommand(&cobra.Command{
		Use:   "restore [id]",
		Short: "Restore a remote backup",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			resp, err := apiClient.Do("POST", "/api/v1/backup/"+url.PathEscape(args[0])+"/restore", nil)
			if err != nil {
				return err
			}
			printResponse(resp)
			return nil
		},
	})

	rootCmd.AddCommand(backupCmd)
}
