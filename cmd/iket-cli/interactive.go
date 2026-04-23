package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/bhangun/iket/pkg/config"
	"github.com/spf13/cobra"
)

func initServiceWizard(serviceCmd *cobra.Command) {
	var interactive bool

	createCmd := &cobra.Command{
		Use:   "create [file]",
		Short: "Create a service (interactive wizard or from file)",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !interactive {
				if len(args) == 0 {
					return fmt.Errorf("file path required or use --interactive")
				}
				// Existing logic for file-based create
				data, err := os.ReadFile(args[0])
				if err != nil {
					return err
				}
				var svc map[string]interface{}
				if err := json.Unmarshal(data, &svc); err != nil {
					return err
				}
				path := "/api/v1/services"
				if dryRun {
					path += "?dry_run=true"
				}
				resp, err := apiClient.Do("POST", path, svc)
				if err != nil {
					return err
				}
				fmt.Println(string(resp))
				return nil
			}

			// Wizard Logic
			reader := bufio.NewReader(os.Stdin)
			fmt.Println("🌟 Iket Service Creation Wizard")
			fmt.Println("-------------------------------")

			svc := config.Service{}
			fmt.Print("Service Name (e.g., Inventory API): ")
			svc.Name, _ = reader.ReadString('\n')
			svc.Name = strings.TrimSpace(svc.Name)

			fmt.Print("Backend Host (e.g., http://localhost:8081): ")
			svc.Host, _ = reader.ReadString('\n')
			svc.Host = strings.TrimSpace(svc.Host)

			fmt.Print("Base Path (e.g., /inventory) [optional]: ")
			svc.BasePath, _ = reader.ReadString('\n')
			svc.BasePath = strings.TrimSpace(svc.BasePath)

			// Route loop
			for {
				fmt.Printf("\n--- Adding Route for %s ---\n", svc.Name)
				route := config.RouterConfig{Enabled: true}
				
				fmt.Print("Route Path (e.g., /products): ")
				route.Path, _ = reader.ReadString('\n')
				route.Path = strings.TrimSpace(route.Path)
				if route.Path == "" {
					break
				}

				fmt.Print("Methods (comma separated, e.g., GET,POST) [GET]: ")
				methodsStr, _ := reader.ReadString('\n')
				methodsStr = strings.TrimSpace(methodsStr)
				if methodsStr == "" {
					route.Methods = []string{"GET"}
				} else {
					route.Methods = strings.Split(strings.ToUpper(methodsStr), ",")
				}

				fmt.Print("Require Authentication? (y/n) [n]: ")
				auth, _ := reader.ReadString('\n')
				route.RequireAuth = strings.ToLower(strings.TrimSpace(auth)) == "y"

				svc.Routes = append(svc.Routes, route)

				fmt.Print("\nAdd another route? (y/n) [n]: ")
				another, _ := reader.ReadString('\n')
				if strings.ToLower(strings.TrimSpace(another)) != "y" {
					break
				}
			}

			// Summary & Push
			fmt.Println("\n--- Service Summary ---")
			summary, _ := json.MarshalIndent(map[string]interface{}{"services": []config.Service{svc}}, "", "  ")
			fmt.Println(string(summary))

			fmt.Print("\nPush this service to remote gateway? (y/n) [y]: ")
			confirm, _ := reader.ReadString('\n')
			if strings.ToLower(strings.TrimSpace(confirm)) == "n" {
				fmt.Println("Operation cancelled. You can copy the JSON above to a file.")
				return nil
			}

			path := "/api/v1/services?strategy=merge"
			if dryRun {
				path += "&dry_run=true"
			}
			resp, err := apiClient.Do("POST", path, map[string]interface{}{"services": []config.Service{svc}})
			if err != nil {
				return err
			}

			var pretty bytes.Buffer
			json.Indent(&pretty, resp, "", "  ")
			fmt.Println("\n🚀 Response from Gateway:")
			fmt.Println(pretty.String())

			return nil
		},
	}

	createCmd.Flags().BoolVarP(&interactive, "interactive", "i", false, "Start interactive wizard")
	serviceCmd.AddCommand(createCmd)
}

func initServiceSet(serviceCmd *cobra.Command) {
	var (
		host     string
		desc     string
		basePath string
		group    string
		scopes   []string
	)

	setCmd := &cobra.Command{
		Use:   "set [name]",
		Short: "Update service attributes by name",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			
			// 1. Fetch current services
			resp, err := apiClient.Do("GET", "/api/v1/services", nil)
			if err != nil {
				return err
			}

			var data struct {
				Services []config.Service `json:"services"`
			}
			if err := json.Unmarshal(resp, &data); err != nil {
				return err
			}

			// 2. Find and update
			var target *config.Service
			for i := range data.Services {
				if data.Services[i].Name == name {
					target = &data.Services[i]
					break
				}
			}

			if target == nil {
				return fmt.Errorf("service %q not found", name)
			}

			if host != "" {
				target.Host = host
			}
			if desc != "" {
				target.Description = desc
			}
			if basePath != "" {
				target.BasePath = basePath
			}
			if group != "" {
				target.Group = group
			}
			if len(scopes) > 0 {
				target.Scopes = scopes
			}

			// 3. Push back
			path := "/api/v1/services/" + name
			if dryRun {
				path += "?dry_run=true"
			}
			pushResp, err := apiClient.Do("PUT", path, target)
			if err != nil {
				return err
			}
			fmt.Println(string(pushResp))
			return nil
		},
	}

	setCmd.Flags().StringVar(&host, "host", "", "New backend host")
	setCmd.Flags().StringVar(&desc, "desc", "", "New description")
	setCmd.Flags().StringVar(&basePath, "base-path", "", "New base path")
	setCmd.Flags().StringVar(&group, "group", "", "New service group")
	setCmd.Flags().StringSliceVar(&scopes, "scopes", []string{}, "New required scopes (comma separated)")

	serviceCmd.AddCommand(setCmd)
}

func initRouteSet(routeCmd *cobra.Command) {
	var (
		auth    string
		enabled string
		scopes  []string
	)

	setCmd := &cobra.Command{
		Use:   "set [service_name] [path] [method]",
		Short: "Update route attributes by path and method",
		Args:  cobra.ExactArgs(3),
		RunE: func(cmd *cobra.Command, args []string) error {
			svcName := args[0]
			path := args[1]
			method := strings.ToUpper(args[2])

			// 1. Fetch current services
			resp, err := apiClient.Do("GET", "/api/v1/services", nil)
			if err != nil {
				return err
			}

			var data struct {
				Services []config.Service `json:"services"`
			}
			if err := json.Unmarshal(resp, &data); err != nil {
				return err
			}

			var targetSvc *config.Service
			for i := range data.Services {
				if data.Services[i].Name == svcName {
					targetSvc = &data.Services[i]
					break
				}
			}

			if targetSvc == nil {
				return fmt.Errorf("service %q not found", svcName)
			}

			var targetRoute *config.RouterConfig
			for i := range targetSvc.Routes {
				r := &targetSvc.Routes[i]
				match := false
				if r.Path == path {
					if r.Method == method {
						match = true
					} else {
						for _, m := range r.Methods {
							if strings.ToUpper(m) == method {
								match = true
								break
							}
						}
					}
				}
				if match {
					targetRoute = r
					break
				}
			}

			if targetRoute == nil {
				return fmt.Errorf("route %s %q not found in service %q", method, path, svcName)
			}

			// 3. Update attributes
			if auth != "" {
				targetRoute.RequireAuth = strings.ToLower(auth) == "true" || strings.ToLower(auth) == "y"
			}
			if enabled != "" {
				targetRoute.Enabled = strings.ToLower(enabled) == "true" || strings.ToLower(enabled) == "y"
			}
			if len(scopes) > 0 {
				targetRoute.Scopes = scopes
			}

			// 4. Push whole service update
			apiPath := "/api/v1/services/" + svcName
			if dryRun {
				apiPath += "?dry_run=true"
			}
			pushResp, err := apiClient.Do("PUT", apiPath, targetSvc)
			if err != nil {
				return err
			}
			fmt.Println(string(pushResp))
			return nil
		},
	}

	setCmd.Flags().StringVar(&auth, "auth", "", "Require authentication (true/false)")
	setCmd.Flags().StringVar(&enabled, "enabled", "", "Enable or disable the route (true/false)")
	setCmd.Flags().StringSliceVar(&scopes, "scopes", []string{}, "Required scopes (comma separated)")

	routeCmd.AddCommand(setCmd)
}

