package main

import (
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

var (
	apiClient     *APIClient
	cliConfig     *CLIConfig
	force         bool
	dryRun        bool
	revisionLabel string
	revisionNote  string
	changeRef     string
)

var rootCmd = &cobra.Command{
	Use:     "iket",
	Aliases: []string{"iket-cli"},
	Short:   "Iket Gateway management CLI",
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		topLevel := topLevelCommandName(cmd)
		if topLevel == "cert" || topLevel == "setup" || topLevel == "context" || topLevel == "enroll" || topLevel == "server" || topLevel == "docker" || topLevel == "simulate" || topLevel == "test" {
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
			cmdPath := cmd.CommandPath()
			isDangerous := isDangerousCommandPath(cmdPath, args)

			if isDangerous {
				requireLabel, requireNote, requireChangeRef := strictRevisionMetadataRequirements(cmd, args)
				if requireLabel && strings.TrimSpace(revisionLabel) == "" {
					return fmt.Errorf("strict mode requires --label for mutating commands like %q", cmdPath)
				}
				if requireNote && strings.TrimSpace(revisionNote) == "" {
					return fmt.Errorf("strict mode requires --note for high-impact commands like %q", cmdPath)
				}
				if requireChangeRef && strings.TrimSpace(changeRef) == "" {
					return fmt.Errorf("strict mode requires --change-ref for high-impact commands like %q", cmdPath)
				}
				fmt.Printf("⚠️  STRICT MODE ENABLED for context %q\n", cliConfig.CurrentContext)
				fmt.Printf("You are about to execute: %s %s\n", cmdPath, strings.Join(args, " "))
				if strings.TrimSpace(revisionLabel) != "" {
					fmt.Printf("Revision label: %s\n", strings.TrimSpace(revisionLabel))
				}
				if strings.TrimSpace(revisionNote) != "" {
					fmt.Printf("Revision note: %s\n", strings.TrimSpace(revisionNote))
				}
				if strings.TrimSpace(changeRef) != "" {
					fmt.Printf("Change reference: %s\n", strings.TrimSpace(changeRef))
				}
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

func topLevelCommandName(cmd *cobra.Command) string {
	for cmd.Parent() != nil && cmd.Parent().Parent() != nil {
		cmd = cmd.Parent()
	}
	return cmd.Name()
}

func isDangerousCommandPath(cmdPath string, args []string) bool {
	safeCommandPaths := map[string]bool{
		"iket gateway status":           true,
		"iket gateway self-test":        true,
		"iket gateway metrics":          true,
		"iket gateway system":           true,
		"iket gateway backends":         true,
		"iket gateway policy-hits":      true,
		"iket gateway policy-alerts":    true,
		"iket gateway shadow-report":    true,
		"iket gateway shadow-evaluate":  true,
		"iket simulate":                 true,
		"iket test":                     true,
		"iket service list":             true,
		"iket route list":               true,
		"iket route get":                true,
		"iket logs tail":                true,
		"iket logs list":                true,
		"iket logs trace":               true,
		"iket plugin list":              true,
		"iket plugin get":               true,
		"iket plugin status":            true,
		"iket plugin health":            true,
		"iket plugin diff-config":       true,
		"iket context list":             true,
		"iket context test":             true,
		"iket cert status":              true,
		"iket cert list-remote":         true,
		"iket backup list":              true,
		"iket revision list":            true,
		"iket revision show":            true,
		"iket revision diff":            true,
		"iket notification deliveries":  true,
		"iket notification show":        true,
		"iket proposal list":            true,
		"iket proposal queue":           true,
		"iket proposal show":            true,
		"iket proposal readiness":       true,
		"iket proposal verify":          true,
		"iket proposal canary status":   true,
		"iket proposal canary evaluate": true,
		"iket config diff":              true,
		"iket service diff":             true,
		"iket route diff-create":        true,
		"iket route diff-update":        true,
	}

	if cmdPath == "iket gateway config" && len(args) == 0 {
		return false
	}
	return !safeCommandPaths[cmdPath]
}

func strictRevisionMetadataRequirements(cmd *cobra.Command, args []string) (requireLabel bool, requireNote bool, requireChangeRef bool) {
	if cmd == nil || dryRun {
		return false, false, false
	}
	cmdPath := cmd.CommandPath()
	if !isDangerousCommandPath(cmdPath, args) {
		return false, false, false
	}

	requireLabel = true
	highImpact := map[string]bool{
		"iket service delete":   true,
		"iket route delete":     true,
		"iket route disable":    true,
		"iket plugin disable":   true,
		"iket client delete":    true,
		"iket backup restore":   true,
		"iket revision restore": true,
	}
	if highImpact[cmdPath] {
		return true, true, true
	}

	switch cmdPath {
	case "iket proposal approve", "iket proposal apply", "iket proposal reject", "iket proposal canary advance", "iket proposal canary reconcile", "iket proposal canary expand", "iket proposal canary complete":
		return false, false, false
	case "iket config apply", "iket service apply":
		replace, _ := cmd.Flags().GetBool("replace")
		return true, replace, replace
	case "iket config propose", "iket service propose":
		replace, _ := cmd.Flags().GetBool("replace")
		return true, replace, replace
	case "iket push config", "iket push services":
		strategy, _ := cmd.Flags().GetString("strategy")
		replace := strings.EqualFold(strings.TrimSpace(strategy), "replace")
		return true, replace, replace
	case "iket gateway config":
		return len(args) > 0, len(args) > 0, len(args) > 0
	default:
		return true, false, false
	}
}

func main() {
	rootCmd.PersistentFlags().BoolVarP(&force, "force", "f", false, "Force execution without confirmation")
	rootCmd.PersistentFlags().BoolVar(&dryRun, "dry-run", false, "Simulate the command without making changes")
	rootCmd.PersistentFlags().StringVar(&revisionLabel, "label", "", "Attach a short label to recorded configuration revisions for mutating commands")
	rootCmd.PersistentFlags().StringVar(&revisionNote, "note", "", "Attach a human note to recorded configuration revisions for mutating commands")
	rootCmd.PersistentFlags().StringVar(&changeRef, "change-ref", "", "Attach a change ticket, rollout ID, or external reference to recorded configuration revisions")

	initCertCmd(rootCmd)
	initContextCmd(rootCmd)
	initSetupCmd(rootCmd)
	initEnrollCmd(rootCmd)
	initServerCmd(rootCmd)
	initConfigApplyCmd(rootCmd)
	initPushCmd(rootCmd)
	initPullCmd(rootCmd)
	initGatewayCmd(rootCmd)
	initServiceCmd(rootCmd)
	initRouteCmd(rootCmd)
	initPluginCmd(rootCmd)
	initClientCmd(rootCmd)
	initLogsCmd(rootCmd)
	initSimulateCmd(rootCmd)
	initAdminCoverageCmds(rootCmd)

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
			printResponse(resp)
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
				printResponse(resp)
				return nil
			}

			// Set config from file
			cfg, err := loadStructuredFile(args[0])
			if err != nil {
				return err
			}

			path := appendMutationOptions("/api/v1/gateway/config", dryRun)
			resp, err := apiClient.Do("PUT", path, cfg)
			if err != nil {
				return err
			}
			printResponse(resp)
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
			printResponse(resp)
			return nil
		},
	})

	var (
		selfTestPath   string
		selfTestMethod string
	)
	selfTestCmd := &cobra.Command{
		Use:   "self-test",
		Short: "Run config self-test for a sample request",
		RunE: func(cmd *cobra.Command, args []string) error {
			apiPath := fmt.Sprintf("/api/v1/gateway/config/self-test?path=%s&method=%s", url.QueryEscape(selfTestPath), url.QueryEscape(strings.ToUpper(selfTestMethod)))
			resp, err := apiClient.Do("GET", apiPath, nil)
			if err != nil {
				return err
			}
			printResponse(resp)
			return nil
		},
	}
	selfTestCmd.Flags().StringVar(&selfTestPath, "path", "/example", "Sample request path")
	selfTestCmd.Flags().StringVar(&selfTestMethod, "method", "GET", "Sample request method")
	gatewayCmd.AddCommand(selfTestCmd)

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
			printResponse(resp)
			return nil
		},
	})

	// Add Wizard-based Create and Set
	initServiceWizard(serviceCmd)
	initServiceSet(serviceCmd)

	var (
		applyReplace        bool
		applyMerge          bool
		proposeReplace      bool
		proposeMerge        bool
		proposer            string
		environment         string
		notBefore           string
		canaryServices      []string
		canaryRoutes        []string
		canaryHeaders       []string
		canaryPercent       int
		canarySteps         []int
		canaryMinRequests   int
		canaryMaxErrorRate  float64
		canaryMaxP95Latency string
		canaryAuto          bool
		canaryAutoInterval  string
		canaryAutoReviewer  string
		diffReplace         bool
		diffMerge           bool
	)
	applyCmd := &cobra.Command{
		Use:   "apply [file]",
		Short: "Apply services from a file to the remote gateway",
		Long:  "Apply a full service definition file to the remote gateway. Use --replace to replace the entire remote services set, or --merge to merge into the current state.",
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
			return runPush(args[0], "/api/v1/services", strategy)
		},
	}
	applyCmd.Flags().BoolVar(&applyReplace, "replace", false, "Replace the entire remote services set with the file contents")
	applyCmd.Flags().BoolVar(&applyMerge, "merge", false, "Merge the file contents into the current remote services set")
	serviceCmd.AddCommand(applyCmd)

	proposeCmd := &cobra.Command{
		Use:   "propose [file]",
		Short: "Create a pending service proposal from a file",
		Long:  "Create a pending proposal instead of applying a service definition file immediately. Use --replace to propose replacing the entire remote services set, or --merge to propose a merge into the current state.",
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
			return runPushWithMode(args[0], "/api/v1/services", strategy, false, true, proposer, environment, notBefore, canaryServices, canaryRoutes, canaryHeaders, canaryPercent, canarySteps, canaryMinRequests, canaryMaxErrorRate, canaryMaxP95Latency, canaryAuto, canaryAutoInterval, canaryAutoReviewer)
		},
	}
	proposeCmd.Flags().BoolVar(&proposeReplace, "replace", false, "Create a proposal for replacing the entire remote services set")
	proposeCmd.Flags().BoolVar(&proposeMerge, "merge", false, "Create a proposal for merging into the current remote services set")
	proposeCmd.Flags().StringVar(&proposer, "proposer", "", "Identity to record as the proposal creator")
	proposeCmd.Flags().StringVar(&environment, "env", "", "Environment name to record on the proposal, such as staging or prod")
	proposeCmd.Flags().StringVar(&notBefore, "not-before", "", "Do not allow proposal apply before this RFC3339 timestamp")
	proposeCmd.Flags().StringSliceVar(&canaryServices, "canary-service", nil, "Optional service names to apply first during canary rollout")
	proposeCmd.Flags().StringSliceVar(&canaryRoutes, "canary-route", nil, "Optional route selectors to apply first during canary rollout, for example identity:/auth/{rest:.*}")
	proposeCmd.Flags().StringSliceVar(&canaryHeaders, "canary-header", nil, "Optional header matchers to activate canary routes, for example X-Iket-Canary=identity-v2")
	proposeCmd.Flags().IntVar(&canaryPercent, "canary-percent", 0, "Optional percentage of traffic to shift to canary routes, between 1 and 99")
	proposeCmd.Flags().IntSliceVar(&canarySteps, "canary-step", nil, "Optional canary progression steps, for example --canary-step 10 --canary-step 25 --canary-step 50 --canary-step 100")
	proposeCmd.Flags().IntVar(&canaryMinRequests, "canary-min-requests", 0, "Optional minimum observed canary requests required before completing the canary")
	proposeCmd.Flags().Float64Var(&canaryMaxErrorRate, "canary-max-error-rate", 0, "Optional maximum 5xx error rate allowed for the canary, between 0 and 1")
	proposeCmd.Flags().StringVar(&canaryMaxP95Latency, "canary-max-p95-latency", "", "Optional maximum p95 latency allowed for the canary, for example 500ms or 2s")
	proposeCmd.Flags().BoolVar(&canaryAuto, "canary-auto", false, "Automatically reconcile active canary rollout steps in the background")
	proposeCmd.Flags().StringVar(&canaryAutoInterval, "canary-auto-interval", "", "Optional interval for automatic canary reconcile, for example 30s or 5m")
	proposeCmd.Flags().StringVar(&canaryAutoReviewer, "canary-auto-reviewer", "", "Reviewer identity to record for automatic canary reconcile actions")
	serviceCmd.AddCommand(proposeCmd)

	diffCmd := &cobra.Command{
		Use:   "diff [file]",
		Short: "Preview service changes without applying them",
		Long:  "Preview how a service definition file would change the remote gateway. Use --replace to preview a full remote service replacement, or --merge to preview a merge into the current state.",
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
			return runPushWithOptions(args[0], "/api/v1/services", strategy, true)
		},
	}
	diffCmd.Flags().BoolVar(&diffReplace, "replace", false, "Preview replacing the entire remote services set with the file contents")
	diffCmd.Flags().BoolVar(&diffMerge, "merge", false, "Preview merging the file contents into the current remote services set")
	serviceCmd.AddCommand(diffCmd)

	serviceCmd.AddCommand(&cobra.Command{
		Use:   "delete [name]",
		Short: "Delete a service",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			resp, err := apiClient.Do("DELETE", appendMutationOptions("/api/v1/services/"+args[0], false), nil)
			if err != nil {
				return err
			}
			printResponse(resp)
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
			printResponse(resp)
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
			resp, err := apiClient.Do("POST", appendMutationOptions("/api/v1/routes/"+args[0]+"/enable", false), nil)
			if err != nil {
				return err
			}
			printResponse(resp)
			return nil
		},
	})

	routeCmd.AddCommand(&cobra.Command{
		Use:   "disable [id]",
		Short: "Disable a route",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			resp, err := apiClient.Do("POST", appendMutationOptions("/api/v1/routes/"+args[0]+"/disable", false), nil)
			if err != nil {
				return err
			}
			printResponse(resp)
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
			printResponse(resp)
			return nil
		},
	})

	pluginCmd.AddCommand(&cobra.Command{
		Use:   "enable [name]",
		Short: "Enable a plugin",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			resp, err := apiClient.Do("POST", appendMutationOptions("/api/v1/plugins/"+args[0]+"/enable", false), nil)
			if err != nil {
				return err
			}
			printResponse(resp)
			return nil
		},
	})

	pluginCmd.AddCommand(&cobra.Command{
		Use:   "disable [name]",
		Short: "Disable a plugin",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			resp, err := apiClient.Do("POST", appendMutationOptions("/api/v1/plugins/"+args[0]+"/disable", false), nil)
			if err != nil {
				return err
			}
			printResponse(resp)
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
			printResponse(resp)
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
			resp, err := apiClient.Do("POST", appendMutationOptions("/api/v1/clients", false), payload)
			if err != nil {
				return err
			}
			printResponse(resp)
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
			resp, err := apiClient.Do("DELETE", appendMutationOptions("/api/v1/clients/"+args[0], false), nil)
			if err != nil {
				return err
			}
			printResponse(resp)
			return nil
		},
	})

	rootCmd.AddCommand(clientCmd)
}
