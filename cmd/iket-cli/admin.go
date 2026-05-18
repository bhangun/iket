package main

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

var gatewayPolicyHitsWindow string
var gatewayLimitHitsWindow string
var gatewayLimitBucketsWindow string
var gatewayLimitBucketsMinCount int
var gatewayLimitClassesWindow string
var gatewayLimitClassesMinCount int
var gatewayLimitClassAlertsWindow string
var gatewayLimitClassAlertsMinCount int
var gatewayLimitAlertsWindow string
var gatewayLimitAlertsMinCount int
var gatewayPolicyAlertsWindow string
var gatewayPolicyAlertsMinCount int
var gatewayRoutePolicyPath string
var gatewayRoutePolicyMethod string
var gatewayRoutePolicyHeaders []string
var gatewayRoutePolicyBucketKey string
var gatewayRoutePolicyDiffFromPath string
var gatewayRoutePolicyDiffFromMethod string
var gatewayRoutePolicyDiffFromHeaders []string
var gatewayRoutePolicyDiffFromBucketKey string
var gatewayRoutePolicyDiffToPath string
var gatewayRoutePolicyDiffToMethod string
var gatewayRoutePolicyDiffToHeaders []string
var gatewayRoutePolicyDiffToBucketKey string

func initAdminCoverageCmds(rootCmd *cobra.Command) {
	initGatewayAdminCmds(rootCmd)
	initPluginAdminCmds(rootCmd)
	initRouteAdminCmds(rootCmd)
	initCertRemoteCmds(rootCmd)
	initBackupCmd(rootCmd)
	initRevisionCmd(rootCmd)
	initProposalCmd(rootCmd)
	initNotificationCmd(rootCmd)
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

	gatewayCmd.AddCommand(&cobra.Command{
		Use:   "backends",
		Short: "Get backend health and failover state",
		RunE: func(cmd *cobra.Command, args []string) error {
			resp, err := apiClient.Do("GET", "/api/v1/gateway/backends", nil)
			if err != nil {
				return err
			}
			printResponse(resp)
			return nil
		},
	})

	routePolicyCmd := &cobra.Command{
		Use:   "route-policy",
		Short: "Inspect the resolved AI guardrails and preset stack for a matched route",
		RunE: func(cmd *cobra.Command, args []string) error {
			if strings.TrimSpace(gatewayRoutePolicyPath) == "" {
				return fmt.Errorf("--path is required")
			}
			values := url.Values{}
			values.Set("path", strings.TrimSpace(gatewayRoutePolicyPath))
			if strings.TrimSpace(gatewayRoutePolicyMethod) != "" {
				values.Set("method", strings.ToUpper(strings.TrimSpace(gatewayRoutePolicyMethod)))
			}
			if strings.TrimSpace(gatewayRoutePolicyBucketKey) != "" {
				values.Set("bucket_key", strings.TrimSpace(gatewayRoutePolicyBucketKey))
			}
			for _, header := range gatewayRoutePolicyHeaders {
				if strings.TrimSpace(header) != "" {
					values.Add("header", strings.TrimSpace(header))
				}
			}
			path := "/api/v1/gateway/route-policy?" + values.Encode()
			resp, err := apiClient.Do("GET", path, nil)
			if err != nil {
				return err
			}
			printResponse(resp)
			return nil
		},
	}
	routePolicyCmd.Flags().StringVar(&gatewayRoutePolicyPath, "path", "", "Route path to inspect")
	routePolicyCmd.Flags().StringVar(&gatewayRoutePolicyMethod, "method", "GET", "HTTP method to match")
	routePolicyCmd.Flags().StringSliceVar(&gatewayRoutePolicyHeaders, "header", nil, "Optional route-match header in Name:Value format; repeat as needed")
	routePolicyCmd.Flags().StringVar(&gatewayRoutePolicyBucketKey, "bucket-key", "inspect", "Optional rollout bucket key for percent-gated routes")
	gatewayCmd.AddCommand(routePolicyCmd)

	routePolicyDiffCmd := &cobra.Command{
		Use:   "route-policy-diff",
		Short: "Compare the resolved AI guardrails for two matched routes",
		RunE: func(cmd *cobra.Command, args []string) error {
			if strings.TrimSpace(gatewayRoutePolicyDiffFromPath) == "" || strings.TrimSpace(gatewayRoutePolicyDiffToPath) == "" {
				return fmt.Errorf("--from-path and --to-path are required")
			}
			values := url.Values{}
			values.Set("from_path", strings.TrimSpace(gatewayRoutePolicyDiffFromPath))
			values.Set("to_path", strings.TrimSpace(gatewayRoutePolicyDiffToPath))
			values.Set("from_method", strings.ToUpper(strings.TrimSpace(gatewayRoutePolicyDiffFromMethod)))
			values.Set("to_method", strings.ToUpper(strings.TrimSpace(gatewayRoutePolicyDiffToMethod)))
			if strings.TrimSpace(gatewayRoutePolicyDiffFromBucketKey) != "" {
				values.Set("from_bucket_key", strings.TrimSpace(gatewayRoutePolicyDiffFromBucketKey))
			}
			if strings.TrimSpace(gatewayRoutePolicyDiffToBucketKey) != "" {
				values.Set("to_bucket_key", strings.TrimSpace(gatewayRoutePolicyDiffToBucketKey))
			}
			for _, header := range gatewayRoutePolicyDiffFromHeaders {
				if strings.TrimSpace(header) != "" {
					values.Add("from_header", strings.TrimSpace(header))
				}
			}
			for _, header := range gatewayRoutePolicyDiffToHeaders {
				if strings.TrimSpace(header) != "" {
					values.Add("to_header", strings.TrimSpace(header))
				}
			}
			path := "/api/v1/gateway/route-policy/diff?" + values.Encode()
			resp, err := apiClient.Do("GET", path, nil)
			if err != nil {
				return err
			}
			printResponse(resp)
			return nil
		},
	}
	routePolicyDiffCmd.Flags().StringVar(&gatewayRoutePolicyDiffFromPath, "from-path", "", "First route path to inspect")
	routePolicyDiffCmd.Flags().StringVar(&gatewayRoutePolicyDiffFromMethod, "from-method", "GET", "First route HTTP method")
	routePolicyDiffCmd.Flags().StringSliceVar(&gatewayRoutePolicyDiffFromHeaders, "from-header", nil, "Optional first route-match header in Name:Value format; repeat as needed")
	routePolicyDiffCmd.Flags().StringVar(&gatewayRoutePolicyDiffFromBucketKey, "from-bucket-key", "inspect", "Optional first rollout bucket key for percent-gated routes")
	routePolicyDiffCmd.Flags().StringVar(&gatewayRoutePolicyDiffToPath, "to-path", "", "Second route path to inspect")
	routePolicyDiffCmd.Flags().StringVar(&gatewayRoutePolicyDiffToMethod, "to-method", "GET", "Second route HTTP method")
	routePolicyDiffCmd.Flags().StringSliceVar(&gatewayRoutePolicyDiffToHeaders, "to-header", nil, "Optional second route-match header in Name:Value format; repeat as needed")
	routePolicyDiffCmd.Flags().StringVar(&gatewayRoutePolicyDiffToBucketKey, "to-bucket-key", "inspect", "Optional second rollout bucket key for percent-gated routes")
	gatewayCmd.AddCommand(routePolicyDiffCmd)

	gatewayCmd.AddCommand(&cobra.Command{
		Use:   "limit-hits",
		Short: "Get route rate/concurrency limiter hit counters by type and route",
		RunE: func(cmd *cobra.Command, args []string) error {
			path := "/api/v1/gateway/limit-hits"
			if strings.TrimSpace(gatewayLimitHitsWindow) != "" {
				path += "?window=" + url.QueryEscape(strings.TrimSpace(gatewayLimitHitsWindow))
			}
			resp, err := apiClient.Do("GET", path, nil)
			if err != nil {
				return err
			}
			printResponse(resp)
			return nil
		},
	})
	gatewayCmd.Commands()[len(gatewayCmd.Commands())-1].Flags().StringVar(&gatewayLimitHitsWindow, "window", "5m", "Recent window to summarize, such as 5m or 1h")

	gatewayCmd.AddCommand(&cobra.Command{
		Use:   "limit-buckets",
		Short: "Show recent limiter pressure grouped by anonymized bucket",
		RunE: func(cmd *cobra.Command, args []string) error {
			values := url.Values{}
			if strings.TrimSpace(gatewayLimitBucketsWindow) != "" {
				values.Set("window", strings.TrimSpace(gatewayLimitBucketsWindow))
			}
			if gatewayLimitBucketsMinCount > 0 {
				values.Set("min_count", fmt.Sprintf("%d", gatewayLimitBucketsMinCount))
			}
			path := "/api/v1/gateway/limit-buckets"
			if encoded := values.Encode(); encoded != "" {
				path += "?" + encoded
			}
			resp, err := apiClient.Do("GET", path, nil)
			if err != nil {
				return err
			}
			printResponse(resp)
			return nil
		},
	})
	gatewayCmd.Commands()[len(gatewayCmd.Commands())-1].Flags().StringVar(&gatewayLimitBucketsWindow, "window", "5m", "Recent window to summarize, such as 5m or 1h")
	gatewayCmd.Commands()[len(gatewayCmd.Commands())-1].Flags().IntVar(&gatewayLimitBucketsMinCount, "min-count", 1, "Minimum limiter hits in the window before a bucket appears")

	gatewayCmd.AddCommand(&cobra.Command{
		Use:   "limit-classes",
		Short: "Show recent limiter pressure grouped by named bucket class",
		RunE: func(cmd *cobra.Command, args []string) error {
			values := url.Values{}
			if strings.TrimSpace(gatewayLimitClassesWindow) != "" {
				values.Set("window", strings.TrimSpace(gatewayLimitClassesWindow))
			}
			if gatewayLimitClassesMinCount > 0 {
				values.Set("min_count", fmt.Sprintf("%d", gatewayLimitClassesMinCount))
			}
			path := "/api/v1/gateway/limit-classes"
			if encoded := values.Encode(); encoded != "" {
				path += "?" + encoded
			}
			resp, err := apiClient.Do("GET", path, nil)
			if err != nil {
				return err
			}
			printResponse(resp)
			return nil
		},
	})
	gatewayCmd.Commands()[len(gatewayCmd.Commands())-1].Flags().StringVar(&gatewayLimitClassesWindow, "window", "5m", "Recent window to summarize, such as 5m or 1h")
	gatewayCmd.Commands()[len(gatewayCmd.Commands())-1].Flags().IntVar(&gatewayLimitClassesMinCount, "min-count", 1, "Minimum limiter hits in the window before a class appears")

	gatewayCmd.AddCommand(&cobra.Command{
		Use:   "limit-class-alerts",
		Short: "Detect recent limiter saturation spikes grouped by named bucket class",
		RunE: func(cmd *cobra.Command, args []string) error {
			values := url.Values{}
			if strings.TrimSpace(gatewayLimitClassAlertsWindow) != "" {
				values.Set("window", strings.TrimSpace(gatewayLimitClassAlertsWindow))
			}
			if gatewayLimitClassAlertsMinCount > 0 {
				values.Set("min_count", fmt.Sprintf("%d", gatewayLimitClassAlertsMinCount))
			}
			path := "/api/v1/gateway/limit-class-alerts"
			if encoded := values.Encode(); encoded != "" {
				path += "?" + encoded
			}
			resp, err := apiClient.Do("GET", path, nil)
			if err != nil {
				return err
			}
			printResponse(resp)
			return nil
		},
	})
	gatewayCmd.Commands()[len(gatewayCmd.Commands())-1].Flags().StringVar(&gatewayLimitClassAlertsWindow, "window", "5m", "Recent window to summarize, such as 5m or 1h")
	gatewayCmd.Commands()[len(gatewayCmd.Commands())-1].Flags().IntVar(&gatewayLimitClassAlertsMinCount, "min-count", 3, "Minimum limiter hits in the window before a class alert appears")

	gatewayCmd.AddCommand(&cobra.Command{
		Use:   "limit-class-incidents",
		Short: "Show currently open limiter incidents grouped by named bucket class",
		RunE: func(cmd *cobra.Command, args []string) error {
			resp, err := apiClient.Do("GET", "/api/v1/gateway/limit-class-incidents", nil)
			if err != nil {
				return err
			}
			printResponse(resp)
			return nil
		},
	})

	gatewayCmd.AddCommand(&cobra.Command{
		Use:   "notify-limit-class-alerts",
		Short: "Emit gateway limiter class alert notifications through configured webhooks",
		RunE: func(cmd *cobra.Command, args []string) error {
			values := url.Values{}
			if strings.TrimSpace(gatewayLimitClassAlertsWindow) != "" {
				values.Set("window", strings.TrimSpace(gatewayLimitClassAlertsWindow))
			}
			if gatewayLimitClassAlertsMinCount > 0 {
				values.Set("min_count", fmt.Sprintf("%d", gatewayLimitClassAlertsMinCount))
			}
			path := "/api/v1/gateway/limit-class-alerts/notify"
			if encoded := values.Encode(); encoded != "" {
				path += "?" + encoded
			}
			resp, err := apiClient.Do("POST", path, nil)
			if err != nil {
				return err
			}
			printResponse(resp)
			return nil
		},
	})

	gatewayCmd.AddCommand(&cobra.Command{
		Use:   "limit-alerts",
		Short: "Detect recent limiter saturation spikes by route and limiter type",
		RunE: func(cmd *cobra.Command, args []string) error {
			values := url.Values{}
			if strings.TrimSpace(gatewayLimitAlertsWindow) != "" {
				values.Set("window", strings.TrimSpace(gatewayLimitAlertsWindow))
			}
			if gatewayLimitAlertsMinCount > 0 {
				values.Set("min_count", fmt.Sprintf("%d", gatewayLimitAlertsMinCount))
			}
			path := "/api/v1/gateway/limit-alerts"
			if encoded := values.Encode(); encoded != "" {
				path += "?" + encoded
			}
			resp, err := apiClient.Do("GET", path, nil)
			if err != nil {
				return err
			}
			printResponse(resp)
			return nil
		},
	})
	gatewayCmd.Commands()[len(gatewayCmd.Commands())-1].Flags().StringVar(&gatewayLimitAlertsWindow, "window", "5m", "Recent window to evaluate, such as 5m or 1h")
	gatewayCmd.Commands()[len(gatewayCmd.Commands())-1].Flags().IntVar(&gatewayLimitAlertsMinCount, "min-count", 3, "Minimum limiter hits in the window before a route/type becomes an alert")

	gatewayCmd.AddCommand(&cobra.Command{
		Use:   "notify-limit-alerts",
		Short: "Emit gateway limiter alert notifications through configured webhooks",
		RunE: func(cmd *cobra.Command, args []string) error {
			values := url.Values{}
			if strings.TrimSpace(gatewayLimitAlertsWindow) != "" {
				values.Set("window", strings.TrimSpace(gatewayLimitAlertsWindow))
			}
			if gatewayLimitAlertsMinCount > 0 {
				values.Set("min_count", fmt.Sprintf("%d", gatewayLimitAlertsMinCount))
			}
			path := "/api/v1/gateway/limit-alerts/notify"
			if encoded := values.Encode(); encoded != "" {
				path += "?" + encoded
			}
			resp, err := apiClient.Do("POST", path, nil)
			if err != nil {
				return err
			}
			printResponse(resp)
			return nil
		},
	})
	gatewayCmd.Commands()[len(gatewayCmd.Commands())-1].Flags().StringVar(&gatewayLimitAlertsWindow, "window", "5m", "Recent window to evaluate, such as 5m or 1h")
	gatewayCmd.Commands()[len(gatewayCmd.Commands())-1].Flags().IntVar(&gatewayLimitAlertsMinCount, "min-count", 3, "Minimum limiter hits in the window before a route/type becomes an alert")

	gatewayCmd.AddCommand(&cobra.Command{
		Use:   "policy-hits",
		Short: "Get gateway policy-hit counters by reason and route",
		RunE: func(cmd *cobra.Command, args []string) error {
			path := "/api/v1/gateway/policy-hits"
			if strings.TrimSpace(gatewayPolicyHitsWindow) != "" {
				path += "?window=" + url.QueryEscape(strings.TrimSpace(gatewayPolicyHitsWindow))
			}
			resp, err := apiClient.Do("GET", path, nil)
			if err != nil {
				return err
			}
			printResponse(resp)
			return nil
		},
	})
	gatewayCmd.Commands()[len(gatewayCmd.Commands())-1].Flags().StringVar(&gatewayPolicyHitsWindow, "window", "5m", "Recent window to summarize, such as 5m or 1h")

	gatewayCmd.AddCommand(&cobra.Command{
		Use:   "policy-alerts",
		Short: "Detect recent policy-hit spikes by route and reason",
		RunE: func(cmd *cobra.Command, args []string) error {
			values := url.Values{}
			if strings.TrimSpace(gatewayPolicyAlertsWindow) != "" {
				values.Set("window", strings.TrimSpace(gatewayPolicyAlertsWindow))
			}
			if gatewayPolicyAlertsMinCount > 0 {
				values.Set("min_count", fmt.Sprintf("%d", gatewayPolicyAlertsMinCount))
			}
			path := "/api/v1/gateway/policy-alerts"
			if encoded := values.Encode(); encoded != "" {
				path += "?" + encoded
			}
			resp, err := apiClient.Do("GET", path, nil)
			if err != nil {
				return err
			}
			printResponse(resp)
			return nil
		},
	})
	gatewayCmd.Commands()[len(gatewayCmd.Commands())-1].Flags().StringVar(&gatewayPolicyAlertsWindow, "window", "5m", "Recent window to evaluate, such as 5m or 1h")
	gatewayCmd.Commands()[len(gatewayCmd.Commands())-1].Flags().IntVar(&gatewayPolicyAlertsMinCount, "min-count", 3, "Minimum hits in the window before a route/reason becomes an alert")

	gatewayCmd.AddCommand(&cobra.Command{
		Use:   "notify-policy-alerts",
		Short: "Emit gateway policy alert notifications through configured webhooks",
		RunE: func(cmd *cobra.Command, args []string) error {
			values := url.Values{}
			if strings.TrimSpace(gatewayPolicyAlertsWindow) != "" {
				values.Set("window", strings.TrimSpace(gatewayPolicyAlertsWindow))
			}
			if gatewayPolicyAlertsMinCount > 0 {
				values.Set("min_count", fmt.Sprintf("%d", gatewayPolicyAlertsMinCount))
			}
			path := "/api/v1/gateway/policy-alerts/notify"
			if encoded := values.Encode(); encoded != "" {
				path += "?" + encoded
			}
			resp, err := apiClient.Do("POST", path, nil)
			if err != nil {
				return err
			}
			printResponse(resp)
			return nil
		},
	})
	gatewayCmd.Commands()[len(gatewayCmd.Commands())-1].Flags().StringVar(&gatewayPolicyAlertsWindow, "window", "5m", "Recent window to evaluate, such as 5m or 1h")
	gatewayCmd.Commands()[len(gatewayCmd.Commands())-1].Flags().IntVar(&gatewayPolicyAlertsMinCount, "min-count", 3, "Minimum hits in the window before a route/reason becomes an alert")

	gatewayCmd.AddCommand(&cobra.Command{
		Use:   "shadow-report",
		Short: "Get aggregated live-vs-shadow route comparison data",
		RunE: func(cmd *cobra.Command, args []string) error {
			resp, err := apiClient.Do("GET", "/api/v1/gateway/shadow-report", nil)
			if err != nil {
				return err
			}
			printResponse(resp)
			return nil
		},
	})

	gatewayCmd.AddCommand(&cobra.Command{
		Use:   "shadow-evaluate",
		Short: "Evaluate shadow route health against configured thresholds",
		RunE: func(cmd *cobra.Command, args []string) error {
			resp, err := apiClient.Do("GET", "/api/v1/gateway/shadow-evaluate", nil)
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
			resp, err := apiClient.Do("PUT", appendMutationOptions("/api/v1/plugins/"+url.PathEscape(args[0])+"/config", dryRun), payload)
			if err != nil {
				return err
			}
			printResponse(resp)
			return nil
		},
	}
	pluginCmd.AddCommand(configSetCmd)

	pluginCmd.AddCommand(&cobra.Command{
		Use:   "diff-config [name] [file]",
		Short: "Preview plugin config changes from a file",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			payload, err := loadStructuredFile(args[1])
			if err != nil {
				return err
			}
			resp, err := apiClient.Do("PUT", appendMutationOptions("/api/v1/plugins/"+url.PathEscape(args[0])+"/config", true), payload)
			if err != nil {
				return err
			}
			printResponse(resp)
			return nil
		},
	})
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
			resp, err := apiClient.Do("POST", appendMutationOptions("/api/v1/routes", dryRun), payload)
			if err != nil {
				return err
			}
			printResponse(resp)
			return nil
		},
	}
	routeCmd.AddCommand(createCmd)

	routeCmd.AddCommand(&cobra.Command{
		Use:   "diff-create [file]",
		Short: "Preview creating a route from a file",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			payload, err := loadStructuredFile(args[0])
			if err != nil {
				return err
			}
			resp, err := apiClient.Do("POST", appendMutationOptions("/api/v1/routes", true), payload)
			if err != nil {
				return err
			}
			printResponse(resp)
			return nil
		},
	})

	updateCmd := &cobra.Command{
		Use:   "update [id] [file]",
		Short: "Update a route from a file",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			payload, err := loadStructuredFile(args[1])
			if err != nil {
				return err
			}
			resp, err := apiClient.Do("PUT", appendMutationOptions("/api/v1/routes/"+url.PathEscape(args[0]), dryRun), payload)
			if err != nil {
				return err
			}
			printResponse(resp)
			return nil
		},
	}
	routeCmd.AddCommand(updateCmd)

	routeCmd.AddCommand(&cobra.Command{
		Use:   "diff-update [id] [file]",
		Short: "Preview updating a route from a file",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			payload, err := loadStructuredFile(args[1])
			if err != nil {
				return err
			}
			resp, err := apiClient.Do("PUT", appendMutationOptions("/api/v1/routes/"+url.PathEscape(args[0]), true), payload)
			if err != nil {
				return err
			}
			printResponse(resp)
			return nil
		},
	})

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

func initRevisionCmd(rootCmd *cobra.Command) {
	revisionCmd := &cobra.Command{
		Use:   "revision",
		Short: "Configuration revision history and rollback",
	}

	revisionCmd.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List recorded remote configuration revisions",
		RunE: func(cmd *cobra.Command, args []string) error {
			resp, err := apiClient.Do("GET", "/api/v1/revisions", nil)
			if err != nil {
				return err
			}
			printResponse(resp)
			return nil
		},
	})

	revisionCmd.AddCommand(&cobra.Command{
		Use:   "show [id]",
		Short: "Show a recorded remote configuration revision",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			resp, err := apiClient.Do("GET", "/api/v1/revisions/"+url.PathEscape(args[0]), nil)
			if err != nil {
				return err
			}
			printResponse(resp)
			return nil
		},
	})

	revisionCmd.AddCommand(&cobra.Command{
		Use:   "diff [from] [to]",
		Short: "Compare two revisions or a revision against current",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := "/api/v1/revisions/diff?from=" + url.QueryEscape(args[0]) + "&to=" + url.QueryEscape(args[1])
			resp, err := apiClient.Do("GET", path, nil)
			if err != nil {
				return err
			}
			printResponse(resp)
			return nil
		},
	})

	revisionCmd.AddCommand(&cobra.Command{
		Use:   "restore [id]",
		Short: "Restore a recorded remote configuration revision",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			resp, err := apiClient.Do("POST", "/api/v1/revisions/"+url.PathEscape(args[0])+"/restore", nil)
			if err != nil {
				return err
			}
			printResponse(resp)
			return nil
		},
	})

	rootCmd.AddCommand(revisionCmd)
}

func initProposalCmd(rootCmd *cobra.Command) {
	var (
		proposalReviewer            string
		proposalReviewNote          string
		proposalProposer            string
		proposalEnv                 string
		proposalQueueStatus         string
		proposalQueueNextAction     string
		proposalQueueUrgency        string
		proposalBatchAction         string
		proposalBatchView           string
		proposalBatchOutput         string
		proposalQueueReadyOnly      bool
		proposalQueueBlockedOnly    bool
		proposalQueueLimit          int
		proposalNotBefore           string
		proposalCanaryServices      []string
		proposalCanaryRoutes        []string
		proposalCanaryHeaders       []string
		proposalCanaryPercent       int
		proposalCanarySteps         []int
		proposalCanaryMinRequests   int
		proposalCanaryMaxErrorRate  float64
		proposalCanaryMaxP95Latency string
		proposalCanaryAuto          bool
		proposalCanaryAutoInterval  string
		proposalCanaryAutoReviewer  string
	)

	proposalCmd := &cobra.Command{
		Use:   "proposal",
		Short: "Pending configuration proposals and approvals",
	}

	proposalCmd.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List pending and reviewed proposals",
		RunE: func(cmd *cobra.Command, args []string) error {
			resp, err := apiClient.Do("GET", "/api/v1/proposals", nil)
			if err != nil {
				return err
			}
			printResponse(resp)
			return nil
		},
	})

	queueCmd := &cobra.Command{
		Use:   "queue",
		Short: "Show proposals with readiness summaries and current blockers",
	}
	queueCmd.Flags().StringVar(&proposalEnv, "env", "", "Filter queue entries to one environment")
	queueCmd.Flags().StringVar(&proposalQueueStatus, "status", "", "Filter queue entries to one proposal status")
	queueCmd.Flags().StringVar(&proposalQueueNextAction, "next-action", "", "Filter queue entries to one next action such as apply, needs_approval, needs_schedule, or needs_verification")
	queueCmd.Flags().StringVar(&proposalQueueUrgency, "urgency", "", "Filter queue entries to one urgency level: fresh, aging, or overdue")
	queueCmd.Flags().BoolVar(&proposalQueueReadyOnly, "ready-only", false, "Only include proposals ready to apply")
	queueCmd.Flags().BoolVar(&proposalQueueBlockedOnly, "blocked-only", false, "Only include proposals that still have blockers")
	queueCmd.Flags().IntVar(&proposalQueueLimit, "limit", 0, "Limit the number of queue entries returned")
	queueCmd.RunE = func(cmd *cobra.Command, args []string) error {
		if proposalQueueReadyOnly && proposalQueueBlockedOnly {
			return fmt.Errorf("--ready-only and --blocked-only cannot be used together")
		}
		path := "/api/v1/proposals/queue"
		path = appendQueryParam(path, "environment", proposalEnv)
		path = appendQueryParam(path, "status", proposalQueueStatus)
		path = appendQueryParam(path, "next_action", proposalQueueNextAction)
		path = appendQueryParam(path, "urgency", proposalQueueUrgency)
		if proposalQueueReadyOnly {
			path = appendQueryParam(path, "ready", "true")
		}
		if proposalQueueBlockedOnly {
			path = appendQueryParam(path, "ready", "false")
		}
		if proposalQueueLimit > 0 {
			path = appendQueryParam(path, "limit", fmt.Sprintf("%d", proposalQueueLimit))
		}
		resp, err := apiClient.Do("GET", path, nil)
		if err != nil {
			return err
		}
		printResponse(resp)
		return nil
	}
	proposalCmd.AddCommand(queueCmd)

	digestCmd := &cobra.Command{
		Use:   "digest",
		Short: "Show a compact rollout digest from the proposal queue and blocked report",
		RunE: func(cmd *cobra.Command, args []string) error {
			digest, err := loadProposalQueueDigest(proposalEnv, proposalQueueStatus, proposalQueueNextAction, proposalQueueUrgency, proposalQueueReadyOnly, proposalQueueBlockedOnly, proposalQueueLimit)
			if err != nil {
				return err
			}
			printResponse(digest)
			return nil
		},
	}
	digestCmd.Flags().StringVar(&proposalEnv, "env", "", "Only include proposals in one environment")
	digestCmd.Flags().StringVar(&proposalQueueStatus, "status", "", "Only include proposals in one status")
	digestCmd.Flags().StringVar(&proposalQueueNextAction, "next-action", "", "Only include proposals with one next action such as apply, needs_approval, needs_schedule, or needs_verification")
	digestCmd.Flags().StringVar(&proposalQueueUrgency, "urgency", "", "Only include proposals with one urgency level: fresh, aging, or overdue")
	digestCmd.Flags().BoolVar(&proposalQueueReadyOnly, "ready-only", false, "Only include proposals ready to apply")
	digestCmd.Flags().BoolVar(&proposalQueueBlockedOnly, "blocked-only", false, "Only include proposals that still have blockers")
	digestCmd.Flags().IntVar(&proposalQueueLimit, "limit", 0, "Limit the number of queue entries used for the digest")
	proposalCmd.AddCommand(digestCmd)

	exportDigestCmd := &cobra.Command{
		Use:   "export-digest [file]",
		Short: "Export the compact rollout digest to a JSON or YAML file",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			digest, err := loadProposalQueueDigest(proposalEnv, proposalQueueStatus, proposalQueueNextAction, proposalQueueUrgency, proposalQueueReadyOnly, proposalQueueBlockedOnly, proposalQueueLimit)
			if err != nil {
				return err
			}
			if err := writeStructuredOutputFile(args[0], digest, "proposal digest"); err != nil {
				return err
			}
			fmt.Printf("Exported proposal digest to %s\n", args[0])
			return nil
		},
	}
	exportDigestCmd.Flags().StringVar(&proposalEnv, "env", "", "Only include proposals in one environment")
	exportDigestCmd.Flags().StringVar(&proposalQueueStatus, "status", "", "Only include proposals in one status")
	exportDigestCmd.Flags().StringVar(&proposalQueueNextAction, "next-action", "", "Only include proposals with one next action such as apply, needs_approval, needs_schedule, or needs_verification")
	exportDigestCmd.Flags().StringVar(&proposalQueueUrgency, "urgency", "", "Only include proposals with one urgency level: fresh, aging, or overdue")
	exportDigestCmd.Flags().BoolVar(&proposalQueueReadyOnly, "ready-only", false, "Only include proposals ready to apply")
	exportDigestCmd.Flags().BoolVar(&proposalQueueBlockedOnly, "blocked-only", false, "Only include proposals that still have blockers")
	exportDigestCmd.Flags().IntVar(&proposalQueueLimit, "limit", 0, "Limit the number of queue entries used for the digest")
	proposalCmd.AddCommand(exportDigestCmd)

	notifyDigestCmd := &cobra.Command{
		Use:   "notify-digest",
		Short: "Emit proposal queue digest notifications through configured webhooks",
		RunE: func(cmd *cobra.Command, args []string) error {
			path, err := buildProposalQueuePath(proposalEnv, proposalQueueStatus, proposalQueueNextAction, proposalQueueUrgency, proposalQueueReadyOnly, proposalQueueBlockedOnly, proposalQueueLimit)
			if err != nil {
				return err
			}
			path = strings.Replace(path, "/api/v1/proposals/queue", "/api/v1/proposals/queue/notify-digest", 1)
			resp, err := apiClient.Do("POST", path, nil)
			if err != nil {
				return err
			}
			printResponse(resp)
			return nil
		},
	}
	notifyDigestCmd.Flags().StringVar(&proposalEnv, "env", "", "Only include proposals in one environment")
	notifyDigestCmd.Flags().StringVar(&proposalQueueStatus, "status", "", "Only include proposals in one status")
	notifyDigestCmd.Flags().StringVar(&proposalQueueNextAction, "next-action", "", "Only include proposals with one next action such as apply, needs_approval, needs_schedule, or needs_verification")
	notifyDigestCmd.Flags().StringVar(&proposalQueueUrgency, "urgency", "", "Only include proposals with one urgency level: fresh, aging, or overdue")
	notifyDigestCmd.Flags().BoolVar(&proposalQueueReadyOnly, "ready-only", false, "Only include proposals ready to apply")
	notifyDigestCmd.Flags().BoolVar(&proposalQueueBlockedOnly, "blocked-only", false, "Only include proposals that still have blockers")
	notifyDigestCmd.Flags().IntVar(&proposalQueueLimit, "limit", 0, "Limit the number of queue entries used for the digest notification")
	proposalCmd.AddCommand(notifyDigestCmd)

	blockedReportCmd := &cobra.Command{
		Use:   "blocked-report",
		Short: "Summarize blocked proposals by blocker reason",
		RunE: func(cmd *cobra.Command, args []string) error {
			path := "/api/v1/proposals/queue/blocked-report"
			path = appendQueryParam(path, "environment", proposalEnv)
			path = appendQueryParam(path, "status", proposalQueueStatus)
			resp, err := apiClient.Do("GET", path, nil)
			if err != nil {
				return err
			}
			printResponse(resp)
			return nil
		},
	}
	blockedReportCmd.Flags().StringVar(&proposalEnv, "env", "", "Only include blocked proposals in one environment")
	blockedReportCmd.Flags().StringVar(&proposalQueueStatus, "status", "", "Only include blocked proposals in one status")
	proposalCmd.AddCommand(blockedReportCmd)

	exportQueueCmd := &cobra.Command{
		Use:   "export-queue [file]",
		Short: "Export the proposal queue to a JSON or YAML file",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if proposalQueueReadyOnly && proposalQueueBlockedOnly {
				return fmt.Errorf("--ready-only and --blocked-only cannot be used together")
			}
			path := "/api/v1/proposals/queue"
			path = appendQueryParam(path, "environment", proposalEnv)
			path = appendQueryParam(path, "status", proposalQueueStatus)
			path = appendQueryParam(path, "next_action", proposalQueueNextAction)
			path = appendQueryParam(path, "urgency", proposalQueueUrgency)
			if proposalQueueReadyOnly {
				path = appendQueryParam(path, "ready", "true")
			}
			if proposalQueueBlockedOnly {
				path = appendQueryParam(path, "ready", "false")
			}
			if proposalQueueLimit > 0 {
				path = appendQueryParam(path, "limit", fmt.Sprintf("%d", proposalQueueLimit))
			}
			resp, err := apiClient.Do("GET", path, nil)
			if err != nil {
				return err
			}
			if err := writeStructuredOutputFile(args[0], resp, "proposal queue"); err != nil {
				return err
			}
			fmt.Printf("Exported proposal queue to %s\n", args[0])
			return nil
		},
	}
	exportQueueCmd.Flags().StringVar(&proposalEnv, "env", "", "Only include queue entries in one environment")
	exportQueueCmd.Flags().StringVar(&proposalQueueStatus, "status", "", "Only include queue entries in one status")
	exportQueueCmd.Flags().StringVar(&proposalQueueNextAction, "next-action", "", "Only include queue entries with one next action such as apply, needs_approval, needs_schedule, or needs_verification")
	exportQueueCmd.Flags().StringVar(&proposalQueueUrgency, "urgency", "", "Only include queue entries with one urgency level: fresh, aging, or overdue")
	exportQueueCmd.Flags().BoolVar(&proposalQueueReadyOnly, "ready-only", false, "Only export proposals ready to apply")
	exportQueueCmd.Flags().BoolVar(&proposalQueueBlockedOnly, "blocked-only", false, "Only export proposals that still have blockers")
	exportQueueCmd.Flags().IntVar(&proposalQueueLimit, "limit", 0, "Limit the number of queue entries exported")
	proposalCmd.AddCommand(exportQueueCmd)

	exportBlockedCmd := &cobra.Command{
		Use:   "export-blocked [file]",
		Short: "Export the blocked proposal report to a JSON or YAML file",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := "/api/v1/proposals/queue/blocked-report"
			path = appendQueryParam(path, "environment", proposalEnv)
			path = appendQueryParam(path, "status", proposalQueueStatus)
			resp, err := apiClient.Do("GET", path, nil)
			if err != nil {
				return err
			}
			if err := writeStructuredOutputFile(args[0], resp, "blocked report"); err != nil {
				return err
			}
			fmt.Printf("Exported blocked proposal report to %s\n", args[0])
			return nil
		},
	}
	exportBlockedCmd.Flags().StringVar(&proposalEnv, "env", "", "Only include blocked proposals in one environment")
	exportBlockedCmd.Flags().StringVar(&proposalQueueStatus, "status", "", "Only include blocked proposals in one status")
	proposalCmd.AddCommand(exportBlockedCmd)

	approveReadyCmd := &cobra.Command{
		Use:   "approve-ready",
		Short: "Record approvals for approval-blocked proposals oldest-first",
		RunE: func(cmd *cobra.Command, args []string) error {
			path := appendMutationOptions("/api/v1/proposals/queue/approve-ready", dryRun)
			path = appendProposalReviewOptions(path, proposalReviewer, proposalReviewNote)
			path = appendQueryParam(path, "environment", proposalEnv)
			path = appendQueryParam(path, "status", proposalQueueStatus)
			path = appendQueryParam(path, "next_action", proposalQueueNextAction)
			path = appendQueryParam(path, "urgency", proposalQueueUrgency)
			if proposalQueueLimit > 0 {
				path = appendQueryParam(path, "limit", fmt.Sprintf("%d", proposalQueueLimit))
			}
			resp, err := apiClient.Do("POST", path, nil)
			if err != nil {
				return err
			}
			printResponse(resp)
			return nil
		},
	}
	approveReadyCmd.Flags().StringVar(&proposalReviewer, "reviewer", "", "Reviewer identity to record when batch-approving proposals")
	approveReadyCmd.Flags().StringVar(&proposalReviewNote, "review-note", "", "Reviewer note to record when batch-approving proposals")
	approveReadyCmd.Flags().StringVar(&proposalEnv, "env", "", "Only batch-approve proposals in one environment")
	approveReadyCmd.Flags().StringVar(&proposalQueueStatus, "status", "", "Only batch-approve proposals in one proposal status")
	approveReadyCmd.Flags().StringVar(&proposalQueueNextAction, "next-action", "", "Optional guard for the expected queue slice; only needs_approval is allowed here")
	approveReadyCmd.Flags().StringVar(&proposalQueueUrgency, "urgency", "", "Only batch-approve proposals in one urgency level: fresh, aging, or overdue")
	approveReadyCmd.Flags().IntVar(&proposalQueueLimit, "limit", 0, "Limit the number of proposals to approve")
	proposalCmd.AddCommand(approveReadyCmd)

	applyReadyCmd := &cobra.Command{
		Use:   "apply-ready",
		Short: "Apply ready proposals from the queue oldest-ready-first",
		RunE: func(cmd *cobra.Command, args []string) error {
			path := appendMutationOptions("/api/v1/proposals/queue/apply-ready", dryRun)
			path = appendProposalReviewOptions(path, proposalReviewer, proposalReviewNote)
			path = appendQueryParam(path, "environment", proposalEnv)
			path = appendQueryParam(path, "status", proposalQueueStatus)
			path = appendQueryParam(path, "next_action", proposalQueueNextAction)
			path = appendQueryParam(path, "urgency", proposalQueueUrgency)
			if proposalQueueLimit > 0 {
				path = appendQueryParam(path, "limit", fmt.Sprintf("%d", proposalQueueLimit))
			}
			resp, err := apiClient.Do("POST", path, nil)
			if err != nil {
				return err
			}
			printResponse(resp)
			return nil
		},
	}
	applyReadyCmd.Flags().StringVar(&proposalReviewer, "reviewer", "", "Reviewer identity to record when batch-applying ready proposals")
	applyReadyCmd.Flags().StringVar(&proposalReviewNote, "review-note", "", "Reviewer note to record when batch-applying ready proposals")
	applyReadyCmd.Flags().StringVar(&proposalEnv, "env", "", "Only batch-apply ready proposals in one environment")
	applyReadyCmd.Flags().StringVar(&proposalQueueStatus, "status", "", "Only batch-apply proposals in one proposal status")
	applyReadyCmd.Flags().StringVar(&proposalQueueNextAction, "next-action", "", "Optional guard for the expected queue slice; only apply is allowed here")
	applyReadyCmd.Flags().StringVar(&proposalQueueUrgency, "urgency", "", "Only batch-apply proposals in one urgency level: fresh, aging, or overdue")
	applyReadyCmd.Flags().IntVar(&proposalQueueLimit, "limit", 0, "Limit the number of ready proposals to apply")
	proposalCmd.AddCommand(applyReadyCmd)

	batchCmd := &cobra.Command{
		Use:   "batch",
		Short: "Preview and execute filtered proposal queue batches",
	}

	batchPreviewCmd := &cobra.Command{
		Use:   "preview",
		Short: "Preview a filtered batch action against the proposal queue",
		RunE: func(cmd *cobra.Command, args []string) error {
			path, err := buildProposalBatchMutationPath(true, proposalBatchAction, proposalReviewer, proposalReviewNote, proposalEnv, proposalQueueStatus, proposalQueueNextAction, proposalQueueUrgency, proposalQueueLimit)
			if err != nil {
				return err
			}
			resp, err := apiClient.Do("POST", path, nil)
			if err != nil {
				return err
			}
			printResponse(resp)
			return nil
		},
	}
	batchPreviewCmd.Flags().StringVar(&proposalBatchAction, "action", "", "Batch action to preview: approve or apply")
	batchPreviewCmd.Flags().StringVar(&proposalReviewer, "reviewer", "", "Optional reviewer identity to include in the preview request")
	batchPreviewCmd.Flags().StringVar(&proposalReviewNote, "review-note", "", "Optional reviewer note to include in the preview request")
	batchPreviewCmd.Flags().StringVar(&proposalEnv, "env", "", "Only include proposals in one environment")
	batchPreviewCmd.Flags().StringVar(&proposalQueueStatus, "status", "", "Only include proposals in one proposal status")
	batchPreviewCmd.Flags().StringVar(&proposalQueueNextAction, "next-action", "", "Optional guard for the expected queue slice")
	batchPreviewCmd.Flags().StringVar(&proposalQueueUrgency, "urgency", "", "Only include proposals in one urgency level: fresh, aging, or overdue")
	batchPreviewCmd.Flags().IntVar(&proposalQueueLimit, "limit", 0, "Limit the number of proposals in the batch preview")
	batchCmd.AddCommand(batchPreviewCmd)

	batchBlockedCmd := &cobra.Command{
		Use:   "blocked",
		Short: "Summarize blockers for the current filtered batch slice",
		RunE: func(cmd *cobra.Command, args []string) error {
			payload, label, err := loadProposalBatchView("blocked", proposalEnv, proposalQueueStatus, proposalQueueNextAction, proposalQueueUrgency, proposalQueueReadyOnly, proposalQueueBlockedOnly, proposalQueueLimit)
			if err != nil {
				return err
			}
			_ = label
			printResponse(payload)
			return nil
		},
	}
	batchBlockedCmd.Flags().StringVar(&proposalEnv, "env", "", "Only include proposals in one environment")
	batchBlockedCmd.Flags().StringVar(&proposalQueueStatus, "status", "", "Only include proposals in one proposal status")
	batchBlockedCmd.Flags().StringVar(&proposalQueueNextAction, "next-action", "", "Only include proposals in one next action such as apply, needs_approval, needs_schedule, or needs_verification")
	batchBlockedCmd.Flags().StringVar(&proposalQueueUrgency, "urgency", "", "Only include proposals in one urgency level: fresh, aging, or overdue")
	batchBlockedCmd.Flags().BoolVar(&proposalQueueReadyOnly, "ready-only", false, "Only include proposals ready to apply")
	batchBlockedCmd.Flags().BoolVar(&proposalQueueBlockedOnly, "blocked-only", false, "Only include proposals that still have blockers")
	batchBlockedCmd.Flags().IntVar(&proposalQueueLimit, "limit", 0, "Limit the number of proposals included in the blocked summary")
	batchCmd.AddCommand(batchBlockedCmd)

	batchExplainCmd := &cobra.Command{
		Use:   "explain",
		Short: "Explain the dominant blocker and next step for the current filtered batch slice",
		RunE: func(cmd *cobra.Command, args []string) error {
			payload, _, err := loadProposalBatchView("explain", proposalEnv, proposalQueueStatus, proposalQueueNextAction, proposalQueueUrgency, proposalQueueReadyOnly, proposalQueueBlockedOnly, proposalQueueLimit)
			if err != nil {
				return err
			}
			printResponse(payload)
			return nil
		},
	}
	batchExplainCmd.Flags().StringVar(&proposalEnv, "env", "", "Only include proposals in one environment")
	batchExplainCmd.Flags().StringVar(&proposalQueueStatus, "status", "", "Only include proposals in one proposal status")
	batchExplainCmd.Flags().StringVar(&proposalQueueNextAction, "next-action", "", "Only include proposals in one next action such as apply, needs_approval, needs_schedule, or needs_verification")
	batchExplainCmd.Flags().StringVar(&proposalQueueUrgency, "urgency", "", "Only include proposals in one urgency level: fresh, aging, or overdue")
	batchExplainCmd.Flags().BoolVar(&proposalQueueReadyOnly, "ready-only", false, "Only include proposals ready to apply")
	batchExplainCmd.Flags().BoolVar(&proposalQueueBlockedOnly, "blocked-only", false, "Only include proposals that still have blockers")
	batchExplainCmd.Flags().IntVar(&proposalQueueLimit, "limit", 0, "Limit the number of proposals included in the explanation")
	batchCmd.AddCommand(batchExplainCmd)

	batchExportCmd := &cobra.Command{
		Use:   "export [file]",
		Short: "Export a filtered batch queue or digest view to a JSON or YAML file",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			payload, label, err := loadProposalBatchView(proposalBatchView, proposalEnv, proposalQueueStatus, proposalQueueNextAction, proposalQueueUrgency, proposalQueueReadyOnly, proposalQueueBlockedOnly, proposalQueueLimit)
			if err != nil {
				return err
			}
			if err := writeStructuredOutputFile(args[0], payload, label); err != nil {
				return err
			}
			fmt.Printf("Exported %s to %s\n", label, args[0])
			return nil
		},
	}
	batchExportCmd.Flags().StringVar(&proposalBatchView, "view", "queue", "Batch view to export: queue, digest, blocked, or explain")
	batchExportCmd.Flags().StringVar(&proposalEnv, "env", "", "Only include proposals in one environment")
	batchExportCmd.Flags().StringVar(&proposalQueueStatus, "status", "", "Only include proposals in one proposal status")
	batchExportCmd.Flags().StringVar(&proposalQueueNextAction, "next-action", "", "Only include proposals in one next action such as apply, needs_approval, needs_schedule, or needs_verification")
	batchExportCmd.Flags().StringVar(&proposalQueueUrgency, "urgency", "", "Only include proposals in one urgency level: fresh, aging, or overdue")
	batchExportCmd.Flags().BoolVar(&proposalQueueReadyOnly, "ready-only", false, "Only include proposals ready to apply")
	batchExportCmd.Flags().BoolVar(&proposalQueueBlockedOnly, "blocked-only", false, "Only include proposals that still have blockers")
	batchExportCmd.Flags().IntVar(&proposalQueueLimit, "limit", 0, "Limit the number of proposals included in the export")
	batchCmd.AddCommand(batchExportCmd)

	batchApproveCmd := &cobra.Command{
		Use:   "approve",
		Short: "Approve a filtered batch of approval-blocked proposals",
		RunE: func(cmd *cobra.Command, args []string) error {
			path, err := buildProposalBatchMutationPath(dryRun, "approve", proposalReviewer, proposalReviewNote, proposalEnv, proposalQueueStatus, proposalQueueNextAction, proposalQueueUrgency, proposalQueueLimit)
			if err != nil {
				return err
			}
			resp, err := apiClient.Do("POST", path, nil)
			if err != nil {
				return err
			}
			printResponse(resp)
			return nil
		},
	}
	batchApproveCmd.Flags().StringVar(&proposalReviewer, "reviewer", "", "Reviewer identity to record when batch-approving proposals")
	batchApproveCmd.Flags().StringVar(&proposalReviewNote, "review-note", "", "Reviewer note to record when batch-approving proposals")
	batchApproveCmd.Flags().StringVar(&proposalEnv, "env", "", "Only batch-approve proposals in one environment")
	batchApproveCmd.Flags().StringVar(&proposalQueueStatus, "status", "", "Only batch-approve proposals in one proposal status")
	batchApproveCmd.Flags().StringVar(&proposalQueueNextAction, "next-action", "", "Optional guard for the expected queue slice; only needs_approval is allowed here")
	batchApproveCmd.Flags().StringVar(&proposalQueueUrgency, "urgency", "", "Only batch-approve proposals in one urgency level: fresh, aging, or overdue")
	batchApproveCmd.Flags().IntVar(&proposalQueueLimit, "limit", 0, "Limit the number of proposals to approve")
	batchCmd.AddCommand(batchApproveCmd)

	batchApplyCmd := &cobra.Command{
		Use:   "apply",
		Short: "Apply a filtered batch of ready proposals",
		RunE: func(cmd *cobra.Command, args []string) error {
			path, err := buildProposalBatchMutationPath(dryRun, "apply", proposalReviewer, proposalReviewNote, proposalEnv, proposalQueueStatus, proposalQueueNextAction, proposalQueueUrgency, proposalQueueLimit)
			if err != nil {
				return err
			}
			resp, err := apiClient.Do("POST", path, nil)
			if err != nil {
				return err
			}
			printResponse(resp)
			return nil
		},
	}
	batchApplyCmd.Flags().StringVar(&proposalReviewer, "reviewer", "", "Reviewer identity to record when batch-applying ready proposals")
	batchApplyCmd.Flags().StringVar(&proposalReviewNote, "review-note", "", "Reviewer note to record when batch-applying ready proposals")
	batchApplyCmd.Flags().StringVar(&proposalEnv, "env", "", "Only batch-apply ready proposals in one environment")
	batchApplyCmd.Flags().StringVar(&proposalQueueStatus, "status", "", "Only batch-apply proposals in one proposal status")
	batchApplyCmd.Flags().StringVar(&proposalQueueNextAction, "next-action", "", "Optional guard for the expected queue slice; only apply is allowed here")
	batchApplyCmd.Flags().StringVar(&proposalQueueUrgency, "urgency", "", "Only batch-apply proposals in one urgency level: fresh, aging, or overdue")
	batchApplyCmd.Flags().IntVar(&proposalQueueLimit, "limit", 0, "Limit the number of ready proposals to apply")
	batchCmd.AddCommand(batchApplyCmd)

	batchActCmd := &cobra.Command{
		Use:   "act",
		Short: "Run one batch action through a single shared selector-driven entrypoint",
		RunE: func(cmd *cobra.Command, args []string) error {
			return executeProposalBatchAction(
				proposalBatchAction,
				proposalBatchView,
				proposalBatchOutput,
				proposalReviewer,
				proposalReviewNote,
				proposalEnv,
				proposalQueueStatus,
				proposalQueueNextAction,
				proposalQueueUrgency,
				proposalQueueReadyOnly,
				proposalQueueBlockedOnly,
				proposalQueueLimit,
				dryRun,
			)
		},
	}
	batchActCmd.Flags().StringVar(&proposalBatchAction, "action", "", "Batch action to run: approve, apply, blocked, explain, or export")
	batchActCmd.Flags().StringVar(&proposalBatchView, "view", "queue", "Batch view used by export actions: queue, digest, blocked, or explain")
	batchActCmd.Flags().StringVar(&proposalBatchOutput, "output", "", "Output file path used by --action export")
	batchActCmd.Flags().StringVar(&proposalReviewer, "reviewer", "", "Reviewer identity to include for approve/apply actions")
	batchActCmd.Flags().StringVar(&proposalReviewNote, "review-note", "", "Reviewer note to include for approve/apply actions")
	batchActCmd.Flags().StringVar(&proposalEnv, "env", "", "Only include proposals in one environment")
	batchActCmd.Flags().StringVar(&proposalQueueStatus, "status", "", "Only include proposals in one proposal status")
	batchActCmd.Flags().StringVar(&proposalQueueNextAction, "next-action", "", "Only include proposals in one next action such as apply, needs_approval, needs_schedule, or needs_verification")
	batchActCmd.Flags().StringVar(&proposalQueueUrgency, "urgency", "", "Only include proposals in one urgency level: fresh, aging, or overdue")
	batchActCmd.Flags().BoolVar(&proposalQueueReadyOnly, "ready-only", false, "Only include proposals ready to apply")
	batchActCmd.Flags().BoolVar(&proposalQueueBlockedOnly, "blocked-only", false, "Only include proposals that still have blockers")
	batchActCmd.Flags().IntVar(&proposalQueueLimit, "limit", 0, "Limit the number of proposals included in the batch action")
	batchCmd.AddCommand(batchActCmd)

	proposalCmd.AddCommand(batchCmd)

	proposalCmd.AddCommand(&cobra.Command{
		Use:   "show [id]",
		Short: "Show a stored proposal",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			resp, err := apiClient.Do("GET", "/api/v1/proposals/"+url.PathEscape(args[0]), nil)
			if err != nil {
				return err
			}
			printResponse(resp)
			return nil
		},
	})

	proposalCmd.AddCommand(&cobra.Command{
		Use:   "verify [id]",
		Short: "Verify proposal integrity, source lineage, and live drift",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			resp, err := apiClient.Do("GET", "/api/v1/proposals/"+url.PathEscape(args[0])+"/verify", nil)
			if err != nil {
				return err
			}
			printResponse(resp)
			return nil
		},
	})

	proposalCmd.AddCommand(&cobra.Command{
		Use:   "readiness [id]",
		Short: "Explain whether a proposal is ready to apply and what blocks it",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			resp, err := apiClient.Do("GET", "/api/v1/proposals/"+url.PathEscape(args[0])+"/readiness", nil)
			if err != nil {
				return err
			}
			printResponse(resp)
			return nil
		},
	})

	proposalCmd.AddCommand(&cobra.Command{
		Use:   "explain-blocked [id]",
		Short: "Show a concise blocked diagnosis and next step for one proposal",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			resp, err := apiClient.Do("GET", "/api/v1/proposals/"+url.PathEscape(args[0])+"/explain-blocked", nil)
			if err != nil {
				return err
			}
			printResponse(resp)
			return nil
		},
	})

	canaryCmd := &cobra.Command{
		Use:   "canary",
		Short: "Inspect and progress canary proposal rollouts",
	}

	canaryCmd.AddCommand(&cobra.Command{
		Use:   "status [id]",
		Short: "Show current canary rollout status for a proposal",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			resp, err := apiClient.Do("GET", "/api/v1/proposals/"+url.PathEscape(args[0])+"/canary", nil)
			if err != nil {
				return err
			}
			printResponse(resp)
			return nil
		},
	})

	advanceCmd := &cobra.Command{
		Use:   "advance [id]",
		Short: "Advance an active percentage canary rollout to its next planned step",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := appendMutationOptions("/api/v1/proposals/"+url.PathEscape(args[0])+"/canary/advance", false)
			path = appendProposalReviewOptions(path, proposalReviewer, proposalReviewNote)
			resp, err := apiClient.Do("POST", path, nil)
			if err != nil {
				return err
			}
			printResponse(resp)
			return nil
		},
	}

	reconcileCmd := &cobra.Command{
		Use:   "reconcile [id]",
		Short: "Evaluate an active canary rollout and automatically advance, complete, or roll it back",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := appendMutationOptions("/api/v1/proposals/"+url.PathEscape(args[0])+"/canary/reconcile", false)
			path = appendProposalReviewOptions(path, proposalReviewer, proposalReviewNote)
			resp, err := apiClient.Do("POST", path, nil)
			if err != nil {
				return err
			}
			printResponse(resp)
			return nil
		},
	}

	canaryCmd.AddCommand(&cobra.Command{
		Use:   "evaluate [id]",
		Short: "Evaluate current canary rollout health against configured thresholds",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			resp, err := apiClient.Do("GET", "/api/v1/proposals/"+url.PathEscape(args[0])+"/canary/evaluate", nil)
			if err != nil {
				return err
			}
			printResponse(resp)
			return nil
		},
	})

	applyCmd := &cobra.Command{
		Use:   "apply [id]",
		Short: "Approve and apply a stored proposal",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := appendMutationOptions("/api/v1/proposals/"+url.PathEscape(args[0])+"/apply", false)
			path = appendProposalReviewOptions(path, proposalReviewer, proposalReviewNote)
			resp, err := apiClient.Do("POST", path, nil)
			if err != nil {
				return err
			}
			printResponse(resp)
			return nil
		},
	}

	expandCmd := &cobra.Command{
		Use:   "expand [id]",
		Short: "Expand a proposal canary plan or active canary rollout",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := appendMutationOptions("/api/v1/proposals/"+url.PathEscape(args[0])+"/canary/expand", false)
			path = appendProposalReviewOptions(path, proposalReviewer, proposalReviewNote)
			path = appendCanaryOptions(path, proposalCanaryServices, proposalCanaryRoutes)
			path = appendCanaryHeaderOptions(path, proposalCanaryHeaders)
			path = appendCanaryPercentOption(path, proposalCanaryPercent)
			path = appendCanaryStepOptions(path, proposalCanarySteps)
			path = appendCanaryGuardOptions(path, proposalCanaryMinRequests, proposalCanaryMaxErrorRate, proposalCanaryMaxP95Latency)
			path = appendCanaryAutoOptions(path, proposalCanaryAuto, proposalCanaryAutoInterval, proposalCanaryAutoReviewer)
			resp, err := apiClient.Do("POST", path, nil)
			if err != nil {
				return err
			}
			printResponse(resp)
			return nil
		},
	}

	completeCmd := &cobra.Command{
		Use:   "complete [id]",
		Short: "Complete an active proposal canary rollout and apply the full proposal",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := appendMutationOptions("/api/v1/proposals/"+url.PathEscape(args[0])+"/canary/complete", false)
			path = appendProposalReviewOptions(path, proposalReviewer, proposalReviewNote)
			resp, err := apiClient.Do("POST", path, nil)
			if err != nil {
				return err
			}
			printResponse(resp)
			return nil
		},
	}

	approveCmd := &cobra.Command{
		Use:   "approve [id]",
		Short: "Record an approval for a stored proposal without applying it",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := appendMutationOptions("/api/v1/proposals/"+url.PathEscape(args[0])+"/approve", false)
			path = appendProposalReviewOptions(path, proposalReviewer, proposalReviewNote)
			resp, err := apiClient.Do("POST", path, nil)
			if err != nil {
				return err
			}
			printResponse(resp)
			return nil
		},
	}

	promoteCmd := &cobra.Command{
		Use:   "promote [id]",
		Short: "Clone a stored proposal into the next environment with fresh approvals",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := appendMutationOptions("/api/v1/proposals/"+url.PathEscape(args[0])+"/promote", false)
			path = appendProposalPromoteOptions(path, proposalProposer, proposalEnv, proposalNotBefore)
			path = appendCanaryOptions(path, proposalCanaryServices, proposalCanaryRoutes)
			path = appendCanaryHeaderOptions(path, proposalCanaryHeaders)
			path = appendCanaryPercentOption(path, proposalCanaryPercent)
			path = appendCanaryStepOptions(path, proposalCanarySteps)
			path = appendCanaryGuardOptions(path, proposalCanaryMinRequests, proposalCanaryMaxErrorRate, proposalCanaryMaxP95Latency)
			path = appendCanaryAutoOptions(path, proposalCanaryAuto, proposalCanaryAutoInterval, proposalCanaryAutoReviewer)
			resp, err := apiClient.Do("POST", path, nil)
			if err != nil {
				return err
			}
			printResponse(resp)
			return nil
		},
	}

	rejectCmd := &cobra.Command{
		Use:   "reject [id]",
		Short: "Reject a stored proposal without applying it",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := appendMutationOptions("/api/v1/proposals/"+url.PathEscape(args[0])+"/reject", false)
			path = appendProposalReviewOptions(path, proposalReviewer, proposalReviewNote)
			resp, err := apiClient.Do("POST", path, nil)
			if err != nil {
				return err
			}
			printResponse(resp)
			return nil
		},
	}

	applyCmd.Flags().StringVar(&proposalReviewer, "reviewer", "", "Reviewer identity to record when approving or applying a proposal")
	applyCmd.Flags().StringVar(&proposalReviewNote, "review-note", "", "Reviewer note to record when approving or applying a proposal")
	approveCmd.Flags().StringVar(&proposalReviewer, "reviewer", "", "Reviewer identity to record when approving a proposal")
	approveCmd.Flags().StringVar(&proposalReviewNote, "review-note", "", "Reviewer note to record when approving a proposal")
	promoteCmd.Flags().StringVar(&proposalProposer, "proposer", "", "Identity to record as the creator of the promoted proposal")
	promoteCmd.Flags().StringVar(&proposalEnv, "env", "", "Environment name for the promoted proposal, such as staging or prod")
	promoteCmd.Flags().StringVar(&proposalNotBefore, "not-before", "", "Do not allow the promoted proposal to apply before this RFC3339 timestamp")
	promoteCmd.Flags().StringSliceVar(&proposalCanaryServices, "canary-service", nil, "Optional service names to include in the promoted canary rollout")
	promoteCmd.Flags().StringSliceVar(&proposalCanaryRoutes, "canary-route", nil, "Optional route selectors to include in the promoted canary rollout")
	promoteCmd.Flags().StringSliceVar(&proposalCanaryHeaders, "canary-header", nil, "Optional header matchers to include in the promoted canary rollout, for example X-Iket-Canary=identity-v2")
	promoteCmd.Flags().IntVar(&proposalCanaryPercent, "canary-percent", 0, "Optional percentage of traffic to shift to canary routes, between 1 and 99")
	promoteCmd.Flags().IntSliceVar(&proposalCanarySteps, "canary-step", nil, "Optional canary progression steps, for example --canary-step 10 --canary-step 25 --canary-step 50 --canary-step 100")
	promoteCmd.Flags().IntVar(&proposalCanaryMinRequests, "canary-min-requests", 0, "Optional minimum observed canary requests required before completing the canary")
	promoteCmd.Flags().Float64Var(&proposalCanaryMaxErrorRate, "canary-max-error-rate", 0, "Optional maximum 5xx error rate allowed for the canary, between 0 and 1")
	promoteCmd.Flags().StringVar(&proposalCanaryMaxP95Latency, "canary-max-p95-latency", "", "Optional maximum p95 latency allowed for the canary, for example 500ms or 2s")
	promoteCmd.Flags().BoolVar(&proposalCanaryAuto, "canary-auto", false, "Automatically reconcile active canary rollout steps in the background")
	promoteCmd.Flags().StringVar(&proposalCanaryAutoInterval, "canary-auto-interval", "", "Optional interval for automatic canary reconcile, for example 30s or 5m")
	promoteCmd.Flags().StringVar(&proposalCanaryAutoReviewer, "canary-auto-reviewer", "", "Reviewer identity to record for automatic canary reconcile actions")
	expandCmd.Flags().StringVar(&proposalReviewer, "reviewer", "", "Reviewer identity to record when expanding an active canary rollout")
	expandCmd.Flags().StringVar(&proposalReviewNote, "review-note", "", "Reviewer note to record when expanding an active canary rollout")
	expandCmd.Flags().StringSliceVar(&proposalCanaryServices, "canary-service", nil, "Additional service names to include in the canary rollout")
	expandCmd.Flags().StringSliceVar(&proposalCanaryRoutes, "canary-route", nil, "Additional route selectors to include in the canary rollout")
	expandCmd.Flags().StringSliceVar(&proposalCanaryHeaders, "canary-header", nil, "Additional header matchers to include in the canary rollout, for example X-Iket-Canary=identity-v2")
	expandCmd.Flags().IntVar(&proposalCanaryPercent, "canary-percent", 0, "Optional percentage of traffic to shift to canary routes, between 1 and 99")
	expandCmd.Flags().IntSliceVar(&proposalCanarySteps, "canary-step", nil, "Optional canary progression steps, for example --canary-step 10 --canary-step 25 --canary-step 50 --canary-step 100")
	expandCmd.Flags().IntVar(&proposalCanaryMinRequests, "canary-min-requests", 0, "Optional minimum observed canary requests required before completing the canary")
	expandCmd.Flags().Float64Var(&proposalCanaryMaxErrorRate, "canary-max-error-rate", 0, "Optional maximum 5xx error rate allowed for the canary, between 0 and 1")
	expandCmd.Flags().StringVar(&proposalCanaryMaxP95Latency, "canary-max-p95-latency", "", "Optional maximum p95 latency allowed for the canary, for example 500ms or 2s")
	expandCmd.Flags().BoolVar(&proposalCanaryAuto, "canary-auto", false, "Automatically reconcile active canary rollout steps in the background")
	expandCmd.Flags().StringVar(&proposalCanaryAutoInterval, "canary-auto-interval", "", "Optional interval for automatic canary reconcile, for example 30s or 5m")
	expandCmd.Flags().StringVar(&proposalCanaryAutoReviewer, "canary-auto-reviewer", "", "Reviewer identity to record for automatic canary reconcile actions")
	advanceCmd.Flags().StringVar(&proposalReviewer, "reviewer", "", "Reviewer identity to record when advancing an active canary rollout")
	advanceCmd.Flags().StringVar(&proposalReviewNote, "review-note", "", "Reviewer note to record when advancing an active canary rollout")
	reconcileCmd.Flags().StringVar(&proposalReviewer, "reviewer", "", "Reviewer identity to record when reconciling an active canary rollout")
	reconcileCmd.Flags().StringVar(&proposalReviewNote, "review-note", "", "Reviewer note to record when reconciling an active canary rollout")
	completeCmd.Flags().StringVar(&proposalReviewer, "reviewer", "", "Reviewer identity to record when completing an active canary rollout")
	completeCmd.Flags().StringVar(&proposalReviewNote, "review-note", "", "Reviewer note to record when completing an active canary rollout")
	rejectCmd.Flags().StringVar(&proposalReviewer, "reviewer", "", "Reviewer identity to record when rejecting a proposal")
	rejectCmd.Flags().StringVar(&proposalReviewNote, "review-note", "", "Reviewer note to record when rejecting a proposal")

	proposalCmd.AddCommand(approveCmd)
	proposalCmd.AddCommand(applyCmd)
	canaryCmd.AddCommand(advanceCmd)
	canaryCmd.AddCommand(reconcileCmd)
	canaryCmd.AddCommand(expandCmd)
	canaryCmd.AddCommand(completeCmd)
	proposalCmd.AddCommand(canaryCmd)
	proposalCmd.AddCommand(promoteCmd)
	proposalCmd.AddCommand(rejectCmd)

	rootCmd.AddCommand(proposalCmd)
}

type proposalQueueDigestInput struct {
	Queue []struct {
		ID                  string   `json:"id"`
		Environment         string   `json:"environment"`
		NextAction          string   `json:"next_action"`
		Urgency             string   `json:"urgency"`
		SLABreached         bool     `json:"sla_breached"`
		SLAAgeSeconds       int64    `json:"sla_age_seconds"`
		SLAThresholdSeconds int64    `json:"sla_threshold_seconds"`
		ReadyForApply       bool     `json:"ready_for_apply"`
		PriorityScore       int      `json:"priority_score"`
		PriorityReason      string   `json:"priority_reason"`
		ReadyAgeSeconds     int64    `json:"ready_age_seconds"`
		BlockerCount        int      `json:"blocker_count"`
		Blockers            []string `json:"blockers"`
	} `json:"queue"`
	Summary map[string]interface{} `json:"summary"`
}

type proposalBlockedDigestInput struct {
	BlockedProposalCount int `json:"blocked_proposal_count"`
	Blockers             []struct {
		Reason      string   `json:"reason"`
		Count       int      `json:"count"`
		ProposalIDs []string `json:"proposal_ids"`
	} `json:"blockers"`
}

type proposalBatchBlockedSummaryInput struct {
	Queue []struct {
		ID            string   `json:"id"`
		Action        string   `json:"action"`
		Status        string   `json:"status"`
		Environment   string   `json:"environment"`
		NextAction    string   `json:"next_action"`
		ReadyForApply bool     `json:"ready_for_apply"`
		BlockerCount  int      `json:"blocker_count"`
		Blockers      []string `json:"blockers"`
	} `json:"queue"`
	Summary map[string]interface{} `json:"summary"`
}

func buildProposalQueueDigest(queueResp, blockedResp []byte) ([]byte, error) {
	var queue proposalQueueDigestInput
	if err := json.Unmarshal(queueResp, &queue); err != nil {
		return nil, fmt.Errorf("failed to decode proposal queue: %w", err)
	}
	var blocked proposalBlockedDigestInput
	if err := json.Unmarshal(blockedResp, &blocked); err != nil {
		return nil, fmt.Errorf("failed to decode blocked proposal report: %w", err)
	}

	topReady := make([]map[string]interface{}, 0)
	topBlocked := make([]map[string]interface{}, 0)
	topSLABreaches := make([]map[string]interface{}, 0)
	for _, item := range queue.Queue {
		entry := map[string]interface{}{
			"proposal_id":           item.ID,
			"environment":           item.Environment,
			"next_action":           item.NextAction,
			"urgency":               item.Urgency,
			"sla_breached":          item.SLABreached,
			"sla_age_seconds":       item.SLAAgeSeconds,
			"sla_threshold_seconds": item.SLAThresholdSeconds,
			"priority_score":        item.PriorityScore,
			"priority_reason":       item.PriorityReason,
		}
		if item.SLABreached {
			topSLABreaches = append(topSLABreaches, entry)
		}
		if item.ReadyForApply {
			entry["ready_age_seconds"] = item.ReadyAgeSeconds
			topReady = append(topReady, entry)
			continue
		}
		primaryBlocker := ""
		if len(item.Blockers) > 0 {
			primaryBlocker = item.Blockers[0]
		}
		entry["blocker_count"] = item.BlockerCount
		entry["primary_blocker"] = primaryBlocker
		topBlocked = append(topBlocked, entry)
	}

	sort.SliceStable(topReady, func(i, j int) bool {
		ii, _ := topReady[i]["ready_age_seconds"].(int64)
		jj, _ := topReady[j]["ready_age_seconds"].(int64)
		return ii > jj
	})
	sort.SliceStable(topBlocked, func(i, j int) bool {
		ii, _ := topBlocked[i]["priority_score"].(int)
		jj, _ := topBlocked[j]["priority_score"].(int)
		return ii > jj
	})
	sort.SliceStable(topSLABreaches, func(i, j int) bool {
		ii, _ := topSLABreaches[i]["sla_age_seconds"].(int64)
		jj, _ := topSLABreaches[j]["sla_age_seconds"].(int64)
		return ii > jj
	})
	if len(topReady) > 5 {
		topReady = topReady[:5]
	}
	if len(topBlocked) > 5 {
		topBlocked = topBlocked[:5]
	}
	if len(topSLABreaches) > 5 {
		topSLABreaches = topSLABreaches[:5]
	}

	topBlockers := make([]map[string]interface{}, 0, len(blocked.Blockers))
	for _, blocker := range blocked.Blockers {
		topBlockers = append(topBlockers, map[string]interface{}{
			"reason":       blocker.Reason,
			"count":        blocker.Count,
			"proposal_ids": blocker.ProposalIDs,
		})
	}
	if len(topBlockers) > 5 {
		topBlockers = topBlockers[:5]
	}

	result := map[string]interface{}{
		"generated_at":           time.Now().UTC(),
		"queue_summary":          queue.Summary,
		"blocked_proposal_count": blocked.BlockedProposalCount,
		"top_ready":              topReady,
		"top_blocked":            topBlocked,
		"attention_required": map[string]interface{}{
			"top_sla_breaches": topSLABreaches,
			"sla_breach_count": func() interface{} {
				if queue.Summary == nil {
					return 0
				}
				if count, ok := queue.Summary["sla_breach_count"]; ok {
					return count
				}
				return len(topSLABreaches)
			}(),
			"sla_breaches_by_environment": func() interface{} {
				if queue.Summary == nil {
					return map[string]interface{}{}
				}
				if byEnv, ok := queue.Summary["sla_breaches_by_environment"]; ok {
					return byEnv
				}
				return map[string]interface{}{}
			}(),
			"oldest_sla_breach": func() interface{} {
				if queue.Summary == nil {
					return map[string]interface{}{}
				}
				if oldest, ok := queue.Summary["oldest_sla_breach"]; ok {
					return oldest
				}
				return map[string]interface{}{}
			}(),
		},
		"top_blockers": topBlockers,
	}
	return json.MarshalIndent(result, "", "  ")
}

func buildProposalBatchBlockedView(queueResp []byte) ([]byte, error) {
	var queue proposalBatchBlockedSummaryInput
	if err := json.Unmarshal(queueResp, &queue); err != nil {
		return nil, fmt.Errorf("failed to decode proposal queue: %w", err)
	}

	type blockerGroup struct {
		Reason      string   `json:"reason"`
		Count       int      `json:"count"`
		ProposalIDs []string `json:"proposal_ids"`
	}

	index := map[string]*blockerGroup{}
	byNextAction := map[string]int{}
	byAction := map[string]int{}
	blockedProposalIDs := make([]string, 0)

	for _, item := range queue.Queue {
		if item.ReadyForApply || len(item.Blockers) == 0 {
			continue
		}
		blockedProposalIDs = append(blockedProposalIDs, item.ID)
		nextActionKey := strings.TrimSpace(item.NextAction)
		if nextActionKey == "" {
			nextActionKey = "unknown"
		}
		byNextAction[nextActionKey]++
		actionKey := strings.TrimSpace(item.Action)
		if actionKey == "" {
			actionKey = "unknown"
		}
		byAction[actionKey]++
		for _, blocker := range item.Blockers {
			group := index[blocker]
			if group == nil {
				group = &blockerGroup{Reason: blocker}
				index[blocker] = group
			}
			group.Count++
			group.ProposalIDs = append(group.ProposalIDs, item.ID)
		}
	}

	blockers := make([]blockerGroup, 0, len(index))
	for _, group := range index {
		blockers = append(blockers, *group)
	}
	sort.SliceStable(blockers, func(i, j int) bool {
		if blockers[i].Count != blockers[j].Count {
			return blockers[i].Count > blockers[j].Count
		}
		return blockers[i].Reason < blockers[j].Reason
	})

	result := map[string]interface{}{
		"generated_at":           time.Now().UTC(),
		"blocked_proposal_count": len(blockedProposalIDs),
		"blocked_proposal_ids":   blockedProposalIDs,
		"by_next_action":         byNextAction,
		"by_action":              byAction,
		"filters":                queue.Summary["filters"],
		"blockers":               blockers,
	}
	return json.MarshalIndent(result, "", "  ")
}

func buildProposalBatchExplainView(queueResp []byte) ([]byte, error) {
	var queue proposalBatchBlockedSummaryInput
	if err := json.Unmarshal(queueResp, &queue); err != nil {
		return nil, fmt.Errorf("failed to decode proposal queue: %w", err)
	}

	explanation := "No proposals matched the current batch filters."
	primaryBlocker := ""
	nextAction := ""
	affectedCount := 0
	affectedProposalIDs := make([]string, 0)
	byNextAction := map[string]int{}
	byBlocker := map[string]int{}
	topBlockerCount := 0
	var filters map[string]interface{}
	if queue.Summary != nil {
		if rawFilters, ok := queue.Summary["filters"].(map[string]interface{}); ok {
			filters = rawFilters
		}
	}

	for _, item := range queue.Queue {
		if item.ReadyForApply {
			continue
		}
		affectedCount++
		affectedProposalIDs = append(affectedProposalIDs, item.ID)
		nextActionKey := strings.TrimSpace(item.NextAction)
		if nextActionKey == "" {
			nextActionKey = "unknown"
		}
		byNextAction[nextActionKey]++
		if nextAction == "" {
			nextAction = nextActionKey
		}
		if len(item.Blockers) > 0 {
			blocker := item.Blockers[0]
			byBlocker[blocker]++
			if primaryBlocker == "" || byBlocker[blocker] > topBlockerCount {
				primaryBlocker = blocker
				topBlockerCount = byBlocker[blocker]
			}
		}
	}

	if affectedCount > 0 {
		switch nextAction {
		case "apply":
			explanation = fmt.Sprintf("%d proposal(s) in this batch are ready to apply.", affectedCount)
		case "needs_approval":
			explanation = fmt.Sprintf("%d proposal(s) are primarily blocked on approval. Record approvals or use batch approve for this slice.", affectedCount)
		case "needs_schedule":
			explanation = fmt.Sprintf("%d proposal(s) are primarily blocked by schedule or maintenance-window constraints.", affectedCount)
		case "needs_verification":
			explanation = fmt.Sprintf("%d proposal(s) are primarily blocked on verification or shadow/canary checks.", affectedCount)
		default:
			explanation = fmt.Sprintf("%d proposal(s) matched this batch slice but are not ready yet.", affectedCount)
		}
	}

	suggestedAction, suggestedCommand := buildProposalBatchSuggestedRemediation(nextAction, filters)
	suggestedSteps := buildProposalBatchSuggestedSteps(nextAction, filters)
	suggestedStepObjects := buildProposalBatchSuggestedStepObjects(nextAction, filters)
	planStatus, currentStepIndex, currentStep := buildProposalBatchPlanState(affectedCount, suggestedStepObjects)
	executionHints := buildProposalBatchExecutionHints(nextAction, filters, suggestedCommand)
	generatedAt := time.Now().UTC()
	planID := fmt.Sprintf("plan-%s", generatedAt.Format("20060102-150405.000000000"))

	result := map[string]interface{}{
		"generated_at":           generatedAt,
		"affected_count":         affectedCount,
		"affected_proposal_ids":  affectedProposalIDs,
		"primary_blocker":        primaryBlocker,
		"next_action":            nextAction,
		"by_next_action":         byNextAction,
		"by_blocker":             byBlocker,
		"filters":                filters,
		"suggested_action":       suggestedAction,
		"suggested_command":      suggestedCommand,
		"suggested_steps":        suggestedSteps,
		"suggested_step_objects": suggestedStepObjects,
		"suggested_plan": map[string]interface{}{
			"plan_id":            planID,
			"generated_at":       generatedAt,
			"summary":            explanation,
			"status":             planStatus,
			"next_action":        nextAction,
			"primary_blocker":    primaryBlocker,
			"current_step_index": currentStepIndex,
			"current_step":       currentStep,
			"execution_hints":    executionHints,
			"step_count":         len(suggestedStepObjects),
			"steps":              suggestedStepObjects,
		},
		"explanation": explanation,
	}
	return json.MarshalIndent(result, "", "  ")
}

func buildProposalBatchSuggestedRemediation(nextAction string, filters map[string]interface{}) (string, string) {
	selectorFlags := proposalBatchSelectorFlags(filters)
	switch nextAction {
	case "apply":
		return "apply_batch", "iket proposal batch act --action apply" + selectorFlags
	case "needs_approval":
		return "approve_batch", "iket proposal batch act --action approve" + selectorFlags
	case "needs_schedule":
		return "inspect_schedule_constraints", "iket proposal batch blocked" + selectorFlags
	case "needs_verification":
		return "inspect_verification_constraints", "iket proposal batch explain" + selectorFlags
	default:
		if strings.TrimSpace(selectorFlags) == "" {
			return "inspect_batch", "iket proposal batch explain"
		}
		return "inspect_batch", "iket proposal batch explain" + selectorFlags
	}
}

func proposalBatchSelectorFlags(filters map[string]interface{}) string {
	if len(filters) == 0 {
		return ""
	}
	parts := make([]string, 0, 5)
	if environment, ok := filters["environment"].(string); ok && strings.TrimSpace(environment) != "" {
		parts = append(parts, "--env "+environment)
	}
	if status, ok := filters["status"].(string); ok && strings.TrimSpace(status) != "" {
		parts = append(parts, "--status "+status)
	}
	if nextAction, ok := filters["next_action"].(string); ok && strings.TrimSpace(nextAction) != "" {
		parts = append(parts, "--next-action "+nextAction)
	}
	if urgency, ok := filters["urgency"].(string); ok && strings.TrimSpace(urgency) != "" {
		parts = append(parts, "--urgency "+urgency)
	}
	if ready, ok := filters["ready"].(bool); ok {
		if ready {
			parts = append(parts, "--ready-only")
		} else {
			parts = append(parts, "--blocked-only")
		}
	}
	if len(parts) == 0 {
		return ""
	}
	return " " + strings.Join(parts, " ")
}

func buildProposalBatchSuggestedSteps(nextAction string, filters map[string]interface{}) []string {
	stepObjects := buildProposalBatchSuggestedStepObjects(nextAction, filters)
	steps := make([]string, 0, len(stepObjects))
	for _, step := range stepObjects {
		description := strings.TrimSpace(step["description"])
		command := strings.TrimSpace(step["command"])
		if description == "" {
			continue
		}
		if command == "" {
			steps = append(steps, description)
			continue
		}
		steps = append(steps, description+" Command: `"+command+"`.")
	}
	return steps
}

func buildProposalBatchSuggestedStepObjects(nextAction string, filters map[string]interface{}) []map[string]string {
	selectorFlags := proposalBatchSelectorFlags(filters)
	var steps []map[string]string
	switch nextAction {
	case "apply":
		steps = []map[string]string{
			{
				"kind":        "confirm",
				"status":      "pending",
				"description": "Confirm the selected slice is still healthy and expected.",
				"reason":      "Applying a ready batch should follow a final sanity check.",
			},
			{
				"kind":        "preview",
				"status":      "pending",
				"command":     "iket proposal batch act --action apply --dry-run" + selectorFlags,
				"description": "Preview the apply batch before making changes.",
				"reason":      "A dry-run confirms which proposals will be applied.",
			},
			{
				"kind":        "apply",
				"status":      "pending",
				"command":     "iket proposal batch act --action apply" + selectorFlags,
				"description": "Execute the apply batch and include reviewer metadata if required.",
				"reason":      "This performs the selected rollout slice.",
			},
		}
	case "needs_approval":
		steps = []map[string]string{
			{
				"kind":        "inspect",
				"status":      "pending",
				"command":     "iket proposal batch explain" + selectorFlags,
				"description": "Review the blocked slice if more context is needed.",
				"reason":      "This confirms the slice is primarily approval-blocked.",
			},
			{
				"kind":        "preview",
				"status":      "pending",
				"command":     "iket proposal batch act --action approve --dry-run" + selectorFlags,
				"description": "Preview the approval batch before recording approvals.",
				"reason":      "A dry-run shows which proposals will receive approvals.",
			},
			{
				"kind":        "approve",
				"status":      "pending",
				"command":     "iket proposal batch act --action approve" + selectorFlags,
				"description": "Record approvals for the selected slice and include reviewer metadata if required.",
				"reason":      "This advances the approval-blocked proposals.",
			},
		}
	case "needs_schedule":
		steps = []map[string]string{
			{
				"kind":        "inspect",
				"status":      "pending",
				"command":     "iket proposal batch blocked" + selectorFlags,
				"description": "Inspect the blocked slice to confirm the scheduling constraint.",
				"reason":      "Blocked summaries help verify window-related constraints.",
			},
			{
				"kind":        "wait",
				"status":      "pending",
				"description": "Review the proposal queue or readiness details once the maintenance window opens.",
				"reason":      "Scheduling blockers usually clear only when time-based policy conditions change.",
			},
			{
				"kind":        "recheck",
				"status":      "pending",
				"command":     "iket proposal batch explain" + selectorFlags,
				"description": "Re-run the explanation after the schedule window changes, then apply the batch when it becomes ready.",
				"reason":      "This confirms the slice is no longer schedule-blocked.",
			},
		}
	case "needs_verification":
		steps = []map[string]string{
			{
				"kind":        "inspect",
				"status":      "pending",
				"command":     "iket proposal batch explain" + selectorFlags,
				"description": "Inspect verification blockers for the selected slice.",
				"reason":      "Verification blockers often need closer review before rollout can continue.",
			},
			{
				"kind":        "verify",
				"status":      "pending",
				"description": "Run any required verification or shadow/canary checks for the selected slice.",
				"reason":      "These proposals are waiting on verification to pass.",
			},
			{
				"kind":        "recheck",
				"status":      "pending",
				"command":     "iket proposal batch explain" + selectorFlags,
				"description": "Re-run the explanation and then preview or apply the batch once verification blockers clear.",
				"reason":      "This confirms the slice is ready for the next rollout action.",
			},
		}
	default:
		steps = []map[string]string{
			{
				"kind":        "inspect",
				"status":      "pending",
				"command":     "iket proposal batch explain" + selectorFlags,
				"description": "Inspect the selected slice for more context.",
				"reason":      "This gives the most direct explanation for the current batch state.",
			},
			{
				"kind":        "summarize",
				"status":      "pending",
				"command":     "iket proposal batch blocked" + selectorFlags,
				"description": "Use grouped blocker counts if you need a broader blocked summary.",
				"reason":      "Blocked summaries help spot dominant failure modes across the slice.",
			},
		}
	}
	for i := range steps {
		steps[i]["step_index"] = fmt.Sprintf("%d", i)
		if i == 0 {
			steps[i]["status"] = "current"
			continue
		}
		if strings.TrimSpace(steps[i]["status"]) == "" {
			steps[i]["status"] = "pending"
		}
	}
	return steps
}

func buildProposalBatchPlanState(affectedCount int, steps []map[string]string) (string, int, map[string]string) {
	if affectedCount == 0 || len(steps) == 0 {
		return "empty", -1, nil
	}
	for i, step := range steps {
		if strings.TrimSpace(step["status"]) == "current" {
			return "pending", i, step
		}
	}
	return "pending", 0, steps[0]
}

func buildProposalBatchExecutionHints(nextAction string, filters map[string]interface{}, suggestedCommand string) map[string]interface{} {
	selectorFlags := proposalBatchSelectorFlags(filters)
	hints := map[string]interface{}{
		"ready_to_execute":   false,
		"requires_reviewer":  false,
		"execution_mode":     "inspection",
		"recommended_action": strings.TrimSpace(nextAction),
		"next_command":       suggestedCommand,
		"dry_run_command":    "",
		"execute_command":    "",
	}
	switch nextAction {
	case "apply":
		hints["ready_to_execute"] = true
		hints["requires_reviewer"] = true
		hints["execution_mode"] = "mutation"
		hints["recommended_action"] = "apply"
		hints["dry_run_command"] = "iket proposal batch act --action apply --dry-run" + selectorFlags
		hints["execute_command"] = "iket proposal batch act --action apply" + selectorFlags
	case "needs_approval":
		hints["ready_to_execute"] = true
		hints["requires_reviewer"] = true
		hints["execution_mode"] = "mutation"
		hints["recommended_action"] = "approve"
		hints["dry_run_command"] = "iket proposal batch act --action approve --dry-run" + selectorFlags
		hints["execute_command"] = "iket proposal batch act --action approve" + selectorFlags
	case "needs_schedule":
		hints["recommended_action"] = "inspect_schedule_constraints"
		hints["next_command"] = "iket proposal batch blocked" + selectorFlags
	case "needs_verification":
		hints["recommended_action"] = "inspect_verification_constraints"
		hints["next_command"] = "iket proposal batch explain" + selectorFlags
	default:
		hints["recommended_action"] = "inspect"
		if strings.TrimSpace(selectorFlags) == "" {
			hints["next_command"] = "iket proposal batch explain"
		} else {
			hints["next_command"] = "iket proposal batch explain" + selectorFlags
		}
	}
	return hints
}

func loadProposalQueueDigest(environment, status, nextAction, urgency string, readyOnly, blockedOnly bool, limit int) ([]byte, error) {
	if readyOnly && blockedOnly {
		return nil, fmt.Errorf("--ready-only and --blocked-only cannot be used together")
	}
	queuePath := "/api/v1/proposals/queue"
	queuePath = appendQueryParam(queuePath, "environment", environment)
	queuePath = appendQueryParam(queuePath, "status", status)
	queuePath = appendQueryParam(queuePath, "next_action", nextAction)
	queuePath = appendQueryParam(queuePath, "urgency", urgency)
	if readyOnly {
		queuePath = appendQueryParam(queuePath, "ready", "true")
	}
	if blockedOnly {
		queuePath = appendQueryParam(queuePath, "ready", "false")
	}
	if limit > 0 {
		queuePath = appendQueryParam(queuePath, "limit", fmt.Sprintf("%d", limit))
	}
	queueResp, err := apiClient.Do("GET", queuePath, nil)
	if err != nil {
		return nil, err
	}

	blockedPath := "/api/v1/proposals/queue/blocked-report"
	blockedPath = appendQueryParam(blockedPath, "environment", environment)
	blockedPath = appendQueryParam(blockedPath, "status", status)
	blockedResp, err := apiClient.Do("GET", blockedPath, nil)
	if err != nil {
		return nil, err
	}

	return buildProposalQueueDigest(queueResp, blockedResp)
}

func writeStructuredOutputFile(outputPath string, payload []byte, label string) error {
	var content interface{}
	if err := json.Unmarshal(payload, &content); err != nil {
		return fmt.Errorf("failed to decode %s: %w", label, err)
	}
	var (
		output []byte
		err    error
	)
	if strings.HasSuffix(strings.ToLower(outputPath), ".yaml") || strings.HasSuffix(strings.ToLower(outputPath), ".yml") {
		output, err = yaml.Marshal(content)
		if err != nil {
			return fmt.Errorf("failed to encode %s as yaml: %w", label, err)
		}
	} else {
		output, err = json.MarshalIndent(content, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to encode %s as json: %w", label, err)
		}
	}
	if err := os.WriteFile(outputPath, output, 0644); err != nil {
		return fmt.Errorf("failed to write %s export: %w", label, err)
	}
	return nil
}

func buildProposalBatchMutationPath(dryRun bool, action, reviewer, reviewNote, environment, status, nextAction, urgency string, limit int) (string, error) {
	action = strings.TrimSpace(strings.ToLower(action))
	var path string
	switch action {
	case "approve":
		path = appendMutationOptions("/api/v1/proposals/queue/approve-ready", dryRun)
	case "apply":
		path = appendMutationOptions("/api/v1/proposals/queue/apply-ready", dryRun)
	default:
		return "", fmt.Errorf("--action must be approve or apply")
	}
	path = appendProposalReviewOptions(path, reviewer, reviewNote)
	path = appendQueryParam(path, "environment", environment)
	path = appendQueryParam(path, "status", status)
	path = appendQueryParam(path, "next_action", nextAction)
	path = appendQueryParam(path, "urgency", urgency)
	if limit > 0 {
		path = appendQueryParam(path, "limit", fmt.Sprintf("%d", limit))
	}
	return path, nil
}

func validateProposalBatchActOptions(action, view, outputPath string) (string, string, error) {
	action = strings.TrimSpace(strings.ToLower(action))
	view = strings.TrimSpace(strings.ToLower(view))
	switch action {
	case "approve", "apply", "blocked", "explain":
		return action, view, nil
	case "export":
		if strings.TrimSpace(outputPath) == "" {
			return "", "", fmt.Errorf("--output is required when --action export")
		}
		if view == "" {
			view = "queue"
		}
		return action, view, nil
	default:
		return "", "", fmt.Errorf("--action must be approve, apply, blocked, explain, or export")
	}
}

func executeProposalBatchAction(action, view, outputPath, reviewer, reviewNote, environment, status, nextAction, urgency string, readyOnly, blockedOnly bool, limit int, dryRun bool) error {
	normalizedAction, normalizedView, err := validateProposalBatchActOptions(action, view, outputPath)
	if err != nil {
		return err
	}
	switch normalizedAction {
	case "approve", "apply":
		path, err := buildProposalBatchMutationPath(dryRun, normalizedAction, reviewer, reviewNote, environment, status, nextAction, urgency, limit)
		if err != nil {
			return err
		}
		resp, err := apiClient.Do("POST", path, nil)
		if err != nil {
			return err
		}
		printResponse(resp)
		return nil
	case "blocked", "explain":
		payload, _, err := loadProposalBatchView(normalizedAction, environment, status, nextAction, urgency, readyOnly, blockedOnly, limit)
		if err != nil {
			return err
		}
		printResponse(payload)
		return nil
	case "export":
		payload, label, err := loadProposalBatchView(normalizedView, environment, status, nextAction, urgency, readyOnly, blockedOnly, limit)
		if err != nil {
			return err
		}
		if err := writeStructuredOutputFile(outputPath, payload, label); err != nil {
			return err
		}
		fmt.Printf("Exported %s to %s\n", label, outputPath)
		return nil
	default:
		return fmt.Errorf("unsupported batch action %q", normalizedAction)
	}
}

func buildProposalQueuePath(environment, status, nextAction, urgency string, readyOnly, blockedOnly bool, limit int) (string, error) {
	if readyOnly && blockedOnly {
		return "", fmt.Errorf("--ready-only and --blocked-only cannot be used together")
	}
	path := "/api/v1/proposals/queue"
	path = appendQueryParam(path, "environment", environment)
	path = appendQueryParam(path, "status", status)
	path = appendQueryParam(path, "next_action", nextAction)
	path = appendQueryParam(path, "urgency", urgency)
	if readyOnly {
		path = appendQueryParam(path, "ready", "true")
	}
	if blockedOnly {
		path = appendQueryParam(path, "ready", "false")
	}
	if limit > 0 {
		path = appendQueryParam(path, "limit", fmt.Sprintf("%d", limit))
	}
	return path, nil
}

func loadProposalBatchView(view, environment, status, nextAction, urgency string, readyOnly, blockedOnly bool, limit int) ([]byte, string, error) {
	view = strings.TrimSpace(strings.ToLower(view))
	switch view {
	case "", "queue":
		path, err := buildProposalQueuePath(environment, status, nextAction, urgency, readyOnly, blockedOnly, limit)
		if err != nil {
			return nil, "", err
		}
		resp, err := apiClient.Do("GET", path, nil)
		if err != nil {
			return nil, "", err
		}
		return resp, "proposal batch queue", nil
	case "digest":
		resp, err := loadProposalQueueDigest(environment, status, nextAction, urgency, readyOnly, blockedOnly, limit)
		if err != nil {
			return nil, "", err
		}
		return resp, "proposal batch digest", nil
	case "blocked":
		path, err := buildProposalQueuePath(environment, status, nextAction, urgency, readyOnly, blockedOnly, limit)
		if err != nil {
			return nil, "", err
		}
		resp, err := apiClient.Do("GET", path, nil)
		if err != nil {
			return nil, "", err
		}
		blocked, err := buildProposalBatchBlockedView(resp)
		if err != nil {
			return nil, "", err
		}
		return blocked, "proposal batch blocked report", nil
	case "explain":
		path, err := buildProposalQueuePath(environment, status, nextAction, urgency, readyOnly, blockedOnly, limit)
		if err != nil {
			return nil, "", err
		}
		resp, err := apiClient.Do("GET", path, nil)
		if err != nil {
			return nil, "", err
		}
		explain, err := buildProposalBatchExplainView(resp)
		if err != nil {
			return nil, "", err
		}
		return explain, "proposal batch explanation", nil
	default:
		return nil, "", fmt.Errorf("--view must be queue, digest, blocked, or explain")
	}
}

func initNotificationCmd(rootCmd *cobra.Command) {
	var (
		notificationEvent    string
		notificationProposal string
		notificationWebhook  string
		notificationSuccess  string
		notificationLimit    int
	)
	notificationCmd := &cobra.Command{
		Use:   "notification",
		Short: "Notification delivery history and replay",
	}

	deliveriesCmd := &cobra.Command{
		Use:   "deliveries",
		Short: "List notification delivery history",
		RunE: func(cmd *cobra.Command, args []string) error {
			path := "/api/v1/notifications/deliveries"
			path = appendQueryParam(path, "event", notificationEvent)
			path = appendQueryParam(path, "proposal_id", notificationProposal)
			path = appendQueryParam(path, "webhook", notificationWebhook)
			path = appendQueryParam(path, "success", notificationSuccess)
			resp, err := apiClient.Do("GET", path, nil)
			if err != nil {
				return err
			}
			printResponse(resp)
			return nil
		},
	}
	deliveriesCmd.Flags().StringVar(&notificationEvent, "event", "", "Filter notification deliveries by event name")
	deliveriesCmd.Flags().StringVar(&notificationProposal, "proposal", "", "Filter notification deliveries by proposal id")
	deliveriesCmd.Flags().StringVar(&notificationWebhook, "webhook", "", "Filter notification deliveries by webhook name or URL")
	deliveriesCmd.Flags().StringVar(&notificationSuccess, "success", "", "Filter notification deliveries by success state: true or false")
	notificationCmd.AddCommand(deliveriesCmd)

	notificationCmd.AddCommand(&cobra.Command{
		Use:   "show [id]",
		Short: "Show a recorded notification delivery",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			resp, err := apiClient.Do("GET", "/api/v1/notifications/deliveries/"+url.PathEscape(args[0]), nil)
			if err != nil {
				return err
			}
			printResponse(resp)
			return nil
		},
	})

	notificationCmd.AddCommand(&cobra.Command{
		Use:   "replay [id]",
		Short: "Replay a recorded notification delivery",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			resp, err := apiClient.Do("POST", "/api/v1/notifications/deliveries/"+url.PathEscape(args[0])+"/replay", nil)
			if err != nil {
				return err
			}
			printResponse(resp)
			return nil
		},
	})

	replayFailedCmd := &cobra.Command{
		Use:   "replay-failed",
		Short: "Replay failed notification deliveries, optionally filtered",
		RunE: func(cmd *cobra.Command, args []string) error {
			path := "/api/v1/notifications/deliveries/replay-failed"
			path = appendQueryParam(path, "event", notificationEvent)
			path = appendQueryParam(path, "proposal_id", notificationProposal)
			path = appendQueryParam(path, "webhook", notificationWebhook)
			if notificationLimit > 0 {
				path = appendQueryParam(path, "limit", fmt.Sprintf("%d", notificationLimit))
			}
			resp, err := apiClient.Do("POST", path, nil)
			if err != nil {
				return err
			}
			printResponse(resp)
			return nil
		},
	}
	replayFailedCmd.Flags().StringVar(&notificationEvent, "event", "", "Replay only failed deliveries for this event")
	replayFailedCmd.Flags().StringVar(&notificationProposal, "proposal", "", "Replay only failed deliveries for this proposal id")
	replayFailedCmd.Flags().StringVar(&notificationWebhook, "webhook", "", "Replay only failed deliveries for this webhook name or URL")
	replayFailedCmd.Flags().IntVar(&notificationLimit, "limit", 0, "Replay at most this many failed deliveries")
	notificationCmd.AddCommand(replayFailedCmd)

	rootCmd.AddCommand(notificationCmd)
}
