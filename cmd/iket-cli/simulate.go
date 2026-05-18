package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"

	iketconfig "github.com/bhangun/iket/pkg/config"
	"github.com/bhangun/iket/pkg/core/gateway"
	"github.com/bhangun/iket/pkg/logging"
	"github.com/spf13/cobra"
)

type simulateResponse struct {
	SampleMethod string                  `json:"sample_method"`
	SamplePath   string                  `json:"sample_path"`
	Routes       []simulateRouteDecision `json:"routes"`
}

type simulateRouteDecision struct {
	RouteName   string            `json:"route_name"`
	ServiceName string            `json:"service_name"`
	RoutePath   string            `json:"route_path"`
	RequestPath string            `json:"request_path"`
	Matched     bool              `json:"matched"`
	RouteVars   map[string]string `json:"route_vars,omitempty"`
	ProxiedPath string            `json:"proxied_path,omitempty"`
	Destination string            `json:"destination,omitempty"`
	StripPath   bool              `json:"strip_path"`
	URLPattern  string            `json:"url_pattern,omitempty"`
	Enabled     bool              `json:"enabled"`
}

var simulateRouteVarRe = regexp.MustCompile(`\{([^}:]+)(:[^}]+)?\}`)

func initSimulateCmd(rootCmd *cobra.Command) {
	var (
		simulateMethod   string
		simulateJSON     bool
		simulateAll      bool
		simulateConfig   string
		simulateServices string
	)

	simulateCmd := &cobra.Command{
		Use:     "simulate [url-or-path]",
		Aliases: []string{"test"},
		Short:   "Simulate how Iket would match and rewrite a request without calling the upstream",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			requestPath, originalInput, ignoredQuery, err := normalizeSimulateInput(args[0])
			if err != nil {
				return err
			}
			method := strings.ToUpper(simulateMethod)

			result, err := loadSimulationResult(requestPath, method, simulateConfig, simulateServices)
			if err != nil {
				return err
			}

			if simulateJSON {
				data, err := json.MarshalIndent(result, "", "  ")
				if err != nil {
					return err
				}
				fmt.Println(string(data))
				return nil
			}

			return printSimulationResult(originalInput, ignoredQuery, *result, simulateAll)
		},
	}

	simulateCmd.Flags().StringVar(&simulateMethod, "method", http.MethodGet, "Request method to simulate")
	simulateCmd.Flags().BoolVar(&simulateJSON, "json", false, "Print the raw simulation response as JSON")
	simulateCmd.Flags().BoolVar(&simulateAll, "all", false, "Show all matched routes instead of only the selected best match")
	simulateCmd.Flags().StringVar(&simulateConfig, "config", "", "Simulate against a local config.yaml instead of the active context")
	simulateCmd.Flags().StringVar(&simulateServices, "services", "", "Optional local service.yaml to pair with --config")
	rootCmd.AddCommand(simulateCmd)
}

func loadSimulationResult(requestPath, method, configPath, servicesPath string) (*simulateResponse, error) {
	if strings.TrimSpace(configPath) == "" && strings.TrimSpace(servicesPath) != "" {
		return nil, fmt.Errorf("--services requires --config")
	}
	if strings.TrimSpace(configPath) != "" {
		return simulateFromLocalFiles(requestPath, method, configPath, servicesPath)
	}

	cfg, err := loadCLIConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to load CLI config: %w", err)
	}
	ctx := cfg.GetCurrentContext()
	client, err := NewAPIClient(ctx.ServerURL, ctx.SkipVerify, ctx.CAFile, ctx.CertFile, ctx.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize API client: %w", err)
	}

	apiPath := fmt.Sprintf(
		"/api/v1/gateway/config/self-test?path=%s&method=%s",
		url.QueryEscape(requestPath),
		url.QueryEscape(method),
	)
	resp, err := client.Do("GET", apiPath, nil)
	if err != nil {
		return nil, err
	}
	var result simulateResponse
	if err := json.Unmarshal(resp, &result); err != nil {
		return nil, fmt.Errorf("failed to parse simulation response: %w", err)
	}
	return &result, nil
}

func simulateFromLocalFiles(requestPath, method, configPath, servicesPath string) (*simulateResponse, error) {
	logger := logging.NewLogger(false)
	defer logger.Sync()

	cfg, err := iketconfig.LoadConfig(configPath, servicesPath, logger)
	if err != nil {
		return nil, err
	}

	result := &simulateResponse{
		SampleMethod: method,
		SamplePath:   requestPath,
		Routes:       make([]simulateRouteDecision, 0),
	}

	for _, serviceConfig := range cfg.Services {
		for _, service := range serviceConfig.Services {
			for _, rawRoute := range service.Routes {
				route := rawRoute
				route.Path = service.EffectiveRoutePath(rawRoute)
				route.Methods = rawRoute.EffectiveMethods()

				decision := simulateRouteDecision{
					RouteName:   route.Name,
					ServiceName: service.Name,
					RoutePath:   route.Path,
					RequestPath: requestPath,
					StripPath:   route.StripPath,
					Enabled:     route.IsEnabled(),
					Destination: service.Host,
				}
				if decision.RouteName == "" {
					decision.RouteName = route.Path
				}
				if len(route.Backends) > 0 {
					decision.URLPattern = route.Backends[0].URLPattern
				}

				vars, matched := gateway.MatchRouteTemplate(route, method, requestPath, nil)
				decision.Matched = matched
				if matched {
					decision.RouteVars = vars
					proxiedPath, err := gateway.ComputeProxiedPath(&service, route, requestPath, vars)
					if err != nil {
						return nil, fmt.Errorf("failed to compute proxied path for route %s: %w", route.Path, err)
					}
					decision.ProxiedPath = proxiedPath
				}

				result.Routes = append(result.Routes, decision)
			}
		}
	}

	return result, nil
}

func normalizeSimulateInput(input string) (requestPath, originalInput, ignoredQuery string, err error) {
	originalInput = strings.TrimSpace(input)
	if originalInput == "" {
		return "", "", "", fmt.Errorf("url or path is required")
	}

	if strings.HasPrefix(originalInput, "http://") || strings.HasPrefix(originalInput, "https://") {
		parsed, parseErr := url.Parse(originalInput)
		if parseErr != nil {
			return "", "", "", parseErr
		}
		requestPath = parsed.EscapedPath()
		if requestPath == "" {
			requestPath = "/"
		}
		ignoredQuery = parsed.RawQuery
		return requestPath, originalInput, ignoredQuery, nil
	}

	requestPath = originalInput
	if !strings.HasPrefix(requestPath, "/") {
		requestPath = "/" + requestPath
	}
	return requestPath, originalInput, "", nil
}

func printSimulationResult(originalInput, ignoredQuery string, result simulateResponse, showAll bool) error {
	matched := make([]simulateRouteDecision, 0)
	for _, route := range result.Routes {
		if route.Matched {
			matched = append(matched, route)
		}
	}

	fmt.Printf("Simulation input: %s\n", originalInput)
	fmt.Printf("Method: %s\n", strings.ToUpper(result.SampleMethod))
	fmt.Printf("Gateway path: %s\n", result.SamplePath)
	if ignoredQuery != "" {
		fmt.Printf("Ignored query string: %s\n", ignoredQuery)
	}
	fmt.Println("Upstream request sent: no")
	fmt.Println()

	if len(matched) == 0 {
		fmt.Println("Result: no route matched this request.")
		return nil
	}

	sort.SliceStable(matched, func(i, j int) bool {
		return simulateRouteSpecificityScore(matched[i]) > simulateRouteSpecificityScore(matched[j])
	})

	selected := matched[0]
	if !selected.Enabled {
		fmt.Println("Result: a route pattern matches, but the selected route is disabled.")
	} else {
		fmt.Println("Result: request would be accepted by the selected route.")
	}
	fmt.Println()

	printSimulatedRoute("Selected route", selected)
	if len(matched) > 1 {
		fmt.Printf("Other matching routes: %d\n", len(matched)-1)
	}
	if showAll && len(matched) > 1 {
		fmt.Println()
		fmt.Println("All matching routes:")
		for i, route := range matched {
			fmt.Printf("%d. %s [%s] -> %s\n", i+1, firstNonEmpty(route.RouteName, route.RoutePath), route.ServiceName, route.RoutePath)
		}
	}

	if !selected.Enabled {
		return nil
	}
	fmt.Println()
	fmt.Printf("Would proxy to: %s%s\n", selected.Destination, selected.ProxiedPath)
	return nil
}

func printSimulatedRoute(label string, route simulateRouteDecision) {
	fmt.Printf("%s:\n", label)
	fmt.Printf("  service: %s\n", route.ServiceName)
	fmt.Printf("  route: %s\n", firstNonEmpty(route.RouteName, route.RoutePath))
	fmt.Printf("  route_path: %s\n", route.RoutePath)
	fmt.Printf("  enabled: %t\n", route.Enabled)
	fmt.Printf("  strip_path: %t\n", route.StripPath)
	if route.URLPattern != "" {
		fmt.Printf("  url_pattern: %s\n", route.URLPattern)
	}
	if len(route.RouteVars) > 0 {
		fmt.Printf("  route_vars: %s\n", formatVars(route.RouteVars))
	}
	if route.ProxiedPath != "" {
		fmt.Printf("  proxied_path: %s\n", route.ProxiedPath)
	}
	if route.Destination != "" {
		fmt.Printf("  upstream: %s\n", route.Destination)
	}
}

func formatVars(vars map[string]string) string {
	keys := make([]string, 0, len(vars))
	for key := range vars {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, fmt.Sprintf("%s=%q", key, vars[key]))
	}
	return strings.Join(parts, ", ")
}

func simulateRouteSpecificityScore(route simulateRouteDecision) int {
	score := len(route.RoutePath)
	score += strings.Count(route.RoutePath, "/") * 10
	score -= len(simulateRouteVarRe.FindAllStringSubmatch(route.RoutePath, -1)) * 5
	if strings.Contains(route.RoutePath, "{rest:.*}") {
		score -= 50
	}
	if strings.HasSuffix(route.RoutePath, "/*") || route.RoutePath == "/*" {
		score -= 50
	}
	if !route.Enabled {
		score -= 1000
	}
	return score
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}
