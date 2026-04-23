package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

func initPushCmd(rootCmd *cobra.Command) {
	pushCmd := &cobra.Command{
		Use:   "push",
		Short: "Export local configuration/services to remote gateway",
	}

	var strategy string

	// Push config
	configCmd := &cobra.Command{
		Use:   "config [file]",
		Short: "Push local gateway configuration to remote",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runPush(args[0], "/api/v1/gateway/config", strategy)
		},
	}
	configCmd.Flags().StringVar(&strategy, "strategy", "merge", "Sync strategy: merge or replace")

	// Push services
	servicesCmd := &cobra.Command{
		Use:   "services [file]",
		Short: "Push local service definitions to remote",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runPush(args[0], "/api/v1/services", strategy)
		},
	}
	servicesCmd.Flags().StringVar(&strategy, "strategy", "merge", "Sync strategy: merge or replace")

	pushCmd.AddCommand(configCmd, servicesCmd)
	rootCmd.AddCommand(pushCmd)
}

func runPush(filePath, apiPath, strategy string) error {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	// Convert YAML to Map (to support both YAML and JSON input)
	var content interface{}
	if err := yaml.Unmarshal(data, &content); err != nil {
		return fmt.Errorf("failed to parse file: %w", err)
	}

	// For services, ensure we send a wrapper if it's not already there
	if strings.Contains(apiPath, "services") {
		m, ok := content.(map[string]interface{})
		if ok {
			if _, hasServices := m["services"]; !hasServices {
				// If it's a list, wrap it
				if list, isList := m["services"].([]interface{}); isList {
					content = map[string]interface{}{"services": list}
				} else if _, isList := content.([]interface{}); isList {
					content = map[string]interface{}{"services": content}
				}
			}
		}
	}

	method := "POST"
	if strings.Contains(apiPath, "config") {
		method = "PUT"
	}

	pathWithStrategy := fmt.Sprintf("%s?strategy=%s", apiPath, strategy)
	if dryRun {
		pathWithStrategy += "&dry_run=true"
	}

	resp, err := apiClient.Do(method, pathWithStrategy, content)
	if err != nil {
		return err
	}

	var pretty bytes.Buffer
	json.Indent(&pretty, resp, "", "  ")
	fmt.Println(pretty.String())

	return nil
}
