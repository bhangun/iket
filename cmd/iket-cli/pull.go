package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

func initPullCmd(rootCmd *cobra.Command) {
	pullCmd := &cobra.Command{
		Use:   "pull",
		Short: "Fetch remote configuration/services to local files",
	}

	var format string

	// Pull config
	configCmd := &cobra.Command{
		Use:   "config [file]",
		Short: "Pull remote gateway configuration to a local file",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := "config.yaml"
			if len(args) > 0 {
				path = args[0]
			}
			return runPull("/api/v1/gateway/config", path, format)
		},
	}
	configCmd.Flags().StringVarP(&format, "format", "t", "yaml", "Output format: yaml or json")

	// Pull services
	servicesCmd := &cobra.Command{
		Use:   "services [file]",
		Short: "Pull remote service definitions to a local file",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := "service.yaml"
			if len(args) > 0 {
				path = args[0]
			}
			return runPull("/api/v1/services", path, format)
		},
	}
	servicesCmd.Flags().StringVarP(&format, "format", "t", "yaml", "Output format: yaml or json")

	pullCmd.AddCommand(configCmd, servicesCmd)
	rootCmd.AddCommand(pullCmd)
}

func runPull(apiPath, filePath, format string) error {
	resp, err := apiClient.Do("GET", apiPath, nil)
	if err != nil {
		return err
	}

	var content interface{}
	if err := json.Unmarshal(resp, &content); err != nil {
		return fmt.Errorf("failed to parse remote response: %w", err)
	}

	// Determine format from extension if not explicitly set to something other than default
	ext := strings.ToLower(filepath.Ext(filePath))
	if ext == ".json" && format == "yaml" {
		format = "json"
	}

	var output []byte
	if format == "json" {
		output, err = json.MarshalIndent(content, "", "  ")
	} else {
		output, err = yaml.Marshal(content)
	}

	if err != nil {
		return fmt.Errorf("failed to encode local file: %w", err)
	}

	if err := os.WriteFile(filePath, output, 0644); err != nil {
		return fmt.Errorf("failed to write to file %s: %w", filePath, err)
	}

	fmt.Printf("Successfully pulled remote state to %s\n", filePath)
	return nil
}
