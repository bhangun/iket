package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

func initSetupCmd(rootCmd *cobra.Command) {
	setupCmd := &cobra.Command{
		Use:   "setup",
		Short: "Guided setup for connecting to Iket Gateway",
		RunE: func(cmd *cobra.Command, args []string) error {
			reader := bufio.NewReader(os.Stdin)
			fmt.Println("🚀 Welcome to Iket Setup!")
			fmt.Println("This wizard will help you connect your CLI to an Iket Gateway.")
			fmt.Println()

			// 1. Name
			fmt.Print("Enter a name for this context (e.g., local, docker, prod) [default]: ")
			name, _ := reader.ReadString('\n')
			name = strings.TrimSpace(name)
			if name == "" {
				name = "default"
			}

			// 2. URL
			fmt.Print("Enter the Gateway URL (e.g., http://localhost:8080 or http://localhost:7100): ")
			url, _ := reader.ReadString('\n')
			url = strings.TrimSpace(url)
			if url == "" {
				return fmt.Errorf("URL is required")
			}

			// 3. TLS / mTLS
			var cert, key, ca string
			skipVerify := false
			if strings.HasPrefix(url, "https") {
				fmt.Print("Does this connection require mTLS? (y/n): ")
				mtls, _ := reader.ReadString('\n')
				if strings.ToLower(strings.TrimSpace(mtls)) == "y" {
					fmt.Print("Path to client certificate (crt): ")
					cert, _ = reader.ReadString('\n')
					cert = strings.TrimSpace(cert)

					fmt.Print("Path to client key: ")
					key, _ = reader.ReadString('\n')
					key = strings.TrimSpace(key)

					fmt.Print("Path to CA certificate (optional): ")
					ca, _ = reader.ReadString('\n')
					ca = strings.TrimSpace(ca)
				}

				fmt.Print("Skip TLS verification? (y/n) [n]: ")
				skip, _ := reader.ReadString('\n')
				if strings.ToLower(strings.TrimSpace(skip)) == "y" {
					skipVerify = true
				}
			}

			// 4. Strict Mode
			fmt.Print("Enable strict mode for this context? (requires confirmation for dangerous commands) (y/n) [n]: ")
			strictInput, _ := reader.ReadString('\n')
			strict := strings.ToLower(strings.TrimSpace(strictInput)) == "y"

			// Save config
			cfg, err := loadCLIConfig()
			if err != nil {
				return err
			}

			ctx := Context{
				ServerURL:  url,
				CertFile:   cert,
				KeyFile:    key,
				CAFile:     ca,
				SkipVerify: skipVerify,
				Strict:     strict,
			}

			cfg.Contexts[name] = ctx
			cfg.CurrentContext = name

			// Try to verify connection
			fmt.Printf("\nVerifying connection to %s...\n", url)
			client, err := NewAPIClient(ctx.ServerURL, ctx.SkipVerify, ctx.CAFile, ctx.CertFile, ctx.KeyFile)
			if err == nil {
				_, err = client.Do("GET", "/api/v1/gateway/status", nil)
			}

			if err != nil {
				fmt.Printf("⚠️  Warning: Could not connect to gateway: %v\n", err)
				fmt.Print("Save configuration anyway? (y/n) [y]: ")
				save, _ := reader.ReadString('\n')
				if strings.ToLower(strings.TrimSpace(save)) == "n" {
					fmt.Println("Setup cancelled.")
					return nil
				}
			} else {
				fmt.Println("✅ Connection successful!")
			}

			if err := saveCLIConfig(cfg); err != nil {
				return err
			}

			fmt.Printf("\n✨ Context %q configured and set as active.\n", name)
			fmt.Println("Try running: iket-cli gateway status")
			return nil
		},
	}

	rootCmd.AddCommand(setupCmd)
}
