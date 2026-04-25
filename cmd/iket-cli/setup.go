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

			fmt.Print("Enter a name for this context (e.g., local, docker, prod) [default]: ")
			name, _ := reader.ReadString('\n')
			name = strings.TrimSpace(name)
			if name == "" {
				name = "default"
			}

			fmt.Print("Enter the Gateway URL (e.g., http://localhost:8080 or https://localhost:8443): ")
			serverURL, _ := reader.ReadString('\n')
			serverURL = strings.TrimSpace(serverURL)
			if serverURL == "" {
				return fmt.Errorf("URL is required")
			}

			var (
				certPath string
				keyPath  string
				caPath   string
				bundle   certBundle
			)
			skipVerify := false
			if strings.HasPrefix(strings.ToLower(serverURL), "https") {
				if discovered, err := discoverCertBundle(""); err == nil {
					fmt.Printf("Discovered a client certificate bundle in %s.\n", discovered.SourceHint)
					fmt.Print("Use it for this context? (Y/n): ")
					useDetected, _ := reader.ReadString('\n')
					if strings.ToLower(strings.TrimSpace(useDetected)) != "n" {
						bundle = discovered
					}
				}

				if bundle.Dir == "" {
					fmt.Print("Does this connection require mTLS? (y/n): ")
					mtls, _ := reader.ReadString('\n')
					if strings.ToLower(strings.TrimSpace(mtls)) == "y" {
						fmt.Print("Path to client certificate (crt): ")
						certPath, _ = reader.ReadString('\n')
						certPath = strings.TrimSpace(certPath)

						fmt.Print("Path to client key: ")
						keyPath, _ = reader.ReadString('\n')
						keyPath = strings.TrimSpace(keyPath)

						fmt.Print("Path to CA certificate (optional): ")
						caPath, _ = reader.ReadString('\n')
						caPath = strings.TrimSpace(caPath)
					}
				}

				fmt.Print("Skip TLS verification? (y/n) [n]: ")
				skip, _ := reader.ReadString('\n')
				if strings.ToLower(strings.TrimSpace(skip)) == "y" {
					skipVerify = true
				}
			}

			fmt.Print("Enable strict mode for this context? (requires confirmation for dangerous commands) (y/n) [n]: ")
			strictInput, _ := reader.ReadString('\n')
			strict := strings.ToLower(strings.TrimSpace(strictInput)) == "y"

			ctx := Context{
				ServerURL:  serverURL,
				SkipVerify: skipVerify,
				Strict:     strict,
			}

			if bundle.Dir != "" {
				installed, err := installCertBundle(name, bundle)
				if err != nil {
					return err
				}
				ctx.CAFile = installed.CAFile
				ctx.CertFile = installed.CertFile
				ctx.KeyFile = installed.KeyFile
			} else {
				var err error
				ctx.CertFile, err = validateOptionalFile(certPath, "client certificate")
				if err != nil {
					return err
				}
				ctx.KeyFile, err = validateOptionalFile(keyPath, "client key")
				if err != nil {
					return err
				}
				ctx.CAFile, err = validateOptionalFile(caPath, "CA certificate")
				if err != nil {
					return err
				}
			}

			fmt.Printf("\nVerifying connection to %s...\n", serverURL)
			if err := verifyCLIContext(ctx); err != nil {
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

			if err := saveContextEntry(name, ctx, true); err != nil {
				return err
			}

			fmt.Printf("\n✨ Context %q configured and set as active.\n", name)
			fmt.Println("Try running: iket gateway status")
			return nil
		},
	}

	var (
		dockerContextName string
		dockerURL         string
		dockerCertDir     string
		dockerStrict      bool
		dockerSkipVerify  bool
		dockerNoVerify    bool
	)
	dockerCmd := &cobra.Command{
		Use:   "docker",
		Short: "Bootstrap a trusted local Docker or shared-volume mTLS context",
		Long:  "On a trusted server host, either import an existing client bundle or mint a local admin client certificate from the server CA, then create or update a ready-to-use CLI context.",
		RunE: func(cmd *cobra.Command, args []string) error {
			var (
				installed  Context
				sourceHint string
			)
			bundle, bundleErr := discoverCertBundle(dockerCertDir)
			if bundleErr == nil {
				installed, bundleErr = installCertBundle(dockerContextName, bundle)
				if bundleErr != nil {
					return bundleErr
				}
				sourceHint = bundle.SourceHint
			} else {
				caDir, caErr := discoverCADir(dockerCertDir)
				if caErr != nil {
					return fmt.Errorf("%v; also could not find local CA material: %v", bundleErr, caErr)
				}
				installed, caErr = issueManagedContextCertFromCA(dockerContextName, caDir, dockerContextName)
				if caErr != nil {
					return fmt.Errorf("found local CA material in %s but could not issue a local admin certificate: %w", caDir, caErr)
				}
				sourceHint = caDir + " (issued local admin cert from trusted host CA)"
			}

			ctx := Context{
				ServerURL:  dockerURL,
				CertFile:   installed.CertFile,
				KeyFile:    installed.KeyFile,
				CAFile:     installed.CAFile,
				SkipVerify: dockerSkipVerify,
				Strict:     dockerStrict,
			}

			if !dockerNoVerify {
				if err := verifyCLIContext(ctx); err != nil {
					return fmt.Errorf("bootstrap material from %s prepared, but gateway verification failed: %w", sourceHint, err)
				}
			}

			if err := saveContextEntry(dockerContextName, ctx, true); err != nil {
				return err
			}

			fmt.Printf("Configured context %q using bootstrap material from %s\n", dockerContextName, sourceHint)
			fmt.Printf("Active context URL: %s\n", dockerURL)
			fmt.Println("Try running: iket gateway status")
			return nil
		},
	}
	dockerCmd.Flags().StringVar(&dockerContextName, "name", "docker", "Context name to create or update")
	dockerCmd.Flags().StringVar(&dockerURL, "url", "https://localhost:8443", "Gateway URL for the Docker-managed Iket server")
	dockerCmd.Flags().StringVar(&dockerCertDir, "cert-dir", "", "Trusted local server cert directory containing ca.crt and optionally client.crt/client.key")
	dockerCmd.Flags().BoolVar(&dockerStrict, "strict", false, "Enable strict mode for the created context")
	dockerCmd.Flags().BoolVar(&dockerSkipVerify, "skip-verify", false, "Skip server TLS verification")
	dockerCmd.Flags().BoolVar(&dockerNoVerify, "no-verify", false, "Skip the post-import gateway connectivity check")
	setupCmd.AddCommand(dockerCmd)

	rootCmd.AddCommand(setupCmd)
}
