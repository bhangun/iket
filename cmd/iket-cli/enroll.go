package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

type enrollmentBundle struct {
	Token     string `json:"token"`
	ServerURL string `json:"server_url"`
	EnrollURL string `json:"enroll_url"`
	ClientCN  string `json:"client_cn"`
	CAPEM     string `json:"ca_pem"`
	ExpiresAt string `json:"expires_at"`
}

func initEnrollCmd(rootCmd *cobra.Command) {
	enrollCmd := &cobra.Command{
		Use:   "enroll",
		Short: "Bootstrap direct admin access with a one-time enrollment token",
	}

	var (
		tokenName      string
		tokenTTL       int
		tokenServerURL string
		tokenEnrollURL string
		tokenClientCN  string
		tokenOutput    string
	)
	createTokenCmd := &cobra.Command{
		Use:   "create-token",
		Short: "Create a short-lived enrollment token using the current admin context",
		RunE: func(cmd *cobra.Command, args []string) error {
			client, ctx, err := loadAPIClientFromCurrentContext()
			if err != nil {
				return err
			}

			if strings.TrimSpace(tokenServerURL) == "" {
				tokenServerURL = ctx.ServerURL
			}
			if strings.TrimSpace(tokenEnrollURL) == "" {
				tokenEnrollURL = inferEnrollURL(ctx.ServerURL)
			}

			resp, err := client.Do("POST", "/api/v1/enrollment/tokens", map[string]interface{}{
				"name":        tokenName,
				"ttl_minutes": tokenTTL,
				"server_url":  tokenServerURL,
				"enroll_url":  tokenEnrollURL,
				"client_cn":   tokenClientCN,
			})
			if err != nil {
				return err
			}

			if tokenOutput != "" {
				var payload interface{}
				if err := json.Unmarshal(resp, &payload); err != nil {
					return err
				}
				data, err := json.MarshalIndent(payload, "", "  ")
				if err != nil {
					return err
				}
				if err := os.WriteFile(tokenOutput, data, 0600); err != nil {
					return err
				}
				fmt.Printf("Enrollment token saved to %s\n", tokenOutput)
			}
			printResponse(resp)
			return nil
		},
	}
	createTokenCmd.Flags().StringVar(&tokenName, "name", "laptop-admin", "Friendly name for the enrollment token")
	createTokenCmd.Flags().IntVar(&tokenTTL, "ttl-minutes", 15, "Token lifetime in minutes")
	createTokenCmd.Flags().StringVar(&tokenServerURL, "server-url", "", "Server URL to embed in the token bundle")
	createTokenCmd.Flags().StringVar(&tokenEnrollURL, "enroll-url", "", "Enrollment URL to embed in the token bundle")
	createTokenCmd.Flags().StringVar(&tokenClientCN, "client-cn", "", "Common name to use for the issued client certificate")
	createTokenCmd.Flags().StringVar(&tokenOutput, "out", "", "Write the token bundle JSON to a file")

	listTokensCmd := &cobra.Command{
		Use:   "list-tokens",
		Short: "List active and historical enrollment tokens",
		RunE: func(cmd *cobra.Command, args []string) error {
			client, _, err := loadAPIClientFromCurrentContext()
			if err != nil {
				return err
			}
			resp, err := client.Do("GET", "/api/v1/enrollment/tokens", nil)
			if err != nil {
				return err
			}
			printResponse(resp)
			return nil
		},
	}

	revokeTokenCmd := &cobra.Command{
		Use:   "revoke-token [id]",
		Short: "Revoke an enrollment token by id",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, _, err := loadAPIClientFromCurrentContext()
			if err != nil {
				return err
			}
			resp, err := client.Do("DELETE", "/api/v1/enrollment/tokens/"+url.PathEscape(args[0]), nil)
			if err != nil {
				return err
			}
			printResponse(resp)
			return nil
		},
	}

	var (
		useContextName string
		useToken       string
		useTokenFile   string
		useServerURL   string
		useActivate    bool
	)
	useCmd := &cobra.Command{
		Use:   "use",
		Short: "Redeem an enrollment token and create a local CLI context",
		RunE: func(cmd *cobra.Command, args []string) error {
			bundle, err := loadEnrollmentBundle(useToken, useTokenFile)
			if err != nil {
				return err
			}
			if strings.TrimSpace(useServerURL) != "" {
				bundle.ServerURL = useServerURL
			}
			if bundle.EnrollURL == "" {
				return fmt.Errorf("enroll_url is required")
			}
			if bundle.Token == "" {
				return fmt.Errorf("token is required")
			}

			keyPEM, csrPEM, err := generateClientCSR(firstNonEmptyString(bundle.ClientCN, useContextName))
			if err != nil {
				return err
			}

			respData, err := redeemEnrollment(bundle, csrPEM)
			if err != nil {
				return err
			}

			installed, err := writeManagedContextCerts(useContextName, respData.CAPEM, respData.CertPEM, keyPEM)
			if err != nil {
				return err
			}
			ctx := Context{
				ServerURL:  firstNonEmptyString(respData.ServerURL, bundle.ServerURL),
				CAFile:     installed.CAFile,
				CertFile:   installed.CertFile,
				KeyFile:    installed.KeyFile,
				SkipVerify: false,
			}
			if err := saveContextEntry(useContextName, ctx, useActivate); err != nil {
				return err
			}
			if err := verifyCLIContext(ctx); err != nil {
				return fmt.Errorf("enrollment succeeded but gateway verification failed: %w", err)
			}

			fmt.Printf("Enrolled context %q\n", useContextName)
			fmt.Printf("Server URL: %s\n", ctx.ServerURL)
			return nil
		},
	}
	useCmd.Flags().StringVar(&useContextName, "name", "remote", "Context name to create or update")
	useCmd.Flags().StringVar(&useToken, "token", "", "Raw enrollment token")
	useCmd.Flags().StringVar(&useTokenFile, "file", "", "Path to an enrollment token bundle JSON file")
	useCmd.Flags().StringVar(&useServerURL, "server-url", "", "Override the stored server URL")
	useCmd.Flags().BoolVar(&useActivate, "activate", true, "Set the enrolled context as the active context")

	enrollCmd.AddCommand(createTokenCmd, listTokensCmd, revokeTokenCmd, useCmd)
	rootCmd.AddCommand(enrollCmd)
}

func loadAPIClientFromCurrentContext() (*APIClient, Context, error) {
	cfg, err := loadCLIConfig()
	if err != nil {
		return nil, Context{}, err
	}
	ctx := cfg.GetCurrentContext()
	client, err := NewAPIClient(ctx.ServerURL, ctx.SkipVerify, ctx.CAFile, ctx.CertFile, ctx.KeyFile)
	if err != nil {
		return nil, Context{}, err
	}
	return client, ctx, nil
}

func inferEnrollURL(serverURL string) string {
	parsed, err := url.Parse(serverURL)
	if err != nil || parsed.Host == "" {
		return "https://localhost:9443/api/v1/enroll"
	}
	host := parsed.Hostname()
	if host == "" {
		host = "localhost"
	}
	return fmt.Sprintf("https://%s:9443/api/v1/enroll", host)
}

func loadEnrollmentBundle(rawToken, tokenFile string) (enrollmentBundle, error) {
	if strings.TrimSpace(rawToken) != "" && strings.TrimSpace(tokenFile) != "" {
		return enrollmentBundle{}, fmt.Errorf("--token and --file cannot be combined")
	}
	if strings.TrimSpace(tokenFile) != "" {
		data, err := os.ReadFile(tokenFile)
		if err != nil {
			return enrollmentBundle{}, err
		}
		var wrapper struct {
			Data enrollmentBundle `json:"data"`
		}
		if err := json.Unmarshal(data, &wrapper); err == nil && wrapper.Data.Token != "" {
			return wrapper.Data, nil
		}
		var direct enrollmentBundle
		if err := json.Unmarshal(data, &direct); err != nil {
			return enrollmentBundle{}, err
		}
		return direct, nil
	}
	if strings.TrimSpace(rawToken) == "" {
		return enrollmentBundle{}, fmt.Errorf("either --token or --file is required")
	}
	return enrollmentBundle{Token: strings.TrimSpace(rawToken)}, nil
}

func generateClientCSR(commonName string) (string, string, error) {
	if commonName == "" {
		commonName = "iket"
	}
	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return "", "", err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{"Iket"},
		},
	}, key)
	if err != nil {
		return "", "", err
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	return string(keyPEM), string(csrPEM), nil
}

type enrollmentRedeemResponse struct {
	CertPEM   string `json:"cert_pem"`
	CAPEM     string `json:"ca_pem"`
	ServerURL string `json:"server_url"`
}

func redeemEnrollment(bundle enrollmentBundle, csrPEM string) (enrollmentRedeemResponse, error) {
	payload := map[string]interface{}{
		"token":      bundle.Token,
		"csr_pem":    csrPEM,
		"server_url": bundle.ServerURL,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return enrollmentRedeemResponse{}, err
	}

	req, err := http.NewRequest(http.MethodPost, bundle.EnrollURL, bytes.NewReader(body))
	if err != nil {
		return enrollmentRedeemResponse{}, err
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	if strings.HasPrefix(strings.ToLower(bundle.EnrollURL), "https://") {
		tlsConfig := &tls.Config{}
		if bundle.CAPEM != "" {
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM([]byte(bundle.CAPEM)) {
				return enrollmentRedeemResponse{}, fmt.Errorf("failed to parse ca_pem from token bundle")
			}
			tlsConfig.RootCAs = pool
		}
		client.Transport = &http.Transport{TLSClientConfig: tlsConfig}
	}

	resp, err := client.Do(req)
	if err != nil {
		return enrollmentRedeemResponse{}, err
	}
	defer resp.Body.Close()

	var wrapper struct {
		Data  enrollmentRedeemResponse `json:"data"`
		Error struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&wrapper); err != nil {
		return enrollmentRedeemResponse{}, err
	}
	if resp.StatusCode >= 400 {
		if wrapper.Error.Message != "" {
			return enrollmentRedeemResponse{}, fmt.Errorf(wrapper.Error.Message)
		}
		return enrollmentRedeemResponse{}, fmt.Errorf("enrollment failed with status %d", resp.StatusCode)
	}
	return wrapper.Data, nil
}

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}
