package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

var (
	certDir        string
	caDir          string
	serverHostname string
	serverIP       string
	caDays         int
	certDays       int
	keySize        int
)

func initCertCmd(rootCmd *cobra.Command) {
	certCmd := &cobra.Command{
		Use:   "cert",
		Short: "Certificate management",
		Long:  `Generate, verify, and manage mTLS certificates for Iket components.`,
	}

	// Generate certificates
	genCmd := &cobra.Command{
		Use:   "gen [component]",
		Short: "Generate certificates",
		Long: `Generate mTLS certificates for Iket components.

Component can be:
  - (empty)    : Generate all certificates (CA + server + client)
  - ca         : Generate only CA certificate
  - server     : Generate server certificate (requires existing CA)
  - client     : Generate CLI client certificate (requires existing CA)

Examples:
  # Generate all certificates for development
  iket cert gen

  # Generate all certificates with custom hostnames
  iket cert gen --server-hostname iket.example.com --server-ip 192.168.1.100

  # Generate only client certificate
  iket cert gen client
`,
		Args: cobra.MaximumNArgs(1),
		RunE: runCertGen,
	}

	genCmd.Flags().StringVar(&certDir, "cert-dir", "", "Certificate output directory (default: ~/.iket/certs)")
	genCmd.Flags().StringVar(&caDir, "ca-dir", "", "CA directory (default: same as cert-dir)")
	genCmd.Flags().StringVar(&serverHostname, "server-hostname", "localhost", "Server hostname")
	genCmd.Flags().StringVar(&serverIP, "server-ip", "127.0.0.1", "Server IP address")
	genCmd.Flags().IntVar(&caDays, "ca-days", 3650, "CA certificate validity in days")
	genCmd.Flags().IntVar(&certDays, "cert-days", 365, "Server/client certificate validity in days")
	genCmd.Flags().IntVar(&keySize, "key-size", 4096, "RSA key size in bits")

	certCmd.AddCommand(genCmd)

	// Certificate status
	statusCmd := &cobra.Command{
		Use:   "status",
		Short: "Show certificate status",
		RunE:  runCertStatus,
	}
	statusCmd.Flags().StringVar(&certDir, "cert-dir", "", "Certificate directory")
	certCmd.AddCommand(statusCmd)

	var (
		importContextName string
		importURL         string
		importCertDir     string
		importStrict      bool
		importSkipVerify  bool
		importNoVerify    bool
		importActivate    bool
	)
	importCmd := &cobra.Command{
		Use:   "import",
		Short: "Import a client certificate bundle into a CLI context",
		Long:  "Copy ca.crt, client.crt, and client.key into ~/.iket/certs/contexts and create or update a matching CLI context.",
		RunE: func(cmd *cobra.Command, args []string) error {
			var err error
			importURL, err = normalizeAdminURL(importURL)
			if err != nil {
				return err
			}

			if strings.TrimSpace(importCertDir) != "" {
				fmt.Printf("Inspecting certificate directory: %s\n", describeCertMaterial(importCertDir))
			}

			bundle, err := discoverCertBundle(importCertDir)
			if err != nil {
				return err
			}

			installed, err := installCertBundle(importContextName, bundle)
			if err != nil {
				return err
			}

			cfg, err := loadCLIConfig()
			if err != nil {
				return err
			}

			ctx := cfg.Contexts[importContextName]
			if strings.TrimSpace(importURL) != "" {
				ctx.ServerURL = importURL
			}
			if ctx.ServerURL == "" {
				ctx.ServerURL = "https://localhost:8443"
			}
			ctx.CAFile = installed.CAFile
			ctx.CertFile = installed.CertFile
			ctx.KeyFile = installed.KeyFile
			ctx.SkipVerify = importSkipVerify
			ctx.Strict = importStrict

			if !importNoVerify {
				if err := verifyCLIContext(ctx); err != nil {
					return fmt.Errorf("certificates imported from %s, but gateway verification failed: %w", bundle.SourceHint, err)
				}
			}

			if err := saveContextEntry(importContextName, ctx, importActivate); err != nil {
				return err
			}

			fmt.Printf("Imported certificates from %s into context %q\n", bundle.SourceHint, importContextName)
			fmt.Printf("Stored managed CLI certificates in %s\n", filepath.Dir(installed.CAFile))
			fmt.Printf("Context URL: %s\n", ctx.ServerURL)
			return nil
		},
	}
	importCmd.Flags().StringVar(&importContextName, "name", "docker", "Context name to create or update")
	importCmd.Flags().StringVar(&importURL, "url", "", "Gateway URL to store on the context (defaults to existing value or https://localhost:8443)")
	importCmd.Flags().StringVar(&importCertDir, "cert-dir", "", "Directory containing ca.crt, client.crt, and client.key")
	importCmd.Flags().BoolVar(&importStrict, "strict", false, "Enable strict mode on the stored context")
	importCmd.Flags().BoolVar(&importSkipVerify, "skip-verify", false, "Skip server TLS verification")
	importCmd.Flags().BoolVar(&importNoVerify, "no-verify", false, "Skip the post-import gateway connectivity check")
	importCmd.Flags().BoolVar(&importActivate, "activate", true, "Set the imported context as the active context")
	certCmd.AddCommand(importCmd)

	rootCmd.AddCommand(certCmd)
}

func getDefaultCertDir() string {
	if certDir != "" {
		return certDir
	}
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "./certs"
	}
	return filepath.Join(homeDir, ".iket", "certs")
}

func getDefaultCADir() string {
	if caDir != "" {
		return caDir
	}
	return getDefaultCertDir()
}

func runCertGen(cmd *cobra.Command, args []string) error {
	component := ""
	if len(args) > 0 {
		component = args[0]
	}

	certDir := getDefaultCertDir()
	caDir := getDefaultCADir()

	if err := os.MkdirAll(certDir, 0700); err != nil {
		return err
	}
	if caDir != certDir {
		if err := os.MkdirAll(caDir, 0700); err != nil {
			return err
		}
	}

	switch component {
	case "":
		return generateAllCerts(certDir, caDir)
	case "ca":
		return generateCA(caDir)
	case "server":
		return generateServerCert(certDir, caDir)
	case "client":
		return generateClientCert(certDir, caDir)
	default:
		return fmt.Errorf("unknown component: %s", component)
	}
}

func generateAllCerts(certDir, caDir string) error {
	if err := generateCA(caDir); err != nil {
		return err
	}
	if err := generateServerCert(certDir, caDir); err != nil {
		return err
	}
	return generateClientCert(certDir, caDir)
}

func generateCA(caDir string) error {
	fmt.Println("Generating CA certificate...")
	key, err := rsa.GenerateKey(rand.Reader, keySize)
	if err != nil {
		return err
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if err := os.WriteFile(filepath.Join(caDir, "ca.key"), keyPEM, 0600); err != nil {
		return err
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Iket CA",
			Organization: []string{"Iket"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(0, 0, caDays),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	return os.WriteFile(filepath.Join(caDir, "ca.crt"), certPEM, 0644)
}

func generateServerCert(certDir, caDir string) error {
	fmt.Printf("Generating server certificate for %s (%s)...\n", serverHostname, serverIP)
	return generateCert(certDir, caDir, "server", serverHostname, serverIP, true)
}

func generateClientCert(certDir, caDir string) error {
	fmt.Println("Generating client certificate...")
	return generateCert(certDir, caDir, "client", "iket", "", false)
}

func generateCert(certDir, caDir, name, hostname, ip string, isServer bool) error {
	caKey, caCert, err := loadCA(caDir)
	if err != nil {
		return err
	}

	key, err := rsa.GenerateKey(rand.Reader, keySize)
	if err != nil {
		return err
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName:   fmt.Sprintf("iket-%s", name),
			Organization: []string{"Iket"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().AddDate(0, 0, certDays),
		KeyUsage:  x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}

	if isServer {
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
		template.DNSNames = []string{hostname, "localhost"}
		if ip != "" {
			template.IPAddresses = []net.IP{net.ParseIP(ip), net.ParseIP("127.0.0.1")}
		}
	} else {
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, &key.PublicKey, caKey)
	if err != nil {
		return err
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if err := os.WriteFile(filepath.Join(certDir, name+".key"), keyPEM, 0600); err != nil {
		return err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	return os.WriteFile(filepath.Join(certDir, name+".crt"), certPEM, 0644)
}

func loadCA(caDir string) (*rsa.PrivateKey, *x509.Certificate, error) {
	keyPEM, err := os.ReadFile(filepath.Join(caDir, "ca.key"))
	if err != nil {
		return nil, nil, err
	}
	block, _ := pem.Decode(keyPEM)
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, nil, err
	}

	certPEM, err := os.ReadFile(filepath.Join(caDir, "ca.crt"))
	if err != nil {
		return nil, nil, err
	}
	block, _ = pem.Decode(certPEM)
	cert, err := x509.ParseCertificate(block.Bytes)
	return key, cert, err
}

func runCertStatus(cmd *cobra.Command, args []string) error {
	dir := getDefaultCertDir()
	fmt.Printf("Certificates in %s:\n", dir)
	files, _ := os.ReadDir(dir)
	for _, f := range files {
		fmt.Printf("  - %s\n", f.Name())
	}
	return nil
}
