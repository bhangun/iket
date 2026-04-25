package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type certBundle struct {
	Dir        string
	CAFile     string
	CertFile   string
	KeyFile    string
	SourceHint string
}

func expandPath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}
	if path == "~" || strings.HasPrefix(path, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			if path == "~" {
				return home
			}
			return filepath.Join(home, path[2:])
		}
	}
	return path
}

func absolutePath(path string) string {
	path = expandPath(path)
	if path == "" {
		return ""
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return path
	}
	return abs
}

func candidateCertDirs(explicitDir string) []string {
	seen := map[string]struct{}{}
	var candidates []string
	add := func(path string) {
		path = absolutePath(path)
		if path == "" {
			return
		}
		if _, ok := seen[path]; ok {
			return
		}
		seen[path] = struct{}{}
		candidates = append(candidates, path)
	}

	add(explicitDir)
	add(os.Getenv("IKET_CERTS_DIR"))
	add(getDefaultCertDir())
	add("./certs")
	add("../certs")
	add("/app/certs")

	if wd, err := os.Getwd(); err == nil {
		add(filepath.Join(wd, "certs"))
		add(filepath.Join(wd, "..", "certs"))
	}

	return candidates
}

func discoverCertBundleInDirs(candidates []string) (certBundle, error) {
	var tried []string
	for _, dir := range candidates {
		if dir == "" {
			continue
		}
		tried = append(tried, dir)

		info, err := os.Stat(dir)
		if err != nil || !info.IsDir() {
			continue
		}

		bundle := certBundle{
			Dir:      dir,
			CAFile:   filepath.Join(dir, "ca.crt"),
			CertFile: filepath.Join(dir, "client.crt"),
			KeyFile:  filepath.Join(dir, "client.key"),
		}
		if fileExists(bundle.CAFile) && fileExists(bundle.CertFile) && fileExists(bundle.KeyFile) {
			bundle.SourceHint = dir
			return bundle, nil
		}
	}

	if len(tried) == 0 {
		return certBundle{}, fmt.Errorf("no certificate directories configured")
	}
	return certBundle{}, fmt.Errorf("no usable client certificate bundle found in: %s", strings.Join(tried, ", "))
}

func discoverCertBundle(explicitDir string) (certBundle, error) {
	return discoverCertBundleInDirs(candidateCertDirs(explicitDir))
}

func discoverCADir(explicitDir string) (string, error) {
	candidates := candidateCertDirs(explicitDir)
	var tried []string
	for _, dir := range candidates {
		if dir == "" {
			continue
		}
		tried = append(tried, dir)
		if fileExists(filepath.Join(dir, "ca.crt")) && fileExists(filepath.Join(dir, "ca.key")) {
			return dir, nil
		}
	}
	if len(tried) == 0 {
		return "", fmt.Errorf("no certificate directories configured")
	}
	return "", fmt.Errorf("no usable CA material found in: %s", strings.Join(tried, ", "))
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func validateOptionalFile(path string, label string) (string, error) {
	path = absolutePath(path)
	if path == "" {
		return "", nil
	}
	if !fileExists(path) {
		return "", fmt.Errorf("%s file not found: %s", label, path)
	}
	return path, nil
}

func sanitizedContextName(name string) string {
	name = strings.TrimSpace(strings.ToLower(name))
	if name == "" {
		return "default"
	}
	var b strings.Builder
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '-' || r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		return "default"
	}
	return out
}

func managedCertDirForContext(name string) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".iket", "certs", "contexts", sanitizedContextName(name)), nil
}

func copyFile(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	defer out.Close()

	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return out.Close()
}

func installCertBundle(name string, bundle certBundle) (Context, error) {
	targetDir, err := managedCertDirForContext(name)
	if err != nil {
		return Context{}, err
	}
	if err := os.MkdirAll(targetDir, 0700); err != nil {
		return Context{}, err
	}

	caPath := filepath.Join(targetDir, "ca.crt")
	certPath := filepath.Join(targetDir, "client.crt")
	keyPath := filepath.Join(targetDir, "client.key")

	if err := copyFile(bundle.CAFile, caPath, 0644); err != nil {
		return Context{}, fmt.Errorf("copy ca certificate: %w", err)
	}
	if err := copyFile(bundle.CertFile, certPath, 0644); err != nil {
		return Context{}, fmt.Errorf("copy client certificate: %w", err)
	}
	if err := copyFile(bundle.KeyFile, keyPath, 0600); err != nil {
		return Context{}, fmt.Errorf("copy client key: %w", err)
	}

	return Context{
		CAFile:   caPath,
		CertFile: certPath,
		KeyFile:  keyPath,
	}, nil
}

func writeManagedContextCerts(name, caPEM, certPEM, keyPEM string) (Context, error) {
	targetDir, err := managedCertDirForContext(name)
	if err != nil {
		return Context{}, err
	}
	if err := os.MkdirAll(targetDir, 0700); err != nil {
		return Context{}, err
	}

	caPath := filepath.Join(targetDir, "ca.crt")
	certPath := filepath.Join(targetDir, "client.crt")
	keyPath := filepath.Join(targetDir, "client.key")

	if err := os.WriteFile(caPath, []byte(caPEM), 0644); err != nil {
		return Context{}, err
	}
	if err := os.WriteFile(certPath, []byte(certPEM), 0644); err != nil {
		return Context{}, err
	}
	if err := os.WriteFile(keyPath, []byte(keyPEM), 0600); err != nil {
		return Context{}, err
	}

	return Context{
		CAFile:   caPath,
		CertFile: certPath,
		KeyFile:  keyPath,
	}, nil
}

func issueManagedContextCertFromCA(name, caDir, commonName string) (Context, error) {
	caKey, caCert, err := loadCA(caDir)
	if err != nil {
		return Context{}, err
	}
	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return Context{}, err
	}
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return Context{}, err
	}
	if strings.TrimSpace(commonName) == "" {
		commonName = "iket"
	}
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{"Iket"},
		},
		NotBefore:   time.Now().Add(-1 * time.Hour),
		NotAfter:    time.Now().AddDate(1, 0, 0),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, &key.PublicKey, caKey)
	if err != nil {
		return Context{}, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	caPEMBytes, err := os.ReadFile(filepath.Join(caDir, "ca.crt"))
	if err != nil {
		return Context{}, err
	}
	return writeManagedContextCerts(name, string(caPEMBytes), string(certPEM), string(keyPEM))
}

func saveContextEntry(name string, ctx Context, activate bool) error {
	cfg, err := loadCLIConfig()
	if err != nil {
		return err
	}
	cfg.Contexts[name] = ctx
	if activate || cfg.CurrentContext == "" || len(cfg.Contexts) == 1 {
		cfg.CurrentContext = name
	}
	return saveCLIConfig(cfg)
}

func verifyCLIContext(ctx Context) error {
	client, err := NewAPIClient(ctx.ServerURL, ctx.SkipVerify, ctx.CAFile, ctx.CertFile, ctx.KeyFile)
	if err != nil {
		return err
	}
	_, err = client.Do("GET", "/api/v1/gateway/status", nil)
	return err
}
