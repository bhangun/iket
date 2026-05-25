package api

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/bhangun/iket/pkg/config"
	coreerrors "github.com/bhangun/iket/pkg/core/errors"
)

func parseEnrollmentToken(token string) (string, string, error) {
	parts := strings.SplitN(strings.TrimSpace(token), ".", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", coreerrors.New(coreerrors.CodeEnrollmentTokenInvalid, "Invalid enrollment token")
	}
	return parts[0], parts[1], nil
}

func hashEnrollmentSecret(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

func randomHex(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

func loadEnrollmentCA(tlsCfg config.TLSConfig) (*rsa.PrivateKey, *x509.Certificate, []byte, error) {
	if tlsCfg.ClientCAFile == "" {
		return nil, nil, nil, fmt.Errorf("client CA is not configured")
	}
	caPEM, err := os.ReadFile(tlsCfg.ClientCAFile)
	if err != nil {
		return nil, nil, nil, err
	}
	caBlock, _ := pem.Decode(caPEM)
	if caBlock == nil {
		return nil, nil, nil, fmt.Errorf("invalid client CA certificate")
	}
	caCert, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		return nil, nil, nil, err
	}

	caKeyPath := filepath.Join(filepath.Dir(tlsCfg.ClientCAFile), "ca.key")
	caKeyPEM, err := os.ReadFile(caKeyPath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil, nil, fmt.Errorf("ca.key not found next to %s; enrollment requires a locally managed CA", tlsCfg.ClientCAFile)
		}
		return nil, nil, nil, err
	}
	keyBlock, _ := pem.Decode(caKeyPEM)
	if keyBlock == nil {
		return nil, nil, nil, fmt.Errorf("invalid ca private key")
	}
	caKey, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, nil, nil, err
	}
	return caKey, caCert, caPEM, nil
}

func signEnrollmentCSR(csrPEM []byte, commonName string, caKey *rsa.PrivateKey, caCert *x509.Certificate) ([]byte, *x509.Certificate, error) {
	block, _ := pem.Decode(csrPEM)
	if block == nil {
		return nil, nil, fmt.Errorf("invalid csr_pem")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, nil, err
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, nil, err
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{"Iket"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, csr.PublicKey, caKey)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}), cert, nil
}
