package config

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
	"time"
)

func EnsureTLSAssets(tlsCfg TLSConfig) error {
	if !tlsCfg.Enabled || !tlsCfg.ShouldAutoGenerate() {
		return nil
	}
	if tlsCfg.CertFile == "" || tlsCfg.KeyFile == "" || tlsCfg.ClientCAFile == "" {
		return fmt.Errorf("tls auto-generation requires certFile, keyFile, and clientCAFile")
	}

	certDir := filepath.Dir(tlsCfg.CertFile)
	clientCertPath := filepath.Join(certDir, "client.crt")
	clientKeyPath := filepath.Join(certDir, "client.key")
	serverAssetsExist := fileExists(tlsCfg.CertFile) && fileExists(tlsCfg.KeyFile) && fileExists(tlsCfg.ClientCAFile)
	sharedClientExists := fileExists(clientCertPath) && fileExists(clientKeyPath)

	if serverAssetsExist && (!tlsCfg.ShouldGenerateSharedClient() || sharedClientExists) {
		return nil
	}

	if err := os.MkdirAll(certDir, 0700); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(tlsCfg.KeyFile), 0700); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(tlsCfg.ClientCAFile), 0700); err != nil {
		return err
	}

	caKeyPath := filepath.Join(filepath.Dir(tlsCfg.ClientCAFile), "ca.key")
	caKey, caCert, err := ensureCA(caKeyPath, tlsCfg.ClientCAFile)
	if err != nil {
		return err
	}

	hosts := []string{"localhost", "iket"}
	ips := []net.IP{net.ParseIP("127.0.0.1")}
	if err := ensureSignedCert(tlsCfg.CertFile, tlsCfg.KeyFile, "iket-server", hosts, ips, true, caKey, caCert); err != nil {
		return err
	}
	if tlsCfg.ShouldGenerateSharedClient() {
		if err := ensureSignedCert(clientCertPath, clientKeyPath, "iket", nil, nil, false, caKey, caCert); err != nil {
			return err
		}
	}

	return nil
}

func ensureCA(keyPath, certPath string) (*rsa.PrivateKey, *x509.Certificate, error) {
	if fileExists(keyPath) && fileExists(certPath) {
		return loadCAFromFiles(keyPath, certPath)
	}

	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, nil, err
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Iket CA",
			Organization: []string{"Iket"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	if err := writeRSAPrivateKey(keyPath, key); err != nil {
		return nil, nil, err
	}
	if err := writeCertificate(certPath, certDER); err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, err
	}
	return key, cert, nil
}

func ensureSignedCert(certPath, keyPath, commonName string, hosts []string, ips []net.IP, serverCert bool, caKey *rsa.PrivateKey, caCert *x509.Certificate) error {
	if fileExists(certPath) && fileExists(keyPath) {
		return nil
	}

	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return err
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return err
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{"Iket"},
		},
		NotBefore: time.Now().Add(-1 * time.Hour),
		NotAfter:  time.Now().AddDate(1, 0, 0),
		KeyUsage:  x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}
	if serverCert {
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
		template.DNSNames = hosts
		template.IPAddresses = ips
	} else {
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, &key.PublicKey, caKey)
	if err != nil {
		return err
	}
	if err := writeRSAPrivateKey(keyPath, key); err != nil {
		return err
	}
	return writeCertificate(certPath, certDER)
}

func loadCAFromFiles(keyPath, certPath string) (*rsa.PrivateKey, *x509.Certificate, error) {
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, nil, err
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, nil, fmt.Errorf("invalid ca private key")
	}
	key, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, nil, err
	}

	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, nil, err
	}
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, nil, fmt.Errorf("invalid ca certificate")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, nil, err
	}
	return key, cert, nil
}

func writeRSAPrivateKey(path string, key *rsa.PrivateKey) error {
	block := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}
	return os.WriteFile(path, pem.EncodeToMemory(block), 0600)
}

func writeCertificate(path string, certDER []byte) error {
	block := &pem.Block{Type: "CERTIFICATE", Bytes: certDER}
	return os.WriteFile(path, pem.EncodeToMemory(block), 0644)
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}
