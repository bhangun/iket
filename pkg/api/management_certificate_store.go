package api

import (
	"crypto/sha1"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	coreerrors "github.com/bhangun/iket/pkg/core/errors"
)

type enrollmentTokenRecord struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	TokenHash string    `json:"token_hash"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	UsedAt    time.Time `json:"used_at,omitempty"`
	ServerURL string    `json:"server_url,omitempty"`
	EnrollURL string    `json:"enroll_url,omitempty"`
	ClientCN  string    `json:"client_cn,omitempty"`
}

func loadManagedCertificates() ([]map[string]interface{}, error) {
	if err := os.MkdirAll(certificatesDir(), 0755); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(certificatesDir())
	if err != nil {
		return nil, err
	}
	out := make([]map[string]interface{}, 0)
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(certificatesDir(), entry.Name()))
		if err != nil {
			continue
		}
		var meta map[string]interface{}
		if err := json.Unmarshal(data, &meta); err == nil {
			out = append(out, meta)
		}
	}
	return out, nil
}

func saveManagedCertificate(name, certType, certPEM, keyPEM string) (map[string]interface{}, error) {
	if name == "" || certPEM == "" {
		return nil, fmt.Errorf("name and cert_pem are required")
	}
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return nil, fmt.Errorf("invalid cert_pem")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("invalid certificate: %w", err)
	}
	if err := os.MkdirAll(certificatesDir(), 0755); err != nil {
		return nil, err
	}
	sum := sha1.Sum([]byte(name + cert.Subject.String() + time.Now().String()))
	id := fmt.Sprintf("%x", sum[:6])
	meta := map[string]interface{}{
		"id":          id,
		"name":        name,
		"type":        certType,
		"subject":     cert.Subject.String(),
		"issuer":      cert.Issuer.String(),
		"valid_from":  cert.NotBefore,
		"valid_until": cert.NotAfter,
		"status":      "valid",
		"cert_pem":    certPEM,
	}
	if keyPEM != "" {
		meta["key_pem"] = keyPEM
	}
	data, _ := json.MarshalIndent(meta, "", "  ")
	if err := os.WriteFile(filepath.Join(certificatesDir(), id+".json"), data, 0644); err != nil {
		return nil, err
	}
	return meta, nil
}

func deleteManagedCertificate(id string) error {
	path := filepath.Join(certificatesDir(), id+".json")
	if _, err := os.Stat(path); err != nil {
		return coreerrors.New(coreerrors.CodeCertificateNotFound, "Certificate not found")
	}
	return os.Remove(path)
}

func saveEnrollmentTokenRecord(record enrollmentTokenRecord) error {
	if err := os.MkdirAll(enrollmentTokensDir(), 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(enrollmentTokensDir(), record.ID+".json"), data, 0600)
}

func loadEnrollmentTokenRecord(id string) (*enrollmentTokenRecord, error) {
	data, err := os.ReadFile(filepath.Join(enrollmentTokensDir(), id+".json"))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, coreerrors.New(coreerrors.CodeEnrollmentTokenNotFound, "Enrollment token not found")
		}
		return nil, err
	}
	var record enrollmentTokenRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return nil, err
	}
	return &record, nil
}

func listEnrollmentTokenRecords() ([]enrollmentTokenRecord, error) {
	if err := os.MkdirAll(enrollmentTokensDir(), 0700); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(enrollmentTokensDir())
	if err != nil {
		return nil, err
	}
	out := make([]enrollmentTokenRecord, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(enrollmentTokensDir(), entry.Name()))
		if err != nil {
			continue
		}
		var record enrollmentTokenRecord
		if err := json.Unmarshal(data, &record); err == nil {
			out = append(out, record)
		}
	}
	return out, nil
}

func deleteEnrollmentTokenRecord(id string) error {
	path := filepath.Join(enrollmentTokensDir(), id+".json")
	if _, err := os.Stat(path); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return coreerrors.New(coreerrors.CodeEnrollmentTokenNotFound, "Enrollment token not found")
		}
		return err
	}
	return os.Remove(path)
}

func isActiveEnrollmentToken(record enrollmentTokenRecord, now time.Time) bool {
	return record.UsedAt.IsZero() && now.Before(record.ExpiresAt)
}
