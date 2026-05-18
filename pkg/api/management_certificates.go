package api

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/bhangun/iket/pkg/config"
	coreerrors "github.com/bhangun/iket/pkg/core/errors"
	"github.com/bhangun/iket/pkg/core/gateway"
	"github.com/bhangun/iket/pkg/logging"
	"github.com/gorilla/mux"
	"io/fs"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func (api *ManagementAPI) listCertificates(w http.ResponseWriter, r *http.Request) {
	certificates, err := loadManagedCertificates()
	if err != nil {
		api.writeManagedError(w, managedConfigError("Failed to load certificates", err), http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"certificates": certificates,
	}
	api.writeJSON(w, response)
}

func (api *ManagementAPI) uploadCertificate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name    string `json:"name"`
		Type    string `json:"type"`
		CertPEM string `json:"cert_pem"`
		KeyPEM  string `json:"key_pem"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.writeManagedError(w, managedError(coreerrors.CodeCertificateInvalidPayload, "Invalid certificate payload", err), http.StatusBadRequest)
		return
	}
	meta, err := saveManagedCertificate(req.Name, req.Type, req.CertPEM, req.KeyPEM)
	if err != nil {
		api.writeManagedError(w, err, http.StatusBadRequest)
		return
	}

	response := APIResponse{
		Success: true,
		Message: "Certificate uploaded successfully",
		Data: map[string]interface{}{
			"certificate_id": meta["id"],
		},
	}
	api.writeJSON(w, response)
}

func (api *ManagementAPI) createEnrollmentToken(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name      string `json:"name"`
		TTLMinute int    `json:"ttl_minutes"`
		ServerURL string `json:"server_url"`
		EnrollURL string `json:"enroll_url"`
		ClientCN  string `json:"client_cn"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.writeManagedError(w, managedError(coreerrors.CodeEnrollmentTokenInvalidPayload, "Invalid enrollment token payload", err), http.StatusBadRequest)
		return
	}

	if strings.TrimSpace(req.Name) == "" {
		req.Name = "iket-cli"
	}
	if req.TTLMinute <= 0 {
		req.TTLMinute = 15
	}
	if req.TTLMinute > 1440 {
		api.writeManagedError(w, managedValidationError("ttl_minutes must be between 1 and 1440", nil), http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(req.ClientCN) == "" {
		req.ClientCN = sanitizedClientCommonName(req.Name)
	}

	existing, err := listEnrollmentTokenRecords()
	if err != nil {
		api.writeManagedError(w, managedConfigError("Failed to inspect enrollment tokens", err), http.StatusInternalServerError)
		return
	}
	activeCount := 0
	now := time.Now().UTC()
	for _, record := range existing {
		if isActiveEnrollmentToken(record, now) {
			activeCount++
		}
	}
	maxActive := api.gateway.GetConfig().Security.TLS.EffectiveEnrollmentMaxActive()
	if activeCount >= maxActive {
		api.writeManagedError(w, managedError(coreerrors.CodeEnrollmentTokenLimitReached, fmt.Sprintf("active enrollment token limit reached (%d)", maxActive), nil), http.StatusConflict)
		return
	}

	caKey, caCert, caPEM, err := loadEnrollmentCA(api.gateway.GetConfig().Security.TLS)
	if err != nil {
		api.writeManagedError(w, err, http.StatusBadRequest)
		return
	}
	_ = caKey
	_ = caCert

	id, err := randomHex(6)
	if err != nil {
		api.writeManagedError(w, managedConfigError("Failed to generate enrollment token", err), http.StatusInternalServerError)
		return
	}
	secret, err := randomHex(16)
	if err != nil {
		api.writeManagedError(w, managedConfigError("Failed to generate enrollment token", err), http.StatusInternalServerError)
		return
	}

	record := enrollmentTokenRecord{
		ID:        id,
		Name:      req.Name,
		TokenHash: hashEnrollmentSecret(secret),
		CreatedAt: time.Now().UTC(),
		ExpiresAt: time.Now().UTC().Add(time.Duration(req.TTLMinute) * time.Minute),
		ServerURL: strings.TrimSpace(req.ServerURL),
		EnrollURL: strings.TrimSpace(req.EnrollURL),
		ClientCN:  req.ClientCN,
	}
	if err := saveEnrollmentTokenRecord(record); err != nil {
		api.writeManagedError(w, managedConfigError("Failed to persist enrollment token", err), http.StatusInternalServerError)
		return
	}

	api.logger.Info("Enrollment token created",
		logging.String("event", "enrollment_token_created"),
		logging.String("token_id", id),
		logging.String("token_name", req.Name),
		logging.String("client_cn", req.ClientCN),
		logging.String("client_ip", gateway.GetClientIP(r)),
		logging.Int("ttl_minutes", req.TTLMinute),
		logging.Int("active_tokens", activeCount+1),
	)

	api.writeJSON(w, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"id":         id,
			"name":       req.Name,
			"token":      id + "." + secret,
			"expires_at": record.ExpiresAt,
			"server_url": record.ServerURL,
			"enroll_url": record.EnrollURL,
			"client_cn":  record.ClientCN,
			"ca_pem":     string(caPEM),
		},
	})
}

func (api *ManagementAPI) enrollClientCertificate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token     string `json:"token"`
		Name      string `json:"name"`
		CSRPEM    string `json:"csr_pem"`
		ServerURL string `json:"server_url"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.writeManagedError(w, managedError(coreerrors.CodeEnrollmentRequestInvalid, "Invalid enrollment request", err), http.StatusBadRequest)
		return
	}

	id, secret, err := parseEnrollmentToken(req.Token)
	if err != nil {
		api.writeManagedError(w, err, http.StatusBadRequest)
		return
	}
	record, err := loadEnrollmentTokenRecord(id)
	if err != nil {
		api.writeManagedError(w, err, http.StatusNotFound)
		return
	}
	if record.TokenHash != hashEnrollmentSecret(secret) {
		api.writeManagedError(w, managedError(coreerrors.CodeEnrollmentTokenInvalid, "Invalid enrollment token", nil), http.StatusUnauthorized)
		return
	}
	if !record.UsedAt.IsZero() {
		api.writeManagedError(w, managedError(coreerrors.CodeEnrollmentTokenAlreadyUsed, "Enrollment token has already been used", nil), http.StatusConflict)
		return
	}
	if time.Now().UTC().After(record.ExpiresAt) {
		api.writeManagedError(w, managedError(coreerrors.CodeEnrollmentTokenExpired, "Enrollment token has expired", nil), http.StatusUnauthorized)
		return
	}
	if strings.TrimSpace(req.CSRPEM) == "" {
		api.writeManagedError(w, managedRequiredFieldError("csr_pem is required"), http.StatusBadRequest)
		return
	}

	caKey, caCert, caPEM, err := loadEnrollmentCA(api.gateway.GetConfig().Security.TLS)
	if err != nil {
		api.writeManagedError(w, err, http.StatusBadRequest)
		return
	}

	commonName := record.ClientCN
	if commonName == "" {
		commonName = sanitizedClientCommonName(firstNonEmpty(req.Name, record.Name, "iket-cli"))
	}
	certPEM, cert, err := signEnrollmentCSR([]byte(req.CSRPEM), commonName, caKey, caCert)
	if err != nil {
		api.writeManagedError(w, managedError(coreerrors.CodeCSRInvalid, "Failed to sign CSR", err), http.StatusBadRequest)
		return
	}

	record.UsedAt = time.Now().UTC()
	if strings.TrimSpace(req.ServerURL) != "" {
		record.ServerURL = strings.TrimSpace(req.ServerURL)
	}
	if err := saveEnrollmentTokenRecord(*record); err != nil {
		api.writeManagedError(w, managedConfigError("Failed to finalize enrollment token", err), http.StatusInternalServerError)
		return
	}

	api.logger.Info("Enrollment token redeemed",
		logging.String("event", "enrollment_token_redeemed"),
		logging.String("token_id", record.ID),
		logging.String("token_name", record.Name),
		logging.String("client_cn", commonName),
		logging.String("client_ip", gateway.GetClientIP(r)),
	)

	api.writeJSON(w, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"cert_pem":    string(certPEM),
			"ca_pem":      string(caPEM),
			"server_url":  record.ServerURL,
			"subject":     cert.Subject.String(),
			"valid_until": cert.NotAfter,
		},
	})
}

func (api *ManagementAPI) listEnrollmentTokens(w http.ResponseWriter, r *http.Request) {
	records, err := listEnrollmentTokenRecords()
	if err != nil {
		api.writeManagedError(w, managedConfigError("Failed to list enrollment tokens", err), http.StatusInternalServerError)
		return
	}
	now := time.Now().UTC()
	items := make([]map[string]interface{}, 0, len(records))
	activeCount := 0
	for _, record := range records {
		active := isActiveEnrollmentToken(record, now)
		if active {
			activeCount++
		}
		items = append(items, map[string]interface{}{
			"id":         record.ID,
			"name":       record.Name,
			"created_at": record.CreatedAt,
			"expires_at": record.ExpiresAt,
			"used_at":    record.UsedAt,
			"server_url": record.ServerURL,
			"enroll_url": record.EnrollURL,
			"client_cn":  record.ClientCN,
			"active":     active,
		})
	}
	api.writeJSON(w, map[string]interface{}{
		"tokens":             items,
		"active_count":       activeCount,
		"max_active_allowed": api.gateway.GetConfig().Security.TLS.EffectiveEnrollmentMaxActive(),
	})
}

func (api *ManagementAPI) revokeEnrollmentToken(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	record, err := loadEnrollmentTokenRecord(id)
	if err != nil {
		api.writeManagedError(w, err, http.StatusNotFound)
		return
	}
	if err := deleteEnrollmentTokenRecord(id); err != nil {
		api.writeManagedError(w, managedConfigError("Failed to revoke enrollment token", err), http.StatusInternalServerError)
		return
	}

	api.logger.Info("Enrollment token revoked",
		logging.String("event", "enrollment_token_revoked"),
		logging.String("token_id", id),
		logging.String("token_name", record.Name),
		logging.String("client_ip", gateway.GetClientIP(r)),
	)

	api.writeJSON(w, APIResponse{
		Success: true,
		Message: "Enrollment token revoked",
		Data: map[string]interface{}{
			"id":   id,
			"name": record.Name,
		},
	})
}

func (api *ManagementAPI) deleteCertificate(w http.ResponseWriter, r *http.Request) {
	if err := deleteManagedCertificate(mux.Vars(r)["id"]); err != nil {
		api.writeManagedError(w, err, http.StatusNotFound)
		return
	}

	response := APIResponse{
		Success: true,
		Message: "Certificate deleted successfully",
	}
	api.writeJSON(w, response)
}

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
