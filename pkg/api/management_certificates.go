package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	coreerrors "github.com/bhangun/iket/pkg/core/errors"
	"github.com/bhangun/iket/pkg/core/gateway"
	"github.com/bhangun/iket/pkg/logging"
	"github.com/gorilla/mux"
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
		req.Name = "iket"
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
	tlsCfg, err := api.enrollmentTLSConfig()
	if err != nil {
		api.writeManagedError(w, err, http.StatusInternalServerError)
		return
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
	maxActive := tlsCfg.EffectiveEnrollmentMaxActive()
	if activeCount >= maxActive {
		api.writeManagedError(w, managedError(coreerrors.CodeEnrollmentTokenLimitReached, fmt.Sprintf("active enrollment token limit reached (%d)", maxActive), nil), http.StatusConflict)
		return
	}

	caKey, caCert, caPEM, err := loadEnrollmentCA(tlsCfg)
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
	tlsCfg, err := api.enrollmentTLSConfig()
	if err != nil {
		api.writeManagedError(w, err, http.StatusInternalServerError)
		return
	}

	caKey, caCert, caPEM, err := loadEnrollmentCA(tlsCfg)
	if err != nil {
		api.writeManagedError(w, err, http.StatusBadRequest)
		return
	}

	commonName := record.ClientCN
	if commonName == "" {
		commonName = sanitizedClientCommonName(firstNonEmpty(req.Name, record.Name, "iket"))
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
	tlsCfg, err := api.enrollmentTLSConfig()
	if err != nil {
		api.writeManagedError(w, err, http.StatusInternalServerError)
		return
	}
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
		"max_active_allowed": tlsCfg.EffectiveEnrollmentMaxActive(),
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
