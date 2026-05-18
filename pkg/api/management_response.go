package api

import (
	"encoding/json"
	"errors"
	coreerrors "github.com/bhangun/iket/pkg/core/errors"
	"net/http"
	"strings"
)

// Response structures
type APIResponse struct {
	Success bool        `json:"success"`
	Message string      `json:"message,omitempty"`
	Data    interface{} `json:"data,omitempty"`
}

type ErrorResponse struct {
	Error ErrorDetails `json:"error"`
}

type ErrorDetails struct {
	Code    string                 `json:"code"`
	Message string                 `json:"message"`
	Details map[string]interface{} `json:"details,omitempty"`
}

func gatewayErrorMessage(err error) string {
	if err == nil {
		return ""
	}
	var gatewayErr *coreerrors.GatewayError
	if errors.As(err, &gatewayErr) && gatewayErr != nil && strings.TrimSpace(gatewayErr.Message) != "" {
		return gatewayErr.Message
	}
	return err.Error()
}

func gatewayErrorStatus(err error, fallback int) int {
	if code := coreerrors.CodeOf(err); code != "" {
		return coreerrors.HTTPStatusForCode(code)
	}
	return fallback
}

func gatewayErrorDetails(err error) map[string]interface{} {
	var gatewayErr *coreerrors.GatewayError
	if errors.As(err, &gatewayErr) && gatewayErr != nil && gatewayErr.Details != nil {
		return gatewayErr.Details
	}
	return nil
}

func (api *ManagementAPI) writeManagedError(w http.ResponseWriter, err error, fallbackStatus int) {
	code := coreerrors.CodeOf(err)
	if code == "" {
		code = coreerrors.ResolveCode(gatewayErrorMessage(err), gatewayErrorStatus(err, fallbackStatus))
	}
	api.writeStructuredErrorWithCode(w, code, gatewayErrorMessage(err), gatewayErrorStatus(err, fallbackStatus), gatewayErrorDetails(err))
}

func managedError(code, message string, err error) error {
	return coreerrors.NewCodeError(code, message, err)
}

func managedConfigError(message string, err error) error {
	return coreerrors.NewConfigError(message, err)
}

func managedProposalConflict(message string, err error) error {
	return coreerrors.NewProposalConflictError(message, err)
}

func managedProposalVerificationError(message string, err error) error {
	return coreerrors.NewProposalVerificationError(message, err)
}

func managedCanaryConfigError(message string, err error) error {
	return coreerrors.NewCanaryConfigError(message, err)
}

func managedCanaryStateError(message string, err error) error {
	return coreerrors.NewCanaryStateError(message, err)
}

func managedRequiredFieldError(message string) error {
	return coreerrors.NewRequiredFieldError(message)
}

func managedValidationError(message string, err error) error {
	return managedError(coreerrors.CodeValidationError, message, err)
}

func (api *ManagementAPI) writeJSON(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

func (api *ManagementAPI) writeError(w http.ResponseWriter, message string, statusCode int) {
	api.writeStructuredError(w, message, statusCode, nil)
}

func (api *ManagementAPI) writeStructuredError(w http.ResponseWriter, message string, statusCode int, details map[string]interface{}) {
	api.writeStructuredErrorWithCode(w, coreerrors.ResolveCode(message, statusCode), message, statusCode, details)
}

func (api *ManagementAPI) writeStructuredErrorWithCode(w http.ResponseWriter, code string, message string, statusCode int, details map[string]interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	errorResponse := ErrorResponse{
		Error: ErrorDetails{
			Code:    code,
			Message: message,
			Details: details,
		},
	}

	json.NewEncoder(w).Encode(errorResponse)
}

func getErrorCode(statusCode int) string {
	return coreerrors.ResolveCode("", statusCode)
}
