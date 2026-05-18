package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	coreerrors "github.com/bhangun/iket/pkg/core/errors"
	"github.com/bhangun/iket/pkg/core/errors/errortest"
)

func TestWriteErrorResolvesSpecificIketCodes(t *testing.T) {
	tests := []struct {
		name       string
		message    string
		statusCode int
		wantCode   string
	}{
		{name: "plugin", message: "Plugin not found", statusCode: http.StatusNotFound, wantCode: coreerrors.CodePluginNotFound},
		{name: "proposal", message: "proposal is already approved", statusCode: http.StatusConflict, wantCode: coreerrors.CodeProposalStateConflict},
		{name: "enrollment", message: "Enrollment token has expired", statusCode: http.StatusUnauthorized, wantCode: coreerrors.CodeEnrollmentTokenExpired},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()

			var api *ManagementAPI
			api.writeError(recorder, tc.message, tc.statusCode)

			if recorder.Code != tc.statusCode {
				t.Fatalf("expected status %d, got %d", tc.statusCode, recorder.Code)
			}

			var response ErrorResponse
			if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
				t.Fatalf("failed to decode response: %v", err)
			}
			if response.Error.Code != tc.wantCode {
				t.Fatalf("expected code %s, got %s", tc.wantCode, response.Error.Code)
			}
			if response.Error.Message != tc.message {
				t.Fatalf("expected message %q, got %q", tc.message, response.Error.Message)
			}
		})
	}
}

func TestWriteManagedErrorUsesTypedGatewayErrorMetadata(t *testing.T) {
	recorder := httptest.NewRecorder()

	var api *ManagementAPI
	api.writeManagedError(recorder, coreerrors.New(coreerrors.CodeProposalNotFound, "Proposal not found"), http.StatusInternalServerError)

	if recorder.Code != http.StatusNotFound {
		t.Fatalf("expected status %d, got %d", http.StatusNotFound, recorder.Code)
	}

	var response ErrorResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if response.Error.Code != coreerrors.CodeProposalNotFound {
		t.Fatalf("expected code %s, got %s", coreerrors.CodeProposalNotFound, response.Error.Code)
	}
	if response.Error.Message != "Proposal not found" {
		t.Fatalf("expected clean message, got %q", response.Error.Message)
	}
}

func TestWriteManagedErrorIncludesTypedDetails(t *testing.T) {
	recorder := httptest.NewRecorder()
	err := coreerrors.New(coreerrors.CodeForbidden, "capability is not available").WithDetails(map[string]interface{}{
		"capability": "commercial.billing",
		"edition":    "community",
	})

	var api *ManagementAPI
	api.writeManagedError(recorder, err, http.StatusInternalServerError)

	if recorder.Code != http.StatusForbidden {
		t.Fatalf("expected status %d, got %d", http.StatusForbidden, recorder.Code)
	}

	var response ErrorResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if response.Error.Details["capability"] != "commercial.billing" || response.Error.Details["edition"] != "community" {
		t.Fatalf("expected capability details, got %#v", response.Error.Details)
	}
}

func TestParseEnrollmentTokenReturnsTypedError(t *testing.T) {
	_, _, err := parseEnrollmentToken("bad-token")
	if err == nil {
		t.Fatalf("expected error")
	}
	errortest.AssertCodeAndStatus(t, err, coreerrors.CodeEnrollmentTokenInvalid, http.StatusUnauthorized)
}

func TestManagedErrorHelpersUseGovernedCodes(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		wantCode string
		wantHTTP int
	}{
		{
			name:     "config",
			err:      managedConfigError("Failed to reload configuration", errors.New("boom")),
			wantCode: coreerrors.CodeConfigError,
			wantHTTP: http.StatusInternalServerError,
		},
		{
			name:     "proposal conflict",
			err:      managedProposalConflict("Proposal is already approved", nil),
			wantCode: coreerrors.CodeProposalStateConflict,
			wantHTTP: http.StatusConflict,
		},
		{
			name:     "proposal verification",
			err:      managedProposalVerificationError("Proposal verification failed", nil),
			wantCode: coreerrors.CodeProposalVerificationFailed,
			wantHTTP: http.StatusInternalServerError,
		},
		{
			name:     "canary config",
			err:      managedCanaryConfigError("Failed to build canary config", nil),
			wantCode: coreerrors.CodeCanaryConfigInvalid,
			wantHTTP: http.StatusBadRequest,
		},
		{
			name:     "canary state",
			err:      managedCanaryStateError("Canary rollout is not active", nil),
			wantCode: coreerrors.CodeCanaryStateConflict,
			wantHTTP: http.StatusConflict,
		},
		{
			name:     "required field",
			err:      managedRequiredFieldError("Reviewer is required"),
			wantCode: coreerrors.CodeRequiredFieldMissing,
			wantHTTP: http.StatusBadRequest,
		},
		{
			name:     "validation",
			err:      managedValidationError("Invalid route configuration", nil),
			wantCode: coreerrors.CodeValidationError,
			wantHTTP: http.StatusBadRequest,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			errortest.AssertCode(t, tc.err, tc.wantCode)
			if status := gatewayErrorStatus(tc.err, http.StatusTeapot); status != tc.wantHTTP {
				t.Fatalf("expected HTTP status %d, got %d", tc.wantHTTP, status)
			}
		})
	}
}

func TestWriteManagedErrorResolvesFallbackForPlainErrors(t *testing.T) {
	recorder := httptest.NewRecorder()

	var api *ManagementAPI
	api.writeManagedError(recorder, errors.New("Plugin not found"), http.StatusNotFound)

	if recorder.Code != http.StatusNotFound {
		t.Fatalf("expected status %d, got %d", http.StatusNotFound, recorder.Code)
	}

	var response ErrorResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if response.Error.Code != coreerrors.CodePluginNotFound {
		t.Fatalf("expected code %s, got %s", coreerrors.CodePluginNotFound, response.Error.Code)
	}
}
