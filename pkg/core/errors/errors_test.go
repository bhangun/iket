package errors

import (
	"errors"
	"net/http"
	"testing"
)

func TestWithDetailsDoesNotMutateSharedError(t *testing.T) {
	derived := ErrPluginError.WithDetails(map[string]interface{}{"plugin": "jwt"})

	if ErrPluginError.Details != nil {
		t.Fatalf("expected shared predefined error to remain immutable, got details %#v", ErrPluginError.Details)
	}
	if derived == ErrPluginError {
		t.Fatalf("expected cloned error instance")
	}
	if derived.Details["plugin"] != "jwt" {
		t.Fatalf("expected cloned error to contain details, got %#v", derived.Details)
	}
}

func TestCodeOfRecognizesWrappedGatewayError(t *testing.T) {
	err := NewConfigError("failed to load config", errors.New("disk unavailable"))

	if code := CodeOf(err); code != CodeConfigError {
		t.Fatalf("expected %s, got %s", CodeConfigError, code)
	}
	if !IsCode(err, CodeConfigError) {
		t.Fatalf("expected IsCode to match wrapped gateway error")
	}
}

func TestNewCodeErrorSupportsNilCauseWithoutMutation(t *testing.T) {
	err := NewProposalConflictError("proposal already approved", nil)

	if err == nil {
		t.Fatalf("expected error instance")
	}
	if err.Code != CodeProposalStateConflict {
		t.Fatalf("expected %s, got %s", CodeProposalStateConflict, err.Code)
	}
	if err.Err != nil {
		t.Fatalf("expected nil cause, got %#v", err.Err)
	}
	if err == ErrPluginError {
		t.Fatalf("expected fresh instance, not shared predefined error")
	}
}

func TestResolveCodeCoversIketManagementExceptions(t *testing.T) {
	tests := []struct {
		name       string
		message    string
		statusCode int
		want       string
	}{
		{name: "plugin not found", message: "Plugin not found", statusCode: http.StatusNotFound, want: CodePluginNotFound},
		{name: "proposal state conflict", message: "proposal is already approved", statusCode: http.StatusConflict, want: CodeProposalStateConflict},
		{name: "enrollment token expired", message: "Enrollment token has expired", statusCode: http.StatusUnauthorized, want: CodeEnrollmentTokenExpired},
		{name: "route required field", message: "service_name and route.path are required", statusCode: http.StatusBadRequest, want: CodeRequiredFieldMissing},
		{name: "canary validation", message: "invalid canary_percent, expected integer between 1 and 99", statusCode: http.StatusBadRequest, want: CodeCanaryConfigInvalid},
		{name: "config unavailable", message: "Configuration not available", statusCode: http.StatusInternalServerError, want: CodeConfigNotAvailable},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := ResolveCode(tc.message, tc.statusCode); got != tc.want {
				t.Fatalf("ResolveCode(%q, %d) = %s, want %s", tc.message, tc.statusCode, got, tc.want)
			}
		})
	}
}

func TestDescriptorCatalogDefaultsAndStatuses(t *testing.T) {
	tests := []struct {
		name        string
		code        string
		wantMessage string
		wantStatus  int
	}{
		{name: "config unavailable", code: CodeConfigNotAvailable, wantMessage: "Configuration not available", wantStatus: http.StatusInternalServerError},
		{name: "plugin unsupported", code: CodePluginUnsupported, wantMessage: "Plugin does not support this operation", wantStatus: http.StatusNotImplemented},
		{name: "certificate pem invalid", code: CodeCertificatePEMInvalid, wantMessage: "Invalid cert_pem", wantStatus: http.StatusBadRequest},
		{name: "proposal verification", code: CodeProposalVerificationFailed, wantMessage: "Proposal verification failed", wantStatus: http.StatusInternalServerError},
		{name: "canary state conflict", code: CodeCanaryStateConflict, wantMessage: "Canary rollout state conflict", wantStatus: http.StatusConflict},
		{name: "upstream error", code: CodeUpstreamError, wantMessage: "Upstream request failed", wantStatus: http.StatusBadGateway},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if !KnownCode(tc.code) {
				t.Fatalf("expected %s to be a known code", tc.code)
			}
			if got := DefaultMessage(tc.code); got != tc.wantMessage {
				t.Fatalf("DefaultMessage(%s) = %q, want %q", tc.code, got, tc.wantMessage)
			}
			if got := HTTPStatusForCode(tc.code); got != tc.wantStatus {
				t.Fatalf("HTTPStatusForCode(%s) = %d, want %d", tc.code, got, tc.wantStatus)
			}
		})
	}
}

func TestFallbackCodeForStatusMatrix(t *testing.T) {
	tests := []struct {
		status int
		want   string
	}{
		{status: http.StatusBadRequest, want: CodeValidationError},
		{status: http.StatusUnauthorized, want: CodeAuthenticationRequired},
		{status: http.StatusForbidden, want: CodePermissionDenied},
		{status: http.StatusNotFound, want: CodeConfigNotFound},
		{status: http.StatusConflict, want: CodeConflict},
		{status: http.StatusTooManyRequests, want: CodeRateLimitExceeded},
		{status: http.StatusNotImplemented, want: CodeFeatureNotSupported},
		{status: http.StatusBadGateway, want: CodeUpstreamError},
		{status: http.StatusServiceUnavailable, want: CodeServiceUnavailable},
		{status: http.StatusInternalServerError, want: CodeInternalError},
	}

	for _, tc := range tests {
		t.Run(http.StatusText(tc.status), func(t *testing.T) {
			if got := fallbackCodeForStatus(tc.status); got != tc.want {
				t.Fatalf("fallbackCodeForStatus(%d) = %s, want %s", tc.status, got, tc.want)
			}
		})
	}
}

func TestResolveCodeHonorsEmbeddedCodesAndFallbackHeuristics(t *testing.T) {
	tests := []struct {
		name       string
		message    string
		statusCode int
		want       string
	}{
		{
			name:       "embedded plugin code wins",
			message:    "PLUGIN_NOT_FOUND: Plugin not found in registry",
			statusCode: http.StatusInternalServerError,
			want:       CodePluginNotFound,
		},
		{
			name:       "required field heuristic",
			message:    "csr_pem is required",
			statusCode: http.StatusBadRequest,
			want:       CodeRequiredFieldMissing,
		},
		{
			name:       "canary heuristic",
			message:    "invalid canary_percent, expected integer between 1 and 99",
			statusCode: http.StatusBadRequest,
			want:       CodeCanaryConfigInvalid,
		},
		{
			name:       "failed to upstream fallback",
			message:    "failed to reach upstream gateway",
			statusCode: http.StatusBadGateway,
			want:       CodeUpstreamError,
		},
		{
			name:       "plain validation heuristic",
			message:    "route method must be uppercase",
			statusCode: http.StatusBadRequest,
			want:       CodeValidationError,
		},
		{
			name:       "empty message uses status fallback",
			message:    "",
			statusCode: http.StatusNotImplemented,
			want:       CodeFeatureNotSupported,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := ResolveCode(tc.message, tc.statusCode); got != tc.want {
				t.Fatalf("ResolveCode(%q, %d) = %s, want %s", tc.message, tc.statusCode, got, tc.want)
			}
		})
	}
}

func TestConstructorsProduceGovernedCodesAndStatuses(t *testing.T) {
	cause := errors.New("disk unavailable")

	tests := []struct {
		name       string
		err        *GatewayError
		wantCode   string
		wantStatus int
		wantCause  bool
	}{
		{
			name:       "config error",
			err:        NewConfigError("failed to load config", cause),
			wantCode:   CodeConfigError,
			wantStatus: http.StatusInternalServerError,
			wantCause:  true,
		},
		{
			name:       "route error",
			err:        NewRouteError("failed to update route", cause),
			wantCode:   CodeRouteError,
			wantStatus: http.StatusInternalServerError,
			wantCause:  true,
		},
		{
			name:       "plugin error",
			err:        NewPluginError("jwt", "failed to validate token", cause),
			wantCode:   CodePluginError,
			wantStatus: http.StatusServiceUnavailable,
			wantCause:  true,
		},
		{
			name:       "validation error",
			err:        NewValidationError("request.body", "failed to read request body"),
			wantCode:   CodeValidationFailed,
			wantStatus: http.StatusBadRequest,
			wantCause:  false,
		},
		{
			name:       "required field",
			err:        NewRequiredFieldError("reviewer is required"),
			wantCode:   CodeRequiredFieldMissing,
			wantStatus: http.StatusBadRequest,
			wantCause:  false,
		},
		{
			name:       "proposal conflict",
			err:        NewProposalConflictError("proposal is already approved", nil),
			wantCode:   CodeProposalStateConflict,
			wantStatus: http.StatusConflict,
			wantCause:  false,
		},
		{
			name:       "proposal verification",
			err:        NewProposalVerificationError("failed to verify proposal", cause),
			wantCode:   CodeProposalVerificationFailed,
			wantStatus: http.StatusInternalServerError,
			wantCause:  true,
		},
		{
			name:       "canary config",
			err:        NewCanaryConfigError("invalid canary plan", nil),
			wantCode:   CodeCanaryConfigInvalid,
			wantStatus: http.StatusBadRequest,
			wantCause:  false,
		},
		{
			name:       "canary state",
			err:        NewCanaryStateError("canary rollout is not active", cause),
			wantCode:   CodeCanaryStateConflict,
			wantStatus: http.StatusConflict,
			wantCause:  true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.err == nil {
				t.Fatalf("expected constructor to return error")
			}
			if got := CodeOf(tc.err); got != tc.wantCode {
				t.Fatalf("CodeOf() = %s, want %s", got, tc.wantCode)
			}
			if got := tc.err.HTTPStatusCode(); got != tc.wantStatus {
				t.Fatalf("HTTPStatusCode() = %d, want %d", got, tc.wantStatus)
			}
			if (tc.err.Err != nil) != tc.wantCause {
				t.Fatalf("expected cause presence %t, got %#v", tc.wantCause, tc.err.Err)
			}
		})
	}
}
