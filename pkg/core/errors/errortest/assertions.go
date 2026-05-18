package errortest

import (
	"net/http"
	"testing"

	coreerrors "github.com/bhangun/iket/pkg/core/errors"
)

// AssertCode verifies that an error resolves to the expected Iket code.
func AssertCode(t *testing.T, err error, wantCode string) {
	t.Helper()

	if !coreerrors.IsCode(err, wantCode) {
		t.Fatalf("expected code %s, got %s", wantCode, coreerrors.CodeOf(err))
	}
}

// AssertCodeAndStatus verifies both the Iket code and its governed HTTP mapping.
func AssertCodeAndStatus(t *testing.T, err error, wantCode string, wantStatus int) {
	t.Helper()

	AssertCode(t, err, wantCode)

	if gotStatus := coreerrors.HTTPStatusForCode(wantCode); gotStatus != wantStatus {
		t.Fatalf("expected HTTP status %d for code %s, got %d", wantStatus, wantCode, gotStatus)
	}
}

// AssertBadRequest is a convenience helper for common validation-style errors.
func AssertBadRequest(t *testing.T, err error, wantCode string) {
	t.Helper()
	AssertCodeAndStatus(t, err, wantCode, http.StatusBadRequest)
}
