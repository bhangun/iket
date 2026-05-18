package main

import (
	"strings"
	"testing"
)

func TestShouldFallbackToLogPolling(t *testing.T) {
	if !shouldFallbackToLogPolling(assertErr("API error (500): {\"error\":{\"code\":\"INTERNAL_ERROR\",\"message\":\"Streaming not supported\"}}")) {
		t.Fatalf("expected streaming-not-supported error to trigger fallback")
	}
	if shouldFallbackToLogPolling(assertErr("some other error")) {
		t.Fatalf("did not expect unrelated error to trigger fallback")
	}
}

func TestLogEntryKeyStable(t *testing.T) {
	entry := cliLogEntry{
		Timestamp: "2026-05-17T10:00:00Z",
		Level:     "info",
		Message:   "hello",
		Fields: map[string]interface{}{
			"service": "identity",
		},
	}
	if logEntryKey(entry) == "" {
		t.Fatalf("expected non-empty log entry key")
	}
}

func TestSummarizeTraceEntries(t *testing.T) {
	summary := summarizeTraceEntries("req-123", []cliLogEntry{
		{
			Timestamp: "2026-05-17T10:00:00Z",
			Level:     "info",
			Message:   "request started",
			Fields: map[string]interface{}{
				"request_id":   "req-123",
				"method":       "GET",
				"path":         "/auth/profile",
				"service_name": "identity",
				"route_name":   "/auth/{rest:.*}",
			},
		},
		{
			Timestamp: "2026-05-17T10:00:01Z",
			Level:     "info",
			Message:   "request finished",
			Fields: map[string]interface{}{
				"request_id":  "req-123",
				"status_code": 200,
			},
		},
	})

	for _, want := range []string{
		"request_id=req-123",
		"GET /auth/profile",
		"status=200",
		"service=identity",
		"route=/auth/{rest:.*}",
	} {
		if !strings.Contains(summary, want) {
			t.Fatalf("expected summary %q to contain %q", summary, want)
		}
	}
}

func TestSummarizeTraceEntriesFallsBackToRequestID(t *testing.T) {
	summary := summarizeTraceEntries("req-456", []cliLogEntry{
		{
			Timestamp: "2026-05-17T10:00:00Z",
			Level:     "info",
			Message:   "something happened",
		},
	})
	if summary != "Trace summary: request_id=req-456" {
		t.Fatalf("unexpected fallback summary: %q", summary)
	}
}

type assertErr string

func (e assertErr) Error() string { return string(e) }
