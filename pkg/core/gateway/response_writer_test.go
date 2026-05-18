package gateway

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestResponseWriterImplementsFlusherWhenUnderlyingWriterSupportsIt(t *testing.T) {
	recorder := httptest.NewRecorder()
	rw := &responseWriter{ResponseWriter: recorder, statusCode: http.StatusOK}

	flusher, ok := interface{}(rw).(http.Flusher)
	if !ok {
		t.Fatalf("expected wrapped response writer to implement http.Flusher")
	}

	flusher.Flush()
}
