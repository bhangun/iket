package apikey

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestClientUsageResponseWriterCapturesOutcome(t *testing.T) {
	recorder := httptest.NewRecorder()
	writer := newClientUsageResponseWriter(recorder)

	writer.WriteHeader(http.StatusCreated)
	if _, err := writer.Write([]byte("created")); err != nil {
		t.Fatalf("failed to write response body: %v", err)
	}

	outcome := writer.clientUsageOutcome(1500 * time.Microsecond)
	if outcome.statusCode != http.StatusCreated {
		t.Fatalf("expected status %d, got %+v", http.StatusCreated, outcome)
	}
	if outcome.bytesWritten != int64(len("created")) {
		t.Fatalf("expected body byte count, got %+v", outcome)
	}
	if outcome.durationMillis != 1 {
		t.Fatalf("expected duration rounded up to 1ms, got %+v", outcome)
	}
}

func TestClientUsageResponseWriterDefaultsStatusToOK(t *testing.T) {
	recorder := httptest.NewRecorder()
	writer := newClientUsageResponseWriter(recorder)

	outcome := writer.clientUsageOutcome(0)
	if outcome.statusCode != http.StatusOK {
		t.Fatalf("expected default status 200, got %+v", outcome)
	}
}

func TestClientUsageResponseWriterReadFromCapturesBytes(t *testing.T) {
	recorder := httptest.NewRecorder()
	writer := newClientUsageResponseWriter(recorder)

	n, err := writer.ReadFrom(strings.NewReader("streamed"))
	if err != nil {
		t.Fatalf("failed to read from stream: %v", err)
	}

	outcome := writer.clientUsageOutcome(time.Millisecond)
	if n != int64(len("streamed")) || outcome.bytesWritten != int64(len("streamed")) {
		t.Fatalf("expected streamed byte count, n=%d outcome=%+v", n, outcome)
	}
	if outcome.statusCode != http.StatusOK {
		t.Fatalf("expected ReadFrom to imply 200 status, got %+v", outcome)
	}
}

func TestClientUsageResponseWriterFlushCapturesImplicitOK(t *testing.T) {
	recorder := httptest.NewRecorder()
	writer := newClientUsageResponseWriter(recorder)

	writer.Flush()

	outcome := writer.clientUsageOutcome(0)
	if outcome.statusCode != http.StatusOK {
		t.Fatalf("expected flush to capture implicit 200, got %+v", outcome)
	}
}

func TestClientUsageResponseWriterDelegatesPush(t *testing.T) {
	pusher := &clientUsagePusherRecorder{ResponseRecorder: httptest.NewRecorder()}
	writer := newClientUsageResponseWriter(pusher)

	if err := writer.Push("/style.css", nil); err != nil {
		t.Fatalf("expected push to delegate: %v", err)
	}
	if pusher.target != "/style.css" {
		t.Fatalf("expected pushed target, got %q", pusher.target)
	}
}

func TestClientUsageResponseWriterPushReturnsNotSupported(t *testing.T) {
	writer := newClientUsageResponseWriter(httptest.NewRecorder())

	if err := writer.Push("/style.css", nil); err != http.ErrNotSupported {
		t.Fatalf("expected ErrNotSupported, got %v", err)
	}
}

func TestClientUsageResponseWriterReadFromUsesUnderlyingReaderFrom(t *testing.T) {
	recorder := &clientUsageReaderFromRecorder{ResponseRecorder: httptest.NewRecorder()}
	writer := newClientUsageResponseWriter(recorder)

	n, err := writer.ReadFrom(strings.NewReader("delegated"))
	if err != nil {
		t.Fatalf("failed delegated ReadFrom: %v", err)
	}

	if !recorder.usedReadFrom {
		t.Fatalf("expected underlying ReaderFrom to be used")
	}
	if n != int64(len("delegated")) || writer.clientUsageOutcome(0).bytesWritten != int64(len("delegated")) {
		t.Fatalf("expected delegated byte count, n=%d outcome=%+v", n, writer.clientUsageOutcome(0))
	}
}

func TestClientUsageResponseWriterDelegatesCloseNotify(t *testing.T) {
	closeNotify := make(chan bool, 1)
	recorder := &clientUsageCloseNotifyRecorder{
		ResponseRecorder: httptest.NewRecorder(),
		closeNotify:      closeNotify,
	}
	writer := newClientUsageResponseWriter(recorder)

	got := writer.CloseNotify()
	closeNotify <- true

	select {
	case closed := <-got:
		if !closed {
			t.Fatalf("expected close notification")
		}
	case <-time.After(time.Second):
		t.Fatalf("expected close notification to delegate")
	}
}

type clientUsagePusherRecorder struct {
	*httptest.ResponseRecorder
	target string
}

func (r *clientUsagePusherRecorder) Push(target string, _ *http.PushOptions) error {
	r.target = target
	return nil
}

type clientUsageReaderFromRecorder struct {
	*httptest.ResponseRecorder
	usedReadFrom bool
}

func (r *clientUsageReaderFromRecorder) ReadFrom(reader io.Reader) (int64, error) {
	r.usedReadFrom = true
	return io.Copy(r.ResponseRecorder, reader)
}

type clientUsageCloseNotifyRecorder struct {
	*httptest.ResponseRecorder
	closeNotify <-chan bool
}

func (r *clientUsageCloseNotifyRecorder) CloseNotify() <-chan bool {
	return r.closeNotify
}
