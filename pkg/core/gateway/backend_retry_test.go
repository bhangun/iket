package gateway

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bhangun/iket/pkg/config"
)

func TestRetryingTransportRetriesRetryableStatuses(t *testing.T) {
	var attempts int32
	transport := &retryingTransport{
		base: roundTripperFunc(func(r *http.Request) (*http.Response, error) {
			if atomic.AddInt32(&attempts, 1) == 1 {
				return &http.Response{
					StatusCode: http.StatusServiceUnavailable,
					Header:     make(http.Header),
					Body:       io.NopCloser(strings.NewReader("try again")),
					Request:    r,
				}, nil
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader("ok")),
				Request:    r,
			}, nil
		}),
		route: config.RouterConfig{
			RetryCount:    1,
			RetryStatuses: []int{http.StatusServiceUnavailable},
		},
	}

	req := httptest.NewRequest(http.MethodGet, "http://gateway.local/hello", nil)
	resp, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatalf("expected retry transport to succeed, got %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 after retry, got %d", resp.StatusCode)
	}
	if got := atomic.LoadInt32(&attempts); got != 2 {
		t.Fatalf("expected 2 upstream attempts, got %d", got)
	}
}

func TestRetryingTransportPreservesRequestBodyAcrossRetries(t *testing.T) {
	var attempts int32
	transport := &retryingTransport{
		base: roundTripperFunc(func(r *http.Request) (*http.Response, error) {
			bodyBytes, err := io.ReadAll(r.Body)
			if err != nil {
				t.Fatalf("failed to read attempt body: %v", err)
			}
			if string(bodyBytes) != "payload" {
				t.Fatalf("expected request body payload, got %q", string(bodyBytes))
			}
			if atomic.AddInt32(&attempts, 1) == 1 {
				return &http.Response{
					StatusCode: http.StatusBadGateway,
					Header:     make(http.Header),
					Body:       io.NopCloser(strings.NewReader("retry")),
					Request:    r,
				}, nil
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader("ok")),
				Request:    r,
			}, nil
		}),
		route: config.RouterConfig{
			RetryCount:    1,
			RetryStatuses: []int{http.StatusBadGateway},
			RetryUnsafe:   true,
		},
	}

	req := httptest.NewRequest(http.MethodPost, "http://gateway.local/hello", io.NopCloser(strings.NewReader("payload")))
	resp, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatalf("expected retry transport to succeed, got %v", err)
	}
	resp.Body.Close()
	if got := atomic.LoadInt32(&attempts); got != 2 {
		t.Fatalf("expected 2 attempts with replayed body, got %d", got)
	}
}

func TestRetryingTransportDoesNotRetryUnsafeMethodsByDefault(t *testing.T) {
	var attempts int32
	transport := &retryingTransport{
		base: roundTripperFunc(func(r *http.Request) (*http.Response, error) {
			atomic.AddInt32(&attempts, 1)
			return &http.Response{
				StatusCode: http.StatusBadGateway,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader("retry")),
				Request:    r,
			}, nil
		}),
		route: config.RouterConfig{
			RetryCount:    2,
			RetryStatuses: []int{http.StatusBadGateway},
		},
	}

	req := httptest.NewRequest(http.MethodPost, "http://gateway.local/hello", io.NopCloser(strings.NewReader("payload")))
	resp, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatalf("expected single POST attempt to return response, got %v", err)
	}
	resp.Body.Close()
	if got := atomic.LoadInt32(&attempts); got != 1 {
		t.Fatalf("expected unsafe method to avoid retries, got %d attempts", got)
	}
}

func TestRetryingTransportCanRetryUnsafeMethodsWhenEnabled(t *testing.T) {
	var attempts int32
	transport := &retryingTransport{
		base: roundTripperFunc(func(r *http.Request) (*http.Response, error) {
			if atomic.AddInt32(&attempts, 1) == 1 {
				return &http.Response{
					StatusCode: http.StatusBadGateway,
					Header:     make(http.Header),
					Body:       io.NopCloser(strings.NewReader("retry")),
					Request:    r,
				}, nil
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader("ok")),
				Request:    r,
			}, nil
		}),
		route: config.RouterConfig{
			RetryCount:    1,
			RetryStatuses: []int{http.StatusBadGateway},
			RetryUnsafe:   true,
		},
	}

	req := httptest.NewRequest(http.MethodPost, "http://gateway.local/hello", io.NopCloser(strings.NewReader("payload")))
	resp, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatalf("expected POST retry to succeed, got %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 after unsafe retry, got %d", resp.StatusCode)
	}
	if got := atomic.LoadInt32(&attempts); got != 2 {
		t.Fatalf("expected 2 attempts for unsafe retry, got %d", got)
	}
}

func TestRetryJitterOffsetStaysWithinBounds(t *testing.T) {
	max := 25 * time.Millisecond
	for i := 0; i < 50; i++ {
		offset := retryJitterOffset(max)
		if offset < 0 || offset > max {
			t.Fatalf("expected jitter offset in [0,%s], got %s", max, offset)
		}
	}
}
