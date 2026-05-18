package gateway

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bhangun/iket/pkg/config"
)

func TestHedgingTransportUsesFasterBackupForSafeMethod(t *testing.T) {
	transport := &retryingTransport{
		base: roundTripperFunc(func(r *http.Request) (*http.Response, error) {
			switch r.URL.Host {
			case "primary.internal":
				time.Sleep(25 * time.Millisecond)
				return &http.Response{
					StatusCode: http.StatusOK,
					Header:     make(http.Header),
					Body:       io.NopCloser(strings.NewReader("primary")),
					Request:    r,
				}, nil
			case "backup.internal":
				return &http.Response{
					StatusCode: http.StatusOK,
					Header:     make(http.Header),
					Body:       io.NopCloser(strings.NewReader("backup")),
					Request:    r,
				}, nil
			default:
				t.Fatalf("unexpected host %q", r.URL.Host)
				return nil, nil
			}
		}),
		route: config.RouterConfig{
			HedgeDelay: "5ms",
		},
		hedge: &hedgeTarget{
			scheme: "http",
			host:   "backup.internal",
			path:   "/hello",
		},
	}

	req := httptest.NewRequest(http.MethodGet, "http://primary.internal/hello", nil)
	resp, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatalf("expected hedged request to succeed, got %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "backup" {
		t.Fatalf("expected faster backup response to win, got %q", string(body))
	}
}

func TestHedgingTransportDoesNotHedgeUnsafeMethodByDefault(t *testing.T) {
	var backupCalls int32
	transport := &retryingTransport{
		base: roundTripperFunc(func(r *http.Request) (*http.Response, error) {
			if r.URL.Host == "backup.internal" {
				atomic.AddInt32(&backupCalls, 1)
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader(r.URL.Host)),
				Request:    r,
			}, nil
		}),
		route: config.RouterConfig{
			HedgeDelay: "5ms",
		},
		hedge: &hedgeTarget{
			scheme: "http",
			host:   "backup.internal",
			path:   "/hello",
		},
	}

	req := httptest.NewRequest(http.MethodPost, "http://primary.internal/hello", io.NopCloser(strings.NewReader("payload")))
	resp, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatalf("expected POST request to succeed, got %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "primary.internal" {
		t.Fatalf("expected primary response for unsafe method, got %q", string(body))
	}
	if got := atomic.LoadInt32(&backupCalls); got != 0 {
		t.Fatalf("expected no backup hedge for unsafe method, got %d backup calls", got)
	}
}

func TestHedgingTransportCanRecoverWhenPrimaryFailsFirst(t *testing.T) {
	var backupCalls int32
	transport := &retryingTransport{
		base: roundTripperFunc(func(r *http.Request) (*http.Response, error) {
			switch r.URL.Host {
			case "primary.internal":
				return nil, fmt.Errorf("primary failed")
			case "backup.internal":
				atomic.AddInt32(&backupCalls, 1)
				return &http.Response{
					StatusCode: http.StatusOK,
					Header:     make(http.Header),
					Body:       io.NopCloser(strings.NewReader("backup")),
					Request:    r,
				}, nil
			default:
				t.Fatalf("unexpected host %q", r.URL.Host)
				return nil, nil
			}
		}),
		route: config.RouterConfig{
			HedgeDelay: "1ms",
		},
		hedge: &hedgeTarget{
			scheme: "http",
			host:   "backup.internal",
			path:   "/hello",
		},
	}

	req := httptest.NewRequest(http.MethodGet, "http://primary.internal/hello", nil)
	resp, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatalf("expected backup hedge to recover request, got %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "backup" {
		t.Fatalf("expected backup response to win after primary failure, got %q", string(body))
	}
	if atomic.LoadInt32(&backupCalls) != 1 {
		t.Fatalf("expected one backup call, got %d", atomic.LoadInt32(&backupCalls))
	}
}
