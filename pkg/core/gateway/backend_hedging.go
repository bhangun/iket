package gateway

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/bhangun/iket/pkg/config"
)

type hedgeTarget struct {
	backend     config.Backend
	destination string
	scheme      string
	host        string
	path        string
}

func (t *retryingTransport) roundTripWithHedge(base http.RoundTripper, req *http.Request) (*http.Response, error) {
	bodyBytes, err := cloneRequestBody(req)
	if err != nil {
		return nil, err
	}

	type result struct {
		resp *http.Response
		err  error
	}
	results := make(chan result, 2)
	ctx, cancel := context.WithCancel(req.Context())
	defer cancel()

	launch := func(host, scheme, path string) {
		attemptReq := req.Clone(ctx)
		attemptReq.URL.Scheme = scheme
		attemptReq.URL.Host = host
		attemptReq.URL.Path = path
		attemptReq.Host = host
		if len(bodyBytes) > 0 {
			attemptReq.Body = io.NopCloser(bytes.NewReader(bodyBytes))
			attemptReq.ContentLength = int64(len(bodyBytes))
			attemptReq.GetBody = func() (io.ReadCloser, error) {
				return io.NopCloser(bytes.NewReader(bodyBytes)), nil
			}
		}
		resp, roundTripErr := base.RoundTrip(attemptReq)
		select {
		case results <- result{resp: resp, err: roundTripErr}:
		case <-ctx.Done():
			if resp != nil && resp.Body != nil {
				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
			}
		}
	}

	go launch(req.URL.Host, req.URL.Scheme, req.URL.Path)
	delay := routeHedgeDelay(t.route)
	if delay <= 0 {
		delay = time.Millisecond
	}
	go func() {
		timer := time.NewTimer(delay)
		defer timer.Stop()
		select {
		case <-timer.C:
			launch(t.hedge.host, t.hedge.scheme, t.hedge.path)
		case <-ctx.Done():
			return
		}
	}()

	var firstErr error
	for i := 0; i < 2; i++ {
		result := <-results
		if result.err == nil && result.resp != nil {
			cancel()
			return result.resp, nil
		}
		if firstErr == nil {
			if result.err != nil {
				firstErr = result.err
			} else if result.resp != nil {
				firstErr = fmt.Errorf("upstream responded with status %d", result.resp.StatusCode)
			}
		}
	}
	cancel()
	return nil, firstErr
}

func routeHedgeDelay(route config.RouterConfig) time.Duration {
	if strings.TrimSpace(route.HedgeDelay) == "" {
		return 0
	}
	delay, err := time.ParseDuration(strings.TrimSpace(route.HedgeDelay))
	if err != nil || delay < 0 {
		return 0
	}
	return delay
}

func routeHedgingAllowed(route config.RouterConfig, method string) bool {
	if route.HedgeUnsafe {
		return true
	}
	switch strings.ToUpper(strings.TrimSpace(method)) {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace:
		return routeHedgeDelay(route) > 0
	default:
		return false
	}
}
