package gateway

import (
	"bytes"
	"io"
	"net/http"
	"time"

	"github.com/bhangun/iket/pkg/config"
)

type retryingTransport struct {
	base        http.RoundTripper
	route       config.RouterConfig
	backend     config.Backend
	destination string
	hedge       *hedgeTarget
}

func (t *retryingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	base := t.base
	if base == nil {
		base = cloneDefaultTransport()
	}
	if t.hedge != nil && routeHedgingAllowed(t.route, req.Method) {
		return t.roundTripWithHedge(base, req)
	}

	base = transportWithBackendTimeout(base, t.backend)
	attempts := routeRetryAttempts(t.route)
	retryStatuses := routeRetryStatusSet(t.route)
	backoff := routeRetryBackoff(t.route)
	jitter := routeRetryJitter(t.route)

	bodyBytes, err := cloneRequestBody(req)
	if err != nil {
		return nil, err
	}

	var lastResp *http.Response
	var lastErr error
	for attempt := 0; attempt < attempts; attempt++ {
		attemptReq := req.Clone(req.Context())
		if len(bodyBytes) > 0 {
			attemptReq.Body = io.NopCloser(bytes.NewReader(bodyBytes))
			attemptReq.ContentLength = int64(len(bodyBytes))
			attemptReq.GetBody = func() (io.ReadCloser, error) {
				return io.NopCloser(bytes.NewReader(bodyBytes)), nil
			}
		}
		resp, roundTripErr := base.RoundTrip(attemptReq)
		if roundTripErr == nil && !retryStatuses[resp.StatusCode] {
			return resp, nil
		}
		if !routeRetryAllowedForMethod(t.route, req.Method) {
			if resp != nil {
				return resp, nil
			}
			return nil, roundTripErr
		}
		if roundTripErr == nil {
			lastResp = resp
		} else {
			lastErr = roundTripErr
		}
		if attempt == attempts-1 {
			break
		}
		if resp != nil {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
		delay := backoff + retryJitterOffset(jitter)
		if delay > 0 {
			timer := time.NewTimer(delay)
			select {
			case <-req.Context().Done():
				timer.Stop()
				if lastErr != nil {
					return nil, lastErr
				}
				if lastResp != nil {
					return lastResp, nil
				}
				return nil, req.Context().Err()
			case <-timer.C:
			}
		}
	}

	if lastResp != nil {
		return lastResp, nil
	}
	return nil, lastErr
}
