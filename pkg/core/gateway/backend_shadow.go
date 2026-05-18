package gateway

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/bhangun/iket/pkg/config"
	"github.com/bhangun/iket/pkg/logging"
)

type shadowTarget struct {
	backend     config.Backend
	destination string
	scheme      string
	host        string
	path        string
}

func routeShadowAllowed(route config.RouterConfig, method string) bool {
	if route.ShadowTrafficPercent <= 0 {
		return false
	}
	if route.ShadowUnsafe {
		return true
	}
	switch strings.ToUpper(strings.TrimSpace(method)) {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace:
		return true
	default:
		return false
	}
}

func routeShadowTrafficMatches(route config.RouterConfig, bucketKey string) bool {
	if route.ShadowTrafficPercent <= 0 {
		return false
	}
	if route.ShadowTrafficPercent >= 100 {
		return true
	}
	return percentageBucketForKey(bucketKey) < route.ShadowTrafficPercent
}

func dispatchShadowRequest(g *Gateway, base http.RoundTripper, req *http.Request, route config.RouterConfig, target *shadowTarget, logger *logging.Logger) {
	if base == nil || req == nil || target == nil || g == nil {
		return
	}
	start := time.Now()
	shadowReq := req.Clone(req.Context())
	bodyBytes, err := cloneRequestBody(req)
	if err != nil {
		if logger != nil {
			logger.Warn("Skipping shadow request due to body clone failure", logging.Error(err))
		}
		return
	}
	if len(bodyBytes) > 0 {
		shadowReq.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		shadowReq.ContentLength = int64(len(bodyBytes))
		shadowReq.GetBody = func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(bodyBytes)), nil
		}
	}
	shadowReq.URL.Scheme = target.scheme
	shadowReq.URL.Host = target.host
	shadowReq.URL.Path = target.path
	shadowReq.Host = target.host
	applyUpstreamHeaders(shadowReq, shadowReq.Header, route, nil)
	shadowReq.Header.Set("X-Iket-Shadow", "true")

	resp, roundTripErr := base.RoundTrip(shadowReq)
	if roundTripErr != nil {
		g.recordShadowResult(route, target.backend, target.destination, 0, time.Since(start), roundTripErr)
		if logger != nil {
			logger.Warn("Shadow request failed", logging.Error(roundTripErr), logging.String("destination", target.destination))
		}
		return
	}
	g.recordShadowResult(route, target.backend, target.destination, resp.StatusCode, time.Since(start), nil)
	if resp != nil && resp.Body != nil {
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
}

func (g *Gateway) recordShadowResult(route config.RouterConfig, backend config.Backend, destination string, statusCode int, latency time.Duration, shadowErr error) {
	key := g.backendStateKey(route, backend, destination)
	g.backendStateMu.Lock()
	defer g.backendStateMu.Unlock()
	state := g.backendState[key]
	state.ShadowRequests++
	state.LastShadowStatusCode = statusCode
	state.LastShadowLatency = latency
	state.ShadowLatencyEWMA = updateLatencyEWMA(state.ShadowLatencyEWMA, latency)
	recordedFailure := false
	if shadowErr != nil {
		state.ShadowFailures++
		state.LastShadowError = shadowErr.Error()
		recordedFailure = true
	} else {
		state.LastShadowError = ""
	}
	if statusCode >= http.StatusInternalServerError && !recordedFailure {
		state.ShadowFailures++
		if state.LastShadowError == "" {
			state.LastShadowError = fmt.Sprintf("shadow upstream responded with status %d", statusCode)
		}
	}
	g.backendState[key] = state
}
