package gateway

import (
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/bhangun/iket/pkg/config"
)

func cloneDefaultTransport() *http.Transport {
	base, ok := http.DefaultTransport.(*http.Transport)
	if ok {
		return base.Clone()
	}
	return &http.Transport{}
}

func transportWithBackendTimeout(base http.RoundTripper, backend config.Backend) http.RoundTripper {
	timeout := backendRequestTimeout(backend)
	if timeout <= 0 {
		return base
	}
	transport, ok := base.(*http.Transport)
	if !ok {
		return base
	}
	transport = transport.Clone()
	transport.ResponseHeaderTimeout = timeout
	transport.TLSHandshakeTimeout = timeout
	transport.DialContext = (&net.Dialer{Timeout: timeout}).DialContext
	return transport
}

func backendRequestTimeout(backend config.Backend) time.Duration {
	if strings.TrimSpace(backend.Timeout) == "" {
		return 0
	}
	timeout, err := time.ParseDuration(strings.TrimSpace(backend.Timeout))
	if err != nil || timeout <= 0 {
		return 0
	}
	return timeout
}
