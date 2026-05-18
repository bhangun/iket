package gateway

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/bhangun/iket/pkg/config"
)

func enforceAllowedUpstreamHost(req *http.Request, destURL *url.URL, route config.RouterConfig) error {
	route = graphQLOperationAIRequestRoute(route, req)
	if destURL == nil || len(route.AllowedUpstreamHosts) == 0 {
		return nil
	}
	host := strings.TrimSpace(destURL.Hostname())
	if host == "" {
		return fmt.Errorf("resolved upstream host is not allowed")
	}
	for _, allowed := range route.AllowedUpstreamHosts {
		if strings.EqualFold(strings.TrimSpace(allowed), host) {
			return nil
		}
	}
	return fmt.Errorf("resolved upstream host is not allowed")
}
