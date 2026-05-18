package gateway

import (
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/bhangun/iket/pkg/config"
	"github.com/bhangun/iket/pkg/logging"

	"github.com/gorilla/mux"
)

// proxyHandler creates a reverse proxy handler for the given route.
func (g *Gateway) proxyHandler(route config.RouterConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		fmt.Printf("proxyHandler called for path: %s\n", r.URL.Path)
		if servePluginRouteIfMatched(w, r) {
			return
		}

		selectedBackend, selectedDestination := g.selectRouteBackend(route, rolloutBucketKey(r))
		if selectedDestination == "" {
			g.logger.Warn("All configured backends are currently unavailable",
				logging.String("route_path", route.Path),
				logging.String("service_name", route.ServiceName),
			)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusServiceUnavailable)
			w.Write([]byte(`{"error":"Service Unavailable","message":"All configured backends are temporarily unavailable"}`))
			return
		}

		// Use parent service's host as destination unless the selected backend overrides it.
		destination := strings.TrimSpace(selectedDestination)
		if destination == "" {
			destination = strings.TrimSpace(selectedBackend.Host)
		}
		if destination == "" {
			destination = strings.TrimSpace(route.ServiceHost)
		}
		if destination == "" {
			service := g.config.FindServiceForRoute(route.Path, r.Method, route.MatchHeaders)
			if service != nil {
				destination = strings.TrimSpace(service.Host)
			}
		}
		if destination == "" {
			g.logger.Error("No parent service found for route", nil, logging.String("route_path", route.Path), logging.String("method", r.Method))
			http.Error(w, "No backend service configured for this route", http.StatusBadGateway)
			return
		}
		service := &config.Service{Name: route.ServiceName, Host: destination}
		if route.ServiceName == "" || destination == "" {
			if resolved := g.config.FindServiceForRoute(route.Path, r.Method, route.MatchHeaders); resolved != nil {
				service = resolved
			}
		}

		// Parse destination URL
		destURL, err := url.Parse(destination)
		if err != nil {
			g.logger.Error("Failed to parse destination URL", err, logging.String("destination", destination))
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		if err := enforceAllowedUpstreamHost(r, destURL, route); err != nil {
			g.logger.Warn("Resolved upstream host rejected by route allowlist",
				logging.Error(err),
				logging.String("policy_reason", "upstream_host_allowlist"),
				logging.String("route_path", route.Path),
				logging.String("destination", destination),
			)
			writePolicyError(g, route, w, http.StatusForbidden, "upstream_host_allowlist", err.Error())
			return
		}
		if err := enforceRouteProtocol(r, route); err != nil {
			g.logger.Warn("Request rejected by route protocol policy",
				logging.Error(err),
				logging.String("policy_reason", "protocol"),
				logging.String("route_path", route.Path),
				logging.String("route_protocol", strings.ToLower(strings.TrimSpace(route.Protocol))),
				logging.String("request_method", r.Method),
				logging.String("content_type", r.Header.Get("Content-Type")),
			)
			status := http.StatusBadRequest
			if strings.Contains(strings.ToLower(err.Error()), "content-type") {
				status = http.StatusUnsupportedMediaType
			}
			writePolicyError(g, route, w, status, "protocol", err.Error())
			return
		}
		if err := enforceRequiredRequestHeaders(r, route); err != nil {
			g.logger.Warn("Request rejected by required header policy",
				logging.Error(err),
				logging.String("policy_reason", "required_header"),
				logging.String("route_path", route.Path),
			)
			writePolicyError(g, route, w, http.StatusBadRequest, "required_header", err.Error())
			return
		}

		origPath := r.URL.Path
		routeVars := mux.Vars(r)
		if len(routeVars) == 0 {
			routeVars = GetRouteVars(r)
		}
		primeGraphQLOperationContext(r, route)
		proxiedPath, err := ComputeProxiedPathForBackend(service, route, selectedBackend, origPath, routeVars)
		if err != nil {
			g.logger.Error("Failed to compute proxied path", err, logging.String("route_path", route.Path), logging.String("destination", destination))
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		r.URL.Path = proxiedPath
		applyQueryTransforms(r, route)
		if err := enforceRequestBodyLimit(r, route); err != nil {
			g.logger.Warn("Request body exceeds configured route limit",
				logging.Error(err),
				logging.String("policy_reason", "request_body_size"),
				logging.String("route_path", route.Path),
				logging.Int64("max_request_body_bytes", route.MaxRequestBodyBytes),
			)
			writePolicyError(g, route, w, http.StatusRequestEntityTooLarge, "request_body_size", err.Error())
			return
		}
		if err := enforceGraphQLRoutePolicy(r, route); err != nil {
			reason := policyReasonForGraphQLError(err)
			g.logger.Warn("Request rejected by GraphQL route policy",
				logging.Error(err),
				logging.String("policy_reason", reason),
				logging.String("route_path", route.Path),
			)
			writePolicyError(g, route, w, http.StatusForbidden, reason, err.Error())
			return
		}
		if err := enforceAllowedModels(r, route); err != nil {
			reason := "model_allowlist"
			g.logger.Warn("Request model rejected by route allowlist",
				logging.Error(err),
				logging.String("policy_reason", reason),
				logging.String("route_path", route.Path),
			)
			status := http.StatusBadRequest
			if strings.Contains(err.Error(), "not allowed") {
				status = http.StatusForbidden
			}
			writePolicyError(g, route, w, status, reason, err.Error())
			return
		}
		if err := enforceAllowedTools(r, route); err != nil {
			reason := "tool_allowlist"
			g.logger.Warn("Request tool rejected by route allowlist",
				logging.Error(err),
				logging.String("policy_reason", reason),
				logging.String("route_path", route.Path),
			)
			status := http.StatusBadRequest
			if strings.Contains(err.Error(), "not allowed") {
				status = http.StatusForbidden
			}
			writePolicyError(g, route, w, status, reason, err.Error())
			return
		}
		if err := enforceTokenBudgets(r, route); err != nil {
			reason := policyReasonForRequestError(err, "token_budget")
			g.logger.Warn("Request rejected by token budget policy",
				logging.Error(err),
				logging.String("policy_reason", reason),
				logging.String("route_path", route.Path),
			)
			status := http.StatusBadRequest
			if strings.Contains(err.Error(), "exceeds") {
				status = http.StatusForbidden
			}
			writePolicyError(g, route, w, status, reason, err.Error())
			return
		}
		if err := enforceConversationBudgets(r, route); err != nil {
			reason := policyReasonForRequestError(err, "conversation_budget")
			g.logger.Warn("Request rejected by conversation budget policy",
				logging.Error(err),
				logging.String("policy_reason", reason),
				logging.String("route_path", route.Path),
			)
			status := http.StatusBadRequest
			if strings.Contains(err.Error(), "exceeds") {
				status = http.StatusForbidden
			}
			writePolicyError(g, route, w, status, reason, err.Error())
			return
		}
		if err := enforceRequestBodyPatterns(r, route); err != nil {
			reason := policyReasonForRequestError(err, "request_content_policy")
			g.logger.Warn("Request rejected by body content policy",
				logging.Error(err),
				logging.String("policy_reason", reason),
				logging.String("route_path", route.Path),
			)
			status := http.StatusBadRequest
			if strings.Contains(err.Error(), "blocked") {
				status = http.StatusForbidden
			}
			writePolicyError(g, route, w, status, reason, err.Error())
			return
		}

		// Debug WS handshake issues (Cloudflare/proxies may strip hop-by-hop headers).
		// Keep this narrow to WS endpoints to avoid noisy logs and avoid logging tokens.
		if strings.Contains(origPath, "/chat/ws") || origPath == "/ws" || strings.Contains(origPath, "/jahsy/ws") {
			upgrade := r.Header.Get("Upgrade")
			conn := r.Header.Get("Connection")
			secKey := r.Header.Get("Sec-WebSocket-Key")
			secVer := r.Header.Get("Sec-WebSocket-Version")
			g.logger.Info("WS handshake headers",
				logging.String("path", origPath),
				logging.String("upgrade", upgrade),
				logging.String("connection", conn),
				logging.Bool("has_sec_key", secKey != ""),
				logging.String("sec_version", secVer),
				logging.String("proto", r.Proto),
			)
		}

		g.logger.Info("Proxying request",
			logging.String("original_path", origPath),
			logging.String("proxied_path", r.URL.Path),
			logging.String("destination", destURL.String()),
			logging.String("backend_url_pattern", selectedBackend.URLPattern),
			logging.Int("backend_weight", effectiveBackendWeight(selectedBackend)),
		)
		if isWebSocketRequest(r) {
			g.logger.Info("Initiating WebSocket proxy", logging.String("path", r.URL.Path), logging.String("destination", destURL.String()))
			wsOpts := route.WebSocket
			if wsOpts == nil {
				wsOpts = &config.WebSocketOptions{
					HandshakeTimeout:  45 * time.Second,
					ReadBufferSize:    4096,
					WriteBufferSize:   4096,
					EnableCompression: true,
					CheckOrigin:       false,
				}
			}
			proxyWebSocket(w, r, destURL, route, g.logger, wsOpts)
			return
		}

		var hedge *hedgeTarget
		if routeHedgingAllowed(route, r.Method) && len(route.Backends) > 1 {
			hedgeBackend, hedgeDestination := g.selectAlternateRouteBackend(route, selectedBackend, rolloutBucketKey(r))
			if hedgeDestination != "" {
				hedgeURL, parseErr := url.Parse(hedgeDestination)
				if parseErr == nil {
					hedgePath, pathErr := ComputeProxiedPathForBackend(service, route, hedgeBackend, origPath, routeVars)
					if pathErr == nil {
						hedge = &hedgeTarget{
							backend:     hedgeBackend,
							destination: hedgeDestination,
							scheme:      hedgeURL.Scheme,
							host:        hedgeURL.Host,
							path:        hedgePath,
						}
					}
				}
			}
		}
		var shadow *shadowTarget
		if routeShadowAllowed(route, r.Method) && routeShadowTrafficMatches(route, rolloutBucketKey(r)) && len(route.Backends) > 1 {
			shadowBackend, shadowDestination := g.selectAlternateRouteBackend(route, selectedBackend, rolloutBucketKey(r))
			if shadowDestination != "" {
				shadowURL, parseErr := url.Parse(shadowDestination)
				if parseErr == nil {
					shadowPath, pathErr := ComputeProxiedPathForBackend(service, route, shadowBackend, origPath, routeVars)
					if pathErr == nil {
						shadow = &shadowTarget{
							backend:     shadowBackend,
							destination: shadowDestination,
							scheme:      shadowURL.Scheme,
							host:        shadowURL.Host,
							path:        shadowPath,
						}
					}
				}
			}
		}

		proxy := httputil.NewSingleHostReverseProxy(destURL)
		if strings.EqualFold(strings.TrimSpace(route.Protocol), "sse") {
			proxy.FlushInterval = -1
		}
		proxy.Director = func(req *http.Request) {
			req.URL.Scheme = destURL.Scheme
			req.URL.Host = destURL.Host
			req.Host = destURL.Host
			if err := applyRequestJSONTransforms(req, route); err != nil {
				g.logger.Warn("Failed to apply request JSON transforms",
					logging.Error(err),
					logging.String("route_path", route.Path),
				)
			}
			applyUpstreamHeaders(req, req.Header, route, nil)
		}
		proxy.Transport = &retryingTransport{
			base:        cloneDefaultTransport(),
			route:       route,
			backend:     selectedBackend,
			destination: destination,
			hedge:       hedge,
		}
		requestStart := time.Now()
		proxy.ModifyResponse = func(resp *http.Response) error {
			if shouldRecordBackendFailureStatus(resp.StatusCode) {
				g.recordBackendFailureWithStatus(route, selectedBackend, destination, resp.StatusCode, fmt.Errorf("upstream responded with status %d", resp.StatusCode), time.Now().UTC())
			} else {
				g.recordBackendSuccessWithStatus(route, selectedBackend, destination, resp.StatusCode, time.Since(requestStart), time.Now().UTC())
			}
			upstreamHeaders := resp.Header.Clone()
			applyDownstreamHeaders(resp.Header, route, resp.Request, resp.StatusCode, upstreamHeaders)
			if strings.EqualFold(strings.TrimSpace(route.Protocol), "sse") {
				if contentType := strings.ToLower(strings.TrimSpace(resp.Header.Get("Content-Type"))); contentType != "" && !strings.Contains(contentType, "text/event-stream") {
					return fmt.Errorf("sse routes require upstream responses with content-type text/event-stream")
				}
				resp.Header.Set("X-Gateway", "Iket")
				resp.Header.Set("X-Gateway-Route", route.Path)
				if requestID := GetRequestID(r); requestID != "" {
					resp.Header.Set("X-Request-Id", requestID)
				}
				if strings.TrimSpace(selectedBackend.Host) != "" {
					resp.Header.Set("X-Gateway-Backend", selectedBackend.Host)
				}
				return nil
			}
			if err := enforceResponseBodyLimit(resp, route); err != nil {
				return err
			}
			if handled, err := applySuccessResponseEnvelope(resp, route, upstreamHeaders); err != nil {
				return err
			} else if handled {
				return nil
			}
			if handled, err := applyErrorResponseEnvelope(resp, route, upstreamHeaders); err != nil {
				return err
			} else if handled {
				return nil
			}
			if err := applyResponseJSONTransforms(resp, route, upstreamHeaders); err != nil {
				return err
			}
			if handled, err := applyResponseBodyPatterns(g, resp, route); err != nil {
				return err
			} else if handled {
				return nil
			}
			resp.Header.Set("X-Gateway", "Iket")
			resp.Header.Set("X-Gateway-Route", route.Path)
			if requestID := GetRequestID(r); requestID != "" {
				resp.Header.Set("X-Request-Id", requestID)
			}
			if strings.TrimSpace(selectedBackend.Host) != "" {
				resp.Header.Set("X-Gateway-Backend", selectedBackend.Host)
			}
			return nil
		}
		proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
			g.recordBackendFailure(route, selectedBackend, destination, err)
			g.logger.Error("Proxy error", err, logging.String("destination", destination), logging.String("path", r.URL.Path))
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadGateway)
			w.Write([]byte(`{"error":"Bad Gateway","message":"Unable to reach the upstream service"}`))
		}
		if shadow != nil {
			go dispatchShadowRequest(g, cloneDefaultTransport(), r, route, shadow, g.logger)
		}
		proxy.ServeHTTP(w, r)
	}
}
