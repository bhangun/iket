package gateway

import (
	"net/http"
	"strings"

	"github.com/bhangun/iket/pkg/config"
	coreerrors "github.com/bhangun/iket/pkg/core/errors"
)

func enforceRouteProtocol(req *http.Request, route config.RouterConfig) error {
	if req == nil {
		return nil
	}
	protocol := strings.ToLower(strings.TrimSpace(route.Protocol))
	if protocol == "" || protocol == "http" {
		return nil
	}

	contentType := strings.ToLower(strings.TrimSpace(req.Header.Get("Content-Type")))
	switch protocol {
	case "graphql":
		if req.Method != http.MethodPost && req.Method != http.MethodGet {
			return coreerrors.NewCodeError(coreerrors.CodeValidationError, "graphql routes only support GET or POST requests", nil)
		}
		if req.Method == http.MethodPost && contentType != "" &&
			!strings.Contains(contentType, "application/json") &&
			!strings.Contains(contentType, "+json") &&
			!strings.Contains(contentType, "application/graphql") {
			return coreerrors.NewCodeError(coreerrors.CodeValidationError, "graphql routes require a GraphQL-compatible content-type", nil)
		}
		return nil
	case "grpc":
		if !strings.Contains(contentType, "application/grpc") {
			return coreerrors.NewCodeError(coreerrors.CodeValidationError, "grpc routes require content-type application/grpc", nil)
		}
		return nil
	case "grpc-web":
		if req.Method != http.MethodPost {
			return coreerrors.NewCodeError(coreerrors.CodeValidationError, "grpc-web routes only support POST requests", nil)
		}
		if !strings.Contains(contentType, "application/grpc-web") {
			return coreerrors.NewCodeError(coreerrors.CodeValidationError, "grpc-web routes require content-type application/grpc-web", nil)
		}
		if header := strings.TrimSpace(req.Header.Get("X-Grpc-Web")); header != "" && header != "1" {
			return coreerrors.NewCodeError(coreerrors.CodeValidationError, "grpc-web routes require X-Grpc-Web header value 1 when provided", nil)
		}
		return nil
	case "websocket":
		if !isWebSocketRequest(req) {
			return coreerrors.NewCodeError(coreerrors.CodeValidationError, "websocket routes require a websocket upgrade request", nil)
		}
		return nil
	case "sse":
		if req.Method != http.MethodGet && req.Method != http.MethodPost {
			return coreerrors.NewCodeError(coreerrors.CodeValidationError, "sse routes only support GET or POST requests", nil)
		}
		accept := strings.ToLower(strings.TrimSpace(req.Header.Get("Accept")))
		if accept != "" && !strings.Contains(accept, "text/event-stream") {
			return coreerrors.NewCodeError(coreerrors.CodeValidationError, "sse routes require Accept text/event-stream", nil)
		}
		return nil
	default:
		return nil
	}
}
