package gateway

import (
	"net/http"
	"regexp"

	"github.com/bhangun/iket/pkg/config"
	coreerrors "github.com/bhangun/iket/pkg/core/errors"
)

func enforceRequestBodyPatterns(req *http.Request, route config.RouterConfig) error {
	route = graphQLOperationRequestRoute(route, req)
	if req == nil || (len(route.RequestBodyBlockRegex) == 0 && len(route.RequestBodyRequireRegex) == 0 && len(route.RequestPIIBlockTypes) == 0) {
		return nil
	}
	bodyBytes, err := cloneRequestBody(req)
	if err != nil {
		return err
	}
	if len(bodyBytes) == 0 {
		if len(route.RequestBodyRequireRegex) > 0 {
			return coreerrors.NewRequiredFieldError("request body is missing required content policy marker")
		}
		return nil
	}
	body := string(bodyBytes)
	for _, pattern := range append([]string{}, route.RequestBodyBlockRegex...) {
		matched, err := regexp.MatchString(pattern, body)
		if err != nil {
			return coreerrors.NewCodeError(coreerrors.CodeValidationError, "request body blocked by content policy", err)
		}
		if matched {
			return coreerrors.NewCodeError(coreerrors.CodeValidationError, "request body blocked by content policy", nil)
		}
	}
	for _, pattern := range piiPatternsForTypes(route.RequestPIIBlockTypes) {
		matched, err := regexp.MatchString(pattern, body)
		if err != nil {
			return coreerrors.NewCodeError(coreerrors.CodeValidationError, "request body blocked by content policy", err)
		}
		if matched {
			return coreerrors.NewCodeError(coreerrors.CodeValidationError, "request body blocked by content policy", nil)
		}
	}
	for _, pattern := range route.RequestBodyRequireRegex {
		matched, err := regexp.MatchString(pattern, body)
		if err != nil {
			return coreerrors.NewRequiredFieldError("request body is missing required content policy marker")
		}
		if !matched {
			return coreerrors.NewRequiredFieldError("request body is missing required content policy marker")
		}
	}
	return nil
}
