package gateway

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/bhangun/iket/pkg/config"
	coreerrors "github.com/bhangun/iket/pkg/core/errors"
)

func enforceRequiredRequestHeaders(req *http.Request, route config.RouterConfig) error {
	route = graphQLOperationRequestRoute(route, req)
	if req == nil {
		return nil
	}
	for _, name := range route.RequiredRequestHeaders {
		headerName := strings.TrimSpace(name)
		if headerName == "" {
			continue
		}
		if strings.TrimSpace(req.Header.Get(headerName)) == "" {
			return coreerrors.NewRequiredFieldError(fmt.Sprintf("missing required request header %q", headerName))
		}
	}
	for name, pattern := range route.RequiredRequestHeaderRegex {
		headerName := strings.TrimSpace(name)
		if headerName == "" {
			continue
		}
		value := req.Header.Get(headerName)
		if strings.TrimSpace(value) == "" {
			return coreerrors.NewRequiredFieldError(fmt.Sprintf("missing required request header %q", headerName))
		}
		matched, err := regexp.MatchString(pattern, value)
		if err != nil {
			return coreerrors.NewCodeError(coreerrors.CodeValidationError, "required request header failed validation", err)
		}
		if !matched {
			return coreerrors.NewCodeError(coreerrors.CodeValidationError, "required request header failed validation", nil)
		}
	}
	return nil
}
