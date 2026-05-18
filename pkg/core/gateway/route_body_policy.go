package gateway

import (
	"bytes"
	"io"
	"net/http"
	"strconv"

	"github.com/bhangun/iket/pkg/config"
	coreerrors "github.com/bhangun/iket/pkg/core/errors"
)

func enforceRequestBodyLimit(req *http.Request, route config.RouterConfig) error {
	if req == nil || req.Body == nil || route.MaxRequestBodyBytes <= 0 {
		return nil
	}
	if req.ContentLength > route.MaxRequestBodyBytes {
		return coreerrors.NewCodeError(coreerrors.CodeValidationError, "request body exceeds configured route limit", nil)
	}
	bodyBytes, err := cloneRequestBody(req)
	if err != nil {
		return err
	}
	if int64(len(bodyBytes)) > route.MaxRequestBodyBytes {
		return coreerrors.NewCodeError(coreerrors.CodeValidationError, "request body exceeds configured route limit", nil)
	}
	return nil
}

func enforceResponseBodyLimit(resp *http.Response, route config.RouterConfig) error {
	if resp == nil || resp.Body == nil || route.MaxResponseBodyBytes <= 0 {
		return nil
	}
	if resp.ContentLength > route.MaxResponseBodyBytes {
		return coreerrors.NewCodeError(coreerrors.CodeValidationError, "response body exceeds configured route limit", nil)
	}
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if err := resp.Body.Close(); err != nil {
		return err
	}
	if int64(len(bodyBytes)) > route.MaxResponseBodyBytes {
		return coreerrors.NewCodeError(coreerrors.CodeValidationError, "response body exceeds configured route limit", nil)
	}
	resp.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	resp.ContentLength = int64(len(bodyBytes))
	resp.Header.Set("Content-Length", strconv.Itoa(len(bodyBytes)))
	return nil
}
