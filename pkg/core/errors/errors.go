package errors

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// GatewayError represents a structured error with additional context
type GatewayError struct {
	Code    string                 `json:"code"`
	Message string                 `json:"message"`
	Details map[string]interface{} `json:"details,omitempty"`
	Err     error                  `json:"-"`
}

// Error implements the error interface
func (e *GatewayError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %s (%s)", e.Code, e.Message, e.Err.Error())
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// Unwrap returns the underlying error
func (e *GatewayError) Unwrap() error {
	return e.Err
}

// WithDetails adds additional context to the error
func (e *GatewayError) WithDetails(details map[string]interface{}) *GatewayError {
	e.Details = details
	return e
}

// WithError wraps an underlying error
func (e *GatewayError) WithError(err error) *GatewayError {
	e.Err = err
	return e
}

// WriteHTTP writes the error to an HTTP response
func (e *GatewayError) WriteHTTP(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")

	statusCode := e.HTTPStatusCode()
	w.WriteHeader(statusCode)

	json.NewEncoder(w).Encode(map[string]interface{}{
		"error":   e.Code,
		"message": e.Message,
		"details": e.Details,
	})
}

// HTTPStatusCode returns the appropriate HTTP status code for this error
func (e *GatewayError) HTTPStatusCode() int {
	switch e.Code {
	case "CONFIG_NOT_FOUND", "ROUTE_NOT_FOUND":
		return http.StatusNotFound
	case "INVALID_CONFIG", "INVALID_ROUTE", "VALIDATION_FAILED":
		return http.StatusBadRequest
	case "UNAUTHORIZED", "AUTHENTICATION_FAILED":
		return http.StatusUnauthorized
	case "FORBIDDEN", "INSUFFICIENT_PERMISSIONS":
		return http.StatusForbidden
	case "RATE_LIMIT_EXCEEDED":
		return http.StatusTooManyRequests
	case "SERVICE_UNAVAILABLE", "PLUGIN_ERROR":
		return http.StatusServiceUnavailable
	default:
		return http.StatusInternalServerError
	}
}

// Predefined errors
var (
	ErrConfigNotFound = &GatewayError{
		Code:    "CONFIG_NOT_FOUND",
		Message: "Configuration file not found",
	}

	ErrInvalidConfig = &GatewayError{
		Code:    "INVALID_CONFIG",
		Message: "Invalid configuration format",
	}

	ErrRouteNotFound = &GatewayError{
		Code:    "ROUTE_NOT_FOUND",
		Message: "Route not found",
	}

	ErrInvalidRoute = &GatewayError{
		Code:    "INVALID_ROUTE",
		Message: "Invalid route configuration",
	}

	ErrUnauthorized = &GatewayError{
		Code:    "UNAUTHORIZED",
		Message: "Authentication required",
	}

	ErrForbidden = &GatewayError{
		Code:    "FORBIDDEN",
		Message: "Access denied",
	}

	ErrRateLimitExceeded = &GatewayError{
		Code:    "RATE_LIMIT_EXCEEDED",
		Message: "Rate limit exceeded",
	}

	ErrPluginError = &GatewayError{
		Code:    "PLUGIN_ERROR",
		Message: "Plugin execution failed",
	}

	ErrServiceUnavailable = &GatewayError{
		Code:    "SERVICE_UNAVAILABLE",
		Message: "Service temporarily unavailable",
	}
)

// Helper functions for creating errors with context
func NewConfigError(message string, err error) *GatewayError {
	return &GatewayError{
		Code:    "CONFIG_ERROR",
		Message: message,
		Err:     err,
	}
}

func NewRouteError(message string, err error) *GatewayError {
	return &GatewayError{
		Code:    "ROUTE_ERROR",
		Message: message,
		Err:     err,
	}
}

func NewPluginError(pluginName, message string, err error) *GatewayError {
	return &GatewayError{
		Code:    "PLUGIN_ERROR",
		Message: fmt.Sprintf("Plugin '%s': %s", pluginName, message),
		Err:     err,
	}
}

func NewValidationError(field, message string) *GatewayError {
	return &GatewayError{
		Code:    "VALIDATION_FAILED",
		Message: fmt.Sprintf("Validation failed for field '%s': %s", field, message),
		Details: map[string]interface{}{
			"field": field,
		},
	}
}
