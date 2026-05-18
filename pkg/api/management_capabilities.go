package api

import (
	"net/http"

	"github.com/bhangun/iket/pkg/app"
	coreerrors "github.com/bhangun/iket/pkg/core/errors"
)

func (api *ManagementAPI) requireCapability(w http.ResponseWriter, key string) bool {
	check := app.CheckCapability(key)
	if check.Supported {
		return true
	}
	api.writeManagedError(w, managedCapabilityError(check), http.StatusForbidden)
	return false
}

func (api *ManagementAPI) requireCapabilities(w http.ResponseWriter, keys ...string) bool {
	check := app.CheckCapabilities(keys...)
	if check.Supported {
		return true
	}
	api.writeManagedError(w, managedCapabilitiesError(check), http.StatusForbidden)
	return false
}

// RequireCapability writes a structured 403 response and returns false when the
// active Iket edition does not support the requested capability.
func (api *ManagementAPI) RequireCapability(w http.ResponseWriter, key string) bool {
	return api.requireCapability(w, key)
}

// RequireCapabilities writes a structured 403 response and returns false when
// the active Iket edition does not support every requested capability.
func (api *ManagementAPI) RequireCapabilities(w http.ResponseWriter, keys ...string) bool {
	return api.requireCapabilities(w, keys...)
}

func (api *ManagementAPI) withCapability(key string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !api.requireCapability(w, key) {
			return
		}
		next(w, r)
	}
}

// WithCapability wraps a management handler with edition/capability enforcement.
// Enterprise packages can use this to protect enterprise-only endpoints without
// duplicating edition checks or response formatting.
func (api *ManagementAPI) WithCapability(key string, next http.HandlerFunc) http.HandlerFunc {
	return api.withCapability(key, next)
}

func (api *ManagementAPI) withCapabilities(keys []string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !api.requireCapabilities(w, keys...) {
			return
		}
		next(w, r)
	}
}

// WithCapabilities wraps a management handler with multi-capability
// enforcement. Use this for enterprise routes that require several edition
// gates, such as billing plus audit trails.
func (api *ManagementAPI) WithCapabilities(keys []string, next http.HandlerFunc) http.HandlerFunc {
	return api.withCapabilities(keys, next)
}

func managedCapabilityError(check app.CapabilityCheck) error {
	message := check.Message
	if message == "" {
		message = "capability is not available in this edition"
	}
	return coreerrors.New(coreerrors.CodeForbidden, message).WithDetails(map[string]interface{}{
		"capability":   check.Key,
		"supported":    check.Supported,
		"edition":      check.Edition,
		"display_name": check.DisplayName,
	})
}

func managedCapabilitiesError(check app.CapabilitySetCheck) error {
	message := check.Message
	if message == "" {
		message = "required capabilities are not available in this edition"
	}
	details := map[string]interface{}{
		"supported":                check.Supported,
		"edition":                  check.Edition,
		"display_name":             check.DisplayName,
		"capabilities":             check.Capabilities,
		"unsupported_capabilities": check.UnsupportedCapabilities,
	}
	if len(check.UnsupportedCapabilities) > 0 {
		details["capability"] = check.UnsupportedCapabilities[0].Key
	}
	return coreerrors.New(coreerrors.CodeForbidden, message).WithDetails(details)
}
