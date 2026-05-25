package api

import (
	"net/http"
	"strings"

	coreerrors "github.com/bhangun/iket/pkg/core/errors"
	"github.com/bhangun/iket/pkg/core/gateway"
)

func (api *ManagementAPI) getGatewayRoutePolicy(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimSpace(r.URL.Query().Get("path"))
	if path == "" {
		api.writeManagedError(w, managedRequiredFieldError("path query parameter is required"), http.StatusBadRequest)
		return
	}
	method := strings.ToUpper(strings.TrimSpace(r.URL.Query().Get("method")))
	if method == "" {
		method = http.MethodGet
	}
	bucketKey := strings.TrimSpace(r.URL.Query().Get("bucket_key"))
	headers, err := gateway.ParseRoutePolicyHeaderParams(r.URL.Query()["header"])
	if err != nil {
		api.writeManagedError(w, managedValidationError(err.Error(), nil), http.StatusBadRequest)
		return
	}
	inspection, ok := api.gateway.InspectRoutePolicy(method, path, headers, bucketKey)
	if !ok {
		api.writeManagedError(w, managedError(coreerrors.CodeRouteNotFound, "route not found for the supplied method/path/header combination", nil), http.StatusNotFound)
		return
	}
	api.writeJSON(w, map[string]interface{}{
		"inspection": inspection,
	})
}

func (api *ManagementAPI) diffGatewayRoutePolicy(w http.ResponseWriter, r *http.Request) {
	fromPath := strings.TrimSpace(r.URL.Query().Get("from_path"))
	toPath := strings.TrimSpace(r.URL.Query().Get("to_path"))
	if fromPath == "" || toPath == "" {
		api.writeManagedError(w, managedRequiredFieldError("from_path and to_path query parameters are required"), http.StatusBadRequest)
		return
	}
	fromMethod := strings.ToUpper(strings.TrimSpace(r.URL.Query().Get("from_method")))
	if fromMethod == "" {
		fromMethod = http.MethodGet
	}
	toMethod := strings.ToUpper(strings.TrimSpace(r.URL.Query().Get("to_method")))
	if toMethod == "" {
		toMethod = http.MethodGet
	}
	fromBucketKey := strings.TrimSpace(r.URL.Query().Get("from_bucket_key"))
	toBucketKey := strings.TrimSpace(r.URL.Query().Get("to_bucket_key"))
	fromHeaders, err := gateway.ParseRoutePolicyHeaderParams(r.URL.Query()["from_header"])
	if err != nil {
		api.writeManagedError(w, managedValidationError("from_header "+err.Error(), nil), http.StatusBadRequest)
		return
	}
	toHeaders, err := gateway.ParseRoutePolicyHeaderParams(r.URL.Query()["to_header"])
	if err != nil {
		api.writeManagedError(w, managedValidationError("to_header "+err.Error(), nil), http.StatusBadRequest)
		return
	}
	diff, ok := api.gateway.DiffRoutePolicy(fromMethod, fromPath, fromHeaders, fromBucketKey, toMethod, toPath, toHeaders, toBucketKey)
	if !ok {
		api.writeManagedError(w, managedError(coreerrors.CodeRouteNotFound, "one or both routes were not found for the supplied comparison inputs", nil), http.StatusNotFound)
		return
	}
	api.writeJSON(w, map[string]interface{}{
		"diff": diff,
	})
}
