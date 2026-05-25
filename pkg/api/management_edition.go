package api

import (
	"net/http"
	"strings"

	"github.com/bhangun/iket/pkg/app"
	coreerrors "github.com/bhangun/iket/pkg/core/errors"
	"github.com/gorilla/mux"
)

func (api *ManagementAPI) getGatewayEdition(w http.ResponseWriter, r *http.Request) {
	api.writeJSON(w, app.CurrentEdition())
}

func (api *ManagementAPI) listGatewayCapabilities(w http.ResponseWriter, r *http.Request) {
	api.writeJSON(w, app.CurrentCapabilityCatalog(r.URL.Query().Get("category")))
}

func (api *ManagementAPI) listGatewayExtensions(w http.ResponseWriter, r *http.Request) {
	filter, err := managementRouteExtensionFilterFromRequest(r)
	if err != nil {
		api.writeManagedError(w, err, http.StatusBadRequest)
		return
	}
	api.writeJSON(w, CurrentManagementRouteExtensionCatalog(filter))
}

func (api *ManagementAPI) getGatewayExtension(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSpace(mux.Vars(r)["name"])
	if name == "" {
		api.writeManagedError(w, managedRequiredFieldError("management extension name is required"), http.StatusBadRequest)
		return
	}
	extension, ok := CurrentManagementRouteExtension(name)
	if !ok {
		api.writeManagedError(w, managedError(coreerrors.CodeManagementExtensionNotFound, "Management extension not found", nil), http.StatusNotFound)
		return
	}
	api.writeJSON(w, extension)
}

func (api *ManagementAPI) getGatewayCapability(w http.ResponseWriter, r *http.Request) {
	key := strings.TrimSpace(mux.Vars(r)["key"])
	if key == "" {
		api.writeManagedError(w, managedRequiredFieldError("capability key is required"), http.StatusBadRequest)
		return
	}
	api.writeJSON(w, app.CheckCapability(key))
}
