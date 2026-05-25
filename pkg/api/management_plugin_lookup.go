package api

import (
	"net/http"

	coreerrors "github.com/bhangun/iket/pkg/core/errors"
	pluginpkg "github.com/bhangun/iket/pkg/plugin"
	"github.com/gorilla/mux"
)

func pluginNameFromRequest(r *http.Request) string {
	return mux.Vars(r)["name"]
}

func (api *ManagementAPI) registeredPluginFromRequest(w http.ResponseWriter, r *http.Request) (string, pluginpkg.Plugin, bool) {
	pluginName := pluginNameFromRequest(r)
	plugin, err := api.registry.Get(pluginName)
	if err != nil {
		api.writeManagedError(w, managedError(coreerrors.CodePluginNotFound, "Plugin not found", err), http.StatusNotFound)
		return "", nil, false
	}
	return pluginName, plugin, true
}
