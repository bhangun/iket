package api

import pluginpkg "github.com/bhangun/iket/pkg/plugin"

// PluginInfo is the compact inventory shape returned by plugin list responses.
type PluginInfo struct {
	Name                    string            `json:"name"`
	Type                    string            `json:"type"`
	Enabled                 bool              `json:"enabled"`
	Status                  string            `json:"status"`
	Tags                    map[string]string `json:"tags"`
	Capabilities            []string          `json:"capabilities,omitempty"`
	DiagnosticsAvailable    bool              `json:"diagnostics_available,omitempty"`
	DiagnosticsStatus       string            `json:"diagnostics_status,omitempty"`
	DiagnosticsWarningCodes []string          `json:"diagnostics_warning_codes,omitempty"`
}

type pluginInventorySnapshot struct {
	Info           PluginInfo
	Health         map[string]interface{}
	StatusMessage  string
	Diagnostics    map[string]interface{}
	Tagged         bool
	HasHealth      bool
	HasStatus      bool
	HasDiagnostics bool
}

func (api *ManagementAPI) pluginInventorySnapshot(name string, p pluginpkg.Plugin) pluginInventorySnapshot {
	snapshot := pluginInventorySnapshot{
		Info: PluginInfo{
			Name:         name,
			Type:         pluginTypeLabel(p),
			Enabled:      api.pluginEnabled(name),
			Status:       "healthy",
			Tags:         make(map[string]string),
			Capabilities: pluginCapabilityLabels(p),
		},
	}

	if taggedPlugin, ok := p.(pluginpkg.TaggedPlugin); ok {
		snapshot.Tagged = true
		snapshot.Info.Tags = taggedPlugin.Tags()
	}
	if healthChecker, ok := p.(pluginpkg.HealthChecker); ok {
		snapshot.HasHealth = true
		if err := healthChecker.Health(); err != nil {
			snapshot.Info.Status = "unhealthy"
			snapshot.Health = map[string]interface{}{
				"status":  "unhealthy",
				"message": err.Error(),
			}
		} else {
			snapshot.Health = map[string]interface{}{
				"status":  "healthy",
				"message": "Plugin is functioning normally",
			}
		}
	}
	if statusReporter, ok := p.(pluginpkg.StatusReporter); ok {
		snapshot.HasStatus = true
		snapshot.StatusMessage = statusReporter.Status()
	}
	if diagnosticsReporter, ok := p.(pluginpkg.DiagnosticsReporter); ok {
		snapshot.HasDiagnostics = true
		snapshot.Diagnostics = diagnosticsReporter.Diagnostics()
		status := stringValue(snapshot.Diagnostics["status"])
		if status == "" {
			status = "unknown"
		}
		snapshot.Info.DiagnosticsAvailable = true
		snapshot.Info.DiagnosticsStatus = status
		snapshot.Info.DiagnosticsWarningCodes = stringSliceValue(snapshot.Diagnostics["warning_codes"])
	}
	return snapshot
}

func pluginTypeLabel(p pluginpkg.Plugin) string {
	if typedPlugin, ok := p.(pluginpkg.TypedPlugin); ok {
		return string(typedPlugin.Type())
	}
	if typedPlugin, ok := p.(interface{ Type() string }); ok {
		return typedPlugin.Type()
	}
	return "unknown"
}

func pluginCapabilityLabels(p pluginpkg.Plugin) []string {
	capabilities := make([]string, 0, 10)
	if _, ok := p.(pluginpkg.TypedPlugin); ok {
		capabilities = append(capabilities, "typed")
	}
	if _, ok := p.(pluginpkg.TaggedPlugin); ok {
		capabilities = append(capabilities, "tagged")
	}
	if _, ok := p.(pluginpkg.MiddlewarePlugin); ok {
		capabilities = append(capabilities, "middleware")
	}
	if _, ok := p.(pluginpkg.HealthChecker); ok {
		capabilities = append(capabilities, "health")
	}
	if _, ok := p.(pluginpkg.StatusReporter); ok {
		capabilities = append(capabilities, "status_reporter")
	}
	if _, ok := p.(pluginpkg.DiagnosticsReporter); ok {
		capabilities = append(capabilities, "diagnostics")
	}
	if _, ok := p.(pluginpkg.ReloadablePlugin); ok {
		capabilities = append(capabilities, "reload")
	}
	if _, ok := p.(pluginpkg.LifecyclePlugin); ok {
		capabilities = append(capabilities, "lifecycle")
	}
	if _, ok := p.(pluginpkg.ClientUsageObserver); ok {
		capabilities = append(capabilities, "client_usage_observer")
	}
	if _, ok := p.(pluginpkg.ClientUsageObserverRegistrar); ok {
		capabilities = append(capabilities, "client_usage_registrar")
	}
	return capabilities
}
