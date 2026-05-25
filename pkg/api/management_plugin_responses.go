package api

import (
	"time"

	pluginpkg "github.com/bhangun/iket/pkg/plugin"
)

func pluginDetailsResponse(snapshot pluginInventorySnapshot) map[string]interface{} {
	details := map[string]interface{}{
		"name":         snapshot.Info.Name,
		"type":         snapshot.Info.Type,
		"enabled":      snapshot.Info.Enabled,
		"status":       snapshot.Info.Status,
		"capabilities": snapshot.Info.Capabilities,
	}
	if snapshot.Tagged {
		details["tags"] = snapshot.Info.Tags
	}
	if snapshot.HasHealth {
		details["health"] = snapshot.Health
	}
	if snapshot.HasStatus {
		details["status_message"] = snapshot.StatusMessage
	}
	if snapshot.HasDiagnostics {
		details["diagnostics"] = snapshot.Diagnostics
	}
	return details
}

func pluginHealthResponse(p pluginpkg.Plugin) (map[string]interface{}, bool) {
	reporter, ok := p.(pluginpkg.HealthChecker)
	if !ok {
		return nil, false
	}

	response := map[string]interface{}{
		"status":     "healthy",
		"last_check": time.Now(),
		"message":    "Plugin is functioning normally",
	}
	if err := reporter.Health(); err != nil {
		response["status"] = "unhealthy"
		response["message"] = err.Error()
	}
	return response, true
}

func pluginStatusResponse(p pluginpkg.Plugin, enabled bool) (map[string]interface{}, bool) {
	statusReporter, hasStatus := p.(pluginpkg.StatusReporter)
	diagnosticsReporter, hasDiagnostics := p.(pluginpkg.DiagnosticsReporter)
	if !hasStatus && !hasDiagnostics {
		return nil, false
	}

	var diagnostics map[string]interface{}
	if hasDiagnostics {
		diagnostics = diagnosticsReporter.Diagnostics()
	}

	statusValue := "unknown"
	statusSource := "diagnostics"
	if hasStatus {
		statusValue = statusReporter.Status()
		statusSource = "status_reporter"
	} else if diagnosticsStatus := stringValue(diagnostics["status"]); diagnosticsStatus != "" {
		statusValue = diagnosticsStatus
	}

	response := map[string]interface{}{
		"status":        statusValue,
		"status_source": statusSource,
		"enabled":       enabled,
		"last_update":   time.Now(),
	}
	if hasDiagnostics {
		response["diagnostics"] = diagnostics
	}
	return response, true
}
