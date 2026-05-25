package api

type pluginListSummary struct {
	Total               int            `json:"total"`
	Matched             int            `json:"matched"`
	Enabled             int            `json:"enabled"`
	Disabled            int            `json:"disabled"`
	ByType              map[string]int `json:"by_type"`
	ByStatus            map[string]int `json:"by_status"`
	ByDiagnosticsStatus map[string]int `json:"by_diagnostics_status"`
	ByCapability        map[string]int `json:"by_capability"`
}

func pluginListSummaryFromInfos(infos []PluginInfo, matched int) pluginListSummary {
	summary := pluginListSummary{
		Total:               len(infos),
		Matched:             matched,
		ByType:              make(map[string]int),
		ByStatus:            make(map[string]int),
		ByDiagnosticsStatus: make(map[string]int),
		ByCapability:        make(map[string]int),
	}
	for _, info := range infos {
		if info.Enabled {
			summary.Enabled++
		} else {
			summary.Disabled++
		}
		incrementPluginListSummaryCount(summary.ByType, info.Type, "unknown")
		incrementPluginListSummaryCount(summary.ByStatus, info.Status, "unknown")
		diagnosticsStatus := info.DiagnosticsStatus
		if !info.DiagnosticsAvailable || diagnosticsStatus == "" {
			diagnosticsStatus = "unavailable"
		}
		incrementPluginListSummaryCount(summary.ByDiagnosticsStatus, diagnosticsStatus, "unavailable")
		for _, capability := range info.Capabilities {
			incrementPluginListSummaryCount(summary.ByCapability, capability, "")
		}
	}
	return summary
}

func incrementPluginListSummaryCount(counts map[string]int, value string, fallback string) {
	value = normalizePluginFilterValue(value)
	if value == "" {
		value = fallback
	}
	if value == "" {
		return
	}
	counts[value]++
}
