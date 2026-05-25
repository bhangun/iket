package api

import "net/http"

func (api *ManagementAPI) getGatewayShadowReport(w http.ResponseWriter, r *http.Request) {
	summaries := api.gateway.ShadowRouteSummaries()
	api.writeJSON(w, map[string]interface{}{
		"routes": summaries,
		"total":  len(summaries),
	})
}

func (api *ManagementAPI) getGatewayShadowEvaluation(w http.ResponseWriter, r *http.Request) {
	evaluations := api.gateway.ShadowRouteEvaluations()
	healthy := 0
	failed := 0
	withPolicy := 0
	for _, evaluation := range evaluations {
		if evaluation.PolicyConfigured {
			withPolicy++
		}
		if evaluation.Healthy {
			healthy++
		} else {
			failed++
		}
	}
	api.writeJSON(w, map[string]interface{}{
		"routes":      evaluations,
		"total":       len(evaluations),
		"with_policy": withPolicy,
		"healthy":     healthy,
		"failed":      failed,
		"all_healthy": failed == 0,
	})
}
