package api

import (
	"github.com/gorilla/mux"
	"net/http"
)

// RegisterRoutes registers all management API routes
func (api *ManagementAPI) RegisterRoutes(router *mux.Router) {
	// API v1 routes
	v1 := router.PathPrefix("/api/v1").Subrouter()

	// Add CORS middleware for management API
	v1.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

			if r.Method == "OPTIONS" {
				w.WriteHeader(http.StatusOK)
				return
			}

			next.ServeHTTP(w, r)
		})
	})

	// Gateway management
	v1.HandleFunc("/gateway/status", api.getGatewayStatus).Methods("GET")
	v1.HandleFunc("/gateway/edition", api.getGatewayEdition).Methods("GET")
	v1.HandleFunc("/gateway/capabilities", api.listGatewayCapabilities).Methods("GET")
	v1.HandleFunc("/gateway/capabilities/{key}", api.getGatewayCapability).Methods("GET")
	v1.HandleFunc("/gateway/extensions", api.listGatewayExtensions).Methods("GET")
	v1.HandleFunc("/gateway/extensions/{name}", api.getGatewayExtension).Methods("GET")
	v1.HandleFunc("/gateway/config", api.getGatewayConfig).Methods("GET")
	v1.HandleFunc("/gateway/config", api.updateGatewayConfig).Methods("PUT")
	v1.HandleFunc("/gateway/config/self-test", api.selfTestGatewayConfig).Methods("GET")
	v1.HandleFunc("/gateway/reload", api.reloadGateway).Methods("POST")
	v1.HandleFunc("/gateway/metrics", api.getGatewayMetrics).Methods("GET")
	v1.HandleFunc("/gateway/backends", api.getGatewayBackends).Methods("GET")
	v1.HandleFunc("/gateway/route-policy", api.getGatewayRoutePolicy).Methods("GET")
	v1.HandleFunc("/gateway/route-policy/diff", api.diffGatewayRoutePolicy).Methods("GET")
	v1.HandleFunc("/gateway/limit-hits", api.getGatewayLimitHits).Methods("GET")
	v1.HandleFunc("/gateway/limit-buckets", api.getGatewayLimitBuckets).Methods("GET")
	v1.HandleFunc("/gateway/limit-classes", api.getGatewayLimitClasses).Methods("GET")
	v1.HandleFunc("/gateway/limit-class-alerts", api.getGatewayLimitClassAlerts).Methods("GET")
	v1.HandleFunc("/gateway/limit-class-incidents", api.getGatewayLimitClassIncidents).Methods("GET")
	v1.HandleFunc("/gateway/limit-class-alerts/notify", api.notifyGatewayLimitClassAlerts).Methods("POST")
	v1.HandleFunc("/gateway/limit-alerts", api.getGatewayLimitAlerts).Methods("GET")
	v1.HandleFunc("/gateway/limit-alerts/notify", api.notifyGatewayLimitAlerts).Methods("POST")
	v1.HandleFunc("/gateway/policy-hits", api.getGatewayPolicyHits).Methods("GET")
	v1.HandleFunc("/gateway/policy-alerts", api.getGatewayPolicyAlerts).Methods("GET")
	v1.HandleFunc("/gateway/policy-alerts/notify", api.notifyGatewayPolicyAlerts).Methods("POST")
	v1.HandleFunc("/gateway/shadow-report", api.getGatewayShadowReport).Methods("GET")
	v1.HandleFunc("/gateway/shadow-evaluate", api.getGatewayShadowEvaluation).Methods("GET")

	// Plugin management
	v1.HandleFunc("/plugins", api.listPlugins).Methods("GET")
	v1.HandleFunc("/plugins/{name}", api.getPluginDetails).Methods("GET")
	v1.HandleFunc("/plugins/{name}/config", api.updatePluginConfig).Methods("PUT")
	v1.HandleFunc("/plugins/{name}/enable", api.enablePlugin).Methods("POST")
	v1.HandleFunc("/plugins/{name}/disable", api.disablePlugin).Methods("POST")
	v1.HandleFunc("/plugins/{name}/health", api.getPluginHealth).Methods("GET")
	v1.HandleFunc("/plugins/{name}/status", api.getPluginStatus).Methods("GET")

	// Route management
	v1.HandleFunc("/routes", api.listRoutes).Methods("GET")
	v1.HandleFunc("/routes", api.createRoute).Methods("POST")
	v1.HandleFunc("/routes/{id}", api.getRouteDetails).Methods("GET")
	v1.HandleFunc("/routes/{id}", api.updateRoute).Methods("PUT")
	v1.HandleFunc("/routes/{id}", api.deleteRoute).Methods("DELETE")
	v1.HandleFunc("/routes/{id}/enable", api.enableRoute).Methods("POST")
	v1.HandleFunc("/routes/{id}/disable", api.disableRoute).Methods("POST")

	// Monitoring & logs
	v1.HandleFunc("/logs", api.getLogs).Methods("GET")
	v1.HandleFunc("/logs/stream", api.streamLogs).Methods("GET")
	v1.HandleFunc("/metrics/system", api.getSystemMetrics).Methods("GET")

	// WebSocket endpoints
	v1.HandleFunc("/ws/status", api.wsStatus).Methods("GET")
	v1.HandleFunc("/ws/metrics", api.wsMetrics).Methods("GET")
	v1.HandleFunc("/ws/logs", api.wsLogs).Methods("GET")

	// Certificate management
	v1.HandleFunc("/certificates", api.listCertificates).Methods("GET")
	v1.HandleFunc("/certificates", api.uploadCertificate).Methods("POST")
	v1.HandleFunc("/certificates/{id}", api.deleteCertificate).Methods("DELETE")
	v1.HandleFunc("/enrollment/tokens", api.createEnrollmentToken).Methods("POST")
	v1.HandleFunc("/enrollment/tokens", api.listEnrollmentTokens).Methods("GET")
	v1.HandleFunc("/enrollment/tokens/{id}", api.revokeEnrollmentToken).Methods("DELETE")

	// Backup & restore
	v1.HandleFunc("/backup", api.createBackup).Methods("POST")
	v1.HandleFunc("/backup", api.listBackups).Methods("GET")
	v1.HandleFunc("/backup/{id}/restore", api.restoreBackup).Methods("POST")
	v1.HandleFunc("/revisions", api.listRevisions).Methods("GET")
	v1.HandleFunc("/revisions/diff", api.diffRevisions).Methods("GET")
	v1.HandleFunc("/revisions/{id}", api.getRevision).Methods("GET")
	v1.HandleFunc("/revisions/{id}/restore", api.restoreRevision).Methods("POST")
	v1.HandleFunc("/proposals", api.listProposals).Methods("GET")
	v1.HandleFunc("/proposals/queue", api.getProposalQueue).Methods("GET")
	v1.HandleFunc("/proposals/queue/blocked-report", api.getBlockedProposalQueueReport).Methods("GET")
	v1.HandleFunc("/proposals/queue/notify-digest", api.notifyProposalQueueDigest).Methods("POST")
	v1.HandleFunc("/proposals/queue/approve-ready", api.approveReadyProposalQueue).Methods("POST")
	v1.HandleFunc("/proposals/queue/apply-ready", api.applyReadyProposalQueue).Methods("POST")
	v1.HandleFunc("/proposals/{id}", api.getProposal).Methods("GET")
	v1.HandleFunc("/proposals/{id}/verify", api.verifyProposal).Methods("GET")
	v1.HandleFunc("/proposals/{id}/readiness", api.getProposalReadiness).Methods("GET")
	v1.HandleFunc("/proposals/{id}/explain-blocked", api.explainBlockedProposal).Methods("GET")
	v1.HandleFunc("/proposals/{id}/canary", api.getProposalCanaryStatus).Methods("GET")
	v1.HandleFunc("/proposals/{id}/canary/evaluate", api.evaluateProposalCanary).Methods("GET")
	v1.HandleFunc("/proposals/{id}/canary/advance", api.advanceProposalCanary).Methods("POST")
	v1.HandleFunc("/proposals/{id}/canary/reconcile", api.reconcileProposalCanary).Methods("POST")
	v1.HandleFunc("/proposals/{id}/canary/expand", api.expandProposalCanary).Methods("POST")
	v1.HandleFunc("/proposals/{id}/canary/complete", api.completeProposalCanary).Methods("POST")
	v1.HandleFunc("/proposals/{id}/approve", api.approveProposal).Methods("POST")
	v1.HandleFunc("/proposals/{id}/apply", api.applyProposal).Methods("POST")
	v1.HandleFunc("/proposals/{id}/promote", api.promoteProposal).Methods("POST")
	v1.HandleFunc("/proposals/{id}/reject", api.rejectProposal).Methods("POST")
	v1.HandleFunc("/notifications/deliveries", api.listNotificationDeliveries).Methods("GET")
	v1.HandleFunc("/notifications/deliveries/{id}", api.getNotificationDelivery).Methods("GET")
	v1.HandleFunc("/notifications/deliveries/{id}/replay", api.replayNotificationDelivery).Methods("POST")
	v1.HandleFunc("/notifications/deliveries/replay-failed", api.replayFailedNotificationDeliveries).Methods("POST")

	// Service management
	v1.HandleFunc("/services", api.getServices).Methods("GET")
	v1.HandleFunc("/services", api.createService).Methods("POST")
	v1.HandleFunc("/services/{name}", api.updateService).Methods("PUT")
	v1.HandleFunc("/services/{name}", api.deleteService).Methods("DELETE")

	// Client management
	v1.HandleFunc("/clients", api.listClients).Methods("GET")
	v1.HandleFunc("/clients", api.addClient).Methods("POST")
	v1.HandleFunc("/clients/{key}", api.removeClient).Methods("DELETE")

	api.registerManagementRouteExtensions(v1)
}

func (api *ManagementAPI) RegisterEnrollmentRoutes(router *mux.Router) {
	v1 := router.PathPrefix("/api/v1").Subrouter()
	v1.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
			if r.Method == "OPTIONS" {
				w.WriteHeader(http.StatusOK)
				return
			}
			next.ServeHTTP(w, r)
		})
	})
	v1.HandleFunc("/enroll", api.enrollClientCertificate).Methods("POST")
}
