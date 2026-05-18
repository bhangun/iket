package api

import (
	"github.com/bhangun/iket/pkg/core/gateway"
	"github.com/bhangun/iket/pkg/logging"
	"github.com/bhangun/iket/pkg/plugin"
	"github.com/gorilla/websocket"
	"net/http"
	"sync"
	"time"
)

// ManagementAPI provides REST endpoints for gateway management
type ManagementAPI struct {
	gateway    *gateway.Gateway
	logger     *logging.Logger
	registry   *plugin.Registry
	mu         sync.RWMutex
	startedAt  time.Time
	lastReload time.Time

	// WebSocket upgrader
	upgrader websocket.Upgrader

	// Real-time update channels
	statusSubscribers  map[*websocket.Conn]bool
	metricsSubscribers map[*websocket.Conn]bool
	logsSubscribers    map[*websocket.Conn]bool
	subscriberMu       sync.RWMutex

	queueDigestNotifyMu                     sync.Mutex
	lastQueueDigestNotificationAt           map[string]time.Time
	lastQueueDigestNotificationChecksum     map[string]string
	queueDigestSLABreachState               map[string]proposalQueueSLABreachState
	slaBreachEscalationState                map[string]proposalQueueSLABreachEscalationState
	lastPolicyAlertNotificationAt           time.Time
	lastPolicyAlertNotificationChecksum     string
	lastLimitAlertNotificationAt            time.Time
	lastLimitAlertNotificationChecksum      string
	lastLimitClassAlertNotificationAt       time.Time
	lastLimitClassAlertNotificationChecksum string
	policyAlertIncidentState                map[string]gatewayPolicyAlertIncidentState
	limitAlertIncidentState                 map[string]gatewayLimitAlertIncidentState
	limitClassAlertIncidentState            map[string]gatewayLimitClassAlertIncidentState
}

const defaultProposalCanaryAutoReconcileInterval = 30 * time.Second

// NewManagementAPI creates a new management API instance
func NewManagementAPI(gateway *gateway.Gateway, logger *logging.Logger, registry *plugin.Registry) *ManagementAPI {
	api := &ManagementAPI{
		gateway:    gateway,
		logger:     logger,
		registry:   registry,
		startedAt:  time.Now(),
		lastReload: time.Now(),
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool {
				return true // Allow all origins for now
			},
		},
		statusSubscribers:                   make(map[*websocket.Conn]bool),
		metricsSubscribers:                  make(map[*websocket.Conn]bool),
		logsSubscribers:                     make(map[*websocket.Conn]bool),
		lastQueueDigestNotificationAt:       make(map[string]time.Time),
		lastQueueDigestNotificationChecksum: make(map[string]string),
		queueDigestSLABreachState:           make(map[string]proposalQueueSLABreachState),
		slaBreachEscalationState:            make(map[string]proposalQueueSLABreachEscalationState),
		policyAlertIncidentState:            make(map[string]gatewayPolicyAlertIncidentState),
		limitAlertIncidentState:             make(map[string]gatewayLimitAlertIncidentState),
		limitClassAlertIncidentState:        make(map[string]gatewayLimitClassAlertIncidentState),
	}

	// Start real-time update goroutines
	go api.broadcastStatusUpdates()
	go api.broadcastMetricsUpdates()
	go api.autoReconcileCanaries()
	go api.autoNotifyProposalQueueDigests()
	go api.autoNotifyGatewayPolicyAlerts()
	go api.autoNotifyGatewayLimitAlerts()
	go api.autoNotifyGatewayLimitClassAlerts()

	return api
}
