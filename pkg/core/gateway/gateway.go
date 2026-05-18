package gateway

import (
	"net/http"
	"sync"

	"github.com/bhangun/iket/pkg/config"
	"github.com/bhangun/iket/pkg/core/errors"
	"github.com/bhangun/iket/pkg/logging"
	"github.com/bhangun/iket/pkg/metrics"
	"github.com/bhangun/iket/pkg/plugin"

	"github.com/gorilla/mux"
)

// Gateway represents the main API gateway instance.
type Gateway struct {
	config         *config.Config
	configProvider config.Provider
	router         *mux.Router
	metrics        *metrics.Collector
	logger         *logging.Logger
	server         *http.Server
	tlsServer      *http.Server
	http3Server    http3Transport

	mu       sync.RWMutex
	shutdown chan struct{}

	backendStateMu sync.RWMutex
	backendState   map[string]backendRuntimeState

	rateLimitStateMu sync.Mutex
	rateLimitState   map[string]*routeRateLimitBucket

	concurrencyStateMu sync.Mutex
	concurrencyState   map[string]*routeConcurrencyBucket

	limitHitStateMu sync.RWMutex
	limitHitState   routeLimitHitRuntimeState

	policyStateMu sync.RWMutex
	policyState   policyHitRuntimeState

	version        string
	pluginRegistry *plugin.Registry
}

// Dependencies contains all the dependencies required to create a Gateway.
type Dependencies struct {
	Config         *config.Config
	ConfigProvider config.Provider
	Logger         *logging.Logger
	Metrics        *metrics.Collector
	Registry       *plugin.Registry
}

// NewGateway creates a new Gateway instance with the provided dependencies.
func NewGateway(deps Dependencies, version string) (*Gateway, error) {
	if deps.Config == nil {
		return nil, errors.NewConfigError("config is required", nil)
	}
	if deps.Logger == nil {
		return nil, errors.NewConfigError("logger is required", nil)
	}
	if err := deps.Config.Validate(); err != nil {
		return nil, errors.NewConfigError("invalid configuration", err)
	}

	gateway := &Gateway{
		config:           deps.Config,
		configProvider:   deps.ConfigProvider,
		router:           mux.NewRouter(),
		metrics:          deps.Metrics,
		logger:           deps.Logger,
		shutdown:         make(chan struct{}),
		backendState:     make(map[string]backendRuntimeState),
		rateLimitState:   make(map[string]*routeRateLimitBucket),
		concurrencyState: make(map[string]*routeConcurrencyBucket),
		limitHitState: routeLimitHitRuntimeState{
			ByType:  make(map[string]int),
			ByRoute: make(map[string]routeLimitHitRouteRuntimeEntry),
		},
		policyState: policyHitRuntimeState{
			ByReason: make(map[string]int),
			ByRoute:  make(map[string]policyHitRouteRuntimeState),
		},
		version:        version,
		pluginRegistry: deps.Registry,
	}
	if gateway.pluginRegistry == nil {
		gateway.pluginRegistry = plugin.NewRegistry()
	}

	return gateway, nil
}

// Initialize performs setup after external handlers have been registered.
func (g *Gateway) Initialize() error {
	if err := g.setupRoutes(); err != nil {
		return errors.NewConfigError("failed to setup routes", err)
	}
	if err := g.setupMiddleware(); err != nil {
		return errors.NewConfigError("failed to setup middleware", err)
	}
	if err := g.loadPlugins(); err != nil {
		return errors.NewConfigError("failed to load plugins", err)
	}

	go g.activeBackendProbeLoop()

	g.logger.Info("Gateway initialized successfully")
	return nil
}

func (g *Gateway) Version() string {
	return g.version
}
