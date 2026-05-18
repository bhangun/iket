package config

import (
	"bufio"
	"crypto/rsa"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"net/http"
	"os"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"

	coreerrors "github.com/bhangun/iket/pkg/core/errors"
	"github.com/bhangun/iket/pkg/logging"

	"github.com/golang-jwt/jwt/v4"
)

// Config represents the main configuration structure
type Config struct {
	Server   ServerConfig                      `yaml:"server"`
	Security SecurityConfig                    `yaml:"security"`
	Storage  StorageConfig                     `yaml:"storage,omitempty"`
	Services []ServiceConfig                   `yaml:"services,omitempty"` // New service-based configuration
	Plugins  map[string]map[string]interface{} `yaml:"plugins"`
}

type StorageConfig struct {
	Mode        string `yaml:"mode,omitempty" json:"mode,omitempty"`
	SQLitePath  string `yaml:"sqlite_path,omitempty" json:"sqlite_path,omitempty"`
	PostgresURL string `yaml:"postgres_url,omitempty" json:"postgres_url,omitempty"`
	MirrorFiles *bool  `yaml:"mirror_files,omitempty" json:"mirror_files,omitempty"`
}

func (s StorageConfig) EffectiveMode() string {
	if strings.TrimSpace(s.Mode) == "" {
		return "sqlite"
	}
	return strings.ToLower(strings.TrimSpace(s.Mode))
}

func (s StorageConfig) EffectiveMirrorFiles() bool {
	return s.MirrorFiles == nil || *s.MirrorFiles
}

// ServerConfig represents server configuration
type ServerConfig struct {
	Port          int       `yaml:"port"`
	ReadTimeout   string    `yaml:"readTimeout"`
	WriteTimeout  string    `yaml:"writeTimeout"`
	IdleTimeout   string    `yaml:"idleTimeout"`
	PluginsDir    string    `yaml:"pluginsDir,omitempty"`
	EnableLogging bool      `yaml:"enableLogging"`
	TLS           TLSConfig `yaml:"tls,omitempty"`
}

// SecurityConfig represents security configuration
type SecurityConfig struct {
	TLS                  TLSConfig             `yaml:"tls"`
	EnableBasicAuth      bool                  `yaml:"enableBasicAuth"`
	BasicAuthUsers       map[string]string     `yaml:"basicAuthUsers"`
	IPWhitelist          []string              `yaml:"ipWhitelist"`
	Headers              map[string]string     `yaml:"headers"`
	Clients              map[string]string     `yaml:"clients"` // clientID: clientSecret
	Jwt                  JWTConfig             `yaml:"jwt"`
	MutationPolicy       MutationPolicy        `yaml:"mutationPolicy,omitempty"`
	NotificationWebhooks []NotificationWebhook `yaml:"notificationWebhooks,omitempty"`
}

type MutationPolicy struct {
	Enabled                                                     bool                          `yaml:"enabled,omitempty" json:"enabled,omitempty"`
	EnforcedScopes                                              []string                      `yaml:"enforcedScopes,omitempty" json:"enforcedScopes,omitempty"`
	RequireLabel                                                bool                          `yaml:"requireLabel,omitempty" json:"requireLabel,omitempty"`
	RequireNoteForHighImpact                                    bool                          `yaml:"requireNoteForHighImpact,omitempty" json:"requireNoteForHighImpact,omitempty"`
	RequireChangeRefForHighImpact                               bool                          `yaml:"requireChangeRefForHighImpact,omitempty" json:"requireChangeRefForHighImpact,omitempty"`
	RequireDifferentReviewerForProposals                        bool                          `yaml:"requireDifferentReviewerForProposals,omitempty" json:"requireDifferentReviewerForProposals,omitempty"`
	MinApproversForHighImpactProposals                          int                           `yaml:"minApproversForHighImpactProposals,omitempty" json:"minApproversForHighImpactProposals,omitempty"`
	RequireNotBeforeForHighImpactProposals                      bool                          `yaml:"requireNotBeforeForHighImpactProposals,omitempty" json:"requireNotBeforeForHighImpactProposals,omitempty"`
	RequireVerificationForPromotedHighImpactProposals           bool                          `yaml:"requireVerificationForPromotedHighImpactProposals,omitempty" json:"requireVerificationForPromotedHighImpactProposals,omitempty"`
	RequireShadowEvaluationForPromotedHighImpactProposals       bool                          `yaml:"requireShadowEvaluationForPromotedHighImpactProposals,omitempty" json:"requireShadowEvaluationForPromotedHighImpactProposals,omitempty"`
	MinShadowHealthyVerificationsForPromotedHighImpactProposals int                           `yaml:"minShadowHealthyVerificationsForPromotedHighImpactProposals,omitempty" json:"minShadowHealthyVerificationsForPromotedHighImpactProposals,omitempty"`
	MaxProposalAge                                              string                        `yaml:"maxProposalAge,omitempty" json:"maxProposalAge,omitempty"`
	MaxApprovalAge                                              string                        `yaml:"maxApprovalAge,omitempty" json:"maxApprovalAge,omitempty"`
	BlockedApplyWindows                                         []MutationApplyWindow         `yaml:"blockedApplyWindows,omitempty" json:"blockedApplyWindows,omitempty"`
	ProposalQueue                                               ProposalQueuePolicy           `yaml:"proposalQueue,omitempty" json:"proposalQueue,omitempty"`
	PolicyAlertNotifications                                    PolicyAlertNotificationPolicy `yaml:"policyAlertNotifications,omitempty" json:"policyAlertNotifications,omitempty"`
}

type ProposalQueuePolicy struct {
	DefaultUrgency     ProposalQueueUrgencyThresholds            `yaml:"defaultUrgency,omitempty" json:"defaultUrgency,omitempty"`
	EnvironmentUrgency map[string]ProposalQueueUrgencyThresholds `yaml:"environmentUrgency,omitempty" json:"environmentUrgency,omitempty"`
	Notifications      ProposalQueueNotificationPolicy           `yaml:"notifications,omitempty" json:"notifications,omitempty"`
}

type ProposalQueueUrgencyThresholds struct {
	ReadyAgingAfter     string `yaml:"readyAgingAfter,omitempty" json:"readyAgingAfter,omitempty"`
	ReadyOverdueAfter   string `yaml:"readyOverdueAfter,omitempty" json:"readyOverdueAfter,omitempty"`
	BlockedAgingAfter   string `yaml:"blockedAgingAfter,omitempty" json:"blockedAgingAfter,omitempty"`
	BlockedOverdueAfter string `yaml:"blockedOverdueAfter,omitempty" json:"blockedOverdueAfter,omitempty"`
}

type ProposalQueueNotificationPolicy struct {
	Enabled                 bool     `yaml:"enabled,omitempty" json:"enabled,omitempty"`
	Interval                string   `yaml:"interval,omitempty" json:"interval,omitempty"`
	MinNotificationInterval string   `yaml:"minNotificationInterval,omitempty" json:"minNotificationInterval,omitempty"`
	OnlyOnSLABreach         bool     `yaml:"onlyOnSLABreach,omitempty" json:"onlyOnSLABreach,omitempty"`
	OnlyOnChange            bool     `yaml:"onlyOnChange,omitempty" json:"onlyOnChange,omitempty"`
	Environments            []string `yaml:"environments,omitempty" json:"environments,omitempty"`
}

type PolicyAlertNotificationPolicy struct {
	Enabled                 bool   `yaml:"enabled,omitempty" json:"enabled,omitempty"`
	Interval                string `yaml:"interval,omitempty" json:"interval,omitempty"`
	MinNotificationInterval string `yaml:"minNotificationInterval,omitempty" json:"minNotificationInterval,omitempty"`
	OnlyOnChange            bool   `yaml:"onlyOnChange,omitempty" json:"onlyOnChange,omitempty"`
	Window                  string `yaml:"window,omitempty" json:"window,omitempty"`
	MinCount                int    `yaml:"minCount,omitempty" json:"minCount,omitempty"`
	MinSeverity             string `yaml:"minSeverity,omitempty" json:"minSeverity,omitempty"`
}

type MutationApplyWindow struct {
	Name     string   `yaml:"name,omitempty" json:"name,omitempty"`
	Days     []string `yaml:"days,omitempty" json:"days,omitempty"`
	Start    string   `yaml:"start" json:"start"`
	End      string   `yaml:"end" json:"end"`
	Timezone string   `yaml:"timezone,omitempty" json:"timezone,omitempty"`
	Scopes   []string `yaml:"scopes,omitempty" json:"scopes,omitempty"`
}

type NotificationWebhook struct {
	Name                      string            `yaml:"name,omitempty" json:"name,omitempty"`
	URL                       string            `yaml:"url" json:"url"`
	Format                    string            `yaml:"format,omitempty" json:"format,omitempty"`
	Events                    []string          `yaml:"events,omitempty" json:"events,omitempty"`
	Environments              []string          `yaml:"environments,omitempty" json:"environments,omitempty"`
	MinSLABreachCount         int               `yaml:"minSLABreachCount,omitempty" json:"minSLABreachCount,omitempty"`
	MinConsecutiveSLABreaches int               `yaml:"minConsecutiveSLABreaches,omitempty" json:"minConsecutiveSLABreaches,omitempty"`
	MinSLABreachDuration      string            `yaml:"minSLABreachDuration,omitempty" json:"minSLABreachDuration,omitempty"`
	MinSLABreachTier          string            `yaml:"minSLABreachTier,omitempty" json:"minSLABreachTier,omitempty"`
	SLABreachCooldown         string            `yaml:"slaBreachCooldown,omitempty" json:"slaBreachCooldown,omitempty"`
	Headers                   map[string]string `yaml:"headers,omitempty" json:"headers,omitempty"`
	Timeout                   string            `yaml:"timeout,omitempty" json:"timeout,omitempty"`
	RetryCount                int               `yaml:"retryCount,omitempty" json:"retryCount,omitempty"`
	RetryBackoff              string            `yaml:"retryBackoff,omitempty" json:"retryBackoff,omitempty"`
	SigningSecret             string            `yaml:"signingSecret,omitempty" json:"signingSecret,omitempty"`
	SignatureHeader           string            `yaml:"signatureHeader,omitempty" json:"signatureHeader,omitempty"`
	TimestampHeader           string            `yaml:"timestampHeader,omitempty" json:"timestampHeader,omitempty"`
	InsecureSkipVerify        bool              `yaml:"insecureSkipVerify,omitempty" json:"insecureSkipVerify,omitempty"`
}

// RouterConfig represents a route configuration
type RouterConfig struct {
	Path                           string            `yaml:"path"`
	Methods                        []string          `yaml:"methods"`
	Method                         string            `yaml:"method"` // Single method for new format
	MatchHeaders                   map[string]string `yaml:"matchHeaders,omitempty" json:"matchHeaders,omitempty"`
	MatchPercent                   int               `yaml:"matchPercent,omitempty" json:"matchPercent,omitempty"`
	RetryCount                     int               `yaml:"retryCount,omitempty" json:"retryCount,omitempty"`
	RetryBackoff                   string            `yaml:"retryBackoff,omitempty" json:"retryBackoff,omitempty"`
	RetryJitter                    string            `yaml:"retryJitter,omitempty" json:"retryJitter,omitempty"`
	RetryStatuses                  []int             `yaml:"retryStatusCodes,omitempty" json:"retryStatusCodes,omitempty"`
	RetryUnsafe                    bool              `yaml:"retryUnsafeMethods,omitempty" json:"retryUnsafeMethods,omitempty"`
	HedgeDelay                     string            `yaml:"hedgeDelay,omitempty" json:"hedgeDelay,omitempty"`
	HedgeUnsafe                    bool              `yaml:"hedgeUnsafeMethods,omitempty" json:"hedgeUnsafeMethods,omitempty"`
	AdaptiveLatencyRouting         bool              `yaml:"adaptiveLatencyRouting,omitempty" json:"adaptive_latency_routing,omitempty"`
	ShadowTrafficPercent           int               `yaml:"shadowTrafficPercent,omitempty" json:"shadow_traffic_percent,omitempty"`
	ShadowUnsafe                   bool              `yaml:"shadowUnsafeMethods,omitempty" json:"shadow_unsafe_methods,omitempty"`
	ShadowMinRequests              int               `yaml:"shadowMinRequests,omitempty" json:"shadow_min_requests,omitempty"`
	ShadowMaxErrorRate             float64           `yaml:"shadowMaxErrorRate,omitempty" json:"shadow_max_error_rate,omitempty"`
	ShadowMaxLatencyDelta          string            `yaml:"shadowMaxLatencyDelta,omitempty" json:"shadow_max_latency_delta,omitempty"`
	RequireAuth                    bool              `yaml:"requireAuth"`
	RateLimit                      *int              `yaml:"rateLimit"`
	Timeout                        *time.Duration    `yaml:"timeout"`
	Headers                        map[string]string `yaml:"headers"`
	RequestHeaders                 map[string]string `yaml:"requestHeaders,omitempty" json:"request_headers,omitempty"`
	RemoveRequestHeaders           []string          `yaml:"removeRequestHeaders,omitempty" json:"remove_request_headers,omitempty"`
	RequestRedactHeaders           []string          `yaml:"requestRedactHeaders,omitempty" json:"request_redact_headers,omitempty"`
	RequiredRequestHeaders         []string          `yaml:"requiredRequestHeaders,omitempty" json:"required_request_headers,omitempty"`
	RequiredRequestHeaderRegex     map[string]string `yaml:"requiredRequestHeaderRegex,omitempty" json:"required_request_header_regex,omitempty"`
	RequestJSONFields              map[string]string `yaml:"requestJSONFields,omitempty" json:"request_json_fields,omitempty"`
	RemoveRequestJSONFields        []string          `yaml:"removeRequestJSONFields,omitempty" json:"remove_request_json_fields,omitempty"`
	RequestRedactJSONFields        []string          `yaml:"requestRedactJSONFields,omitempty" json:"request_redact_json_fields,omitempty"`
	RequestBodyBlockRegex          []string          `yaml:"requestBodyBlockRegex,omitempty" json:"request_body_block_regex,omitempty"`
	RequestBodyRequireRegex        []string          `yaml:"requestBodyRequireRegex,omitempty" json:"request_body_require_regex,omitempty"`
	RequestPIIBlockTypes           []string          `yaml:"requestPIIBlockTypes,omitempty" json:"request_pii_block_types,omitempty"`
	QueryParams                    map[string]string `yaml:"queryParams,omitempty" json:"query_params,omitempty"`
	RemoveQueryParams              []string          `yaml:"removeQueryParams,omitempty" json:"remove_query_params,omitempty"`
	Protocol                       string            `yaml:"protocol,omitempty" json:"protocol,omitempty"`
	GraphQLAllowIntrospection      *bool             `yaml:"graphqlAllowIntrospection,omitempty" json:"graphql_allow_introspection,omitempty"`
	GraphQLRequirePersistedQuery   bool              `yaml:"graphqlRequirePersistedQuery,omitempty" json:"graphql_require_persisted_query,omitempty"`
	GraphQLPersistedQueryField     string            `yaml:"graphqlPersistedQueryField,omitempty" json:"graphql_persisted_query_field,omitempty"`
	GraphQLAllowedOperations       []string          `yaml:"graphqlAllowedOperations,omitempty" json:"graphql_allowed_operations,omitempty"`
	GraphQLOperationNameRequired   bool              `yaml:"graphqlOperationNameRequired,omitempty" json:"graphql_operation_name_required,omitempty"`
	AllowedModels                  []string          `yaml:"allowedModels,omitempty" json:"allowed_models,omitempty"`
	ModelField                     string            `yaml:"modelField,omitempty" json:"model_field,omitempty"`
	AllowedToolNames               []string          `yaml:"allowedToolNames,omitempty" json:"allowed_tool_names,omitempty"`
	ToolField                      string            `yaml:"toolField,omitempty" json:"tool_field,omitempty"`
	MaxMessages                    int               `yaml:"maxMessages,omitempty" json:"max_messages,omitempty"`
	MessagesField                  string            `yaml:"messagesField,omitempty" json:"messages_field,omitempty"`
	MaxToolCalls                   int               `yaml:"maxToolCalls,omitempty" json:"max_tool_calls,omitempty"`
	ToolCallsField                 string            `yaml:"toolCallsField,omitempty" json:"tool_calls_field,omitempty"`
	MaxInputTokens                 int               `yaml:"maxInputTokens,omitempty" json:"max_input_tokens,omitempty"`
	InputTokensField               string            `yaml:"inputTokensField,omitempty" json:"input_tokens_field,omitempty"`
	MaxOutputTokens                int               `yaml:"maxOutputTokens,omitempty" json:"max_output_tokens,omitempty"`
	OutputTokensField              string            `yaml:"outputTokensField,omitempty" json:"output_tokens_field,omitempty"`
	AllowedUpstreamHosts           []string          `yaml:"allowedUpstreamHosts,omitempty" json:"allowed_upstream_hosts,omitempty"`
	TransformWhenHeaders           map[string]string `yaml:"transformWhenHeaders,omitempty" json:"transform_when_headers,omitempty"`
	TransformWhenQueryParams       map[string]string `yaml:"transformWhenQueryParams,omitempty" json:"transform_when_query_params,omitempty"`
	TransformWhenHeaderRegex       map[string]string `yaml:"transformWhenHeaderRegex,omitempty" json:"transform_when_header_regex,omitempty"`
	TransformWhenQueryRegex        map[string]string `yaml:"transformWhenQueryRegex,omitempty" json:"transform_when_query_regex,omitempty"`
	TransformMethods               []string          `yaml:"transformMethods,omitempty" json:"transform_methods,omitempty"`
	TransformScopes                []string          `yaml:"transformScopes,omitempty" json:"transform_scopes,omitempty"`
	ResponseTransformStatusCodes   []int             `yaml:"responseTransformStatusCodes,omitempty" json:"response_transform_status_codes,omitempty"`
	ResponseTransformStatusClasses []string          `yaml:"responseTransformStatusClasses,omitempty" json:"response_transform_status_classes,omitempty"`
	ResponseTransformWhenHeaders   map[string]string `yaml:"responseTransformWhenHeaders,omitempty" json:"response_transform_when_headers,omitempty"`
	ResponseTransformHeaderRegex   map[string]string `yaml:"responseTransformHeaderRegex,omitempty" json:"response_transform_header_regex,omitempty"`
	ResponseHeaders                map[string]string `yaml:"responseHeaders,omitempty" json:"response_headers,omitempty"`
	RemoveResponseHeaders          []string          `yaml:"removeResponseHeaders,omitempty" json:"remove_response_headers,omitempty"`
	RedactionValue                 string            `yaml:"redactionValue,omitempty" json:"redaction_value,omitempty"`
	ResponseRedactHeaders          []string          `yaml:"responseRedactHeaders,omitempty" json:"response_redact_headers,omitempty"`
	SuccessResponseFields          map[string]string `yaml:"successResponseFields,omitempty" json:"success_response_fields,omitempty"`
	ErrorResponseFields            map[string]string `yaml:"errorResponseFields,omitempty" json:"error_response_fields,omitempty"`
	ResponseJSONFields             map[string]string `yaml:"responseJSONFields,omitempty" json:"response_json_fields,omitempty"`
	RemoveResponseJSONFields       []string          `yaml:"removeResponseJSONFields,omitempty" json:"remove_response_json_fields,omitempty"`
	ResponseRedactJSONFields       []string          `yaml:"responseRedactJSONFields,omitempty" json:"response_redact_json_fields,omitempty"`
	ResponseBodyBlockRegex         []string          `yaml:"responseBodyBlockRegex,omitempty" json:"response_body_block_regex,omitempty"`
	ResponseBodyRequireRegex       []string          `yaml:"responseBodyRequireRegex,omitempty" json:"response_body_require_regex,omitempty"`
	ResponsePIIBlockTypes          []string          `yaml:"responsePIIBlockTypes,omitempty" json:"response_pii_block_types,omitempty"`
	MaxRequestBodyBytes            int64             `yaml:"maxRequestBodyBytes,omitempty" json:"max_request_body_bytes,omitempty"`
	MaxResponseBodyBytes           int64             `yaml:"maxResponseBodyBytes,omitempty" json:"max_response_body_bytes,omitempty"`
	StripPath                      bool              `yaml:"stripPath"`
	ValidateSchema                 string            `yaml:"validateSchema"`
	WebSocket                      *WebSocketOptions `yaml:"websocket,omitempty"`
	CORS                           *CORSConfig       `yaml:"cors,omitempty" json:"cors,omitempty"`
	RequireJwt                     bool              `yaml:"requireJwt"`
	Enabled                        *bool             `yaml:"enabled"`
	AuthPlugin                     string            `yaml:"auth_plugin,omitempty" json:"auth_plugin,omitempty"`
	// New fields for enhanced configuration
	Name            string    `yaml:"name,omitempty" json:"name,omitempty"`
	Description     string    `yaml:"description,omitempty" json:"description,omitempty"`
	Tags            []string  `yaml:"tags,omitempty" json:"tags,omitempty"`
	Group           string    `yaml:"group,omitempty" json:"group,omitempty"`
	Priority        int       `yaml:"priority,omitempty" json:"priority,omitempty"`
	ConcurrentCalls string    `yaml:"concurrent_calls,omitempty" json:"concurrent_calls,omitempty"`
	MaxRate         string    `yaml:"max_rate,omitempty" json:"max_rate,omitempty"`
	Backends        []Backend `yaml:"backend" json:"backend"`
	Roles           []string  `yaml:"roles,omitempty" json:"roles,omitempty"`
	Scopes          []string  `yaml:"scopes,omitempty" json:"scopes,omitempty"`
	ServiceName     string    `yaml:"-" json:"service_name,omitempty"`
	ServiceHost     string    `yaml:"-" json:"service_host,omitempty"`
}

type CORSConfig struct {
	AllowedOrigins   []string `yaml:"allowedOrigins,omitempty" json:"allowed_origins,omitempty"`
	AllowedMethods   []string `yaml:"allowedMethods,omitempty" json:"allowed_methods,omitempty"`
	AllowedHeaders   []string `yaml:"allowedHeaders,omitempty" json:"allowed_headers,omitempty"`
	ExposedHeaders   []string `yaml:"exposedHeaders,omitempty" json:"exposed_headers,omitempty"`
	AllowCredentials bool     `yaml:"allowCredentials,omitempty" json:"allow_credentials,omitempty"`
	MaxAge           int      `yaml:"maxAge,omitempty" json:"max_age,omitempty"`
}

// TLSConfig represents TLS configuration
type TLSConfig struct {
	Enabled              bool     `yaml:"enabled"`
	Port                 int      `yaml:"port,omitempty"`
	HTTP3Enabled         bool     `yaml:"http3Enabled,omitempty"`
	HTTP3Port            int      `yaml:"http3Port,omitempty"`
	HTTP3Datagrams       bool     `yaml:"http3Datagrams,omitempty"`
	EnrollmentPort       int      `yaml:"enrollmentPort,omitempty"`
	EnrollmentMaxActive  int      `yaml:"enrollmentMaxActive,omitempty"`
	CertFile             string   `yaml:"certFile"`
	KeyFile              string   `yaml:"keyFile"`
	ClientCAFile         string   `yaml:"clientCAFile"`
	ClientAuthType       string   `yaml:"clientAuthType"` // NoClientCert, RequestClientCert, RequireAnyClientCert, VerifyClientCertIfGiven, RequireAndVerifyClientCert
	MinVersion           string   `yaml:"minVersion"`
	Ciphers              []string `yaml:"ciphers"`
	ServerNames          []string `yaml:"serverNames,omitempty"`
	ServerIPs            []string `yaml:"serverIPs,omitempty"`
	AutoGenerate         *bool    `yaml:"autoGenerate,omitempty"`
	GenerateSharedClient *bool    `yaml:"generateSharedClient,omitempty"`
}

type WebSocketOptions struct {
	Timeout             string            `yaml:"timeout,omitempty"`
	BufferSize          int               `yaml:"bufferSize,omitempty"`
	DNSRoundRobin       bool              `yaml:"dnsRoundRobin,omitempty"`
	InjectHeaders       map[string]string `yaml:"injectHeaders,omitempty"`
	AllowedSubprotocols []string          `yaml:"allowedSubprotocols,omitempty"`
	MaxConnections      int               `yaml:"maxConnections,omitempty"`
	MaxConnectionsPerIP int               `yaml:"maxConnectionsPerIP,omitempty"`
	RateLimit           int               `yaml:"rateLimit,omitempty"`
	HandshakeTimeout    time.Duration     `json:"handshake_timeout"`
	ReadBufferSize      int               `json:"read_buffer_size"`
	WriteBufferSize     int               `json:"write_buffer_size"`
	EnableCompression   bool              `json:"enable_compression"`
	CheckOrigin         bool              `json:"check_origin"`
	// InsecureSkipVerify allows the gateway to connect to upstream wss:// backends
	// with self-signed certificates (common for internal services).
	// Prefer proper CA trust in production whenever possible.
	InsecureSkipVerify bool `yaml:"insecureSkipVerify,omitempty" json:"insecureSkipVerify,omitempty"`
}

// JWTConfig holds JWT auth settings
type JWTConfig struct {
	Enabled       bool     `yaml:"enabled"`
	Secret        string   `yaml:"secret"`
	Algorithms    []string `yaml:"algorithms"`
	PublicKeyFile string   `yaml:"publicKeyFile"`
	Required      bool     `yaml:"required"`
}

// ServiceConfig represents the new service-based configuration structure
type ServiceConfig struct {
	Version  int       `yaml:"version" json:"version"`
	Services []Service `yaml:"services" json:"services"`
	CacheTTL string    `yaml:"cache_ttl" json:"cache_ttl"`
	Timeout  string    `yaml:"timeout" json:"timeout"`
}

// Service represents a service in the new configuration format
type Service struct {
	Name        string         `yaml:"name,omitempty" json:"name,omitempty"`
	Description string         `yaml:"description,omitempty" json:"description,omitempty"`
	Host        string         `yaml:"host" json:"host"`
	BasePath    string         `yaml:"base_path,omitempty" json:"base_path,omitempty"`
	Tags        []string       `yaml:"tags,omitempty" json:"tags,omitempty"`
	Group       string         `yaml:"group,omitempty" json:"group,omitempty"`
	Scopes      []string       `yaml:"scopes,omitempty" json:"scopes,omitempty"`
	Routes      []RouterConfig `yaml:"routes" json:"routes"`
}

// Backend represents a backend configuration for routes
type Backend struct {
	URLPattern                      string `yaml:"url_pattern" json:"url_pattern"`
	Host                            string `yaml:"host,omitempty" json:"host,omitempty"`
	Weight                          int    `yaml:"weight,omitempty" json:"weight,omitempty"`
	Timeout                         string `yaml:"timeout,omitempty" json:"timeout,omitempty"`
	FailureThreshold                int    `yaml:"failureThreshold,omitempty" json:"failureThreshold,omitempty"`
	Cooldown                        string `yaml:"cooldown,omitempty" json:"cooldown,omitempty"`
	HalfOpenMaxRequests             int    `yaml:"halfOpenMaxRequests,omitempty" json:"halfOpenMaxRequests,omitempty"`
	RecoverySuccessThreshold        int    `yaml:"recoverySuccessThreshold,omitempty" json:"recoverySuccessThreshold,omitempty"`
	OutlierLatencyThreshold         string `yaml:"outlierLatencyThreshold,omitempty" json:"outlierLatencyThreshold,omitempty"`
	OutlierConsecutiveSlowResponses int    `yaml:"outlierConsecutiveSlowResponses,omitempty" json:"outlierConsecutiveSlowResponses,omitempty"`
	OutlierCooldown                 string `yaml:"outlierCooldown,omitempty" json:"outlierCooldown,omitempty"`
	HealthCheckPath                 string `yaml:"healthCheckPath,omitempty" json:"healthCheckPath,omitempty"`
	HealthInterval                  string `yaml:"healthInterval,omitempty" json:"healthInterval,omitempty"`
	HealthTimeout                   string `yaml:"healthTimeout,omitempty" json:"healthTimeout,omitempty"`
}

func (r RouterConfig) IsEnabled() bool {
	return r.Enabled == nil || *r.Enabled
}

func (r RouterConfig) EffectiveMethods() []string {
	if len(r.Methods) > 0 {
		return r.Methods
	}
	if r.Method != "" {
		return []string{strings.ToUpper(r.Method)}
	}
	return nil
}

func (r RouterConfig) EffectiveMethodsForRegistration() []string {
	methods := append([]string(nil), r.EffectiveMethods()...)
	if r.CORS == nil {
		return methods
	}
	hasOptions := false
	for _, method := range methods {
		if strings.EqualFold(strings.TrimSpace(method), http.MethodOptions) {
			hasOptions = true
			break
		}
	}
	if !hasOptions {
		methods = append(methods, http.MethodOptions)
	}
	return methods
}

func (r RouterConfig) SupportsMethod(method string) bool {
	methods := r.EffectiveMethods()
	if len(methods) == 0 || method == "" {
		return true
	}
	method = strings.ToUpper(method)
	for _, candidate := range methods {
		if strings.ToUpper(candidate) == method {
			return true
		}
	}
	return false
}

func (s Service) EffectiveRoutePath(route RouterConfig) string {
	return joinRouteSegments(s.BasePath, route.Path)
}

func (s Service) UpstreamBasePath() string {
	return joinRouteSegments("", s.BasePath)
}

func joinRouteSegments(parts ...string) string {
	cleaned := make([]string, 0, len(parts))
	for i, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" || part == "/" {
			continue
		}
		if i == 0 && strings.Contains(part, "://") {
			cleaned = append(cleaned, strings.TrimRight(part, "/"))
			continue
		}
		cleaned = append(cleaned, strings.Trim(part, "/"))
	}

	if len(cleaned) == 0 {
		return "/"
	}

	result := strings.Join(cleaned, "/")
	if strings.Contains(cleaned[0], "://") {
		return result
	}
	return "/" + result
}

func cloneRouteWithService(route RouterConfig, service Service) RouterConfig {
	cloned := route
	cloned.Path = service.EffectiveRoutePath(route)
	cloned.Methods = route.EffectiveMethods()
	cloned.ServiceName = service.Name
	cloned.ServiceHost = service.Host
	return cloned
}

func NewBool(v bool) *bool {
	return &v
}

func (t TLSConfig) EffectivePort(defaultPort int) int {
	if t.Port > 0 {
		return t.Port
	}
	return defaultPort
}

func (t TLSConfig) EffectiveHTTP3Port(defaultTLSPort int) int {
	if t.HTTP3Port > 0 {
		return t.HTTP3Port
	}
	return defaultTLSPort
}

func (t TLSConfig) EffectiveEnrollmentPort() int {
	if t.EnrollmentPort > 0 {
		return t.EnrollmentPort
	}
	return 0
}

func (t TLSConfig) EffectiveEnrollmentMaxActive() int {
	if t.EnrollmentMaxActive > 0 {
		return t.EnrollmentMaxActive
	}
	return 10
}

func (t TLSConfig) ShouldAutoGenerate() bool {
	return t.AutoGenerate != nil && *t.AutoGenerate
}

func (t TLSConfig) ShouldGenerateSharedClient() bool {
	return t.GenerateSharedClient != nil && *t.GenerateSharedClient
}

// Provider defines the interface for configuration providers
type Provider interface {
	Load() (*Config, error)
	Save(*Config) error
	Watch(func(*Config) error) error
	Close() error
}

// FileProvider implements configuration loading from files
type FileProvider struct {
	configPath   string
	servicesPath string
	logger       *logging.Logger
	watchers     []func(*Config) error
	mu           sync.RWMutex
	stopWatcher  chan struct{}
}

// NewFileProvider creates a new file-based configuration provider
func NewFileProvider(configPath, servicesPath string, logger *logging.Logger) *FileProvider {
	return &FileProvider{
		configPath:   configPath,
		servicesPath: servicesPath,
		logger:       logger,
		stopWatcher:  make(chan struct{}),
	}
}

// Load loads configuration from files
func (p *FileProvider) Load() (*Config, error) {
	// Load .env file if present
	if _, err := os.Stat(".env"); err == nil {
		file, err := os.Open(".env")
		if err == nil {
			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				line := scanner.Text()
				if strings.HasPrefix(line, "#") || !strings.Contains(line, "=") {
					continue
				}
				parts := strings.SplitN(line, "=", 2)
				key := strings.TrimSpace(parts[0])
				val := strings.TrimSpace(parts[1])
				os.Setenv(key, val)
			}
			file.Close()
		}
	}

	// Load main config
	configData, err := os.ReadFile(p.configPath)
	if err != nil {
		return nil, coreerrors.NewConfigError("failed to read config file", err)
	}

	var config Config
	if err := yaml.Unmarshal(configData, &config); err != nil {
		return nil, coreerrors.NewConfigError("failed to parse config file", err)
	}
	normalizeLegacyConfig(&config)
	// Expand env vars in all string fields
	expandEnvVarsInStruct(&config)

	// Load service config if separate file (new format)
	if p.servicesPath != "" && p.servicesPath != p.configPath {
		// If a --services file is provided, load services from that file
		serviceData, err := os.ReadFile(p.servicesPath)
		if err != nil {
			return nil, coreerrors.NewConfigError("failed to read service config file", err)
		}
		var serviceConfig ServiceConfig
		if err := yaml.Unmarshal(serviceData, &serviceConfig); err != nil {
			return nil, coreerrors.NewConfigError("failed to parse service config file", err)
		}
		// Instead of merging into config.Services[0], append as a new ServiceConfig
		if len(serviceConfig.Services) > 0 {
			config.Services = append(config.Services, serviceConfig)
		}
	}

	// After merging serviceConfig into config.Services, set default backend if missing
	for si := range config.Services {
		for sj := range config.Services[si].Services {
			service := &config.Services[si].Services[sj]
			for rk := range service.Routes {
				route := &service.Routes[rk]
				// If no backends and not a plugin/internal route, set default backend
				if len(route.Backends) == 0 && !isPluginOrInternalRoute(route.Path) {
					route.Backends = []Backend{{URLPattern: route.Path}}
				}
				// Set default backend URLPattern if missing
				for bk := range route.Backends {
					if route.Backends[bk].URLPattern == "" {
						route.Backends[bk].URLPattern = route.Path
					}
				}
			}
		}
	}

	// Validate configuration
	validator := NewConfigValidator()
	if err := validator.Validate(&config); err != nil {
		return nil, err
	}

	return &config, nil
}

// Save saves configuration to files atomically
func (p *FileProvider) Save(cfg *Config) error {
	// Validate before saving
	validator := NewConfigValidator()
	if err := validator.Validate(cfg); err != nil {
		return err
	}

	// Save main config
	if err := p.saveAtomic(p.configPath, cfg); err != nil {
		return err
	}

	// Save service config to separate file if needed
	if p.servicesPath != "" && p.servicesPath != p.configPath {
		if len(cfg.Services) > 0 {
			if err := p.saveServicesAtomic(p.servicesPath, &cfg.Services[0]); err != nil {
				return err
			}
		}
	}

	p.logger.Info("Configuration saved successfully",
		logging.String("config_path", p.configPath),
		logging.String("services_path", p.servicesPath),
	)
	return nil
}

func (p *FileProvider) saveAtomic(path string, cfg *Config) error {
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return coreerrors.NewConfigError("failed to marshal config", err)
	}

	tempFile := path + ".tmp"
	if err := os.WriteFile(tempFile, data, 0644); err != nil {
		return coreerrors.NewConfigError("failed to write temp config file", err)
	}

	if err := os.Rename(tempFile, path); err != nil {
		os.Remove(tempFile) // clean up
		return coreerrors.NewConfigError("failed to commit config file change", err)
	}

	return nil
}

func (p *FileProvider) saveServicesAtomic(path string, svcCfg *ServiceConfig) error {
	data, err := yaml.Marshal(svcCfg)
	if err != nil {
		return coreerrors.NewConfigError("failed to marshal service config", err)
	}

	tempFile := path + ".tmp"
	if err := os.WriteFile(tempFile, data, 0644); err != nil {
		return coreerrors.NewConfigError("failed to write temp service config file", err)
	}

	if err := os.Rename(tempFile, path); err != nil {
		os.Remove(tempFile) // clean up
		return coreerrors.NewConfigError("failed to commit service config file change", err)
	}

	return nil
}

// Watch sets up file watching for configuration changes
func (p *FileProvider) Watch(callback func(*Config) error) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.watchers = append(p.watchers, callback)

	// Start watching if not already started
	if len(p.watchers) == 1 {
		go p.watchFiles()
	}

	return nil
}

// watchFiles monitors configuration files for changes
func (p *FileProvider) watchFiles() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	var lastModTime time.Time

	for {
		select {
		case <-p.stopWatcher:
			return
		case <-ticker.C:
			// Check if files have been modified
			info, err := os.Stat(p.configPath)
			if err != nil {
				p.logger.Error("Failed to stat config file", err)
				continue
			}

			if info.ModTime().After(lastModTime) {
				lastModTime = info.ModTime()

				// Reload configuration
				cfg, err := p.Load()
				if err != nil {
					p.logger.Error("Failed to reload configuration", err)
					continue
				}

				// Notify all watchers
				p.mu.RLock()
				for _, watcher := range p.watchers {
					if err := watcher(cfg); err != nil {
						p.logger.Error("Configuration reload callback failed", err)
					}
				}
				p.mu.RUnlock()

				p.logger.Info("Configuration reloaded successfully")
			}
		}
	}
}

// Close stops the file watcher
func (p *FileProvider) Close() error {
	close(p.stopWatcher)
	return nil
}

// LoadConfig loads configuration from the specified path
func LoadConfig(configPath, servicesPath string, logger *logging.Logger) (*Config, error) {
	provider := NewFileProvider(configPath, servicesPath, logger)
	cfg, err := provider.Load()
	if err != nil {
		return nil, err
	}

	// Expand env vars in plugin configs
	if cfg != nil && cfg.Plugins != nil {
		for _, pluginConfig := range cfg.Plugins {
			expandEnvVarsInMap(pluginConfig)
		}
	}

	// Validate configuration
	validator := NewConfigValidator()
	if err := validator.Validate(cfg); err != nil {
		return nil, err
	}

	// Log successful loading of both config files
	logger.LogConfigLoad(configPath, nil)
	if servicesPath != "" && servicesPath != configPath {
		logger.LogConfigLoad(servicesPath, nil)
	}
	return cfg, nil
}

// LoadFromFile loads configuration from a single file
func LoadFromFile(configPath string) (*Config, error) {
	provider := NewFileProvider(configPath, "", nil)
	return provider.Load()
}

// SaveConfig saves configuration to the specified path
func SaveConfig(cfg *Config, configPath, servicesPath string, logger *logging.Logger) error {
	provider := NewFileProvider(configPath, servicesPath, logger)
	return provider.Save(cfg)
}

// Validate validates the configuration
func (c *Config) Validate() error {
	validator := NewConfigValidator()
	return validator.Validate(c)
}

// GetPluginConfig returns configuration for a specific plugin
func (c *Config) GetPluginConfig(pluginName string) (map[string]interface{}, bool) {
	config, exists := c.Plugins[pluginName]
	return config, exists
}

// SetPluginConfig sets configuration for a specific plugin
func (c *Config) SetPluginConfig(pluginName string, config map[string]interface{}) {
	if c.Plugins == nil {
		c.Plugins = make(map[string]map[string]interface{})
	}
	c.Plugins[pluginName] = config
}

// loadRSAPublicKey loads an RSA public key from a PEM file
func LoadRSAPublicKey(path string) (*rsa.PublicKey, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, errors.New("invalid PEM public key")
	}
	pub, err := jwt.ParseRSAPublicKeyFromPEM(data)
	if err != nil {
		return nil, err
	}
	return pub, nil
}

// GetServiceByName finds a service by its name
func (c *Config) GetServiceByName(name string) (*Service, error) {
	for _, serviceConfig := range c.Services {
		for _, service := range serviceConfig.Services {
			if service.Name == name {
				return &service, nil
			}
		}
	}
	return nil, coreerrors.NewValidationError("service", "service not found")
}

// GetServiceByGroup finds all services in a specific group
func (c *Config) GetServiceByGroup(group string) []Service {
	var services []Service
	for _, serviceConfig := range c.Services {
		for _, service := range serviceConfig.Services {
			if service.Group == group {
				services = append(services, service)
			}
		}
	}
	return services
}

// GetServiceByTag finds all services with a specific tag
func (c *Config) GetServiceByTag(tag string) []Service {
	var services []Service
	for _, serviceConfig := range c.Services {
		for _, service := range serviceConfig.Services {
			for _, serviceTag := range service.Tags {
				if serviceTag == tag {
					services = append(services, service)
					break
				}
			}
		}
	}
	return services
}

// GetAllRoutesFromServices returns all routes from all services
func (c *Config) GetAllRoutesFromServices(logger *logging.Logger) []RouterConfig {
	var allRoutes []RouterConfig
	for _, serviceConfig := range c.Services {
		for _, service := range serviceConfig.Services {
			for _, route := range service.Routes {
				allRoutes = append(allRoutes, cloneRouteWithService(route, service))
			}
			if logger != nil {
				logger.Info("Loaded Services", logging.Any("service", service))
			}
		}
	}
	return allRoutes
}

// GetRouteByPathFromServices finds a route by path from service configurations
func (c *Config) GetRouteByPathFromServices(path string) (*RouterConfig, error) {
	for _, serviceConfig := range c.Services {
		for _, service := range serviceConfig.Services {
			for _, route := range service.Routes {
				if route.Path == path {
					return &route, nil
				}
			}
		}
	}
	return nil, coreerrors.ErrRouteNotFound
}

// AddService adds a new service to the configuration
func (c *Config) AddService(service Service) error {
	if len(c.Services) == 0 {
		c.Services = []ServiceConfig{{
			Version:  1,
			Services: []Service{},
		}}
	}

	c.Services[0].Services = append(c.Services[0].Services, service)
	return nil
}

// RemoveService removes a service by name
func (c *Config) RemoveService(name string) error {
	for i, serviceConfig := range c.Services {
		for j, service := range serviceConfig.Services {
			if service.Name == name {
				c.Services[i].Services = append(c.Services[i].Services[:j], c.Services[i].Services[j+1:]...)
				return nil
			}
		}
	}
	return coreerrors.NewValidationError("service", "service not found")
}

// Add helper to find parent service for a route
func (c *Config) FindServiceForRoute(path string, method string, matchHeaders map[string]string) *Service {
	for _, serviceConfig := range c.Services {
		for _, service := range serviceConfig.Services {
			for _, route := range service.Routes {
				if service.EffectiveRoutePath(route) == path && route.SupportsMethod(method) && routeHeaderMatcherMatches(route.MatchHeaders, matchHeaders) {
					return &service
				}
			}
		}
	}
	return nil
}

func routeHeaderMatcherMatches(expected, actual map[string]string) bool {
	if len(expected) == 0 {
		return true
	}
	if len(actual) == 0 {
		return false
	}
	for key, value := range expected {
		if actualValue, ok := actual[key]; !ok || !strings.EqualFold(strings.TrimSpace(actualValue), strings.TrimSpace(value)) {
			return false
		}
	}
	return true
}

var envVarPattern = regexp.MustCompile(`\$\{([A-Za-z0-9_]+)(:-([^}]*))?\}`)

func expandEnvVarsInStruct(s interface{}) {
	v := reflect.ValueOf(s).Elem()
	for i := 0; i < v.NumField(); i++ {
		field := v.Field(i)
		if field.Kind() == reflect.String {
			field.SetString(expandEnvVars(field.String()))
		} else if field.Kind() == reflect.Struct {
			expandEnvVarsInStruct(field.Addr().Interface())
		} else if field.Kind() == reflect.Slice {
			for j := 0; j < field.Len(); j++ {
				elem := field.Index(j)
				if elem.Kind() == reflect.Struct {
					expandEnvVarsInStruct(elem.Addr().Interface())
				}
			}
		} else if field.Kind() == reflect.Map {
			for _, key := range field.MapKeys() {
				val := field.MapIndex(key)
				if val.Kind() == reflect.String {
					field.SetMapIndex(key, reflect.ValueOf(expandEnvVars(val.String())))
				}
			}
		}
	}
}

func expandEnvVarsInMap(m map[string]interface{}) {
	for k, v := range m {
		switch val := v.(type) {
		case string:
			m[k] = expandEnvVars(val)
		case map[string]interface{}:
			expandEnvVarsInMap(val)
		case []interface{}:
			for i, elem := range val {
				if s, ok := elem.(string); ok {
					val[i] = expandEnvVars(s)
				} else if submap, ok := elem.(map[string]interface{}); ok {
					expandEnvVarsInMap(submap)
				}
			}
		}
	}
}

func normalizeLegacyConfig(cfg *Config) {
	legacyTLS := cfg.Server.TLS
	activeTLS := cfg.Security.TLS

	if !activeTLS.Enabled && legacyTLS.Enabled {
		cfg.Security.TLS = legacyTLS
		return
	}
	if activeTLS.CertFile == "" && legacyTLS.CertFile != "" {
		cfg.Security.TLS.CertFile = legacyTLS.CertFile
	}
	if activeTLS.KeyFile == "" && legacyTLS.KeyFile != "" {
		cfg.Security.TLS.KeyFile = legacyTLS.KeyFile
	}
	if activeTLS.ClientCAFile == "" && legacyTLS.ClientCAFile != "" {
		cfg.Security.TLS.ClientCAFile = legacyTLS.ClientCAFile
	}
	if activeTLS.ClientAuthType == "" && legacyTLS.ClientAuthType != "" {
		cfg.Security.TLS.ClientAuthType = legacyTLS.ClientAuthType
	}
	if activeTLS.MinVersion == "" && legacyTLS.MinVersion != "" {
		cfg.Security.TLS.MinVersion = legacyTLS.MinVersion
	}
	if activeTLS.Port == 0 && legacyTLS.Port > 0 {
		cfg.Security.TLS.Port = legacyTLS.Port
	}
	if activeTLS.EnrollmentPort == 0 && legacyTLS.EnrollmentPort > 0 {
		cfg.Security.TLS.EnrollmentPort = legacyTLS.EnrollmentPort
	}
	if activeTLS.EnrollmentMaxActive == 0 && legacyTLS.EnrollmentMaxActive > 0 {
		cfg.Security.TLS.EnrollmentMaxActive = legacyTLS.EnrollmentMaxActive
	}
	if activeTLS.AutoGenerate == nil && legacyTLS.AutoGenerate != nil {
		cfg.Security.TLS.AutoGenerate = legacyTLS.AutoGenerate
	}
	if len(activeTLS.Ciphers) == 0 && len(legacyTLS.Ciphers) > 0 {
		cfg.Security.TLS.Ciphers = legacyTLS.Ciphers
	}
}

func expandEnvVars(s string) string {
	return envVarPattern.ReplaceAllStringFunc(s, func(m string) string {
		matches := envVarPattern.FindStringSubmatch(m)
		key := matches[1]
		def := ""
		if len(matches) > 3 {
			def = matches[3]
		}
		val := os.Getenv(key)
		if val == "" {
			val = def
		}
		return val
	})
}
