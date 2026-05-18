package config

import (
	"net/http"
	"strings"
	"time"
)

// RouterConfig represents a route configuration
type RouterConfig struct {
	Path                           string                            `yaml:"path"`
	Methods                        []string                          `yaml:"methods"`
	Method                         string                            `yaml:"method"` // Single method for new format
	MatchHeaders                   map[string]string                 `yaml:"matchHeaders,omitempty" json:"matchHeaders,omitempty"`
	MatchPercent                   int                               `yaml:"matchPercent,omitempty" json:"matchPercent,omitempty"`
	RetryCount                     int                               `yaml:"retryCount,omitempty" json:"retryCount,omitempty"`
	RetryBackoff                   string                            `yaml:"retryBackoff,omitempty" json:"retryBackoff,omitempty"`
	RetryJitter                    string                            `yaml:"retryJitter,omitempty" json:"retryJitter,omitempty"`
	RetryStatuses                  []int                             `yaml:"retryStatusCodes,omitempty" json:"retryStatusCodes,omitempty"`
	RetryUnsafe                    bool                              `yaml:"retryUnsafeMethods,omitempty" json:"retryUnsafeMethods,omitempty"`
	HedgeDelay                     string                            `yaml:"hedgeDelay,omitempty" json:"hedgeDelay,omitempty"`
	HedgeUnsafe                    bool                              `yaml:"hedgeUnsafeMethods,omitempty" json:"hedgeUnsafeMethods,omitempty"`
	AdaptiveLatencyRouting         bool                              `yaml:"adaptiveLatencyRouting,omitempty" json:"adaptive_latency_routing,omitempty"`
	ShadowTrafficPercent           int                               `yaml:"shadowTrafficPercent,omitempty" json:"shadow_traffic_percent,omitempty"`
	ShadowUnsafe                   bool                              `yaml:"shadowUnsafeMethods,omitempty" json:"shadow_unsafe_methods,omitempty"`
	ShadowMinRequests              int                               `yaml:"shadowMinRequests,omitempty" json:"shadow_min_requests,omitempty"`
	ShadowMaxErrorRate             float64                           `yaml:"shadowMaxErrorRate,omitempty" json:"shadow_max_error_rate,omitempty"`
	ShadowMaxLatencyDelta          string                            `yaml:"shadowMaxLatencyDelta,omitempty" json:"shadow_max_latency_delta,omitempty"`
	RequireAuth                    bool                              `yaml:"requireAuth"`
	RateLimit                      *int                              `yaml:"rateLimit"`
	RateLimitPolicy                *RateLimitPolicyConfig            `yaml:"rateLimitPolicy,omitempty" json:"rate_limit_policy,omitempty"`
	ConcurrencyLimitPolicy         *ConcurrencyLimitPolicyConfig     `yaml:"concurrencyLimitPolicy,omitempty" json:"concurrency_limit_policy,omitempty"`
	LimitAlertPolicy               *RouteLimitAlertPolicyConfig      `yaml:"limitAlertPolicy,omitempty" json:"limit_alert_policy,omitempty"`
	Timeout                        *time.Duration                    `yaml:"timeout"`
	Headers                        map[string]string                 `yaml:"headers"`
	RequestHeaders                 map[string]string                 `yaml:"requestHeaders,omitempty" json:"request_headers,omitempty"`
	RemoveRequestHeaders           []string                          `yaml:"removeRequestHeaders,omitempty" json:"remove_request_headers,omitempty"`
	RequestRedactHeaders           []string                          `yaml:"requestRedactHeaders,omitempty" json:"request_redact_headers,omitempty"`
	RequiredRequestHeaders         []string                          `yaml:"requiredRequestHeaders,omitempty" json:"required_request_headers,omitempty"`
	RequiredRequestHeaderRegex     map[string]string                 `yaml:"requiredRequestHeaderRegex,omitempty" json:"required_request_header_regex,omitempty"`
	RequestJSONFields              map[string]string                 `yaml:"requestJSONFields,omitempty" json:"request_json_fields,omitempty"`
	RemoveRequestJSONFields        []string                          `yaml:"removeRequestJSONFields,omitempty" json:"remove_request_json_fields,omitempty"`
	RequestRedactJSONFields        []string                          `yaml:"requestRedactJSONFields,omitempty" json:"request_redact_json_fields,omitempty"`
	RequestBodyBlockRegex          []string                          `yaml:"requestBodyBlockRegex,omitempty" json:"request_body_block_regex,omitempty"`
	RequestBodyRequireRegex        []string                          `yaml:"requestBodyRequireRegex,omitempty" json:"request_body_require_regex,omitempty"`
	RequestPIIBlockTypes           []string                          `yaml:"requestPIIBlockTypes,omitempty" json:"request_pii_block_types,omitempty"`
	AIPolicyPreset                 string                            `yaml:"aiPolicyPreset,omitempty" json:"ai_policy_preset,omitempty"`
	AIPolicyPresetChain            []string                          `yaml:"aiPolicyPresetChain,omitempty" json:"ai_policy_preset_chain,omitempty"`
	AIPolicyPresets                map[string]AIPolicyPreset         `yaml:"aiPolicyPresets,omitempty" json:"ai_policy_presets,omitempty"`
	QueryParams                    map[string]string                 `yaml:"queryParams,omitempty" json:"query_params,omitempty"`
	RemoveQueryParams              []string                          `yaml:"removeQueryParams,omitempty" json:"remove_query_params,omitempty"`
	Protocol                       string                            `yaml:"protocol,omitempty" json:"protocol,omitempty"`
	GraphQLAllowIntrospection      *bool                             `yaml:"graphqlAllowIntrospection,omitempty" json:"graphql_allow_introspection,omitempty"`
	GraphQLRequirePersistedQuery   bool                              `yaml:"graphqlRequirePersistedQuery,omitempty" json:"graphql_require_persisted_query,omitempty"`
	GraphQLPersistedQueryField     string                            `yaml:"graphqlPersistedQueryField,omitempty" json:"graphql_persisted_query_field,omitempty"`
	GraphQLAllowedPersistedQueries []string                          `yaml:"graphqlAllowedPersistedQueries,omitempty" json:"graphql_allowed_persisted_queries,omitempty"`
	GraphQLAllowedOperations       []string                          `yaml:"graphqlAllowedOperations,omitempty" json:"graphql_allowed_operations,omitempty"`
	GraphQLAllowedVariables        []string                          `yaml:"graphqlAllowedVariables,omitempty" json:"graphql_allowed_variables,omitempty"`
	GraphQLRequiredVariables       []string                          `yaml:"graphqlRequiredVariables,omitempty" json:"graphql_required_variables,omitempty"`
	GraphQLVariableRegex           map[string]string                 `yaml:"graphqlVariableRegex,omitempty" json:"graphql_variable_regex,omitempty"`
	GraphQLVariableAllowedValues   map[string][]string               `yaml:"graphqlVariableAllowedValues,omitempty" json:"graphql_variable_allowed_values,omitempty"`
	GraphQLOperationPresets        map[string]GraphQLOperationPolicy `yaml:"graphqlOperationPresets,omitempty" json:"graphql_operation_presets,omitempty"`
	GraphQLOperationPolicies       map[string]GraphQLOperationPolicy `yaml:"graphqlOperationPolicies,omitempty" json:"graphql_operation_policies,omitempty"`
	GraphQLOperationNameRequired   bool                              `yaml:"graphqlOperationNameRequired,omitempty" json:"graphql_operation_name_required,omitempty"`
	GraphQLMaxDepth                int                               `yaml:"graphqlMaxDepth,omitempty" json:"graphql_max_depth,omitempty"`
	GraphQLMaxFields               int                               `yaml:"graphqlMaxFields,omitempty" json:"graphql_max_fields,omitempty"`
	AllowedModels                  []string                          `yaml:"allowedModels,omitempty" json:"allowed_models,omitempty"`
	ModelField                     string                            `yaml:"modelField,omitempty" json:"model_field,omitempty"`
	AllowedToolNames               []string                          `yaml:"allowedToolNames,omitempty" json:"allowed_tool_names,omitempty"`
	ToolField                      string                            `yaml:"toolField,omitempty" json:"tool_field,omitempty"`
	MaxMessages                    int                               `yaml:"maxMessages,omitempty" json:"max_messages,omitempty"`
	MessagesField                  string                            `yaml:"messagesField,omitempty" json:"messages_field,omitempty"`
	MaxToolCalls                   int                               `yaml:"maxToolCalls,omitempty" json:"max_tool_calls,omitempty"`
	ToolCallsField                 string                            `yaml:"toolCallsField,omitempty" json:"tool_calls_field,omitempty"`
	MaxInputTokens                 int                               `yaml:"maxInputTokens,omitempty" json:"max_input_tokens,omitempty"`
	InputTokensField               string                            `yaml:"inputTokensField,omitempty" json:"input_tokens_field,omitempty"`
	MaxOutputTokens                int                               `yaml:"maxOutputTokens,omitempty" json:"max_output_tokens,omitempty"`
	OutputTokensField              string                            `yaml:"outputTokensField,omitempty" json:"output_tokens_field,omitempty"`
	AllowedUpstreamHosts           []string                          `yaml:"allowedUpstreamHosts,omitempty" json:"allowed_upstream_hosts,omitempty"`
	TransformWhenHeaders           map[string]string                 `yaml:"transformWhenHeaders,omitempty" json:"transform_when_headers,omitempty"`
	TransformWhenQueryParams       map[string]string                 `yaml:"transformWhenQueryParams,omitempty" json:"transform_when_query_params,omitempty"`
	TransformWhenHeaderRegex       map[string]string                 `yaml:"transformWhenHeaderRegex,omitempty" json:"transform_when_header_regex,omitempty"`
	TransformWhenQueryRegex        map[string]string                 `yaml:"transformWhenQueryRegex,omitempty" json:"transform_when_query_regex,omitempty"`
	TransformMethods               []string                          `yaml:"transformMethods,omitempty" json:"transform_methods,omitempty"`
	TransformScopes                []string                          `yaml:"transformScopes,omitempty" json:"transform_scopes,omitempty"`
	ResponseTransformStatusCodes   []int                             `yaml:"responseTransformStatusCodes,omitempty" json:"response_transform_status_codes,omitempty"`
	ResponseTransformStatusClasses []string                          `yaml:"responseTransformStatusClasses,omitempty" json:"response_transform_status_classes,omitempty"`
	ResponseTransformWhenHeaders   map[string]string                 `yaml:"responseTransformWhenHeaders,omitempty" json:"response_transform_when_headers,omitempty"`
	ResponseTransformHeaderRegex   map[string]string                 `yaml:"responseTransformHeaderRegex,omitempty" json:"response_transform_header_regex,omitempty"`
	ResponseHeaders                map[string]string                 `yaml:"responseHeaders,omitempty" json:"response_headers,omitempty"`
	RemoveResponseHeaders          []string                          `yaml:"removeResponseHeaders,omitempty" json:"remove_response_headers,omitempty"`
	RedactionValue                 string                            `yaml:"redactionValue,omitempty" json:"redaction_value,omitempty"`
	ResponseRedactHeaders          []string                          `yaml:"responseRedactHeaders,omitempty" json:"response_redact_headers,omitempty"`
	SuccessResponseFields          map[string]string                 `yaml:"successResponseFields,omitempty" json:"success_response_fields,omitempty"`
	ErrorResponseFields            map[string]string                 `yaml:"errorResponseFields,omitempty" json:"error_response_fields,omitempty"`
	ResponseJSONFields             map[string]string                 `yaml:"responseJSONFields,omitempty" json:"response_json_fields,omitempty"`
	RemoveResponseJSONFields       []string                          `yaml:"removeResponseJSONFields,omitempty" json:"remove_response_json_fields,omitempty"`
	ResponseRedactJSONFields       []string                          `yaml:"responseRedactJSONFields,omitempty" json:"response_redact_json_fields,omitempty"`
	ResponseBodyBlockRegex         []string                          `yaml:"responseBodyBlockRegex,omitempty" json:"response_body_block_regex,omitempty"`
	ResponseBodyRequireRegex       []string                          `yaml:"responseBodyRequireRegex,omitempty" json:"response_body_require_regex,omitempty"`
	ResponsePIIBlockTypes          []string                          `yaml:"responsePIIBlockTypes,omitempty" json:"response_pii_block_types,omitempty"`
	MaxRequestBodyBytes            int64                             `yaml:"maxRequestBodyBytes,omitempty" json:"max_request_body_bytes,omitempty"`
	MaxResponseBodyBytes           int64                             `yaml:"maxResponseBodyBytes,omitempty" json:"max_response_body_bytes,omitempty"`
	StripPath                      bool                              `yaml:"stripPath"`
	ValidateSchema                 string                            `yaml:"validateSchema"`
	WebSocket                      *WebSocketOptions                 `yaml:"websocket,omitempty"`
	CORS                           *CORSConfig                       `yaml:"cors,omitempty" json:"cors,omitempty"`
	RequireJwt                     bool                              `yaml:"requireJwt"`
	Enabled                        *bool                             `yaml:"enabled"`
	AuthPlugin                     string                            `yaml:"auth_plugin,omitempty" json:"auth_plugin,omitempty"`
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
