package config

type GraphQLOperationPolicy struct {
	Preset                         string              `yaml:"preset,omitempty" json:"preset,omitempty"`
	AllowedVariables               []string            `yaml:"allowedVariables,omitempty" json:"allowed_variables,omitempty"`
	RequiredVariables              []string            `yaml:"requiredVariables,omitempty" json:"required_variables,omitempty"`
	VariableRegex                  map[string]string   `yaml:"variableRegex,omitempty" json:"variable_regex,omitempty"`
	VariableAllowedValues          map[string][]string `yaml:"variableAllowedValues,omitempty" json:"variable_allowed_values,omitempty"`
	AllowedModels                  []string            `yaml:"allowedModels,omitempty" json:"allowed_models,omitempty"`
	ModelField                     string              `yaml:"modelField,omitempty" json:"model_field,omitempty"`
	AllowedToolNames               []string            `yaml:"allowedToolNames,omitempty" json:"allowed_tool_names,omitempty"`
	ToolField                      string              `yaml:"toolField,omitempty" json:"tool_field,omitempty"`
	MaxMessages                    int                 `yaml:"maxMessages,omitempty" json:"max_messages,omitempty"`
	MessagesField                  string              `yaml:"messagesField,omitempty" json:"messages_field,omitempty"`
	MaxToolCalls                   int                 `yaml:"maxToolCalls,omitempty" json:"max_tool_calls,omitempty"`
	ToolCallsField                 string              `yaml:"toolCallsField,omitempty" json:"tool_calls_field,omitempty"`
	MaxInputTokens                 int                 `yaml:"maxInputTokens,omitempty" json:"max_input_tokens,omitempty"`
	InputTokensField               string              `yaml:"inputTokensField,omitempty" json:"input_tokens_field,omitempty"`
	MaxOutputTokens                int                 `yaml:"maxOutputTokens,omitempty" json:"max_output_tokens,omitempty"`
	OutputTokensField              string              `yaml:"outputTokensField,omitempty" json:"output_tokens_field,omitempty"`
	AllowedUpstreamHosts           []string            `yaml:"allowedUpstreamHosts,omitempty" json:"allowed_upstream_hosts,omitempty"`
	RequestHeaders                 map[string]string   `yaml:"requestHeaders,omitempty" json:"request_headers,omitempty"`
	RemoveRequestHeaders           []string            `yaml:"removeRequestHeaders,omitempty" json:"remove_request_headers,omitempty"`
	RequestRedactHeaders           []string            `yaml:"requestRedactHeaders,omitempty" json:"request_redact_headers,omitempty"`
	RequiredRequestHeaders         []string            `yaml:"requiredRequestHeaders,omitempty" json:"required_request_headers,omitempty"`
	RequiredRequestHeaderRegex     map[string]string   `yaml:"requiredRequestHeaderRegex,omitempty" json:"required_request_header_regex,omitempty"`
	QueryParams                    map[string]string   `yaml:"queryParams,omitempty" json:"query_params,omitempty"`
	RemoveQueryParams              []string            `yaml:"removeQueryParams,omitempty" json:"remove_query_params,omitempty"`
	RequestJSONFields              map[string]string   `yaml:"requestJSONFields,omitempty" json:"request_json_fields,omitempty"`
	RemoveRequestJSONFields        []string            `yaml:"removeRequestJSONFields,omitempty" json:"remove_request_json_fields,omitempty"`
	RequestRedactJSONFields        []string            `yaml:"requestRedactJSONFields,omitempty" json:"request_redact_json_fields,omitempty"`
	RequestBodyBlockRegex          []string            `yaml:"requestBodyBlockRegex,omitempty" json:"request_body_block_regex,omitempty"`
	RequestBodyRequireRegex        []string            `yaml:"requestBodyRequireRegex,omitempty" json:"request_body_require_regex,omitempty"`
	RequestPIIBlockTypes           []string            `yaml:"requestPIIBlockTypes,omitempty" json:"request_pii_block_types,omitempty"`
	TransformWhenHeaders           map[string]string   `yaml:"transformWhenHeaders,omitempty" json:"transform_when_headers,omitempty"`
	TransformWhenQueryParams       map[string]string   `yaml:"transformWhenQueryParams,omitempty" json:"transform_when_query_params,omitempty"`
	TransformWhenHeaderRegex       map[string]string   `yaml:"transformWhenHeaderRegex,omitempty" json:"transform_when_header_regex,omitempty"`
	TransformWhenQueryRegex        map[string]string   `yaml:"transformWhenQueryRegex,omitempty" json:"transform_when_query_regex,omitempty"`
	TransformMethods               []string            `yaml:"transformMethods,omitempty" json:"transform_methods,omitempty"`
	AllowedPersistedQueries        []string            `yaml:"allowedPersistedQueries,omitempty" json:"allowed_persisted_queries,omitempty"`
	MaxDepth                       int                 `yaml:"maxDepth,omitempty" json:"max_depth,omitempty"`
	MaxFields                      int                 `yaml:"maxFields,omitempty" json:"max_fields,omitempty"`
	SuccessResponseFields          map[string]string   `yaml:"successResponseFields,omitempty" json:"success_response_fields,omitempty"`
	ErrorResponseFields            map[string]string   `yaml:"errorResponseFields,omitempty" json:"error_response_fields,omitempty"`
	ResponseHeaders                map[string]string   `yaml:"responseHeaders,omitempty" json:"response_headers,omitempty"`
	RemoveResponseHeaders          []string            `yaml:"removeResponseHeaders,omitempty" json:"remove_response_headers,omitempty"`
	ResponseRedactHeaders          []string            `yaml:"responseRedactHeaders,omitempty" json:"response_redact_headers,omitempty"`
	ResponseTransformStatusCodes   []int               `yaml:"responseTransformStatusCodes,omitempty" json:"response_transform_status_codes,omitempty"`
	ResponseTransformStatusClasses []string            `yaml:"responseTransformStatusClasses,omitempty" json:"response_transform_status_classes,omitempty"`
	ResponseTransformWhenHeaders   map[string]string   `yaml:"responseTransformWhenHeaders,omitempty" json:"response_transform_when_headers,omitempty"`
	ResponseTransformHeaderRegex   map[string]string   `yaml:"responseTransformHeaderRegex,omitempty" json:"response_transform_header_regex,omitempty"`
	ResponseJSONFields             map[string]string   `yaml:"responseJSONFields,omitempty" json:"response_json_fields,omitempty"`
	RemoveResponseJSONFields       []string            `yaml:"removeResponseJSONFields,omitempty" json:"remove_response_json_fields,omitempty"`
	ResponseRedactJSONFields       []string            `yaml:"responseRedactJSONFields,omitempty" json:"response_redact_json_fields,omitempty"`
	ResponseBodyBlockRegex         []string            `yaml:"responseBodyBlockRegex,omitempty" json:"response_body_block_regex,omitempty"`
	ResponseBodyRequireRegex       []string            `yaml:"responseBodyRequireRegex,omitempty" json:"response_body_require_regex,omitempty"`
	ResponsePIIBlockTypes          []string            `yaml:"responsePIIBlockTypes,omitempty" json:"response_pii_block_types,omitempty"`
}

type AIPolicyPreset = GraphQLOperationPolicy

type RateLimitPolicyConfig struct {
	RequestsPerSecond float64                        `yaml:"requestsPerSecond,omitempty" json:"requests_per_second,omitempty"`
	Burst             int                            `yaml:"burst,omitempty" json:"burst,omitempty"`
	KeyBy             string                         `yaml:"keyBy,omitempty" json:"key_by,omitempty"`
	KeyHeader         string                         `yaml:"keyHeader,omitempty" json:"key_header,omitempty"`
	ExemptMethods     []string                       `yaml:"exemptMethods,omitempty" json:"exempt_methods,omitempty"`
	ClassPolicies     []LimiterClassRatePolicyConfig `yaml:"classPolicies,omitempty" json:"class_policies,omitempty"`
}

type ConcurrencyLimitPolicyConfig struct {
	MaxInFlight   int                                   `yaml:"maxInFlight,omitempty" json:"max_in_flight,omitempty"`
	KeyBy         string                                `yaml:"keyBy,omitempty" json:"key_by,omitempty"`
	KeyHeader     string                                `yaml:"keyHeader,omitempty" json:"key_header,omitempty"`
	QueueTimeout  string                                `yaml:"queueTimeout,omitempty" json:"queue_timeout,omitempty"`
	MaxQueueDepth int                                   `yaml:"maxQueueDepth,omitempty" json:"max_queue_depth,omitempty"`
	ExemptMethods []string                              `yaml:"exemptMethods,omitempty" json:"exempt_methods,omitempty"`
	ClassPolicies []LimiterClassConcurrencyPolicyConfig `yaml:"classPolicies,omitempty" json:"class_policies,omitempty"`
}

type LimiterClassRatePolicyConfig struct {
	Preset            string  `yaml:"preset,omitempty" json:"preset,omitempty"`
	BucketClass       string  `yaml:"bucketClass,omitempty" json:"bucket_class,omitempty"`
	RequestsPerSecond float64 `yaml:"requestsPerSecond,omitempty" json:"requests_per_second,omitempty"`
	Burst             int     `yaml:"burst,omitempty" json:"burst,omitempty"`
}

type LimiterClassConcurrencyPolicyConfig struct {
	Preset        string `yaml:"preset,omitempty" json:"preset,omitempty"`
	BucketClass   string `yaml:"bucketClass,omitempty" json:"bucket_class,omitempty"`
	MaxInFlight   int    `yaml:"maxInFlight,omitempty" json:"max_in_flight,omitempty"`
	QueueTimeout  string `yaml:"queueTimeout,omitempty" json:"queue_timeout,omitempty"`
	MaxQueueDepth int    `yaml:"maxQueueDepth,omitempty" json:"max_queue_depth,omitempty"`
}
