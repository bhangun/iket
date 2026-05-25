package config

// BFFConfig enables route-local Backend-for-Frontend composition.
//
// It is intentionally optional: ordinary routes keep using the normal reverse
// proxy path, while routes with bff configured can fan out to several upstreams
// and shape one client-focused response.
type BFFConfig struct {
	Enabled                  *bool             `yaml:"enabled,omitempty" json:"enabled,omitempty"`
	Mode                     string            `yaml:"mode,omitempty" json:"mode,omitempty"`
	Timeout                  string            `yaml:"timeout,omitempty" json:"timeout,omitempty"`
	IncludeMeta              bool              `yaml:"includeMeta,omitempty" json:"include_meta,omitempty"`
	AllowPartialResponse     bool              `yaml:"allowPartialResponse,omitempty" json:"allow_partial_response,omitempty"`
	MaxStepResponseBodyBytes int64             `yaml:"maxStepResponseBodyBytes,omitempty" json:"max_step_response_body_bytes,omitempty"`
	RequireRequestJSON       bool              `yaml:"requireRequestJSON,omitempty" json:"require_request_json,omitempty"`
	RequiredRequestJSONPaths []string          `yaml:"requiredRequestJSONPaths,omitempty" json:"required_request_json_paths,omitempty"`
	Steps                    []BFFStepConfig   `yaml:"steps,omitempty" json:"steps,omitempty"`
	ResponseFields           map[string]string `yaml:"responseFields,omitempty" json:"response_fields,omitempty"`
	ResponseHeaders          map[string]string `yaml:"responseHeaders,omitempty" json:"response_headers,omitempty"`
	ResponseStatus           string            `yaml:"responseStatus,omitempty" json:"response_status,omitempty"`
	PartialResponseStatus    int               `yaml:"partialResponseStatus,omitempty" json:"partial_response_status,omitempty"`
}

type BFFStepConfig struct {
	Name                 string            `yaml:"name" json:"name"`
	Method               string            `yaml:"method,omitempty" json:"method,omitempty"`
	URL                  string            `yaml:"url" json:"url"`
	Required             *bool             `yaml:"required,omitempty" json:"required,omitempty"`
	DependsOn            []string          `yaml:"dependsOn,omitempty" json:"depends_on,omitempty"`
	When                 string            `yaml:"when,omitempty" json:"when,omitempty"`
	WhenHeaders          map[string]string `yaml:"whenHeaders,omitempty" json:"when_headers,omitempty"`
	WhenQueryParams      map[string]string `yaml:"whenQueryParams,omitempty" json:"when_query_params,omitempty"`
	RequireJSON          bool              `yaml:"requireJSON,omitempty" json:"require_json,omitempty"`
	RequiredJSONPaths    []string          `yaml:"requiredJSONPaths,omitempty" json:"required_json_paths,omitempty"`
	Timeout              string            `yaml:"timeout,omitempty" json:"timeout,omitempty"`
	RetryCount           int               `yaml:"retryCount,omitempty" json:"retry_count,omitempty"`
	RetryBackoff         string            `yaml:"retryBackoff,omitempty" json:"retry_backoff,omitempty"`
	RetryJitter          string            `yaml:"retryJitter,omitempty" json:"retry_jitter,omitempty"`
	RetryStatuses        []int             `yaml:"retryStatusCodes,omitempty" json:"retry_status_codes,omitempty"`
	RetryUnsafe          bool              `yaml:"retryUnsafeMethods,omitempty" json:"retry_unsafe_methods,omitempty"`
	SuccessStatuses      []int             `yaml:"successStatusCodes,omitempty" json:"success_status_codes,omitempty"`
	CacheTTL             string            `yaml:"cacheTTL,omitempty" json:"cache_ttl,omitempty"`
	CacheKey             string            `yaml:"cacheKey,omitempty" json:"cache_key,omitempty"`
	CacheStatuses        []int             `yaml:"cacheStatusCodes,omitempty" json:"cache_status_codes,omitempty"`
	CacheUnsafe          bool              `yaml:"cacheUnsafeMethods,omitempty" json:"cache_unsafe_methods,omitempty"`
	StaleIfError         string            `yaml:"staleIfError,omitempty" json:"stale_if_error,omitempty"`
	MaxResponseBodyBytes int64             `yaml:"maxResponseBodyBytes,omitempty" json:"max_response_body_bytes,omitempty"`
	Fallback             *BFFStepFallback  `yaml:"fallback,omitempty" json:"fallback,omitempty"`
	Headers              map[string]string `yaml:"headers,omitempty" json:"headers,omitempty"`
	QueryParams          map[string]string `yaml:"queryParams,omitempty" json:"query_params,omitempty"`
	Body                 string            `yaml:"body,omitempty" json:"body,omitempty"`
}

type BFFStepFallback struct {
	Status  int               `yaml:"status,omitempty" json:"status,omitempty"`
	Body    string            `yaml:"body,omitempty" json:"body,omitempty"`
	Headers map[string]string `yaml:"headers,omitempty" json:"headers,omitempty"`
}

func (c *BFFConfig) IsEnabled() bool {
	return c != nil && (c.Enabled == nil || *c.Enabled)
}

func (s BFFStepConfig) EffectiveMethod() string {
	if s.Method == "" {
		return "GET"
	}
	return s.Method
}

func (s BFFStepConfig) IsRequired() bool {
	return s.Required == nil || *s.Required
}
