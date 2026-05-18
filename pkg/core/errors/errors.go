package errors

import (
	"encoding/json"
	stderrors "errors"
	"fmt"
	"net/http"
	"strings"
)

const (
	CodeInternalError                 = "INTERNAL_ERROR"
	CodeConfigNotFound                = "CONFIG_NOT_FOUND"
	CodeConfigNotAvailable            = "CONFIG_NOT_AVAILABLE"
	CodeConfigInvalid                 = "INVALID_CONFIG"
	CodeConfigInvalidFormat           = "CONFIG_INVALID_FORMAT"
	CodeConfigError                   = "CONFIG_ERROR"
	CodeRouteNotFound                 = "ROUTE_NOT_FOUND"
	CodeRouteInvalid                  = "INVALID_ROUTE"
	CodeRouteAlreadyExists            = "ROUTE_ALREADY_EXISTS"
	CodeRouteError                    = "ROUTE_ERROR"
	CodeServiceNotFound               = "SERVICE_NOT_FOUND"
	CodeServiceInvalid                = "SERVICE_INVALID"
	CodePluginNotFound                = "PLUGIN_NOT_FOUND"
	CodePluginConfigNotFound          = "PLUGIN_CONFIG_NOT_FOUND"
	CodePluginUnsupported             = "PLUGIN_UNSUPPORTED"
	CodePluginError                   = "PLUGIN_ERROR"
	CodeManagementExtensionNotFound   = "MANAGEMENT_EXTENSION_NOT_FOUND"
	CodeClientNotFound                = "CLIENT_NOT_FOUND"
	CodeClientInvalid                 = "CLIENT_INVALID"
	CodeClientAlreadyExists           = "CLIENT_ALREADY_EXISTS"
	CodeCertificateNotFound           = "CERTIFICATE_NOT_FOUND"
	CodeCertificateInvalidPayload     = "CERTIFICATE_INVALID_PAYLOAD"
	CodeCertificatePEMInvalid         = "CERTIFICATE_PEM_INVALID"
	CodeCSRInvalid                    = "CSR_INVALID"
	CodeEnrollmentRequestInvalid      = "ENROLLMENT_REQUEST_INVALID"
	CodeEnrollmentTokenNotFound       = "ENROLLMENT_TOKEN_NOT_FOUND"
	CodeEnrollmentTokenInvalid        = "ENROLLMENT_TOKEN_INVALID"
	CodeEnrollmentTokenInvalidPayload = "ENROLLMENT_TOKEN_INVALID_PAYLOAD"
	CodeEnrollmentTokenExpired        = "ENROLLMENT_TOKEN_EXPIRED"
	CodeEnrollmentTokenAlreadyUsed    = "ENROLLMENT_TOKEN_ALREADY_USED"
	CodeEnrollmentTokenLimitReached   = "ENROLLMENT_TOKEN_LIMIT_REACHED"
	CodeProposalNotFound              = "PROPOSAL_NOT_FOUND"
	CodeProposalNotAvailable          = "PROPOSAL_NOT_AVAILABLE"
	CodeProposalStateConflict         = "PROPOSAL_STATE_CONFLICT"
	CodeProposalVerificationFailed    = "PROPOSAL_VERIFICATION_FAILED"
	CodeRevisionNotFound              = "REVISION_NOT_FOUND"
	CodeRevisionConfigMissing         = "REVISION_CONFIG_MISSING"
	CodeNotificationDeliveryNotFound  = "NOTIFICATION_DELIVERY_NOT_FOUND"
	CodeBackupNotFound                = "BACKUP_NOT_FOUND"
	CodeValidationFailed              = "VALIDATION_FAILED"
	CodeValidationError               = "VALIDATION_ERROR"
	CodeRequiredFieldMissing          = "REQUIRED_FIELD_MISSING"
	CodeAuthenticationRequired        = "AUTHENTICATION_REQUIRED"
	CodeUnauthorized                  = "UNAUTHORIZED"
	CodePermissionDenied              = "PERMISSION_DENIED"
	CodeForbidden                     = "FORBIDDEN"
	CodeConflict                      = "CONFLICT"
	CodeCanaryConfigInvalid           = "CANARY_CONFIG_INVALID"
	CodeCanaryStateConflict           = "CANARY_STATE_CONFLICT"
	CodeRateLimitExceeded             = "RATE_LIMIT_EXCEEDED"
	CodeServiceUnavailable            = "SERVICE_UNAVAILABLE"
	CodeFeatureNotSupported           = "FEATURE_NOT_SUPPORTED"
	CodeUpstreamError                 = "UPSTREAM_ERROR"
)

type Descriptor struct {
	Code           string
	DefaultMessage string
	HTTPStatus     int
}

var descriptors = map[string]Descriptor{
	CodeInternalError:                 {Code: CodeInternalError, DefaultMessage: "Internal server error", HTTPStatus: http.StatusInternalServerError},
	CodeConfigNotFound:                {Code: CodeConfigNotFound, DefaultMessage: "Configuration file not found", HTTPStatus: http.StatusNotFound},
	CodeConfigNotAvailable:            {Code: CodeConfigNotAvailable, DefaultMessage: "Configuration not available", HTTPStatus: http.StatusInternalServerError},
	CodeConfigInvalid:                 {Code: CodeConfigInvalid, DefaultMessage: "Invalid configuration", HTTPStatus: http.StatusBadRequest},
	CodeConfigInvalidFormat:           {Code: CodeConfigInvalidFormat, DefaultMessage: "Invalid configuration format", HTTPStatus: http.StatusBadRequest},
	CodeConfigError:                   {Code: CodeConfigError, DefaultMessage: "Configuration error", HTTPStatus: http.StatusInternalServerError},
	CodeRouteNotFound:                 {Code: CodeRouteNotFound, DefaultMessage: "Route not found", HTTPStatus: http.StatusNotFound},
	CodeRouteInvalid:                  {Code: CodeRouteInvalid, DefaultMessage: "Invalid route configuration", HTTPStatus: http.StatusBadRequest},
	CodeRouteAlreadyExists:            {Code: CodeRouteAlreadyExists, DefaultMessage: "Route already exists", HTTPStatus: http.StatusConflict},
	CodeRouteError:                    {Code: CodeRouteError, DefaultMessage: "Route error", HTTPStatus: http.StatusInternalServerError},
	CodeServiceNotFound:               {Code: CodeServiceNotFound, DefaultMessage: "Service not found", HTTPStatus: http.StatusNotFound},
	CodeServiceInvalid:                {Code: CodeServiceInvalid, DefaultMessage: "Invalid service definition", HTTPStatus: http.StatusBadRequest},
	CodePluginNotFound:                {Code: CodePluginNotFound, DefaultMessage: "Plugin not found", HTTPStatus: http.StatusNotFound},
	CodePluginConfigNotFound:          {Code: CodePluginConfigNotFound, DefaultMessage: "Plugin configuration not found", HTTPStatus: http.StatusNotFound},
	CodePluginUnsupported:             {Code: CodePluginUnsupported, DefaultMessage: "Plugin does not support this operation", HTTPStatus: http.StatusNotImplemented},
	CodePluginError:                   {Code: CodePluginError, DefaultMessage: "Plugin execution failed", HTTPStatus: http.StatusServiceUnavailable},
	CodeManagementExtensionNotFound:   {Code: CodeManagementExtensionNotFound, DefaultMessage: "Management extension not found", HTTPStatus: http.StatusNotFound},
	CodeClientNotFound:                {Code: CodeClientNotFound, DefaultMessage: "Client not found", HTTPStatus: http.StatusNotFound},
	CodeClientInvalid:                 {Code: CodeClientInvalid, DefaultMessage: "Invalid client data", HTTPStatus: http.StatusBadRequest},
	CodeClientAlreadyExists:           {Code: CodeClientAlreadyExists, DefaultMessage: "Client already exists", HTTPStatus: http.StatusConflict},
	CodeCertificateNotFound:           {Code: CodeCertificateNotFound, DefaultMessage: "Certificate not found", HTTPStatus: http.StatusNotFound},
	CodeCertificateInvalidPayload:     {Code: CodeCertificateInvalidPayload, DefaultMessage: "Invalid certificate payload", HTTPStatus: http.StatusBadRequest},
	CodeCertificatePEMInvalid:         {Code: CodeCertificatePEMInvalid, DefaultMessage: "Invalid cert_pem", HTTPStatus: http.StatusBadRequest},
	CodeCSRInvalid:                    {Code: CodeCSRInvalid, DefaultMessage: "Invalid csr_pem", HTTPStatus: http.StatusBadRequest},
	CodeEnrollmentRequestInvalid:      {Code: CodeEnrollmentRequestInvalid, DefaultMessage: "Invalid enrollment request", HTTPStatus: http.StatusBadRequest},
	CodeEnrollmentTokenNotFound:       {Code: CodeEnrollmentTokenNotFound, DefaultMessage: "Enrollment token not found", HTTPStatus: http.StatusNotFound},
	CodeEnrollmentTokenInvalid:        {Code: CodeEnrollmentTokenInvalid, DefaultMessage: "Invalid enrollment token", HTTPStatus: http.StatusUnauthorized},
	CodeEnrollmentTokenInvalidPayload: {Code: CodeEnrollmentTokenInvalidPayload, DefaultMessage: "Invalid enrollment token payload", HTTPStatus: http.StatusBadRequest},
	CodeEnrollmentTokenExpired:        {Code: CodeEnrollmentTokenExpired, DefaultMessage: "Enrollment token has expired", HTTPStatus: http.StatusUnauthorized},
	CodeEnrollmentTokenAlreadyUsed:    {Code: CodeEnrollmentTokenAlreadyUsed, DefaultMessage: "Enrollment token has already been used", HTTPStatus: http.StatusConflict},
	CodeEnrollmentTokenLimitReached:   {Code: CodeEnrollmentTokenLimitReached, DefaultMessage: "Active enrollment token limit reached", HTTPStatus: http.StatusConflict},
	CodeProposalNotFound:              {Code: CodeProposalNotFound, DefaultMessage: "Proposal not found", HTTPStatus: http.StatusNotFound},
	CodeProposalNotAvailable:          {Code: CodeProposalNotAvailable, DefaultMessage: "Proposal not available", HTTPStatus: http.StatusNotFound},
	CodeProposalStateConflict:         {Code: CodeProposalStateConflict, DefaultMessage: "Proposal state conflict", HTTPStatus: http.StatusConflict},
	CodeProposalVerificationFailed:    {Code: CodeProposalVerificationFailed, DefaultMessage: "Proposal verification failed", HTTPStatus: http.StatusInternalServerError},
	CodeRevisionNotFound:              {Code: CodeRevisionNotFound, DefaultMessage: "Revision not found", HTTPStatus: http.StatusNotFound},
	CodeRevisionConfigMissing:         {Code: CodeRevisionConfigMissing, DefaultMessage: "Revision has no stored configuration", HTTPStatus: http.StatusInternalServerError},
	CodeNotificationDeliveryNotFound:  {Code: CodeNotificationDeliveryNotFound, DefaultMessage: "Notification delivery not found", HTTPStatus: http.StatusNotFound},
	CodeBackupNotFound:                {Code: CodeBackupNotFound, DefaultMessage: "Backup not found", HTTPStatus: http.StatusNotFound},
	CodeValidationFailed:              {Code: CodeValidationFailed, DefaultMessage: "Validation failed", HTTPStatus: http.StatusBadRequest},
	CodeValidationError:               {Code: CodeValidationError, DefaultMessage: "Validation error", HTTPStatus: http.StatusBadRequest},
	CodeRequiredFieldMissing:          {Code: CodeRequiredFieldMissing, DefaultMessage: "Required field is missing", HTTPStatus: http.StatusBadRequest},
	CodeAuthenticationRequired:        {Code: CodeAuthenticationRequired, DefaultMessage: "Authentication required", HTTPStatus: http.StatusUnauthorized},
	CodeUnauthorized:                  {Code: CodeUnauthorized, DefaultMessage: "Authentication required", HTTPStatus: http.StatusUnauthorized},
	CodePermissionDenied:              {Code: CodePermissionDenied, DefaultMessage: "Permission denied", HTTPStatus: http.StatusForbidden},
	CodeForbidden:                     {Code: CodeForbidden, DefaultMessage: "Access denied", HTTPStatus: http.StatusForbidden},
	CodeConflict:                      {Code: CodeConflict, DefaultMessage: "Conflict", HTTPStatus: http.StatusConflict},
	CodeCanaryConfigInvalid:           {Code: CodeCanaryConfigInvalid, DefaultMessage: "Invalid canary configuration", HTTPStatus: http.StatusBadRequest},
	CodeCanaryStateConflict:           {Code: CodeCanaryStateConflict, DefaultMessage: "Canary rollout state conflict", HTTPStatus: http.StatusConflict},
	CodeRateLimitExceeded:             {Code: CodeRateLimitExceeded, DefaultMessage: "Rate limit exceeded", HTTPStatus: http.StatusTooManyRequests},
	CodeServiceUnavailable:            {Code: CodeServiceUnavailable, DefaultMessage: "Service temporarily unavailable", HTTPStatus: http.StatusServiceUnavailable},
	CodeFeatureNotSupported:           {Code: CodeFeatureNotSupported, DefaultMessage: "Feature not supported", HTTPStatus: http.StatusNotImplemented},
	CodeUpstreamError:                 {Code: CodeUpstreamError, DefaultMessage: "Upstream request failed", HTTPStatus: http.StatusBadGateway},
}

type codeRule struct {
	statuses []int
	code     string
	exact    string
	prefix   string
	contains []string
}

var resolutionRules = []codeRule{
	{statuses: []int{http.StatusNotFound}, code: CodeConfigNotFound, exact: "configuration not found"},
	{statuses: []int{http.StatusInternalServerError}, code: CodeConfigNotAvailable, exact: "configuration not available"},
	{statuses: []int{http.StatusBadRequest}, code: CodeConfigInvalidFormat, exact: "invalid configuration format"},
	{statuses: []int{http.StatusBadRequest}, code: CodeConfigInvalid, exact: "invalid configuration"},
	{statuses: []int{http.StatusNotFound}, code: CodePluginNotFound, exact: "plugin not found"},
	{statuses: []int{http.StatusNotFound}, code: CodePluginConfigNotFound, exact: "plugin configuration not found"},
	{statuses: []int{http.StatusNotImplemented}, code: CodePluginUnsupported, contains: []string{"plugin does not support"}},
	{statuses: []int{http.StatusBadRequest}, code: CodeServiceInvalid, exact: "invalid service definition"},
	{statuses: []int{http.StatusNotFound}, code: CodeServiceNotFound, exact: "service not found"},
	{statuses: []int{http.StatusNotFound}, code: CodeRouteNotFound, exact: "route not found"},
	{statuses: []int{http.StatusBadRequest}, code: CodeRouteInvalid, exact: "invalid route configuration"},
	{statuses: []int{http.StatusConflict}, code: CodeRouteAlreadyExists, exact: "route already exists"},
	{statuses: []int{http.StatusBadRequest}, code: CodeClientInvalid, exact: "invalid client data"},
	{statuses: []int{http.StatusNotFound}, code: CodeClientNotFound, exact: "client not found"},
	{statuses: []int{http.StatusConflict}, code: CodeClientAlreadyExists, exact: "client with this key already exists"},
	{statuses: []int{http.StatusBadRequest}, code: CodeCertificateInvalidPayload, exact: "invalid certificate payload"},
	{statuses: []int{http.StatusBadRequest}, code: CodeCertificatePEMInvalid, exact: "invalid cert_pem"},
	{statuses: []int{http.StatusNotFound}, code: CodeCertificateNotFound, exact: "certificate not found"},
	{statuses: []int{http.StatusBadRequest}, code: CodeEnrollmentTokenInvalidPayload, exact: "invalid enrollment token payload"},
	{statuses: []int{http.StatusBadRequest}, code: CodeEnrollmentRequestInvalid, exact: "invalid enrollment request"},
	{statuses: []int{http.StatusUnauthorized}, code: CodeEnrollmentTokenInvalid, exact: "invalid enrollment token"},
	{statuses: []int{http.StatusUnauthorized}, code: CodeEnrollmentTokenExpired, exact: "enrollment token has expired"},
	{statuses: []int{http.StatusConflict}, code: CodeEnrollmentTokenAlreadyUsed, exact: "enrollment token has already been used"},
	{statuses: []int{http.StatusNotFound}, code: CodeEnrollmentTokenNotFound, exact: "enrollment token not found"},
	{statuses: []int{http.StatusConflict}, code: CodeEnrollmentTokenLimitReached, contains: []string{"enrollment token limit reached"}},
	{statuses: []int{http.StatusConflict}, code: CodeEnrollmentTokenLimitReached, contains: []string{"active enrollment token limit reached"}},
	{statuses: []int{http.StatusBadRequest}, code: CodeCSRInvalid, exact: "invalid csr_pem"},
	{statuses: []int{http.StatusNotFound}, code: CodeProposalNotFound, exact: "proposal not found"},
	{statuses: []int{http.StatusNotFound}, code: CodeProposalNotAvailable, exact: "proposal not available"},
	{statuses: []int{http.StatusConflict}, code: CodeProposalStateConflict, prefix: "proposal is already "},
	{statuses: []int{http.StatusConflict}, code: CodeProposalStateConflict, contains: []string{"proposal cannot be promoted because it is"}},
	{statuses: []int{http.StatusConflict}, code: CodeProposalStateConflict, contains: []string{"proposal cannot expand canary because it is"}},
	{statuses: []int{http.StatusConflict}, code: CodeProposalStateConflict, contains: []string{"proposal canary is not active"}},
	{statuses: []int{http.StatusInternalServerError}, code: CodeProposalVerificationFailed, prefix: "failed to verify proposal:"},
	{statuses: []int{http.StatusInternalServerError}, code: CodeRevisionConfigMissing, exact: "revision has no stored configuration"},
	{statuses: []int{http.StatusNotFound}, code: CodeRevisionNotFound, exact: "revision not found"},
	{statuses: []int{http.StatusNotFound}, code: CodeNotificationDeliveryNotFound, exact: "notification delivery not found"},
	{statuses: []int{http.StatusNotFound}, code: CodeBackupNotFound, exact: "backup not found"},
	{statuses: []int{http.StatusUnauthorized}, code: CodeAuthenticationRequired, exact: "authentication required"},
	{statuses: []int{http.StatusForbidden}, code: CodePermissionDenied, exact: "permission denied"},
	{statuses: []int{http.StatusConflict}, code: CodeCanaryStateConflict, contains: []string{"canary rollout failed configured metric thresholds"}},
	{statuses: []int{http.StatusConflict}, code: CodeCanaryStateConflict, contains: []string{"automatic rollback also failed"}},
}

// GatewayError represents a structured error with additional context.
type GatewayError struct {
	Code    string                 `json:"code"`
	Message string                 `json:"message"`
	Details map[string]interface{} `json:"details,omitempty"`
	Err     error                  `json:"-"`
}

// Error implements the error interface.
func (e *GatewayError) Error() string {
	if e == nil {
		return CodeInternalError
	}
	code := normalizeCode(e.Code)
	message := strings.TrimSpace(e.Message)
	if message == "" {
		message = DefaultMessage(code)
	}
	if e.Err != nil {
		return fmt.Sprintf("%s: %s (%s)", code, message, e.Err.Error())
	}
	return fmt.Sprintf("%s: %s", code, message)
}

// Unwrap returns the underlying error.
func (e *GatewayError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

// Clone returns a detached copy so shared predefined errors stay immutable.
func (e *GatewayError) Clone() *GatewayError {
	if e == nil {
		return nil
	}
	clone := *e
	clone.Code = normalizeCode(clone.Code)
	clone.Details = copyDetails(clone.Details)
	return &clone
}

// WithDetails returns a cloned error with additional context.
func (e *GatewayError) WithDetails(details map[string]interface{}) *GatewayError {
	clone := e.Clone()
	if clone == nil {
		clone = New(CodeInternalError, "")
	}
	clone.Details = copyDetails(details)
	return clone
}

// WithError returns a cloned error with the underlying error attached.
func (e *GatewayError) WithError(err error) *GatewayError {
	clone := e.Clone()
	if clone == nil {
		clone = New(CodeInternalError, "")
	}
	clone.Err = err
	return clone
}

// WriteHTTP writes the error to an HTTP response.
func (e *GatewayError) WriteHTTP(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")

	code := CodeOf(e)
	if code == "" {
		code = CodeInternalError
	}
	message := strings.TrimSpace(e.Message)
	if message == "" {
		message = DefaultMessage(code)
	}

	w.WriteHeader(HTTPStatusForCode(code))
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"error":   code,
		"message": message,
		"details": e.Details,
	})
}

// HTTPStatusCode returns the appropriate HTTP status code for this error.
func (e *GatewayError) HTTPStatusCode() int {
	return HTTPStatusForCode(CodeOf(e))
}

func New(code, message string) *GatewayError {
	code = normalizeCode(code)
	if strings.TrimSpace(message) == "" {
		message = DefaultMessage(code)
	}
	return &GatewayError{
		Code:    code,
		Message: strings.TrimSpace(message),
	}
}

func IsCode(err error, code string) bool {
	return normalizeCode(CodeOf(err)) == normalizeCode(code)
}

func CodeOf(err error) string {
	if err == nil {
		return ""
	}
	var gatewayErr *GatewayError
	if stderrors.As(err, &gatewayErr) && gatewayErr != nil {
		return normalizeCode(gatewayErr.Code)
	}
	return ""
}

func DefaultMessage(code string) string {
	if descriptor, ok := descriptors[normalizeCode(code)]; ok {
		return descriptor.DefaultMessage
	}
	return descriptors[CodeInternalError].DefaultMessage
}

func HTTPStatusForCode(code string) int {
	if descriptor, ok := descriptors[normalizeCode(code)]; ok {
		return descriptor.HTTPStatus
	}
	return http.StatusInternalServerError
}

func KnownCode(code string) bool {
	_, ok := descriptors[normalizeCode(code)]
	return ok
}

func ResolveCode(message string, statusCode int) string {
	trimmed := strings.TrimSpace(message)
	if trimmed == "" {
		return fallbackCodeForStatus(statusCode)
	}

	if prefixCode := parseEmbeddedCode(trimmed); prefixCode != "" {
		return prefixCode
	}

	normalized := strings.ToLower(trimmed)
	for _, rule := range resolutionRules {
		if !statusMatches(rule.statuses, statusCode) {
			continue
		}
		if rule.exact != "" && normalized == rule.exact {
			return rule.code
		}
		if rule.prefix != "" && strings.HasPrefix(normalized, rule.prefix) {
			return rule.code
		}
		if len(rule.contains) > 0 && containsAll(normalized, rule.contains) {
			return rule.code
		}
	}

	if strings.Contains(normalized, " is required") || strings.HasSuffix(normalized, " are required") {
		return CodeRequiredFieldMissing
	}
	if strings.Contains(normalized, "invalid canary_") || strings.Contains(normalized, "canary headers are required") {
		return CodeCanaryConfigInvalid
	}
	if strings.Contains(normalized, "proposal has no stored configuration") {
		return CodeProposalVerificationFailed
	}
	if strings.Contains(normalized, "failed to ") || strings.Contains(normalized, "could not ") {
		if statusCode == http.StatusBadGateway {
			return CodeUpstreamError
		}
		return fallbackCodeForStatus(statusCode)
	}
	if strings.Contains(normalized, "invalid ") || strings.Contains(normalized, " must ") || strings.Contains(normalized, " expected ") {
		return CodeValidationError
	}

	return fallbackCodeForStatus(statusCode)
}

func fallbackCodeForStatus(statusCode int) string {
	switch statusCode {
	case http.StatusUnauthorized:
		return CodeAuthenticationRequired
	case http.StatusForbidden:
		return CodePermissionDenied
	case http.StatusBadRequest:
		return CodeValidationError
	case http.StatusNotFound:
		return CodeConfigNotFound
	case http.StatusConflict:
		return CodeConflict
	case http.StatusTooManyRequests:
		return CodeRateLimitExceeded
	case http.StatusNotImplemented:
		return CodeFeatureNotSupported
	case http.StatusBadGateway:
		return CodeUpstreamError
	case http.StatusServiceUnavailable:
		return CodeServiceUnavailable
	default:
		return CodeInternalError
	}
}

func parseEmbeddedCode(message string) string {
	idx := strings.Index(message, ":")
	if idx <= 0 {
		return ""
	}
	candidate := normalizeCode(message[:idx])
	if KnownCode(candidate) {
		return candidate
	}
	return ""
}

func normalizeCode(code string) string {
	code = strings.TrimSpace(strings.ToUpper(code))
	if code == "" {
		return CodeInternalError
	}
	return code
}

func statusMatches(statuses []int, status int) bool {
	if len(statuses) == 0 {
		return true
	}
	for _, allowed := range statuses {
		if allowed == status {
			return true
		}
	}
	return false
}

func containsAll(message string, parts []string) bool {
	for _, part := range parts {
		if !strings.Contains(message, strings.ToLower(part)) {
			return false
		}
	}
	return true
}

func copyDetails(in map[string]interface{}) map[string]interface{} {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]interface{}, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}

// Predefined errors.
var (
	ErrConfigNotFound     = New(CodeConfigNotFound, "Configuration file not found")
	ErrInvalidConfig      = New(CodeConfigInvalid, "Invalid configuration format")
	ErrRouteNotFound      = New(CodeRouteNotFound, "Route not found")
	ErrInvalidRoute       = New(CodeRouteInvalid, "Invalid route configuration")
	ErrUnauthorized       = New(CodeUnauthorized, "Authentication required")
	ErrForbidden          = New(CodeForbidden, "Access denied")
	ErrRateLimitExceeded  = New(CodeRateLimitExceeded, "Rate limit exceeded")
	ErrPluginError        = New(CodePluginError, "Plugin execution failed")
	ErrServiceUnavailable = New(CodeServiceUnavailable, "Service temporarily unavailable")
)

// Helper functions for creating errors with context.
func wrap(code, message string, err error) *GatewayError {
	gatewayErr := New(code, message)
	if err != nil {
		return gatewayErr.WithError(err)
	}
	return gatewayErr
}

func NewConfigError(message string, err error) *GatewayError {
	return wrap(CodeConfigError, message, err)
}

func NewRouteError(message string, err error) *GatewayError {
	return wrap(CodeRouteError, message, err)
}

func NewPluginError(pluginName, message string, err error) *GatewayError {
	return wrap(CodePluginError, fmt.Sprintf("Plugin '%s': %s", pluginName, message), err)
}

func NewValidationError(field, message string) *GatewayError {
	return New(CodeValidationFailed, fmt.Sprintf("Validation failed for field '%s': %s", field, message)).WithDetails(map[string]interface{}{
		"field": field,
	})
}

func NewCodeError(code, message string, err error) *GatewayError {
	return wrap(code, message, err)
}

func NewRequiredFieldError(message string) *GatewayError {
	return wrap(CodeRequiredFieldMissing, message, nil)
}

func NewProposalConflictError(message string, err error) *GatewayError {
	return wrap(CodeProposalStateConflict, message, err)
}

func NewProposalVerificationError(message string, err error) *GatewayError {
	return wrap(CodeProposalVerificationFailed, message, err)
}

func NewCanaryConfigError(message string, err error) *GatewayError {
	return wrap(CodeCanaryConfigInvalid, message, err)
}

func NewCanaryStateError(message string, err error) *GatewayError {
	return wrap(CodeCanaryStateConflict, message, err)
}
