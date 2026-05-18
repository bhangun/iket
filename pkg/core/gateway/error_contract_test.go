package gateway

import (
	"net/http"
	"strings"
	"testing"

	"github.com/bhangun/iket/pkg/config"
	coreerrors "github.com/bhangun/iket/pkg/core/errors"
	"github.com/bhangun/iket/pkg/core/errors/errortest"
)

func TestGraphQLPolicyHelpersReturnGovernedCodes(t *testing.T) {
	req, err := http.NewRequest(http.MethodPost, "/graphql", strings.NewReader(`{"query":"query Viewer { viewer { id } }"}`))
	if err != nil {
		t.Fatalf("failed to build request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	route := config.RouterConfig{
		Protocol:                     "graphql",
		GraphQLRequirePersistedQuery: true,
	}

	policyErr := enforceGraphQLRoutePolicy(req, route)
	errortest.AssertCodeAndStatus(t, policyErr, coreerrors.CodeRequiredFieldMissing, http.StatusBadRequest)
}

func TestRouteProtocolHelpersReturnValidationCodes(t *testing.T) {
	req, err := http.NewRequest(http.MethodPost, "/rpc.AgentService/Chat", nil)
	if err != nil {
		t.Fatalf("failed to build request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	route := config.RouterConfig{Protocol: "grpc"}
	policyErr := enforceRouteProtocol(req, route)
	errortest.AssertCodeAndStatus(t, policyErr, coreerrors.CodeValidationError, http.StatusBadRequest)
}

func TestRequestPolicyHelpersReturnTypedCodes(t *testing.T) {
	contentReq, err := http.NewRequest(http.MethodPost, "/content", strings.NewReader(`{"message":"blocked content"}`))
	if err != nil {
		t.Fatalf("failed to build content request: %v", err)
	}
	contentRoute := config.RouterConfig{RequestBodyBlockRegex: []string{"blocked"}}
	contentErr := enforceRequestBodyPatterns(contentReq, contentRoute)
	errortest.AssertCodeAndStatus(t, contentErr, coreerrors.CodeValidationError, http.StatusBadRequest)

	headerReq, err := http.NewRequest(http.MethodGet, "/headers", nil)
	if err != nil {
		t.Fatalf("failed to build header request: %v", err)
	}
	headerRoute := config.RouterConfig{RequiredRequestHeaders: []string{"X-Trace-Id"}}
	headerErr := enforceRequiredRequestHeaders(headerReq, headerRoute)
	errortest.AssertCodeAndStatus(t, headerErr, coreerrors.CodeRequiredFieldMissing, http.StatusBadRequest)

	bodyReq, err := http.NewRequest(http.MethodPost, "/body", strings.NewReader(`{"message":"too large"}`))
	if err != nil {
		t.Fatalf("failed to build body request: %v", err)
	}
	bodyRoute := config.RouterConfig{MaxRequestBodyBytes: 4}
	bodyErr := enforceRequestBodyLimit(bodyReq, bodyRoute)
	errortest.AssertCodeAndStatus(t, bodyErr, coreerrors.CodeValidationError, http.StatusBadRequest)
}

func TestGraphQLMetadataAndVariableHelpersReturnTypedCodes(t *testing.T) {
	_, err := extractPersistedQueryIDFromExtensions("{not-json", "extensions.persistedQuery.sha256Hash")
	errortest.AssertCodeAndStatus(t, err, coreerrors.CodeValidationError, http.StatusBadRequest)

	_, err = extractGraphQLVariablesFromRaw("{not-json")
	errortest.AssertCodeAndStatus(t, err, coreerrors.CodeValidationError, http.StatusBadRequest)

	err = enforceGraphQLVariableValuePolicy(
		map[string]string{"tenant": "^[a-z]+$"},
		nil,
		map[string]interface{}{"tenant": "TENANT-1"},
	)
	errortest.AssertCodeAndStatus(t, err, coreerrors.CodeValidationError, http.StatusBadRequest)
}
