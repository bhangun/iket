package gateway

import "strings"

func policyReasonForGraphQLError(err error) string {
	if err == nil {
		return "graphql_policy"
	}
	msg := strings.ToLower(err.Error())
	if strings.Contains(msg, "introspection") {
		return "graphql_introspection"
	}
	if strings.Contains(msg, "persisted query") {
		return "graphql_persisted_query"
	}
	if strings.Contains(msg, "operation") {
		return "graphql_operation_policy"
	}
	if strings.Contains(msg, "variable") {
		return "graphql_variable_policy"
	}
	if strings.Contains(msg, "depth") {
		return "graphql_depth_limit"
	}
	if strings.Contains(msg, "field count") {
		return "graphql_field_limit"
	}
	return "graphql_policy"
}
