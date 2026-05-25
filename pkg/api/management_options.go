package api

// ManagementAPIOption customizes optional management API integrations without
// coupling community builds to enterprise-only packages.
type ManagementAPIOption func(*ManagementAPI)

// WithAPIKeyGenerator replaces the default crypto/rand API key generator.
// Enterprise builds can use this to delegate issuance to an HSM/KMS-backed
// implementation while keeping the community default secure and dependency-free.
func WithAPIKeyGenerator(generator APIKeyGenerator) ManagementAPIOption {
	return func(api *ManagementAPI) {
		if generator != nil {
			api.apiKeyGenerator = generator
		}
	}
}

// WithClientLifecycleHook registers a hook for client key lifecycle events.
// iket-enterprise can attach billing, subscription, CRM, or audit provisioning
// here without adding commercial dependencies to the community package.
func WithClientLifecycleHook(hook ClientLifecycleHook) ManagementAPIOption {
	return func(api *ManagementAPI) {
		if hook != nil {
			api.clientLifecycleHooks = append(api.clientLifecycleHooks, hook)
		}
	}
}
