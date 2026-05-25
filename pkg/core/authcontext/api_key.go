package authcontext

import "context"

const (
	legacyAPIKeyClientIDKey = "apikey_client_id"
	legacyAPIKeyScopesKey   = "apikey_scopes"
	legacyAPIKeyGroupKey    = "apikey_group"
)

type apiKeyClientContextKey struct{}

// APIKeyClient carries authenticated API-key client identity metadata.
type APIKeyClient struct {
	ID     string
	Group  string
	Scopes []string
}

// WithAPIKeyClient stores API-key client metadata with a typed key. It also
// writes the legacy string keys so older integrations continue to work.
func WithAPIKeyClient(ctx context.Context, client APIKeyClient) context.Context {
	client.Scopes = append([]string(nil), client.Scopes...)
	ctx = context.WithValue(ctx, apiKeyClientContextKey{}, client)
	ctx = context.WithValue(ctx, legacyAPIKeyClientIDKey, client.ID)
	ctx = context.WithValue(ctx, legacyAPIKeyScopesKey, append([]string(nil), client.Scopes...))
	ctx = context.WithValue(ctx, legacyAPIKeyGroupKey, client.Group)
	return ctx
}

func APIKeyClientFromContext(ctx context.Context) (APIKeyClient, bool) {
	if ctx == nil {
		return APIKeyClient{}, false
	}
	if client, ok := ctx.Value(apiKeyClientContextKey{}).(APIKeyClient); ok {
		client.Scopes = append([]string(nil), client.Scopes...)
		return client, true
	}

	client := APIKeyClient{}
	found := false
	if id, ok := ctx.Value(legacyAPIKeyClientIDKey).(string); ok {
		client.ID = id
		found = true
	}
	if group, ok := ctx.Value(legacyAPIKeyGroupKey).(string); ok {
		client.Group = group
		found = true
	}
	if scopes, ok := ctx.Value(legacyAPIKeyScopesKey).([]string); ok {
		client.Scopes = append([]string(nil), scopes...)
		found = true
	}
	return client, found
}

func APIKeyClientID(ctx context.Context) (string, bool) {
	client, ok := APIKeyClientFromContext(ctx)
	if !ok {
		return "", false
	}
	return client.ID, true
}

func APIKeyScopes(ctx context.Context) ([]string, bool) {
	client, ok := APIKeyClientFromContext(ctx)
	if !ok {
		return nil, false
	}
	return client.Scopes, true
}

func APIKeyGroup(ctx context.Context) (string, bool) {
	client, ok := APIKeyClientFromContext(ctx)
	if !ok {
		return "", false
	}
	return client.Group, true
}
