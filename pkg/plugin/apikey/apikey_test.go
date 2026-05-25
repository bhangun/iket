package apikey

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/bhangun/iket/pkg/core/authcontext"
	"github.com/bhangun/iket/pkg/core/credentials"
	"github.com/bhangun/iket/pkg/core/requestcontext"
	pluginpkg "github.com/bhangun/iket/pkg/plugin"
)

func TestAPIKeyPluginAcceptsHashedClientKey(t *testing.T) {
	plugin := &APIKeyPlugin{}
	if err := plugin.Initialize(map[string]interface{}{
		"enabled": true,
		"clients": []interface{}{
			map[string]interface{}{
				"id":       "client-a",
				"name":     "Client A",
				"key_hash": credentials.APIKeyHash("secret"),
				"group":    "billing",
				"scopes":   []interface{}{"read", "write"},
				"tags":     []interface{}{"gold", "trial"},
			},
		},
	}); err != nil {
		t.Fatalf("failed to initialize plugin: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-API-Key", "secret")
	resp := httptest.NewRecorder()

	plugin.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, ok := authcontext.APIKeyClientID(r.Context())
		if !ok || got != "client-a" {
			t.Fatalf("expected typed client id in context, got %q ok=%v", got, ok)
		}
		if got := r.Context().Value("apikey_client_id"); got != "client-a" {
			t.Fatalf("expected legacy client id in context, got %v", got)
		}
		principal, ok := authcontext.PrincipalFromContext(r.Context())
		if !ok {
			t.Fatalf("expected typed principal")
		}
		if principal.Source != "apikey" || principal.Subject != "client-a" || principal.ClientID != "client-a" {
			t.Fatalf("unexpected API-key principal identity: %+v", principal)
		}
		if principal.Username != "Client A" || principal.UserID != "client-a" {
			t.Fatalf("unexpected API-key principal profile: %+v", principal)
		}
		if !reflect.DeepEqual(principal.Groups, []string{"billing"}) {
			t.Fatalf("expected API-key group as principal group, got %+v", principal.Groups)
		}
		if !reflect.DeepEqual(principal.Scopes, []string{"read", "write"}) {
			t.Fatalf("expected API-key scopes as principal scopes, got %+v", principal.Scopes)
		}
		if principal.Custom["key_fingerprint"] != credentials.APIKeyFingerprint("secret") {
			t.Fatalf("expected safe key fingerprint in principal custom fields, got %+v", principal.Custom)
		}
		if principal.Custom["tags"] != "gold,trial" || principal.Custom["group"] != "billing" {
			t.Fatalf("expected safe client metadata in principal custom fields, got %+v", principal.Custom)
		}
		if _, exists := principal.Custom["key"]; exists {
			t.Fatalf("principal custom fields must not expose raw API key: %+v", principal.Custom)
		}
		if _, exists := principal.Custom["key_hash"]; exists {
			t.Fatalf("principal custom fields must not expose API key hash: %+v", principal.Custom)
		}
		w.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(resp, req)

	if resp.Code != http.StatusNoContent {
		t.Fatalf("expected request to pass, got %d: %s", resp.Code, resp.Body.String())
	}
}

func TestAPIKeyPluginStillAcceptsLegacyPlaintextClientKey(t *testing.T) {
	plugin := &APIKeyPlugin{}
	if err := plugin.Initialize(map[string]interface{}{
		"enabled": true,
		"clients": []interface{}{
			map[string]interface{}{
				"id":   "client-a",
				"name": "Client A",
				"key":  "legacy-secret",
			},
		},
	}); err != nil {
		t.Fatalf("failed to initialize plugin: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-API-Key", "legacy-secret")
	resp := httptest.NewRecorder()

	plugin.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(resp, req)

	if resp.Code != http.StatusNoContent {
		t.Fatalf("expected legacy request to pass, got %d: %s", resp.Code, resp.Body.String())
	}
}

func TestAPIKeyPluginConfiguresUsageObserverTimeout(t *testing.T) {
	plugin := &APIKeyPlugin{}
	if err := plugin.Initialize(map[string]interface{}{
		"enabled":                true,
		"usage_observer_timeout": "250ms",
	}); err != nil {
		t.Fatalf("failed to initialize plugin: %v", err)
	}

	if got := plugin.clientUsageObserverTimeout(); got != 250*time.Millisecond {
		t.Fatalf("expected configured usage observer timeout 250ms, got %s", got)
	}
}

func TestAPIKeyPluginConfiguresUsageObserverAsync(t *testing.T) {
	plugin := &APIKeyPlugin{}
	if err := plugin.Initialize(map[string]interface{}{
		"enabled":              true,
		"usage_observer_async": true,
	}); err != nil {
		t.Fatalf("failed to initialize plugin: %v", err)
	}

	if !plugin.clientUsageObserverAsync() {
		t.Fatalf("expected usage observers to run asynchronously")
	}
}

func TestAPIKeyPluginConfiguresUsageObserverAsyncMaxInFlight(t *testing.T) {
	plugin := &APIKeyPlugin{}
	if err := plugin.Initialize(map[string]interface{}{
		"enabled":                            true,
		"usage_observer_async":               true,
		"usage_observer_async_max_in_flight": 7,
	}); err != nil {
		t.Fatalf("failed to initialize plugin: %v", err)
	}

	if got := plugin.clientUsageObserverAsyncMaxInFlight(); got != 7 {
		t.Fatalf("expected async usage observer max in-flight 7, got %d", got)
	}
}

func TestAPIKeyPluginRejectsInvalidUsageObserverTimeout(t *testing.T) {
	plugin := &APIKeyPlugin{}
	if err := plugin.Initialize(map[string]interface{}{
		"enabled":                true,
		"usage_observer_timeout": "0s",
	}); err == nil {
		t.Fatalf("expected invalid usage observer timeout to fail initialization")
	}
}

func TestAPIKeyPluginRejectsInvalidUsageObserverAsync(t *testing.T) {
	plugin := &APIKeyPlugin{}
	if err := plugin.Initialize(map[string]interface{}{
		"enabled":              true,
		"usage_observer_async": "true",
	}); err == nil {
		t.Fatalf("expected invalid usage observer async value to fail initialization")
	}
}

func TestAPIKeyPluginRejectsInvalidUsageObserverAsyncMaxInFlight(t *testing.T) {
	plugin := &APIKeyPlugin{}
	if err := plugin.Initialize(map[string]interface{}{
		"enabled":                            true,
		"usage_observer_async":               true,
		"usage_observer_async_max_in_flight": 0,
	}); err == nil {
		t.Fatalf("expected invalid usage observer async max in-flight value to fail initialization")
	}
}

func TestAPIKeyPluginRejectsDisabledClientKey(t *testing.T) {
	plugin := &APIKeyPlugin{}
	if err := plugin.Initialize(map[string]interface{}{
		"enabled": true,
		"clients": []interface{}{
			map[string]interface{}{
				"id":       "client-a",
				"name":     "Client A",
				"key_hash": credentials.APIKeyHash("secret"),
				"enabled":  false,
			},
		},
	}); err != nil {
		t.Fatalf("failed to initialize plugin: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-API-Key", "secret")
	resp := httptest.NewRecorder()

	plugin.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("disabled client should not reach the next handler")
	})).ServeHTTP(resp, req)

	if resp.Code != http.StatusForbidden {
		t.Fatalf("expected disabled client 403, got %d: %s", resp.Code, resp.Body.String())
	}
}

func TestAPIKeyPluginClientInventoryRedactsSecrets(t *testing.T) {
	plugin := &APIKeyPlugin{}
	if err := plugin.Initialize(map[string]interface{}{
		"enabled": true,
		"clients": []interface{}{
			map[string]interface{}{
				"id":       "client-a",
				"name":     "Client A",
				"key_hash": credentials.APIKeyHash("secret"),
				"enabled":  false,
				"group":    "billing",
				"scopes":   []interface{}{"read", "write"},
				"tags":     []interface{}{"gold"},
			},
		},
	}); err != nil {
		t.Fatalf("failed to initialize plugin: %v", err)
	}

	clients := plugin.ListClientInventory()
	if len(clients) != 1 {
		t.Fatalf("expected one inventory record, got %+v", clients)
	}
	client := clients[0]
	if client.KeyFingerprint != credentials.APIKeyFingerprint("secret") || !client.KeyRedacted {
		t.Fatalf("expected redacted key metadata, got %+v", client)
	}
	if client.Enabled {
		t.Fatalf("expected disabled status in inventory, got %+v", client)
	}
	if client.Group != "billing" || len(client.Scopes) != 2 || client.Scopes[1] != "write" || len(client.Tags) != 1 || client.Tags[0] != "gold" {
		t.Fatalf("expected client profile metadata in inventory, got %+v", client)
	}
	if client.Identity == nil || client.Identity.Kind != "client" || client.Identity.Source != "apikey" || client.Identity.Value != "client-a" || client.Identity.Sensitive {
		t.Fatalf("expected stable principal identity in inventory, got %+v", client.Identity)
	}
}

func TestAPIKeyPluginFindClientInventoryAcceptsKeyOrFingerprint(t *testing.T) {
	plugin := &APIKeyPlugin{}
	if err := plugin.Initialize(map[string]interface{}{
		"enabled": true,
		"clients": []interface{}{
			map[string]interface{}{
				"id":       "client-a",
				"name":     "Client A",
				"key_hash": credentials.APIKeyHash("secret"),
			},
		},
	}); err != nil {
		t.Fatalf("failed to initialize plugin: %v", err)
	}

	byKey, ok := plugin.FindClientInventory("secret")
	if !ok {
		t.Fatalf("expected client inventory lookup by raw key to match")
	}
	if byKey.ID != "client-a" || byKey.KeyFingerprint != credentials.APIKeyFingerprint("secret") || !byKey.KeyRedacted {
		t.Fatalf("expected redacted client lookup by key, got %+v", byKey)
	}

	byFingerprint, ok := plugin.FindClientInventory(credentials.APIKeyFingerprint("secret"))
	if !ok {
		t.Fatalf("expected client inventory lookup by fingerprint to match")
	}
	if byFingerprint.ID != byKey.ID || byFingerprint.KeyFingerprint != byKey.KeyFingerprint || byFingerprint.KeyRedacted != byKey.KeyRedacted {
		t.Fatalf("expected fingerprint lookup to match key lookup, got %+v vs %+v", byFingerprint, byKey)
	}
}

func TestAPIKeyPluginRecordsSuccessfulClientUsageInInventory(t *testing.T) {
	plugin := &APIKeyPlugin{}
	if err := plugin.Initialize(map[string]interface{}{
		"enabled": true,
		"clients": []interface{}{
			map[string]interface{}{
				"id":       "client-a",
				"name":     "Client A",
				"key_hash": credentials.APIKeyHash("secret"),
			},
		},
	}); err != nil {
		t.Fatalf("failed to initialize plugin: %v", err)
	}

	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("X-API-Key", "secret")
		resp := httptest.NewRecorder()
		plugin.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		})).ServeHTTP(resp, req)
		if resp.Code != http.StatusNoContent {
			t.Fatalf("expected request %d to pass, got %d: %s", i+1, resp.Code, resp.Body.String())
		}
	}

	client, ok := plugin.FindClientInventory(credentials.APIKeyFingerprint("secret"))
	if !ok {
		t.Fatalf("expected client inventory lookup to match after usage")
	}
	if client.RequestCount != 2 {
		t.Fatalf("expected request count 2, got %+v", client)
	}
	if client.LastUsedAt == nil || client.LastUsedAt.IsZero() {
		t.Fatalf("expected last used timestamp after successful auth, got %+v", client)
	}
}

func TestAPIKeyPluginNotifiesUsageObserversAfterSuccessfulClientUsage(t *testing.T) {
	plugin := &APIKeyPlugin{}
	observer := &recordingAPIKeyUsageObserver{}
	plugin.RegisterClientUsageObserver(observer)
	if err := plugin.Initialize(map[string]interface{}{
		"enabled": true,
		"clients": []interface{}{
			map[string]interface{}{
				"id":       "client-a",
				"name":     "Client A",
				"key_hash": credentials.APIKeyHash("secret"),
				"group":    "billing",
				"scopes":   []interface{}{"read", "write"},
				"tags":     []interface{}{"gold"},
			},
		},
	}); err != nil {
		t.Fatalf("failed to initialize plugin: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "https://api.example.test/v1/orders?token=should-not-leak", nil)
	req = req.WithContext(requestcontext.WithAttribution(req.Context(), requestcontext.Attribution{
		RequestID:   "req-123",
		TenantRealm: "tenant-a",
		ServiceName: "orders",
		RouteName:   "list-orders",
		RoutePath:   "/v1/orders",
	}))
	req.Header.Set("X-API-Key", "secret")
	resp := httptest.NewRecorder()
	plugin.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte("accepted"))
	})).ServeHTTP(resp, req)

	if resp.Code != http.StatusAccepted {
		t.Fatalf("expected request to pass, got %d: %s", resp.Code, resp.Body.String())
	}
	if len(observer.events) != 1 {
		t.Fatalf("expected one usage event, got %+v", observer.events)
	}
	event := observer.events[0]
	if event.Provider != "apikey" || event.ClientID != "client-a" || event.Name != "Client A" {
		t.Fatalf("unexpected usage event identity fields: %+v", event)
	}
	if err := event.Validate(); err != nil {
		t.Fatalf("expected emitted usage event to validate: %v", err)
	}
	if event.Identity == nil || event.Identity.Kind != authcontext.PrincipalIdentityClient || event.Identity.Source != "apikey" || event.Identity.Value != "client-a" || event.Identity.Sensitive {
		t.Fatalf("expected stable API-key identity in usage event, got %+v", event.Identity)
	}
	if event.KeyFingerprint != credentials.APIKeyFingerprint("secret") {
		t.Fatalf("expected fingerprint-only key attribution, got %+v", event)
	}
	if event.Group != "billing" || !reflect.DeepEqual(event.Scopes, []string{"read", "write"}) || !reflect.DeepEqual(event.Tags, []string{"gold"}) {
		t.Fatalf("expected client profile metadata in usage event, got %+v", event)
	}
	if event.RequestCount != 1 || event.OccurredAt.IsZero() {
		t.Fatalf("expected cumulative usage counters in event, got %+v", event)
	}
	if event.SchemaVersion != pluginpkg.ClientUsageEventSchemaVersion || event.EventID == "" || event.Quantity != 1 {
		t.Fatalf("expected idempotent unit metering fields in event, got %+v", event)
	}
	if event.RequestMethod != http.MethodGet || event.RequestPath != "/v1/orders" {
		t.Fatalf("expected query-redacted request coordinates, got %+v", event)
	}
	if event.ResponseStatus != http.StatusAccepted || event.ResponseBytes != int64(len("accepted")) || event.DurationMillis <= 0 {
		t.Fatalf("expected completed response outcome in usage event, got %+v", event)
	}
	if event.RequestID != "req-123" ||
		event.RequestHost != "api.example.test" ||
		event.RequestScheme != "https" ||
		event.TenantRealm != "tenant-a" ||
		event.ServiceName != "orders" ||
		event.RouteName != "list-orders" ||
		event.RoutePath != "/v1/orders" {
		t.Fatalf("expected request attribution in usage event, got %+v", event)
	}
	if event.Dimensions[pluginpkg.ClientUsageDimensionSchemaVersion] != pluginpkg.ClientUsageEventSchemaVersion ||
		event.Dimensions[pluginpkg.ClientUsageDimensionProvider] != "apikey" ||
		event.Dimensions[pluginpkg.ClientUsageDimensionEventID] != event.EventID ||
		event.Dimensions[pluginpkg.ClientUsageDimensionQuantity] != "1" ||
		event.Dimensions[pluginpkg.ClientUsageDimensionClientID] != "client-a" ||
		event.Dimensions[pluginpkg.ClientUsageDimensionClientGroup] != "billing" ||
		event.Dimensions[pluginpkg.ClientUsageDimensionClientScopes] != "read,write" ||
		event.Dimensions[pluginpkg.ClientUsageDimensionClientTags] != "gold" ||
		event.Dimensions[pluginpkg.ClientUsageDimensionRequestID] != "req-123" ||
		event.Dimensions[pluginpkg.ClientUsageDimensionRequestHost] != "api.example.test" ||
		event.Dimensions[pluginpkg.ClientUsageDimensionResponseStatus] != "202" ||
		event.Dimensions[pluginpkg.ClientUsageDimensionResponseClass] != "2xx" ||
		event.Dimensions[pluginpkg.ClientUsageDimensionResponseBytes] != "8" ||
		event.Dimensions[pluginpkg.ClientUsageDimensionTenantRealm] != "tenant-a" ||
		event.Dimensions[pluginpkg.ClientUsageDimensionServiceName] != "orders" ||
		event.Dimensions[pluginpkg.ClientUsageDimensionRouteName] != "list-orders" ||
		event.Dimensions[pluginpkg.ClientUsageDimensionRoutePath] != "/v1/orders" {
		t.Fatalf("expected normalized billing dimensions in usage event, got %+v", event.Dimensions)
	}
	if len(observer.contextIdentities) != 1 || observer.contextIdentities[0].Kind != authcontext.PrincipalIdentityClient || observer.contextIdentities[0].Value != "client-a" {
		t.Fatalf("expected observer context to include principal identity, got %+v", observer.contextIdentities)
	}
}

func TestAPIKeyPluginUsageObserverPanicDoesNotBlockRequestOrOtherObservers(t *testing.T) {
	plugin := &APIKeyPlugin{}
	plugin.RegisterClientUsageObserver(&panickingAPIKeyUsageObserver{})
	observer := &recordingAPIKeyUsageObserver{}
	plugin.RegisterClientUsageObserver(observer)
	if err := plugin.Initialize(map[string]interface{}{
		"enabled": true,
		"clients": []interface{}{
			map[string]interface{}{
				"id":       "client-a",
				"name":     "Client A",
				"key_hash": credentials.APIKeyHash("secret"),
			},
		},
	}); err != nil {
		t.Fatalf("failed to initialize plugin: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/orders", nil)
	req.Header.Set("X-API-Key", "secret")
	resp := httptest.NewRecorder()
	plugin.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(resp, req)

	if resp.Code != http.StatusNoContent {
		t.Fatalf("expected panicking observer to be isolated, got %d: %s", resp.Code, resp.Body.String())
	}
	if len(observer.events) != 1 || observer.events[0].ClientID != "client-a" {
		t.Fatalf("expected healthy observer to still receive usage event, got %+v", observer.events)
	}
}

func TestAPIKeyPluginNotifiesUsageObserverWhenDownstreamPanics(t *testing.T) {
	plugin := &APIKeyPlugin{}
	observer := &recordingAPIKeyUsageObserver{}
	plugin.RegisterClientUsageObserver(observer)
	if err := plugin.Initialize(map[string]interface{}{
		"enabled": true,
		"clients": []interface{}{
			map[string]interface{}{
				"id":       "client-a",
				"name":     "Client A",
				"key_hash": credentials.APIKeyHash("secret"),
			},
		},
	}); err != nil {
		t.Fatalf("failed to initialize plugin: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/orders", nil)
	req.Header.Set("X-API-Key", "secret")
	resp := httptest.NewRecorder()

	panicked := false
	func() {
		defer func() {
			panicked = recover() != nil
		}()
		plugin.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			panic("downstream failed")
		})).ServeHTTP(resp, req)
	}()

	if !panicked {
		t.Fatalf("expected downstream panic to be rethrown")
	}
	if len(observer.events) != 1 {
		t.Fatalf("expected one panic usage event, got %+v", observer.events)
	}
	event := observer.events[0]
	if event.ResponseStatus != http.StatusInternalServerError ||
		event.Dimensions[pluginpkg.ClientUsageDimensionResponseStatus] != "500" ||
		event.Dimensions[pluginpkg.ClientUsageDimensionResponseClass] != "5xx" {
		t.Fatalf("expected panic usage event to record 500 outcome, got %+v", event)
	}
}

func TestAPIKeyPluginUsageObserverMutationDoesNotLeakToOtherObservers(t *testing.T) {
	plugin := &APIKeyPlugin{}
	plugin.RegisterClientUsageObserver(&mutatingAPIKeyUsageObserver{})
	observer := &recordingAPIKeyUsageObserver{}
	plugin.RegisterClientUsageObserver(observer)
	if err := plugin.Initialize(map[string]interface{}{
		"enabled": true,
		"clients": []interface{}{
			map[string]interface{}{
				"id":       "client-a",
				"name":     "Client A",
				"key_hash": credentials.APIKeyHash("secret"),
				"group":    "billing",
				"scopes":   []interface{}{"read", "write"},
				"tags":     []interface{}{"gold"},
			},
		},
	}); err != nil {
		t.Fatalf("failed to initialize plugin: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/orders", nil)
	req.Header.Set("X-API-Key", "secret")
	resp := httptest.NewRecorder()
	plugin.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(resp, req)

	if resp.Code != http.StatusNoContent {
		t.Fatalf("expected request to pass, got %d: %s", resp.Code, resp.Body.String())
	}
	if len(observer.events) != 1 {
		t.Fatalf("expected healthy observer to receive usage event, got %+v", observer.events)
	}
	event := observer.events[0]
	if event.Identity == nil || event.Identity.Value != "client-a" {
		t.Fatalf("expected observer identity to stay isolated, got %+v", event.Identity)
	}
	if !reflect.DeepEqual(event.Scopes, []string{"read", "write"}) || !reflect.DeepEqual(event.Tags, []string{"gold"}) {
		t.Fatalf("expected observer slices to stay isolated, got scopes=%+v tags=%+v", event.Scopes, event.Tags)
	}
	if event.Dimensions[pluginpkg.ClientUsageDimensionClientID] != "client-a" ||
		event.Dimensions[pluginpkg.ClientUsageDimensionTenantRealm] == "mutated-tenant" {
		t.Fatalf("expected observer dimensions to stay isolated, got %+v", event.Dimensions)
	}
}

func TestAPIKeyPluginUsageObserverTimeoutDoesNotHangRequest(t *testing.T) {
	plugin := &APIKeyPlugin{}
	observer := newBlockingAPIKeyUsageObserver()
	plugin.RegisterClientUsageObserver(observer)
	if err := plugin.Initialize(map[string]interface{}{
		"enabled": true,
		"clients": []interface{}{
			map[string]interface{}{
				"id":       "client-a",
				"name":     "Client A",
				"key_hash": credentials.APIKeyHash("secret"),
			},
		},
	}); err != nil {
		t.Fatalf("failed to initialize plugin: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/orders", nil)
	req.Header.Set("X-API-Key", "secret")
	resp := httptest.NewRecorder()
	startedAt := time.Now()
	plugin.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(resp, req)
	elapsed := time.Since(startedAt)

	if resp.Code != http.StatusNoContent {
		t.Fatalf("expected timeout-bounded observer to be isolated, got %d: %s", resp.Code, resp.Body.String())
	}
	if elapsed > clientUsageObserverTimeout+500*time.Millisecond {
		t.Fatalf("expected observer timeout to bound request latency, took %s", elapsed)
	}
	select {
	case deadlineSeen := <-observer.deadlineSeen:
		if !deadlineSeen {
			t.Fatalf("expected observer context to include a deadline")
		}
	case <-time.After(time.Second):
		t.Fatalf("expected blocking observer to be invoked")
	}
	select {
	case <-observer.completed:
	case <-time.After(time.Second):
		t.Fatalf("expected blocking observer to stop when its context is canceled")
	}
}

func TestAPIKeyPluginUsageObserverTimeoutsRunConcurrently(t *testing.T) {
	plugin := &APIKeyPlugin{}
	observers := []*blockingAPIKeyUsageObserver{
		newNamedBlockingAPIKeyUsageObserver("test.blocking_usage_1"),
		newNamedBlockingAPIKeyUsageObserver("test.blocking_usage_2"),
		newNamedBlockingAPIKeyUsageObserver("test.blocking_usage_3"),
		newNamedBlockingAPIKeyUsageObserver("test.blocking_usage_4"),
		newNamedBlockingAPIKeyUsageObserver("test.blocking_usage_5"),
	}
	for _, observer := range observers {
		plugin.RegisterClientUsageObserver(observer)
	}
	if err := plugin.Initialize(map[string]interface{}{
		"enabled": true,
		"clients": []interface{}{
			map[string]interface{}{
				"id":       "client-a",
				"name":     "Client A",
				"key_hash": credentials.APIKeyHash("secret"),
			},
		},
	}); err != nil {
		t.Fatalf("failed to initialize plugin: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/orders", nil)
	req.Header.Set("X-API-Key", "secret")
	resp := httptest.NewRecorder()
	startedAt := time.Now()
	plugin.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(resp, req)
	elapsed := time.Since(startedAt)

	if resp.Code != http.StatusNoContent {
		t.Fatalf("expected timeout-bounded observers to be isolated, got %d: %s", resp.Code, resp.Body.String())
	}
	if elapsed > 3*clientUsageObserverTimeout+100*time.Millisecond {
		t.Fatalf("expected observer timeouts to run concurrently, took %s", elapsed)
	}
	for _, observer := range observers {
		select {
		case <-observer.completed:
		case <-time.After(time.Second):
			t.Fatalf("expected observer %s to stop when context is canceled", observer.name)
		}
	}
}

func TestAPIKeyPluginAsyncUsageObserverDoesNotBlockRequest(t *testing.T) {
	plugin := &APIKeyPlugin{}
	observer := newBlockingAPIKeyUsageObserver()
	plugin.RegisterClientUsageObserver(observer)
	if err := plugin.Initialize(map[string]interface{}{
		"enabled":                true,
		"usage_observer_async":   true,
		"usage_observer_timeout": "500ms",
		"clients": []interface{}{
			map[string]interface{}{
				"id":       "client-a",
				"name":     "Client A",
				"key_hash": credentials.APIKeyHash("secret"),
			},
		},
	}); err != nil {
		t.Fatalf("failed to initialize plugin: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/orders", nil)
	req.Header.Set("X-API-Key", "secret")
	resp := httptest.NewRecorder()
	startedAt := time.Now()
	plugin.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(resp, req)
	elapsed := time.Since(startedAt)

	if resp.Code != http.StatusNoContent {
		t.Fatalf("expected async observer request to pass, got %d: %s", resp.Code, resp.Body.String())
	}
	if elapsed > 250*time.Millisecond {
		t.Fatalf("expected async observer not to add observer timeout latency, took %s", elapsed)
	}
	select {
	case deadlineSeen := <-observer.deadlineSeen:
		if !deadlineSeen {
			t.Fatalf("expected async observer context to include a deadline")
		}
	case <-time.After(time.Second):
		t.Fatalf("expected async observer to be invoked")
	}
	select {
	case <-observer.completed:
	case <-time.After(time.Second):
		t.Fatalf("expected async blocking observer to stop when its context is canceled")
	}
}

func TestAPIKeyPluginAsyncUsageObserverKeepsDetachedContextIdentity(t *testing.T) {
	plugin := &APIKeyPlugin{}
	observer := newChannelAPIKeyUsageObserver()
	plugin.RegisterClientUsageObserver(observer)
	if err := plugin.Initialize(map[string]interface{}{
		"enabled":              true,
		"usage_observer_async": true,
		"clients": []interface{}{
			map[string]interface{}{
				"id":       "client-a",
				"name":     "Client A",
				"key_hash": credentials.APIKeyHash("secret"),
			},
		},
	}); err != nil {
		t.Fatalf("failed to initialize plugin: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/orders", nil)
	req.Header.Set("X-API-Key", "secret")
	resp := httptest.NewRecorder()
	plugin.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(resp, req)

	if resp.Code != http.StatusNoContent {
		t.Fatalf("expected async observer request to pass, got %d: %s", resp.Code, resp.Body.String())
	}
	select {
	case event := <-observer.events:
		if event.ClientID != "client-a" {
			t.Fatalf("expected async usage event to preserve client identity, got %+v", event)
		}
	case <-time.After(time.Second):
		t.Fatalf("expected async usage event to be delivered")
	}
	select {
	case identity := <-observer.contextIdentities:
		if identity.Kind != authcontext.PrincipalIdentityClient || identity.Source != "apikey" || identity.Value != "client-a" {
			t.Fatalf("expected async observer context identity to be detached from request cancellation, got %+v", identity)
		}
	case <-time.After(time.Second):
		t.Fatalf("expected async observer context identity to be delivered")
	}
}

func TestAPIKeyPluginAsyncUsageObserverDropsWhenMaxInFlightReached(t *testing.T) {
	plugin := &APIKeyPlugin{}
	observer := newBlockingAPIKeyUsageObserver()
	plugin.RegisterClientUsageObserver(observer)
	if err := plugin.Initialize(map[string]interface{}{
		"enabled":                            true,
		"usage_observer_async":               true,
		"usage_observer_timeout":             "500ms",
		"usage_observer_async_max_in_flight": 1,
		"clients": []interface{}{
			map[string]interface{}{
				"id":       "client-a",
				"name":     "Client A",
				"key_hash": credentials.APIKeyHash("secret"),
			},
		},
	}); err != nil {
		t.Fatalf("failed to initialize plugin: %v", err)
	}

	assertAPIKeyPluginRequestStatus(t, plugin, "secret", http.StatusNoContent)
	select {
	case <-observer.deadlineSeen:
	case <-time.After(time.Second):
		t.Fatalf("expected first async usage observer to be invoked")
	}

	assertAPIKeyPluginRequestStatus(t, plugin, "secret", http.StatusNoContent)
	if dropped := plugin.usageObserverAsyncDropped.Load(); dropped != 1 {
		t.Fatalf("expected saturated async usage observer to drop one event, got %d", dropped)
	}
	diagnostics := plugin.Diagnostics()
	usageObservers, ok := diagnostics["usage_observers"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected usage observer diagnostics, got %+v", diagnostics)
	}
	if diagnostics["status"] != "degraded" ||
		usageObservers["status"] != "degraded" ||
		!reflect.DeepEqual(usageObservers["warning_codes"], []string{"async_deliveries_dropped"}) {
		t.Fatalf("expected degraded async observer diagnostics after drop, got %+v", diagnostics)
	}

	select {
	case <-observer.completed:
	case <-time.After(time.Second):
		t.Fatalf("expected blocking observer to stop when timeout expires")
	}
}

func TestAPIKeyPluginStatusReportsUsageObserverDeliveryMode(t *testing.T) {
	plugin := &APIKeyPlugin{}
	plugin.RegisterClientUsageObserver(&recordingAPIKeyUsageObserver{})
	if err := plugin.Initialize(map[string]interface{}{
		"enabled":                            true,
		"usage_observer_async":               true,
		"usage_observer_timeout":             "250ms",
		"usage_observer_async_max_in_flight": 7,
		"clients": []interface{}{
			map[string]interface{}{
				"id":       "client-a",
				"name":     "Client A",
				"key_hash": credentials.APIKeyHash("secret"),
			},
		},
	}); err != nil {
		t.Fatalf("failed to initialize plugin: %v", err)
	}

	status := plugin.Status()
	for _, want := range []string{
		"1 clients configured",
		"1 usage observers",
		"observer mode: async",
		"max in-flight: 7",
		"observer timeout: 250ms",
	} {
		if !strings.Contains(status, want) {
			t.Fatalf("expected status %q to contain %q", status, want)
		}
	}
}

func TestAPIKeyPluginDiagnosticsReportsUsageObserverState(t *testing.T) {
	plugin := &APIKeyPlugin{}
	plugin.RegisterClientUsageObserver(&recordingAPIKeyUsageObserver{})
	plugin.RegisterClientUsageObserver(&unnamedAPIKeyUsageObserver{})
	if err := plugin.Initialize(map[string]interface{}{
		"enabled":                            true,
		"usage_observer_async":               true,
		"usage_observer_timeout":             "250ms",
		"usage_observer_async_max_in_flight": 7,
		"clients": []interface{}{
			map[string]interface{}{
				"id":       "client-a",
				"name":     "Client A",
				"key_hash": credentials.APIKeyHash("secret"),
			},
		},
	}); err != nil {
		t.Fatalf("failed to initialize plugin: %v", err)
	}

	diagnostics := plugin.Diagnostics()
	clients, ok := diagnostics["clients"].(map[string]interface{})
	if !ok || clients["configured"] != 1 {
		t.Fatalf("expected diagnostics client count, got %+v", diagnostics)
	}
	usageObservers, ok := diagnostics["usage_observers"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected usage observer diagnostics, got %+v", diagnostics)
	}
	if diagnostics["status"] != "warning" ||
		!reflect.DeepEqual(diagnostics["warning_codes"], []string{"unnamed_observers_registered"}) ||
		usageObservers["status"] != "warning" ||
		!reflect.DeepEqual(usageObservers["warning_codes"], []string{"unnamed_observers_registered"}) ||
		usageObservers["registered"] != 2 ||
		usageObservers["named"] != 1 ||
		usageObservers["unnamed"] != 1 ||
		!reflect.DeepEqual(usageObservers["names"], []string{"test.apikey_usage"}) ||
		usageObservers["delivery_mode"] != "async" ||
		usageObservers["timeout"] != "250ms" ||
		usageObservers["async_max_in_flight"] != 7 ||
		usageObservers["async_in_flight"] != 0 ||
		usageObservers["async_dropped"] != int64(0) {
		t.Fatalf("unexpected usage observer diagnostics: %+v", usageObservers)
	}
}

func TestAPIKeyPluginPreservesUsageTelemetryAcrossReload(t *testing.T) {
	plugin := &APIKeyPlugin{}
	if err := plugin.Initialize(map[string]interface{}{
		"enabled": true,
		"clients": []interface{}{
			map[string]interface{}{
				"id":       "client-a",
				"name":     "Client A",
				"key_hash": credentials.APIKeyHash("secret"),
				"group":    "ops",
			},
		},
	}); err != nil {
		t.Fatalf("failed to initialize plugin: %v", err)
	}
	assertAPIKeyPluginRequestStatus(t, plugin, "secret", http.StatusNoContent)

	if err := plugin.Initialize(map[string]interface{}{
		"enabled": true,
		"clients": []interface{}{
			map[string]interface{}{
				"id":       "client-a",
				"name":     "Client A Prime",
				"key_hash": credentials.APIKeyHash("secret"),
				"group":    "billing",
			},
		},
	}); err != nil {
		t.Fatalf("failed to reinitialize plugin: %v", err)
	}

	client, ok := plugin.FindClientInventory("secret")
	if !ok {
		t.Fatalf("expected client inventory lookup after reload")
	}
	if client.RequestCount != 1 || client.LastUsedAt == nil {
		t.Fatalf("expected usage telemetry to survive reload, got %+v", client)
	}
	if client.Group != "billing" {
		t.Fatalf("expected profile update after reload, got %+v", client)
	}
}

func TestAPIKeyPluginPreservesUsageTelemetryAcrossRotationReload(t *testing.T) {
	plugin := &APIKeyPlugin{}
	if err := plugin.Initialize(map[string]interface{}{
		"enabled": true,
		"clients": []interface{}{
			map[string]interface{}{
				"id":       "client-a",
				"name":     "Client A",
				"key_hash": credentials.APIKeyHash("secret"),
			},
		},
	}); err != nil {
		t.Fatalf("failed to initialize plugin: %v", err)
	}
	assertAPIKeyPluginRequestStatus(t, plugin, "secret", http.StatusNoContent)

	if err := plugin.Initialize(map[string]interface{}{
		"enabled": true,
		"clients": []interface{}{
			map[string]interface{}{
				"id":       "client-a",
				"name":     "Client A",
				"key_hash": credentials.APIKeyHash("rotated-secret"),
			},
		},
	}); err != nil {
		t.Fatalf("failed to reinitialize rotated plugin: %v", err)
	}

	client, ok := plugin.FindClientInventory("rotated-secret")
	if !ok {
		t.Fatalf("expected rotated client inventory lookup after reload")
	}
	if client.RequestCount != 1 || client.LastUsedAt == nil {
		t.Fatalf("expected usage telemetry to survive rotation reload, got %+v", client)
	}
}

func TestAPIKeyPluginDropsUsageTelemetryAfterRemovalReload(t *testing.T) {
	plugin := &APIKeyPlugin{}
	if err := plugin.Initialize(map[string]interface{}{
		"enabled": true,
		"clients": []interface{}{
			map[string]interface{}{
				"id":       "client-a",
				"name":     "Client A",
				"key_hash": credentials.APIKeyHash("secret"),
			},
		},
	}); err != nil {
		t.Fatalf("failed to initialize plugin: %v", err)
	}
	assertAPIKeyPluginRequestStatus(t, plugin, "secret", http.StatusNoContent)

	if err := plugin.Initialize(map[string]interface{}{
		"enabled": true,
		"clients": []interface{}{},
	}); err != nil {
		t.Fatalf("failed to reinitialize plugin without clients: %v", err)
	}
	if err := plugin.Initialize(map[string]interface{}{
		"enabled": true,
		"clients": []interface{}{
			map[string]interface{}{
				"id":       "client-a",
				"name":     "Client A",
				"key_hash": credentials.APIKeyHash("new-secret"),
			},
		},
	}); err != nil {
		t.Fatalf("failed to reinitialize plugin with replacement client: %v", err)
	}

	client, ok := plugin.FindClientInventory("new-secret")
	if !ok {
		t.Fatalf("expected replacement client inventory lookup")
	}
	if client.RequestCount != 0 || client.LastUsedAt != nil {
		t.Fatalf("expected removed client usage telemetry to be dropped, got %+v", client)
	}
}

func TestAPIKeyPluginDoesNotRecordRejectedClientUsage(t *testing.T) {
	plugin := &APIKeyPlugin{}
	observer := &recordingAPIKeyUsageObserver{}
	plugin.RegisterClientUsageObserver(observer)
	if err := plugin.Initialize(map[string]interface{}{
		"enabled": true,
		"clients": []interface{}{
			map[string]interface{}{
				"id":       "client-a",
				"name":     "Client A",
				"key_hash": credentials.APIKeyHash("secret"),
				"enabled":  false,
			},
		},
	}); err != nil {
		t.Fatalf("failed to initialize plugin: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-API-Key", "secret")
	resp := httptest.NewRecorder()
	plugin.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("disabled client should not reach the next handler")
	})).ServeHTTP(resp, req)
	if resp.Code != http.StatusForbidden {
		t.Fatalf("expected disabled client 403, got %d: %s", resp.Code, resp.Body.String())
	}

	client, ok := plugin.FindClientInventory(credentials.APIKeyFingerprint("secret"))
	if !ok {
		t.Fatalf("expected client inventory lookup to match rejected client")
	}
	if client.RequestCount != 0 || client.LastUsedAt != nil {
		t.Fatalf("expected rejected usage to stay uncounted, got %+v", client)
	}
	if len(observer.events) != 0 {
		t.Fatalf("expected rejected client to skip usage observers, got %+v", observer.events)
	}
}

func TestAPIKeyPluginListClientsRedactsLegacySnapshots(t *testing.T) {
	plugin := &APIKeyPlugin{}
	if err := plugin.Initialize(map[string]interface{}{
		"enabled": true,
		"clients": []interface{}{
			map[string]interface{}{
				"id":       "client-a",
				"name":     "Client A",
				"key_hash": credentials.APIKeyHash("secret"),
			},
		},
	}); err != nil {
		t.Fatalf("failed to initialize plugin: %v", err)
	}

	clients := plugin.ListClients()
	if len(clients) != 1 {
		t.Fatalf("expected one client snapshot, got %+v", clients)
	}
	client := clients[0]
	if client.Key != "" || client.KeyHash != "" {
		t.Fatalf("expected legacy client snapshot to redact secrets, got %+v", client)
	}
	if client.KeyFingerprint != credentials.APIKeyFingerprint("secret") {
		t.Fatalf("expected legacy client snapshot fingerprint, got %+v", client)
	}
}

func assertAPIKeyPluginRequestStatus(t *testing.T, plugin *APIKeyPlugin, key string, expectedStatus int) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-API-Key", key)
	resp := httptest.NewRecorder()
	plugin.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(resp, req)
	if resp.Code != expectedStatus {
		t.Fatalf("expected API key request status %d, got %d: %s", expectedStatus, resp.Code, resp.Body.String())
	}
}

type recordingAPIKeyUsageObserver struct {
	events            []pluginpkg.ClientUsageEvent
	contextIdentities []authcontext.PrincipalIdentity
}

func (o *recordingAPIKeyUsageObserver) Name() string {
	return "test.apikey_usage"
}

func (o *recordingAPIKeyUsageObserver) Initialize(map[string]interface{}) error {
	return nil
}

func (o *recordingAPIKeyUsageObserver) ObserveClientUsage(ctx context.Context, event pluginpkg.ClientUsageEvent) {
	o.events = append(o.events, event)
	if identity, ok := authcontext.PrincipalIdentityFromContext(ctx); ok {
		o.contextIdentities = append(o.contextIdentities, identity)
	}
}

type unnamedAPIKeyUsageObserver struct{}

func (o *unnamedAPIKeyUsageObserver) Name() string {
	return ""
}

func (o *unnamedAPIKeyUsageObserver) Initialize(map[string]interface{}) error {
	return nil
}

func (o *unnamedAPIKeyUsageObserver) ObserveClientUsage(context.Context, pluginpkg.ClientUsageEvent) {
}

type channelAPIKeyUsageObserver struct {
	events            chan pluginpkg.ClientUsageEvent
	contextIdentities chan authcontext.PrincipalIdentity
}

func newChannelAPIKeyUsageObserver() *channelAPIKeyUsageObserver {
	return &channelAPIKeyUsageObserver{
		events:            make(chan pluginpkg.ClientUsageEvent, 1),
		contextIdentities: make(chan authcontext.PrincipalIdentity, 1),
	}
}

func (o *channelAPIKeyUsageObserver) Name() string {
	return "test.channel_apikey_usage"
}

func (o *channelAPIKeyUsageObserver) Initialize(map[string]interface{}) error {
	return nil
}

func (o *channelAPIKeyUsageObserver) ObserveClientUsage(ctx context.Context, event pluginpkg.ClientUsageEvent) {
	o.events <- event
	identity, _ := authcontext.PrincipalIdentityFromContext(ctx)
	o.contextIdentities <- identity
}

type panickingAPIKeyUsageObserver struct{}

func (o *panickingAPIKeyUsageObserver) Name() string {
	return "test.panicking_apikey_usage"
}

func (o *panickingAPIKeyUsageObserver) Initialize(map[string]interface{}) error {
	return nil
}

func (o *panickingAPIKeyUsageObserver) ObserveClientUsage(context.Context, pluginpkg.ClientUsageEvent) {
	panic("usage observer failed")
}

type mutatingAPIKeyUsageObserver struct{}

func (o *mutatingAPIKeyUsageObserver) Name() string {
	return "test.mutating_apikey_usage"
}

func (o *mutatingAPIKeyUsageObserver) Initialize(map[string]interface{}) error {
	return nil
}

func (o *mutatingAPIKeyUsageObserver) ObserveClientUsage(_ context.Context, event pluginpkg.ClientUsageEvent) {
	if event.Identity != nil {
		event.Identity.Value = "mutated-client"
	}
	if len(event.Scopes) > 0 {
		event.Scopes[0] = "mutated:scope"
	}
	if len(event.Tags) > 0 {
		event.Tags[0] = "mutated-tag"
	}
	if event.Dimensions != nil {
		event.Dimensions[pluginpkg.ClientUsageDimensionTenantRealm] = "mutated-tenant"
	}
}

type blockingAPIKeyUsageObserver struct {
	name         string
	deadlineSeen chan bool
	completed    chan struct{}
}

func newBlockingAPIKeyUsageObserver() *blockingAPIKeyUsageObserver {
	return newNamedBlockingAPIKeyUsageObserver("test.blocking_apikey_usage")
}

func newNamedBlockingAPIKeyUsageObserver(name string) *blockingAPIKeyUsageObserver {
	return &blockingAPIKeyUsageObserver{
		name:         name,
		deadlineSeen: make(chan bool, 1),
		completed:    make(chan struct{}),
	}
}

func (o *blockingAPIKeyUsageObserver) Name() string {
	return o.name
}

func (o *blockingAPIKeyUsageObserver) Initialize(map[string]interface{}) error {
	return nil
}

func (o *blockingAPIKeyUsageObserver) ObserveClientUsage(ctx context.Context, _ pluginpkg.ClientUsageEvent) {
	_, hasDeadline := ctx.Deadline()
	o.deadlineSeen <- hasDeadline
	<-ctx.Done()
	close(o.completed)
}
