package api

import (
	"context"
	"strings"

	"github.com/bhangun/iket/pkg/core/authcontext"
	"github.com/bhangun/iket/pkg/core/credentials"
	coreerrors "github.com/bhangun/iket/pkg/core/errors"
	"github.com/bhangun/iket/pkg/plugin"
)

const (
	ClientLifecycleOperationAdd     = "client_add"
	ClientLifecycleOperationEnable  = "client_enable"
	ClientLifecycleOperationDisable = "client_disable"
	ClientLifecycleOperationRemove  = "client_remove"
	ClientLifecycleOperationRotate  = "client_rotate"
	ClientLifecycleOperationUpdate  = "client_update"
)

// ClientLifecycleEvent is the stable community-to-enterprise contract for API
// key client provisioning. It intentionally exposes only a key fingerprint so
// billing integrations can correlate usage without receiving the raw secret.
type ClientLifecycleEvent struct {
	Operation         string                         `json:"operation"`
	ClientID          string                         `json:"client_id,omitempty"`
	Name              string                         `json:"name,omitempty"`
	Identity          *authcontext.PrincipalIdentity `json:"identity,omitempty"`
	Group             string                         `json:"group,omitempty"`
	Scopes            []string                       `json:"scopes,omitempty"`
	Tags              []string                       `json:"tags,omitempty"`
	KeyFingerprint    string                         `json:"key_fingerprint,omitempty"`
	OldKeyFingerprint string                         `json:"old_key_fingerprint,omitempty"`
	Enabled           bool                           `json:"enabled,omitempty"`
	PreviousEnabled   bool                           `json:"previous_enabled,omitempty"`
	PreviousName      string                         `json:"previous_name,omitempty"`
	PreviousGroup     string                         `json:"previous_group,omitempty"`
	PreviousScopes    []string                       `json:"previous_scopes,omitempty"`
	PreviousTags      []string                       `json:"previous_tags,omitempty"`
	GeneratedKey      bool                           `json:"generated_key"`
	RevisionLabel     string                         `json:"revision_label,omitempty"`
	RevisionNote      string                         `json:"revision_note,omitempty"`
	ChangeRef         string                         `json:"change_ref,omitempty"`
}

// ClientLifecycleHook lets enterprise packages enforce external provisioning
// before a client key becomes active, then observe successful mutations.
type ClientLifecycleHook interface {
	BeforeClientAdd(context.Context, ClientLifecycleEvent) error
	AfterClientAdd(context.Context, ClientLifecycleEvent)
	BeforeClientStatusChange(context.Context, ClientLifecycleEvent) error
	AfterClientStatusChange(context.Context, ClientLifecycleEvent)
	BeforeClientRotate(context.Context, ClientLifecycleEvent) error
	AfterClientRotate(context.Context, ClientLifecycleEvent)
	BeforeClientRemove(context.Context, ClientLifecycleEvent) error
	AfterClientRemove(context.Context, ClientLifecycleEvent)
}

// ClientUpdateLifecycleHook is optional so older enterprise hooks can keep
// compiling while newer packages opt into profile-change provisioning.
type ClientUpdateLifecycleHook interface {
	BeforeClientUpdate(context.Context, ClientLifecycleEvent) error
	AfterClientUpdate(context.Context, ClientLifecycleEvent)
}

// ClientLifecyclePlugin is the shape iket-enterprise billing plugins can
// implement when they want plugin identity plus client provisioning hooks.
type ClientLifecyclePlugin interface {
	plugin.Plugin
	ClientLifecycleHook
}

type noopClientLifecycleHook struct{}

func (noopClientLifecycleHook) BeforeClientAdd(context.Context, ClientLifecycleEvent) error {
	return nil
}

func (noopClientLifecycleHook) AfterClientAdd(context.Context, ClientLifecycleEvent) {}

func (noopClientLifecycleHook) BeforeClientStatusChange(context.Context, ClientLifecycleEvent) error {
	return nil
}

func (noopClientLifecycleHook) AfterClientStatusChange(context.Context, ClientLifecycleEvent) {}

func (noopClientLifecycleHook) BeforeClientRotate(context.Context, ClientLifecycleEvent) error {
	return nil
}

func (noopClientLifecycleHook) AfterClientRotate(context.Context, ClientLifecycleEvent) {}

func (noopClientLifecycleHook) BeforeClientRemove(context.Context, ClientLifecycleEvent) error {
	return nil
}

func (noopClientLifecycleHook) AfterClientRemove(context.Context, ClientLifecycleEvent) {}

func (api *ManagementAPI) beforeClientAdd(ctx context.Context, event ClientLifecycleEvent) error {
	for _, hook := range api.clientLifecycleHooksOrNoop() {
		if err := hook.BeforeClientAdd(ctx, event); err != nil {
			if coreerrors.CodeOf(err) != "" {
				return err
			}
			return coreerrors.New(coreerrors.CodePluginError, "Client provisioning hook rejected client add").WithError(err)
		}
	}
	return nil
}

func (api *ManagementAPI) afterClientAdd(ctx context.Context, event ClientLifecycleEvent) {
	for _, hook := range api.clientLifecycleHooksOrNoop() {
		hook.AfterClientAdd(ctx, event)
	}
}

func (api *ManagementAPI) beforeClientStatusChange(ctx context.Context, event ClientLifecycleEvent) error {
	for _, hook := range api.clientLifecycleHooksOrNoop() {
		if err := hook.BeforeClientStatusChange(ctx, event); err != nil {
			if coreerrors.CodeOf(err) != "" {
				return err
			}
			return coreerrors.New(coreerrors.CodePluginError, "Client provisioning hook rejected client status change").WithError(err)
		}
	}
	return nil
}

func (api *ManagementAPI) afterClientStatusChange(ctx context.Context, event ClientLifecycleEvent) {
	for _, hook := range api.clientLifecycleHooksOrNoop() {
		hook.AfterClientStatusChange(ctx, event)
	}
}

func (api *ManagementAPI) beforeClientUpdate(ctx context.Context, event ClientLifecycleEvent) error {
	for _, hook := range api.clientLifecycleHooksOrNoop() {
		updateHook, ok := hook.(ClientUpdateLifecycleHook)
		if !ok {
			continue
		}
		if err := updateHook.BeforeClientUpdate(ctx, event); err != nil {
			if coreerrors.CodeOf(err) != "" {
				return err
			}
			return coreerrors.New(coreerrors.CodePluginError, "Client provisioning hook rejected client profile update").WithError(err)
		}
	}
	return nil
}

func (api *ManagementAPI) afterClientUpdate(ctx context.Context, event ClientLifecycleEvent) {
	for _, hook := range api.clientLifecycleHooksOrNoop() {
		updateHook, ok := hook.(ClientUpdateLifecycleHook)
		if ok {
			updateHook.AfterClientUpdate(ctx, event)
		}
	}
}

func (api *ManagementAPI) beforeClientRotate(ctx context.Context, event ClientLifecycleEvent) error {
	for _, hook := range api.clientLifecycleHooksOrNoop() {
		if err := hook.BeforeClientRotate(ctx, event); err != nil {
			if coreerrors.CodeOf(err) != "" {
				return err
			}
			return coreerrors.New(coreerrors.CodePluginError, "Client provisioning hook rejected client rotation").WithError(err)
		}
	}
	return nil
}

func (api *ManagementAPI) afterClientRotate(ctx context.Context, event ClientLifecycleEvent) {
	for _, hook := range api.clientLifecycleHooksOrNoop() {
		hook.AfterClientRotate(ctx, event)
	}
}

func (api *ManagementAPI) beforeClientRemove(ctx context.Context, event ClientLifecycleEvent) error {
	for _, hook := range api.clientLifecycleHooksOrNoop() {
		if err := hook.BeforeClientRemove(ctx, event); err != nil {
			if coreerrors.CodeOf(err) != "" {
				return err
			}
			return coreerrors.New(coreerrors.CodePluginError, "Client provisioning hook rejected client removal").WithError(err)
		}
	}
	return nil
}

func (api *ManagementAPI) afterClientRemove(ctx context.Context, event ClientLifecycleEvent) {
	for _, hook := range api.clientLifecycleHooksOrNoop() {
		hook.AfterClientRemove(ctx, event)
	}
}

func (api *ManagementAPI) clientLifecycleHooksOrNoop() []ClientLifecycleHook {
	if api == nil || len(api.clientLifecycleHooks) == 0 {
		return []ClientLifecycleHook{noopClientLifecycleHook{}}
	}
	return api.clientLifecycleHooks
}

func clientAddLifecycleEvent(client managementClientRequest, generated bool, label, note, changeRef string) ClientLifecycleEvent {
	return withClientLifecycleIdentity(ClientLifecycleEvent{
		Operation:      ClientLifecycleOperationAdd,
		ClientID:       strings.TrimSpace(client.ID),
		Name:           strings.TrimSpace(client.Name),
		Group:          strings.TrimSpace(client.Group),
		Scopes:         trimmedStringSlice(client.Scopes),
		Tags:           trimmedStringSlice(client.Tags),
		KeyFingerprint: apiKeyFingerprint(client.Key),
		GeneratedKey:   generated,
		RevisionLabel:  strings.TrimSpace(label),
		RevisionNote:   strings.TrimSpace(note),
		ChangeRef:      strings.TrimSpace(changeRef),
	})
}

func clientRemoveLifecycleEvent(summary map[string]interface{}, label, note, changeRef string) ClientLifecycleEvent {
	return withClientLifecycleIdentity(ClientLifecycleEvent{
		Operation:      ClientLifecycleOperationRemove,
		ClientID:       stringValue(summary["client_id"]),
		Name:           stringValue(summary["name"]),
		Group:          stringValue(summary["group"]),
		Scopes:         stringSliceValue(summary["scopes"]),
		Tags:           stringSliceValue(summary["tags"]),
		KeyFingerprint: stringValue(summary["key_fingerprint"]),
		RevisionLabel:  strings.TrimSpace(label),
		RevisionNote:   strings.TrimSpace(note),
		ChangeRef:      strings.TrimSpace(changeRef),
	})
}

func clientStatusLifecycleEvent(summary map[string]interface{}, label, note, changeRef string) ClientLifecycleEvent {
	enabled := boolValue(summary["enabled"])
	operation := ClientLifecycleOperationDisable
	if enabled {
		operation = ClientLifecycleOperationEnable
	}
	return withClientLifecycleIdentity(ClientLifecycleEvent{
		Operation:       operation,
		ClientID:        stringValue(summary["client_id"]),
		Name:            stringValue(summary["name"]),
		Group:           stringValue(summary["group"]),
		Scopes:          stringSliceValue(summary["scopes"]),
		Tags:            stringSliceValue(summary["tags"]),
		KeyFingerprint:  stringValue(summary["key_fingerprint"]),
		Enabled:         enabled,
		PreviousEnabled: boolValue(summary["previous_enabled"]),
		RevisionLabel:   strings.TrimSpace(label),
		RevisionNote:    strings.TrimSpace(note),
		ChangeRef:       strings.TrimSpace(changeRef),
	})
}

func clientUpdateLifecycleEvent(summary map[string]interface{}, label, note, changeRef string) ClientLifecycleEvent {
	return withClientLifecycleIdentity(ClientLifecycleEvent{
		Operation:      ClientLifecycleOperationUpdate,
		ClientID:       stringValue(summary["client_id"]),
		Name:           stringValue(summary["name"]),
		Group:          stringValue(summary["group"]),
		Scopes:         stringSliceValue(summary["scopes"]),
		Tags:           stringSliceValue(summary["tags"]),
		KeyFingerprint: stringValue(summary["key_fingerprint"]),
		Enabled:        boolValue(summary["enabled"]),
		PreviousName:   stringValue(summary["previous_name"]),
		PreviousGroup:  stringValue(summary["previous_group"]),
		PreviousScopes: stringSliceValue(summary["previous_scopes"]),
		PreviousTags:   stringSliceValue(summary["previous_tags"]),
		RevisionLabel:  strings.TrimSpace(label),
		RevisionNote:   strings.TrimSpace(note),
		ChangeRef:      strings.TrimSpace(changeRef),
	})
}

func clientRotateLifecycleEvent(summary map[string]interface{}, generated bool, label, note, changeRef string) ClientLifecycleEvent {
	return withClientLifecycleIdentity(ClientLifecycleEvent{
		Operation:         ClientLifecycleOperationRotate,
		ClientID:          stringValue(summary["client_id"]),
		Name:              stringValue(summary["name"]),
		Group:             stringValue(summary["group"]),
		Scopes:            stringSliceValue(summary["scopes"]),
		Tags:              stringSliceValue(summary["tags"]),
		KeyFingerprint:    stringValue(summary["key_fingerprint"]),
		OldKeyFingerprint: stringValue(summary["old_key_fingerprint"]),
		GeneratedKey:      generated,
		RevisionLabel:     strings.TrimSpace(label),
		RevisionNote:      strings.TrimSpace(note),
		ChangeRef:         strings.TrimSpace(changeRef),
	})
}

func withClientLifecycleIdentity(event ClientLifecycleEvent) ClientLifecycleEvent {
	event.Identity = clientLifecycleIdentity(event.ClientID)
	return event
}

func clientLifecycleIdentity(clientID string) *authcontext.PrincipalIdentity {
	clientID = strings.TrimSpace(clientID)
	if clientID == "" {
		return nil
	}
	return &authcontext.PrincipalIdentity{
		Kind:   authcontext.PrincipalIdentityClient,
		Source: "apikey",
		Value:  clientID,
	}
}

func apiKeyFingerprint(key string) string {
	return credentials.APIKeyFingerprint(key)
}

func trimmedStringSlice(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			out = append(out, value)
		}
	}
	return out
}
