package plugin

import (
	"time"

	"github.com/bhangun/iket/pkg/core/authcontext"
)

// ClientInventoryRecord is the redacted client metadata exposed by auth
// plugins to the management API. Secrets should never be returned here.
type ClientInventoryRecord struct {
	ID             string                         `json:"id,omitempty"`
	Name           string                         `json:"name,omitempty"`
	Identity       *authcontext.PrincipalIdentity `json:"identity,omitempty"`
	KeyFingerprint string                         `json:"key_fingerprint,omitempty"`
	KeyRedacted    bool                           `json:"key_redacted"`
	Enabled        bool                           `json:"enabled"`
	Group          string                         `json:"group,omitempty"`
	Scopes         []string                       `json:"scopes,omitempty"`
	Tags           []string                       `json:"tags,omitempty"`
	RequestCount   int64                          `json:"request_count,omitempty"`
	LastUsedAt     *time.Time                     `json:"last_used_at,omitempty"`
}

// ClientInventoryProvider is an optional plugin capability for listing client
// identities without exposing raw credentials or plugin-specific runtime types.
type ClientInventoryProvider interface {
	Plugin
	ListClientInventory() []ClientInventoryRecord
	FindClientInventory(credential string) (ClientInventoryRecord, bool)
}
