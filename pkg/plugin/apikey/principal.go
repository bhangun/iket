package apikey

import (
	"strings"

	"github.com/bhangun/iket/pkg/core/authcontext"
)

func principalFromClient(client ClientApp) authcontext.Principal {
	principal := authcontext.Principal{
		Source:   "apikey",
		Subject:  client.ID,
		UserID:   client.ID,
		Username: client.Name,
		Scopes:   client.Scopes,
		ClientID: client.ID,
		Custom: map[string]string{
			"client_name": client.Name,
		},
	}
	if client.Group != "" {
		principal.Groups = []string{client.Group}
		principal.Custom["group"] = client.Group
	}
	if fingerprint := clientInventoryFingerprint(client); fingerprint != "" {
		principal.Custom["key_fingerprint"] = fingerprint
	}
	if len(client.Tags) > 0 {
		principal.Custom["tags"] = strings.Join(client.Tags, ",")
	}
	return principal
}
