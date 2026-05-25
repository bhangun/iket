package gateway

import "github.com/bhangun/iket/pkg/core/authcontext"

func principalFromBasicIdentity(source, username string) authcontext.Principal {
	return authcontext.Principal{
		Source:   source,
		Subject:  username,
		UserID:   username,
		Username: username,
		ClientID: username,
	}
}
