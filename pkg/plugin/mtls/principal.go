package mtls

import (
	"strings"
	"time"

	"github.com/bhangun/iket/pkg/core/authcontext"
)

func principalFromCertInfo(certInfo *ClientCertInfo) authcontext.Principal {
	if certInfo == nil {
		return authcontext.Principal{Source: "mtls"}
	}
	return authcontext.Principal{
		Source:    "mtls",
		Subject:   certInfo.Subject,
		UserID:    certInfo.CN,
		Username:  certInfo.CN,
		Groups:    certInfo.OU,
		ClientID:  certInfo.CN,
		Issuer:    certInfo.Issuer,
		ExpiresAt: timeFromCertificateTimestamp(certInfo.NotAfter),
		IssuedAt:  timeFromCertificateTimestamp(certInfo.NotBefore),
		Custom: map[string]string{
			"cn":           certInfo.CN,
			"organization": strings.Join(certInfo.O, ","),
			"ou":           strings.Join(certInfo.OU, ","),
			"serial":       certInfo.Serial,
		},
	}
}

func timeFromCertificateTimestamp(value string) *time.Time {
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return nil
	}
	return &parsed
}
