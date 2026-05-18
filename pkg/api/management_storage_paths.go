package api

import (
	"path/filepath"
)

func adminDataDir() string {
	return filepath.Join(".iket-admin")
}

func certificatesDir() string {
	return filepath.Join(adminDataDir(), "certificates")
}

func backupsDir() string {
	return filepath.Join(adminDataDir(), "backups")
}

func enrollmentTokensDir() string {
	return filepath.Join(adminDataDir(), "enrollment-tokens")
}

func revisionsDir() string {
	return filepath.Join(adminDataDir(), "revisions")
}

func proposalsDir() string {
	return filepath.Join(adminDataDir(), "proposals")
}

func notificationDeliveriesDir() string {
	return filepath.Join(adminDataDir(), "notification-deliveries")
}
