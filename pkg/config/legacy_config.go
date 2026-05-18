package config

func normalizeLegacyConfig(cfg *Config) {
	legacyTLS := cfg.Server.TLS
	activeTLS := cfg.Security.TLS

	if !activeTLS.Enabled && legacyTLS.Enabled {
		cfg.Security.TLS = legacyTLS
		return
	}
	if activeTLS.CertFile == "" && legacyTLS.CertFile != "" {
		cfg.Security.TLS.CertFile = legacyTLS.CertFile
	}
	if activeTLS.KeyFile == "" && legacyTLS.KeyFile != "" {
		cfg.Security.TLS.KeyFile = legacyTLS.KeyFile
	}
	if activeTLS.ClientCAFile == "" && legacyTLS.ClientCAFile != "" {
		cfg.Security.TLS.ClientCAFile = legacyTLS.ClientCAFile
	}
	if activeTLS.ClientAuthType == "" && legacyTLS.ClientAuthType != "" {
		cfg.Security.TLS.ClientAuthType = legacyTLS.ClientAuthType
	}
	if activeTLS.MinVersion == "" && legacyTLS.MinVersion != "" {
		cfg.Security.TLS.MinVersion = legacyTLS.MinVersion
	}
	if activeTLS.Port == 0 && legacyTLS.Port > 0 {
		cfg.Security.TLS.Port = legacyTLS.Port
	}
	if activeTLS.EnrollmentPort == 0 && legacyTLS.EnrollmentPort > 0 {
		cfg.Security.TLS.EnrollmentPort = legacyTLS.EnrollmentPort
	}
	if activeTLS.EnrollmentMaxActive == 0 && legacyTLS.EnrollmentMaxActive > 0 {
		cfg.Security.TLS.EnrollmentMaxActive = legacyTLS.EnrollmentMaxActive
	}
	if activeTLS.AutoGenerate == nil && legacyTLS.AutoGenerate != nil {
		cfg.Security.TLS.AutoGenerate = legacyTLS.AutoGenerate
	}
	if len(activeTLS.Ciphers) == 0 && len(legacyTLS.Ciphers) > 0 {
		cfg.Security.TLS.Ciphers = legacyTLS.Ciphers
	}
}
