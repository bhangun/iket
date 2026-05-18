package config

// TLSConfig represents TLS configuration
type TLSConfig struct {
	Enabled              bool     `yaml:"enabled"`
	Port                 int      `yaml:"port,omitempty"`
	HTTP3Enabled         bool     `yaml:"http3Enabled,omitempty"`
	HTTP3Port            int      `yaml:"http3Port,omitempty"`
	HTTP3Datagrams       bool     `yaml:"http3Datagrams,omitempty"`
	EnrollmentPort       int      `yaml:"enrollmentPort,omitempty"`
	EnrollmentMaxActive  int      `yaml:"enrollmentMaxActive,omitempty"`
	CertFile             string   `yaml:"certFile"`
	KeyFile              string   `yaml:"keyFile"`
	ClientCAFile         string   `yaml:"clientCAFile"`
	ClientAuthType       string   `yaml:"clientAuthType"` // NoClientCert, RequestClientCert, RequireAnyClientCert, VerifyClientCertIfGiven, RequireAndVerifyClientCert
	MinVersion           string   `yaml:"minVersion"`
	Ciphers              []string `yaml:"ciphers"`
	ServerNames          []string `yaml:"serverNames,omitempty"`
	ServerIPs            []string `yaml:"serverIPs,omitempty"`
	AutoGenerate         *bool    `yaml:"autoGenerate,omitempty"`
	GenerateSharedClient *bool    `yaml:"generateSharedClient,omitempty"`
}

func (t TLSConfig) EffectivePort(defaultPort int) int {
	if t.Port > 0 {
		return t.Port
	}
	return defaultPort
}

func (t TLSConfig) EffectiveHTTP3Port(defaultTLSPort int) int {
	if t.HTTP3Port > 0 {
		return t.HTTP3Port
	}
	return defaultTLSPort
}

func (t TLSConfig) EffectiveEnrollmentPort() int {
	if t.EnrollmentPort > 0 {
		return t.EnrollmentPort
	}
	return 0
}

func (t TLSConfig) EffectiveEnrollmentMaxActive() int {
	if t.EnrollmentMaxActive > 0 {
		return t.EnrollmentMaxActive
	}
	return 10
}

func (t TLSConfig) ShouldAutoGenerate() bool {
	return t.AutoGenerate != nil && *t.AutoGenerate
}

func (t TLSConfig) ShouldGenerateSharedClient() bool {
	return t.GenerateSharedClient != nil && *t.GenerateSharedClient
}
