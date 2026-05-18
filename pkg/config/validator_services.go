package config

// ServicesConfigRule validates service-based configuration.
type ServicesConfigRule struct{}

var allowedTransformScopes = map[string]struct{}{
	"request_headers":  {},
	"query":            {},
	"request_json":     {},
	"response_headers": {},
	"response_json":    {},
}

var allowedResponseTransformStatusClasses = map[string]struct{}{
	"1xx": {},
	"2xx": {},
	"3xx": {},
	"4xx": {},
	"5xx": {},
}

func (r *ServicesConfigRule) Validate(cfg *Config) error {
	if len(cfg.Services) == 0 {
		return nil
	}
	if err := validateGlobalAIPolicyPresets(cfg); err != nil {
		return err
	}
	for i, serviceConfig := range cfg.Services {
		if err := validateServiceConfig(cfg, i, serviceConfig); err != nil {
			return err
		}
	}
	return nil
}
