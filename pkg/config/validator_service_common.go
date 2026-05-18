package config

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/bhangun/iket/pkg/core/errors"
)

type serviceValidationContext struct {
	cfg                *Config
	serviceConfigIndex int
	serviceIndex       int
	routeIndex         int
	service            Service
	route              RouterConfig
}

func serviceConfigField(serviceConfigIndex int, name string) string {
	return fmt.Sprintf("services[%d].%s", serviceConfigIndex, name)
}

func serviceField(serviceConfigIndex, serviceIndex int, name string) string {
	return fmt.Sprintf("services[%d].services[%d].%s", serviceConfigIndex, serviceIndex, name)
}

func (ctx serviceValidationContext) serviceField(name string) string {
	return serviceField(ctx.serviceConfigIndex, ctx.serviceIndex, name)
}

func (ctx serviceValidationContext) routeField(name string) string {
	if name == "" {
		return fmt.Sprintf("services[%d].services[%d].routes[%d]", ctx.serviceConfigIndex, ctx.serviceIndex, ctx.routeIndex)
	}
	return fmt.Sprintf("services[%d].services[%d].routes[%d].%s", ctx.serviceConfigIndex, ctx.serviceIndex, ctx.routeIndex, name)
}

func (ctx serviceValidationContext) backendField(backendIndex int, name string) string {
	return fmt.Sprintf("services[%d].services[%d].routes[%d].backend[%d].%s", ctx.serviceConfigIndex, ctx.serviceIndex, ctx.routeIndex, backendIndex, name)
}

func validationError(field, message string) error {
	return errors.NewValidationError(field, message)
}

func validateOptionalDuration(field, value, message string) error {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	if _, err := time.ParseDuration(strings.TrimSpace(value)); err != nil {
		return validationError(field, message)
	}
	return nil
}

func validateOptionalPositiveDuration(field, value, message string) error {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	parsed, err := time.ParseDuration(strings.TrimSpace(value))
	if err != nil || parsed <= 0 {
		return validationError(field, message)
	}
	return nil
}

func validateNonEmptyStringSlice(field string, values []string, message string) error {
	for _, value := range values {
		if strings.TrimSpace(value) == "" {
			return validationError(field, message)
		}
	}
	return nil
}

func validateMapKeysNonEmpty[V any](field string, values map[string]V, message string) error {
	for key := range values {
		if strings.TrimSpace(key) == "" {
			return validationError(field, message)
		}
	}
	return nil
}

func validateRegexSlice(field string, patterns []string, emptyMessage, invalidMessage string) error {
	for _, pattern := range patterns {
		if strings.TrimSpace(pattern) == "" {
			return validationError(field, emptyMessage)
		}
		if _, err := regexp.Compile(pattern); err != nil {
			return validationError(field, invalidMessage)
		}
	}
	return nil
}

func validateRegexMap(field string, patterns map[string]string, emptyKeyMessage, invalidPatternMessage string) error {
	for key, pattern := range patterns {
		if strings.TrimSpace(key) == "" {
			return validationError(field, emptyKeyMessage)
		}
		if _, err := regexp.Compile(pattern); err != nil {
			return validationError(field, invalidPatternMessage)
		}
	}
	return nil
}

func validateJSONFieldMap(field string, values map[string]string, allowAppend bool, message string) error {
	for key := range values {
		if !isValidJSONFieldPath(key, allowAppend) {
			return validationError(field, message)
		}
	}
	return nil
}

func validateJSONTransformValues(field string, values map[string]string) error {
	for _, value := range values {
		if err := validateJSONTransformLiteral(value); err != nil {
			return validationError(field, err.Error())
		}
	}
	return nil
}

func validateJSONTransformMap(field string, values map[string]string, allowAppend bool, message string) error {
	if err := validateJSONFieldMap(field, values, allowAppend, message); err != nil {
		return err
	}
	return validateJSONTransformValues(field, values)
}

func validateJSONFieldSlice(field string, values []string, allowAppend bool, message string) error {
	for _, value := range values {
		if !isValidJSONFieldPath(value, allowAppend) {
			return validationError(field, message)
		}
	}
	return nil
}

func validateHTTPMethodSlice(field string, methods []string, message string) error {
	for _, method := range methods {
		if !isValidHTTPMethod(method) {
			return validationError(field, message)
		}
	}
	return nil
}

func validatePIITypeSlice(field string, values []string, message string) error {
	for _, value := range values {
		if !isAllowedPIIType(value) {
			return validationError(field, message)
		}
	}
	return nil
}
