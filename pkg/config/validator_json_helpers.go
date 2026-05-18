package config

import (
	"encoding/json"
	"fmt"
	"strings"
)

func isValidJSONFieldPath(path string, allowAppend bool) bool {
	path = strings.TrimSpace(path)
	if path == "" {
		return false
	}
	parts := strings.Split(path, ".")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			return false
		}
		if strings.HasSuffix(part, "[]") {
			if !allowAppend {
				return false
			}
			part = strings.TrimSuffix(part, "[]")
			if strings.TrimSpace(part) == "" {
				return false
			}
			continue
		}
		if open := strings.Index(part, "["); open >= 0 {
			if !strings.HasSuffix(part, "]") {
				return false
			}
			if open == 0 {
				return false
			}
			index := part[open+1 : len(part)-1]
			if index == "" {
				return false
			}
			for _, ch := range index {
				if ch < '0' || ch > '9' {
					return false
				}
			}
			part = part[:open]
			if strings.TrimSpace(part) == "" {
				return false
			}
		}
	}
	return true
}

func validateJSONTransformLiteral(value string) error {
	value = strings.TrimSpace(value)
	if !strings.HasPrefix(value, "json:") {
		return nil
	}
	literal := strings.TrimSpace(strings.TrimPrefix(value, "json:"))
	if literal == "" {
		return fmt.Errorf("json: transform values must contain valid JSON")
	}
	if strings.Contains(literal, "{{") {
		return nil
	}
	var parsed interface{}
	if err := json.Unmarshal([]byte(literal), &parsed); err != nil {
		return fmt.Errorf("json: transform values must contain valid JSON")
	}
	return nil
}

func isAllowedPIIType(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "email", "phone", "api_key", "card":
		return true
	default:
		return false
	}
}
