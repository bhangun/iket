package api

import (
	"fmt"
	"strings"
)

func intValue(value interface{}) int {
	switch v := value.(type) {
	case int:
		return v
	case int64:
		return int(v)
	case float64:
		return int(v)
	default:
		return 0
	}
}

func int64Value(value interface{}) int64 {
	switch v := value.(type) {
	case int64:
		return v
	case int:
		return int64(v)
	case float64:
		return int64(v)
	default:
		return 0
	}
}

func stringValue(value interface{}) string {
	if value == nil {
		return ""
	}
	return strings.TrimSpace(fmt.Sprint(value))
}

func stringSliceValue(value interface{}) []string {
	switch values := value.(type) {
	case nil:
		return nil
	case []string:
		return trimmedStringSlice(values)
	case []interface{}:
		out := make([]string, 0, len(values))
		for _, value := range values {
			text := stringValue(value)
			if text != "" {
				out = append(out, text)
			}
		}
		return out
	default:
		text := stringValue(value)
		if text == "" {
			return nil
		}
		return []string{text}
	}
}

func boolValue(value interface{}) bool {
	v, _ := value.(bool)
	return v
}

func sanitizedClientCommonName(name string) string {
	name = strings.TrimSpace(strings.ToLower(name))
	if name == "" {
		return "iket"
	}
	var b strings.Builder
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '-' || r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		return "iket"
	}
	return out
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}
