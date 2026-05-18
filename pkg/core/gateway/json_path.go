package gateway

import (
	"encoding/json"
	"strconv"
	"strings"
)

func setNestedJSONField(payload map[string]interface{}, path string, value interface{}) {
	segments := parseJSONFieldPath(path)
	if len(segments) == 0 {
		return
	}
	current := payload
	for _, segment := range segments[:len(segments)-1] {
		if !segment.hasArray() {
			next, exists := current[segment.key]
			if !exists {
				child := make(map[string]interface{})
				current[segment.key] = child
				current = child
				continue
			}
			child, ok := next.(map[string]interface{})
			if !ok {
				child = make(map[string]interface{})
				current[segment.key] = child
			}
			current = child
			continue
		}

		array := ensureJSONArray(current, segment.key)
		var child map[string]interface{}
		if segment.append {
			child = make(map[string]interface{})
			array = append(array, child)
		} else {
			array = ensureJSONArrayIndex(array, segment.index)
			existing, ok := array[segment.index].(map[string]interface{})
			if !ok {
				existing = make(map[string]interface{})
			}
			array[segment.index] = existing
			child = existing
		}
		current[segment.key] = array
		current = child
	}

	last := segments[len(segments)-1]
	if !last.hasArray() {
		current[last.key] = value
		return
	}
	array := ensureJSONArray(current, last.key)
	if last.append {
		array = append(array, value)
	} else {
		array = ensureJSONArrayIndex(array, last.index)
		array[last.index] = value
	}
	current[last.key] = array
}

func deleteNestedJSONField(payload map[string]interface{}, path string) {
	segments := parseJSONFieldPath(path)
	if len(segments) == 0 {
		return
	}
	current := payload
	for _, segment := range segments[:len(segments)-1] {
		next, ok := current[segment.key]
		if !ok {
			return
		}
		if !segment.hasArray() {
			child, ok := next.(map[string]interface{})
			if !ok {
				return
			}
			current = child
			continue
		}
		array, ok := next.([]interface{})
		if !ok || segment.index < 0 || segment.index >= len(array) {
			return
		}
		child, ok := array[segment.index].(map[string]interface{})
		if !ok {
			return
		}
		current = child
	}
	last := segments[len(segments)-1]
	if !last.hasArray() {
		delete(current, last.key)
		return
	}
	next, ok := current[last.key]
	if !ok {
		return
	}
	array, ok := next.([]interface{})
	if !ok || last.index < 0 || last.index >= len(array) {
		return
	}
	array = append(array[:last.index], array[last.index+1:]...)
	current[last.key] = array
}

func redactNestedJSONField(payload map[string]interface{}, path string, replacement string) {
	segments := parseJSONFieldPath(path)
	if len(segments) == 0 {
		return
	}
	current := payload
	for _, segment := range segments[:len(segments)-1] {
		next, ok := current[segment.key]
		if !ok {
			return
		}
		if !segment.hasArray() {
			child, ok := next.(map[string]interface{})
			if !ok {
				return
			}
			current = child
			continue
		}
		array, ok := next.([]interface{})
		if !ok || segment.index < 0 || segment.index >= len(array) {
			return
		}
		child, ok := array[segment.index].(map[string]interface{})
		if !ok {
			return
		}
		current = child
	}
	last := segments[len(segments)-1]
	if !last.hasArray() {
		if _, ok := current[last.key]; ok {
			current[last.key] = replacement
		}
		return
	}
	next, ok := current[last.key]
	if !ok {
		return
	}
	array, ok := next.([]interface{})
	if !ok || last.index < 0 || last.index >= len(array) {
		return
	}
	array[last.index] = replacement
	current[last.key] = array
}

func nestedJSONStringValue(payload map[string]interface{}, path string) (string, bool) {
	segments := parseJSONFieldPath(path)
	if len(segments) == 0 {
		return "", false
	}
	var current interface{} = payload
	for _, segment := range segments {
		obj, ok := current.(map[string]interface{})
		if !ok {
			return "", false
		}
		next, ok := obj[segment.key]
		if !ok {
			return "", false
		}
		if !segment.hasArray() {
			current = next
			continue
		}
		array, ok := next.([]interface{})
		if !ok || segment.append || segment.index < 0 || segment.index >= len(array) {
			return "", false
		}
		current = array[segment.index]
	}
	value, ok := current.(string)
	return value, ok
}

func nestedJSONStringValues(payload map[string]interface{}, path string) []string {
	segments := parseJSONFieldPath(path)
	if len(segments) == 0 {
		return nil
	}
	return collectNestedJSONStringValues(payload, segments)
}

func lookupJSONFieldStringValue(payload map[string]interface{}, path string) string {
	values := nestedJSONStringValues(payload, path)
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

func nestedJSONIntValue(payload map[string]interface{}, path string) (int, bool) {
	segments := parseJSONFieldPath(path)
	if len(segments) == 0 {
		return 0, false
	}
	var current interface{} = payload
	for _, segment := range segments {
		obj, ok := current.(map[string]interface{})
		if !ok {
			return 0, false
		}
		next, ok := obj[segment.key]
		if !ok {
			return 0, false
		}
		if !segment.hasArray() {
			current = next
			continue
		}
		array, ok := next.([]interface{})
		if !ok || segment.append || segment.index < 0 || segment.index >= len(array) {
			return 0, false
		}
		current = array[segment.index]
	}
	switch v := current.(type) {
	case float64:
		return int(v), true
	case int:
		return v, true
	case int64:
		return int(v), true
	case json.Number:
		n, err := v.Int64()
		if err != nil {
			return 0, false
		}
		return int(n), true
	default:
		return 0, false
	}
}

func nestedJSONArrayLength(payload map[string]interface{}, path string) (int, bool) {
	segments := parseJSONFieldPath(path)
	if len(segments) == 0 {
		return 0, false
	}
	var current interface{} = payload
	for _, segment := range segments {
		obj, ok := current.(map[string]interface{})
		if !ok {
			return 0, false
		}
		next, ok := obj[segment.key]
		if !ok {
			return 0, false
		}
		if !segment.hasArray() {
			current = next
			continue
		}
		array, ok := next.([]interface{})
		if !ok || segment.append || segment.index < 0 || segment.index >= len(array) {
			return 0, false
		}
		current = array[segment.index]
	}
	array, ok := current.([]interface{})
	if !ok {
		return 0, false
	}
	return len(array), true
}

func collectNestedJSONStringValues(current interface{}, segments []jsonPathSegment) []string {
	if len(segments) == 0 {
		value, ok := current.(string)
		if !ok || strings.TrimSpace(value) == "" {
			return nil
		}
		return []string{value}
	}
	obj, ok := current.(map[string]interface{})
	if !ok {
		return nil
	}
	segment := segments[0]
	next, ok := obj[segment.key]
	if !ok {
		return nil
	}
	if !segment.hasArray() {
		return collectNestedJSONStringValues(next, segments[1:])
	}
	array, ok := next.([]interface{})
	if !ok {
		return nil
	}
	if segment.append {
		values := make([]string, 0, len(array))
		for _, item := range array {
			values = append(values, collectNestedJSONStringValues(item, segments[1:])...)
		}
		return values
	}
	if segment.index < 0 || segment.index >= len(array) {
		return nil
	}
	return collectNestedJSONStringValues(array[segment.index], segments[1:])
}

type jsonPathSegment struct {
	key    string
	index  int
	append bool
}

func (s jsonPathSegment) hasArray() bool {
	return s.append || s.index >= 0
}

func parseJSONFieldPath(path string) []jsonPathSegment {
	rawParts := strings.Split(strings.TrimSpace(path), ".")
	segments := make([]jsonPathSegment, 0, len(rawParts))
	for _, raw := range rawParts {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		segment := jsonPathSegment{key: raw, index: -1}
		if strings.HasSuffix(raw, "[]") {
			segment.key = strings.TrimSpace(strings.TrimSuffix(raw, "[]"))
			segment.append = true
			segments = append(segments, segment)
			continue
		}
		if open := strings.Index(raw, "["); open >= 0 && strings.HasSuffix(raw, "]") {
			segment.key = strings.TrimSpace(raw[:open])
			indexValue := raw[open+1 : len(raw)-1]
			parsed, err := strconv.Atoi(indexValue)
			if err == nil {
				segment.index = parsed
			}
		}
		segments = append(segments, segment)
	}
	return segments
}

func ensureJSONArray(container map[string]interface{}, key string) []interface{} {
	if existing, ok := container[key]; ok {
		if array, ok := existing.([]interface{}); ok {
			return array
		}
	}
	return make([]interface{}, 0)
}

func ensureJSONArrayIndex(array []interface{}, index int) []interface{} {
	for len(array) <= index {
		array = append(array, nil)
	}
	return array
}
