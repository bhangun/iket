package config

import (
	"os"
	"reflect"
	"regexp"
)

var envVarPattern = regexp.MustCompile(`\$\{([A-Za-z0-9_]+)(:-([^}]*))?\}`)

func expandEnvVarsInStruct(s interface{}) {
	v := reflect.ValueOf(s).Elem()
	for i := 0; i < v.NumField(); i++ {
		field := v.Field(i)
		if field.Kind() == reflect.String {
			field.SetString(expandEnvVars(field.String()))
		} else if field.Kind() == reflect.Struct {
			expandEnvVarsInStruct(field.Addr().Interface())
		} else if field.Kind() == reflect.Slice {
			for j := 0; j < field.Len(); j++ {
				elem := field.Index(j)
				if elem.Kind() == reflect.Struct {
					expandEnvVarsInStruct(elem.Addr().Interface())
				}
			}
		} else if field.Kind() == reflect.Map {
			for _, key := range field.MapKeys() {
				val := field.MapIndex(key)
				if val.Kind() == reflect.String {
					field.SetMapIndex(key, reflect.ValueOf(expandEnvVars(val.String())))
				}
			}
		}
	}
}

func expandEnvVarsInMap(m map[string]interface{}) {
	for k, v := range m {
		switch val := v.(type) {
		case string:
			m[k] = expandEnvVars(val)
		case map[string]interface{}:
			expandEnvVarsInMap(val)
		case []interface{}:
			for i, elem := range val {
				if s, ok := elem.(string); ok {
					val[i] = expandEnvVars(s)
				} else if submap, ok := elem.(map[string]interface{}); ok {
					expandEnvVarsInMap(submap)
				}
			}
		}
	}
}

func expandEnvVars(s string) string {
	return envVarPattern.ReplaceAllStringFunc(s, func(m string) string {
		matches := envVarPattern.FindStringSubmatch(m)
		key := matches[1]
		def := ""
		if len(matches) > 3 {
			def = matches[3]
		}
		val := os.Getenv(key)
		if val == "" {
			val = def
		}
		return val
	})
}
