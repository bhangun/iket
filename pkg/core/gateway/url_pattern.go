package gateway

import (
	"regexp"
	"strings"
)

var routeVarRe = regexp.MustCompile(`\{([A-Za-z0-9_]+)(:[^}]*)?\}`)

// applyURLPattern expands a backend URL pattern like "/api/{rest:.*}" using mux vars.
// If the named var is missing, and the placeholder is {rest...}, it falls back to
// deriving "rest" from the original request path and the route path prefix.
func applyURLPattern(pattern, routePath, origPath string, vars map[string]string) string {
	derivedRest := ""
	if i := findWildcardIndex(routePath); i > 0 {
		prefix := routePath[:i-1]
		if prefix != "" && prefix != "/" && strings.HasPrefix(origPath, prefix) {
			derivedRest = strings.TrimPrefix(origPath[len(prefix):], "/")
		}
	}

	out := routeVarRe.ReplaceAllStringFunc(pattern, func(m string) string {
		sub := routeVarRe.FindStringSubmatch(m)
		if len(sub) < 2 {
			return m
		}
		name := sub[1]
		val := ""
		if vars != nil {
			val = vars[name]
		}
		if val == "" && name == "rest" {
			val = derivedRest
		}
		return strings.TrimPrefix(val, "/")
	})

	out = strings.TrimSpace(out)
	if out == "" {
		return "/"
	}
	if !strings.HasPrefix(out, "/") {
		out = "/" + out
	}
	return out
}

func findWildcardIndex(path string) int {
	for i := 0; i < len(path); i++ {
		if path[i] == '{' {
			return i
		}
	}
	return -1
}
