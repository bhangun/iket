package gateway

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/bhangun/iket/pkg/config"
)

func routeHasTransformConditions(route config.RouterConfig) bool {
	return len(route.TransformWhenHeaders) > 0 ||
		len(route.TransformWhenQueryParams) > 0 ||
		len(route.TransformWhenHeaderRegex) > 0 ||
		len(route.TransformWhenQueryRegex) > 0
}

func routeScopeIsGated(route config.RouterConfig, scope string) bool {
	if !routeHasTransformConditions(route) {
		return false
	}
	if len(route.TransformScopes) == 0 {
		return true
	}
	for _, candidate := range route.TransformScopes {
		if strings.EqualFold(strings.TrimSpace(candidate), scope) {
			return true
		}
	}
	return false
}

func routeTransformsEnabled(r *http.Request, route config.RouterConfig, scope string) bool {
	if !routeHasTransformConditions(route) {
		if len(route.TransformMethods) == 0 {
			return true
		}
		if r == nil {
			return false
		}
		return routeTransformMethodMatches(r.Method, route)
	}
	if r == nil {
		return false
	}
	if !routeTransformMethodMatches(r.Method, route) {
		return false
	}
	if !routeScopeIsGated(route, scope) {
		return true
	}
	for key, expected := range route.TransformWhenHeaders {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		if r.Header.Get(key) != expected {
			return false
		}
	}
	for key, pattern := range route.TransformWhenHeaderRegex {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		matched, err := regexp.MatchString(pattern, r.Header.Get(key))
		if err != nil || !matched {
			return false
		}
	}
	if r.URL != nil {
		query := r.URL.Query()
		for key, expected := range route.TransformWhenQueryParams {
			key = strings.TrimSpace(key)
			if key == "" {
				continue
			}
			if query.Get(key) != expected {
				return false
			}
		}
		for key, pattern := range route.TransformWhenQueryRegex {
			key = strings.TrimSpace(key)
			if key == "" {
				continue
			}
			matched, err := regexp.MatchString(pattern, query.Get(key))
			if err != nil || !matched {
				return false
			}
		}
	}
	return true
}

func routeTransformMethodMatches(method string, route config.RouterConfig) bool {
	if len(route.TransformMethods) == 0 {
		return true
	}
	method = strings.ToUpper(strings.TrimSpace(method))
	for _, candidate := range route.TransformMethods {
		if strings.ToUpper(strings.TrimSpace(candidate)) == method {
			return true
		}
	}
	return false
}

func responseTransformStatusMatches(route config.RouterConfig, statusCode int) bool {
	if statusCode <= 0 {
		return true
	}
	if len(route.ResponseTransformStatusCodes) == 0 && len(route.ResponseTransformStatusClasses) == 0 {
		return true
	}
	for _, allowed := range route.ResponseTransformStatusCodes {
		if allowed == statusCode {
			return true
		}
	}
	statusClass := fmt.Sprintf("%dxx", statusCode/100)
	for _, allowedClass := range route.ResponseTransformStatusClasses {
		if strings.EqualFold(strings.TrimSpace(allowedClass), statusClass) {
			return true
		}
	}
	return false
}

func responseTransformHeadersMatch(route config.RouterConfig, headers http.Header) bool {
	if len(route.ResponseTransformWhenHeaders) == 0 && len(route.ResponseTransformHeaderRegex) == 0 {
		return true
	}
	if headers == nil {
		return false
	}
	for key, expected := range route.ResponseTransformWhenHeaders {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		if headers.Get(key) != expected {
			return false
		}
	}
	for key, pattern := range route.ResponseTransformHeaderRegex {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		matched, err := regexp.MatchString(pattern, headers.Get(key))
		if err != nil || !matched {
			return false
		}
	}
	return true
}

func responseTransformsEnabled(r *http.Request, route config.RouterConfig, scope string, statusCode int, headers http.Header) bool {
	if !routeTransformsEnabled(r, route, scope) {
		return false
	}
	if !responseTransformStatusMatches(route, statusCode) {
		return false
	}
	return responseTransformHeadersMatch(route, headers)
}
