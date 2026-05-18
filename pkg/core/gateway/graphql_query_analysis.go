package gateway

import (
	"regexp"
	"strings"
	"unicode"
)

func graphQLQueryLooksLikeIntrospection(query string) bool {
	query = strings.ToLower(strings.TrimSpace(query))
	if query == "" {
		return false
	}
	return strings.Contains(query, "__schema") || strings.Contains(query, "__type")
}

func graphQLOperationAllowed(allowed []string, operationName string) bool {
	operationName = strings.TrimSpace(operationName)
	if operationName == "" {
		return false
	}
	for _, allowedName := range allowed {
		if strings.EqualFold(strings.TrimSpace(allowedName), operationName) {
			return true
		}
	}
	return false
}

func graphQLPersistedQueryAllowed(allowed []string, persistedQueryID string) bool {
	persistedQueryID = strings.TrimSpace(persistedQueryID)
	if persistedQueryID == "" {
		return false
	}
	for _, allowedHash := range allowed {
		if strings.EqualFold(strings.TrimSpace(allowedHash), persistedQueryID) {
			return true
		}
	}
	return false
}

func inferGraphQLOperationName(query string) string {
	query = strings.TrimSpace(query)
	if query == "" {
		return ""
	}
	matches := regexp.MustCompile(`(?i)\b(query|mutation|subscription)\s+([A-Za-z_][A-Za-z0-9_]*)`).FindStringSubmatch(query)
	if len(matches) >= 3 {
		return strings.TrimSpace(matches[2])
	}
	return ""
}

func graphQLQueryDepth(query string) int {
	query = stripGraphQLIgnoredSyntax(query)
	depth := 0
	maxDepth := 0
	for _, r := range query {
		switch r {
		case '{':
			depth++
			if depth > maxDepth {
				maxDepth = depth
			}
		case '}':
			if depth > 0 {
				depth--
			}
		}
	}
	if maxDepth > 0 {
		return maxDepth - 1
	}
	return 0
}

func graphQLFieldCount(query string) int {
	query = stripGraphQLIgnoredSyntax(query)
	count := 0
	braceDepth := 0
	parenDepth := 0
	runes := []rune(query)
	for i := 0; i < len(runes); i++ {
		r := runes[i]
		switch r {
		case '{':
			braceDepth++
			continue
		case '}':
			if braceDepth > 0 {
				braceDepth--
			}
			continue
		case '(':
			parenDepth++
			continue
		case ')':
			if parenDepth > 0 {
				parenDepth--
			}
			continue
		}
		if !(r == '_' || unicode.IsLetter(r)) {
			continue
		}
		start := i
		i++
		for i < len(runes) && (runes[i] == '_' || unicode.IsLetter(runes[i]) || unicode.IsDigit(runes[i])) {
			i++
		}
		token := string(runes[start:i])
		for i < len(runes) && unicode.IsSpace(runes[i]) {
			i++
		}
		if i < len(runes) && runes[i] == ':' {
			continue
		}
		if braceDepth <= 0 || parenDepth > 0 || isGraphQLKeyword(token) || strings.HasPrefix(token, "__") {
			i--
			continue
		}
		count++
		i--
	}
	return count
}

func stripGraphQLIgnoredSyntax(query string) string {
	lines := strings.Split(query, "\n")
	cleaned := make([]string, 0, len(lines))
	for _, line := range lines {
		if idx := strings.Index(line, "#"); idx >= 0 {
			line = line[:idx]
		}
		cleaned = append(cleaned, line)
	}
	return strings.Join(cleaned, "\n")
}

func isGraphQLKeyword(token string) bool {
	switch strings.ToLower(strings.TrimSpace(token)) {
	case "query", "mutation", "subscription", "fragment", "on", "true", "false", "null":
		return true
	default:
		return false
	}
}
