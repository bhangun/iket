package api

import "strings"

func normalizedLimitClassDigestSeverities(values []string) map[string]struct{} {
	if len(values) == 0 {
		return nil
	}
	normalized := make(map[string]struct{}, len(values))
	for _, value := range values {
		severity := normalizeSLABreachTier(value)
		if severity == "" {
			continue
		}
		normalized[severity] = struct{}{}
	}
	if len(normalized) == 0 {
		return nil
	}
	return normalized
}

func normalizedLimitClassDigestTypes(values []string) map[string]struct{} {
	if len(values) == 0 {
		return nil
	}
	normalized := make(map[string]struct{}, len(values))
	for _, value := range values {
		switch strings.ToLower(strings.TrimSpace(value)) {
		case "alert", "snooze":
			normalized[strings.ToLower(strings.TrimSpace(value))] = struct{}{}
		}
	}
	if len(normalized) == 0 {
		return nil
	}
	return normalized
}

func normalizedLimitClassDigestTypeList(values []string) []string {
	normalized := normalizedLimitClassDigestTypes(values)
	if len(normalized) == 0 {
		return nil
	}
	ordered := make([]string, 0, len(normalized))
	for _, digestType := range []string{"alert", "snooze"} {
		if _, ok := normalized[digestType]; ok {
			ordered = append(ordered, digestType)
		}
	}
	return ordered
}

func normalizedLimitClassDigestSeverityList(values []string) []string {
	normalized := normalizedLimitClassDigestSeverities(values)
	if len(normalized) == 0 {
		return nil
	}
	ordered := make([]string, 0, len(normalized))
	for _, severity := range []string{"warning", "elevated", "critical"} {
		if _, ok := normalized[severity]; ok {
			ordered = append(ordered, severity)
		}
	}
	return ordered
}

func normalizedLimitClassDigestSummarySortMode(value string) string {
	switch mode := strings.ToLower(strings.TrimSpace(value)); mode {
	case "priority_first", "severity_first", "count_first":
		return mode
	default:
		return "priority_first"
	}
}

func normalizedLimitClassDigestTruncatedReasonBucketSortMode(value string) string {
	switch mode := strings.ToLower(strings.TrimSpace(value)); mode {
	case "severity_first", "count_first", "custom_order_first":
		return mode
	default:
		return "custom_order_first"
	}
}

func normalizedLimitClassDigestTruncatedReasonBucketDominantReasonStrategy(value string) string {
	switch mode := strings.ToLower(strings.TrimSpace(value)); mode {
	case "severity_first", "count_first", "default":
		return mode
	default:
		return "default"
	}
}

func limitClassDigestTypeFromEvent(event string) string {
	switch strings.TrimSpace(strings.ToLower(event)) {
	case "gateway.limit_class_alert_digest":
		return "alert"
	case "gateway.limit_class_snooze_expiring_digest":
		return "snooze"
	default:
		return ""
	}
}
