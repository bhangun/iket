package api

import (
	"fmt"
	"strings"
	"time"
)

func slaBreachCountFromEventData(data map[string]interface{}) interface{} {
	if attention, ok := data["attention_required"].(map[string]interface{}); ok {
		if count, ok := attention["sla_breach_count"]; ok {
			return count
		}
	}
	if count, ok := data["sla_breach_count"]; ok {
		return count
	}
	return 0
}

func slaBreachConsecutiveCountFromEventData(data map[string]interface{}) int {
	if state, ok := data["sla_breach_state"].(map[string]interface{}); ok {
		return intValue(state["consecutive_breaches"])
	}
	return 0
}

func slaBreachAgeFromEventData(data map[string]interface{}) time.Duration {
	if state, ok := data["sla_breach_state"].(map[string]interface{}); ok {
		switch value := state["breach_age_seconds"].(type) {
		case int:
			return time.Duration(value) * time.Second
		case int64:
			return time.Duration(value) * time.Second
		case float64:
			return time.Duration(value * float64(time.Second))
		}
	}
	return 0
}

func slaBreachTierFromEventData(data map[string]interface{}) string {
	if state, ok := data["sla_breach_state"].(map[string]interface{}); ok {
		if tier, ok := state["tier"]; ok {
			return normalizeSLABreachTier(fmt.Sprint(tier))
		}
	}
	if tier, ok := data["sla_breach_tier"]; ok {
		return normalizeSLABreachTier(fmt.Sprint(tier))
	}
	return ""
}

func normalizeSLABreachTier(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "warning", "elevated", "critical":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return ""
	}
}

func slaBreachTierRank(tier string) int {
	switch normalizeSLABreachTier(tier) {
	case "warning":
		return 1
	case "elevated":
		return 2
	case "critical":
		return 3
	default:
		return 0
	}
}
