package api

import (
	"fmt"
	"sort"
	"strings"

	"github.com/bhangun/iket/pkg/config"
)

type limitClassDigestHiddenStrategySummary struct {
	name        string
	mode        string
	priority    int
	hiddenCount int
	hiddenItems int
	score       int
	eligible    bool
}

func (api *ManagementAPI) notificationWebhookPayloadForReceiver(webhook config.NotificationWebhook, payload managementWebhookEvent) managementWebhookEvent {
	switch strings.TrimSpace(strings.ToLower(payload.Event)) {
	case "gateway.limit_class_alert_digest", "gateway.limit_class_snooze_expiring_digest":
		return api.shapeLimitClassDigestPayloadForReceiver(webhook, payload)
	default:
		return payload
	}
}

func (api *ManagementAPI) shapeLimitClassDigestPayloadForReceiver(webhook config.NotificationWebhook, payload managementWebhookEvent) managementWebhookEvent {
	shape := newLimitClassDigestReceiverShape(webhook, payload.Event)
	if !shape.matchesDigestType() || !shape.shapesPayload() {
		return payload
	}

	shaped := payload
	data := cloneNotificationPayloadMap(payload.Data)
	switch shape.digestType {
	case "alert":
		api.shapeLimitClassAlertDigestData(data, shape)
	case "snooze":
		api.shapeLimitClassSnoozeDigestData(data, shape)
	}
	shaped.Data = data
	return shaped
}

func (api *ManagementAPI) shapeLimitClassAlertDigestData(data map[string]interface{}, shape limitClassDigestReceiverShape) {
	alerts := notificationPayloadItems(data["alerts"])
	filteredAlerts, summarizedByClass := api.filterLimitClassDigestItems(alerts, shape)
	if shape.summaryOnly {
		filteredAlerts = []interface{}{}
		summarizedByClass = api.limitClassDigestAllItemsByClass(alerts)
	}
	data["alerts"] = filteredAlerts
	data["total_alerts"] = len(filteredAlerts)
	data["summarized_class_alert_count"] = len(alerts) - len(filteredAlerts)
	summaryEntries, otherClassCount, otherAlertCount, otherReasons := api.limitClassDigestSummaryEntriesWithBudget(summarizedByClass, shape.minSummarySeverity, shape.minSummaryPriority, shape.minSummaryCount, shape.maxSummaryClasses, shape.summarySortMode)
	data["summarized_class_alerts_by_class"] = summaryEntries
	data["summarized_other_bucket_class_count"] = otherClassCount
	data["summarized_other_alert_count"] = otherAlertCount
	data["summarized_other_bucket"] = limitClassDigestOtherBucketMetadata(shape, otherClassCount, otherAlertCount, "alert_count", otherReasons)
	shape.applyReceiverMetadata(data)
}

func (api *ManagementAPI) shapeLimitClassSnoozeDigestData(data map[string]interface{}, shape limitClassDigestReceiverShape) {
	snoozes := notificationPayloadItems(data["snoozes"])
	filteredSnoozes, excludedByClass := api.filterLimitClassDigestItems(snoozes, shape)
	if shape.summaryOnly {
		filteredSnoozes = []interface{}{}
		excludedByClass = api.limitClassDigestAllItemsByClass(snoozes)
	}
	data["snoozes"] = filteredSnoozes
	data["total_snoozes"] = len(filteredSnoozes)
	data["excluded_class_snooze_count"] = len(snoozes) - len(filteredSnoozes)
	summaryEntries, otherClassCount, otherSnoozeCount, otherReasons := api.limitClassDigestSummaryEntriesWithBudget(excludedByClass, shape.minSummarySeverity, shape.minSummaryPriority, shape.minSummaryCount, shape.maxSummaryClasses, shape.summarySortMode)
	data["excluded_class_snoozes_by_class"] = summaryEntries
	data["excluded_other_bucket_class_count"] = otherClassCount
	data["excluded_other_snooze_count"] = otherSnoozeCount
	data["excluded_other_bucket"] = limitClassDigestOtherBucketMetadata(shape, otherClassCount, otherSnoozeCount, "snooze_count", otherReasons)
	shape.applyReceiverMetadata(data)
}

func limitClassDigestOtherBucketMetadata(shape limitClassDigestReceiverShape, classCount, itemCount int, itemField string, otherReasons map[string]limitClassDigestOverflowReasonStat) map[string]interface{} {
	visibleReasons := limitClassDigestVisibleOverflowReasons(shape.allowedOverflowReasons, otherReasons)
	dominantRawReason := limitClassDigestOverflowDominantReason(visibleReasons)
	reasonRows, hiddenReasonCount, hiddenClassCount, hiddenItemCount := limitClassDigestVisibleOverflowReasonEntriesWithLabels(shape.allowedOverflowReasons, otherReasons, itemField, shape.overflowReasonLabels, shape.overflowReasonGroupByRaw, shape.overflowReasonOrder)
	reasonRows, truncatedReasonCount, truncatedClassCount, truncatedItemCount := limitClassDigestCapOverflowReasonRows(reasonRows, itemField, shape.maxOverflowReasons)
	truncatedBucket := map[string]interface{}{
		"label":              shape.truncatedReasonBucketLabel,
		"reason_count":       truncatedReasonCount,
		"bucket_class_count": truncatedClassCount,
		itemField:            truncatedItemCount,
	}
	if shape.truncatedReasonBucketMode == "detailed" && truncatedReasonCount > 0 {
		allReasonRows := limitClassDigestOverflowReasonEntries(visibleReasons, itemField, shape.overflowReasonLabels, shape.overflowReasonGroupByRaw)
		sortLimitClassDigestOverflowReasonRows(allReasonRows, shape.overflowReasonOrder)
		truncatedReasonRows := []interface{}{}
		if shape.maxOverflowReasons > 0 && len(allReasonRows) > shape.maxOverflowReasons {
			truncatedReasonRows = append([]interface{}(nil), allReasonRows[shape.maxOverflowReasons:]...)
		}
		sortLimitClassDigestOverflowReasonRowsForNestedBucket(truncatedReasonRows, shape.truncatedReasonBucketReasonOrder, shape.truncatedReasonBucketSortMode)
		truncatedReasonRows, allowedHiddenReasonCount, allowedHiddenClassCount, allowedHiddenItemCount := limitClassDigestFilterOverflowReasonRowsByAllowedSeverities(truncatedReasonRows, itemField, shape.truncatedReasonBucketSeverities)
		truncatedReasonRows, filteredHiddenReasonCount, filteredHiddenClassCount, filteredHiddenItemCount := limitClassDigestFilterOverflowReasonRowsByMinSeverity(truncatedReasonRows, itemField, shape.truncatedReasonBucketMinSeverity)
		truncatedReasonRows, cappedHiddenReasonCount, cappedHiddenClassCount, cappedHiddenItemCount := limitClassDigestCapOverflowReasonRows(truncatedReasonRows, itemField, shape.truncatedReasonBucketMaxReasons)
		truncatedReasonStats := limitClassDigestOverflowReasonStatsFromRows(truncatedReasonRows, visibleReasons, shape.overflowReasonLabels, shape.overflowReasonGroupByRaw)
		truncatedDominantRawReason := limitClassDigestOverflowDominantReasonWithStrategy(truncatedReasonStats, shape.truncatedReasonBucketDominantReasonStrategy)
		truncatedBucket["reasons"] = truncatedReasonRows
		truncatedBucket["dominant_reason"] = limitClassDigestDisplayOverflowReasonGroup(shape.overflowReasonLabels, shape.overflowReasonGroupByRaw, truncatedDominantRawReason)
		truncatedBucket["dominant_raw_reason"] = truncatedDominantRawReason
		truncatedBucket["hidden_by_exact_severity_reason_count"] = allowedHiddenReasonCount
		truncatedBucket["hidden_by_exact_severity_bucket_class_count"] = allowedHiddenClassCount
		truncatedBucket["hidden_by_exact_severity_"+itemField] = allowedHiddenItemCount
		truncatedBucket["hidden_by_min_severity_reason_count"] = filteredHiddenReasonCount
		truncatedBucket["hidden_by_min_severity_bucket_class_count"] = filteredHiddenClassCount
		truncatedBucket["hidden_by_min_severity_"+itemField] = filteredHiddenItemCount
		truncatedBucket["hidden_by_max_reasons_reason_count"] = cappedHiddenReasonCount
		truncatedBucket["hidden_by_max_reasons_bucket_class_count"] = cappedHiddenClassCount
		truncatedBucket["hidden_by_max_reasons_"+itemField] = cappedHiddenItemCount
		activeHiddenStrategies, activeHiddenStrategyOrder, dominantHiddenStrategy := limitClassDigestTruncatedBucketHiddenStrategyMetadata(
			shape,
			itemField,
			allowedHiddenReasonCount,
			allowedHiddenClassCount,
			allowedHiddenItemCount,
			filteredHiddenReasonCount,
			filteredHiddenClassCount,
			filteredHiddenItemCount,
			cappedHiddenReasonCount,
			cappedHiddenClassCount,
			cappedHiddenItemCount,
		)
		truncatedBucket["active_hidden_reason_strategies"] = activeHiddenStrategies
		truncatedBucket["hidden_reason_strategy_order"] = activeHiddenStrategyOrder
		truncatedBucket["dominant_hidden_reason_strategy"] = dominantHiddenStrategy
		truncatedBucket["hidden_reason_count"] = allowedHiddenReasonCount + filteredHiddenReasonCount + cappedHiddenReasonCount
		truncatedBucket["hidden_bucket_class_count"] = allowedHiddenClassCount + filteredHiddenClassCount + cappedHiddenClassCount
		truncatedBucket["hidden_"+itemField] = allowedHiddenItemCount + filteredHiddenItemCount + cappedHiddenItemCount
	}
	return map[string]interface{}{
		"label":                        shape.otherBucketLabel,
		"bucket_class_count":           classCount,
		itemField:                      itemCount,
		"reasons":                      reasonRows,
		"dominant_reason":              limitClassDigestDisplayOverflowReasonGroup(shape.overflowReasonLabels, shape.overflowReasonGroupByRaw, dominantRawReason),
		"dominant_raw_reason":          dominantRawReason,
		"hidden_reason_count":          hiddenReasonCount,
		"hidden_bucket_class_count":    hiddenClassCount,
		"hidden_" + itemField:          hiddenItemCount,
		"truncated_reason_count":       truncatedReasonCount,
		"truncated_bucket_class_count": truncatedClassCount,
		"truncated_" + itemField:       truncatedItemCount,
		"truncated_reason_bucket":      truncatedBucket,
	}
}

func limitClassDigestCapOverflowReasonRows(rows []interface{}, itemField string, maxReasons int) ([]interface{}, int, int, int) {
	if maxReasons <= 0 || len(rows) <= maxReasons {
		return rows, 0, 0, 0
	}
	visible := append([]interface{}(nil), rows[:maxReasons]...)
	truncatedRows := rows[maxReasons:]
	truncatedClassCount := 0
	truncatedItemCount := 0
	for _, rowValue := range truncatedRows {
		row, _ := rowValue.(map[string]interface{})
		truncatedClassCount += intValue(row["bucket_class_count"])
		truncatedItemCount += intValue(row[itemField])
	}
	return visible, len(truncatedRows), truncatedClassCount, truncatedItemCount
}

func limitClassDigestFilterOverflowReasonRowsByMinSeverity(rows []interface{}, itemField, minSeverity string) ([]interface{}, int, int, int) {
	if len(rows) == 0 || strings.TrimSpace(minSeverity) == "" {
		return rows, 0, 0, 0
	}
	filtered := make([]interface{}, 0, len(rows))
	hiddenReasonCount := 0
	hiddenClassCount := 0
	hiddenItemCount := 0
	minRank := slaBreachTierRank(normalizeSLABreachTier(minSeverity))
	for _, rowValue := range rows {
		row, _ := rowValue.(map[string]interface{})
		rowSeverity := normalizeSLABreachTier(fmt.Sprint(row["severity"]))
		if slaBreachTierRank(rowSeverity) >= minRank {
			filtered = append(filtered, rowValue)
			continue
		}
		hiddenReasonCount++
		hiddenClassCount += intValue(row["bucket_class_count"])
		hiddenItemCount += intValue(row[itemField])
	}
	return filtered, hiddenReasonCount, hiddenClassCount, hiddenItemCount
}

func limitClassDigestFilterOverflowReasonRowsByAllowedSeverities(rows []interface{}, itemField string, allowed map[string]struct{}) ([]interface{}, int, int, int) {
	if len(rows) == 0 || len(allowed) == 0 {
		return rows, 0, 0, 0
	}
	filtered := make([]interface{}, 0, len(rows))
	hiddenReasonCount := 0
	hiddenClassCount := 0
	hiddenItemCount := 0
	for _, rowValue := range rows {
		row, _ := rowValue.(map[string]interface{})
		rowSeverity := normalizeSLABreachTier(fmt.Sprint(row["severity"]))
		if _, ok := allowed[rowSeverity]; ok {
			filtered = append(filtered, rowValue)
			continue
		}
		hiddenReasonCount++
		hiddenClassCount += intValue(row["bucket_class_count"])
		hiddenItemCount += intValue(row[itemField])
	}
	return filtered, hiddenReasonCount, hiddenClassCount, hiddenItemCount
}

func limitClassDigestTruncatedBucketHiddenStrategyMetadata(
	shape limitClassDigestReceiverShape,
	itemField string,
	exactSeverityReasonCount int,
	exactSeverityClassCount int,
	exactSeverityItemCount int,
	minSeverityReasonCount int,
	minSeverityClassCount int,
	minSeverityItemCount int,
	maxReasonsReasonCount int,
	maxReasonsClassCount int,
	maxReasonsItemCount int,
) (map[string]interface{}, []string, string) {
	strategies := make(map[string]interface{})
	effectiveOrder := limitClassDigestEffectiveTruncatedReasonBucketHiddenStrategyOrder(shape)
	order := make([]string, 0, len(effectiveOrder))
	priority := 1
	summaries := make([]limitClassDigestHiddenStrategySummary, 0, len(effectiveOrder))
	for _, strategyName := range effectiveOrder {
		var (
			strategy map[string]interface{}
			active   bool
			hidden   int
			items    int
		)
		switch strategyName {
		case "exact_severity":
			active = len(shape.truncatedReasonBucketSeverities) > 0
			if active {
				mode := limitClassDigestHiddenStrategyDominantModeForStrategy(shape, strategyName)
				score, contributions := limitClassDigestHiddenStrategyScore(shape, strategyName, priority, exactSeverityReasonCount, exactSeverityItemCount)
				eligible := limitClassDigestHiddenStrategyEligible(shape, strategyName, exactSeverityReasonCount, exactSeverityItemCount)
				strategy = map[string]interface{}{
					"active":                    true,
					"dominant_mode":             mode,
					"priority":                  priority,
					"score":                     score,
					"score_contributions":       contributions,
					"eligible_for_dominance":    eligible,
					"eligibility_thresholds":    limitClassDigestHiddenStrategyEligibilityThresholds(shape, strategyName),
					"severities":                shape.truncatedReasonBucketSeverityList,
					"hidden_reason_count":       exactSeverityReasonCount,
					"hidden_bucket_class_count": exactSeverityClassCount,
					"hidden_" + itemField:       exactSeverityItemCount,
				}
				hidden = exactSeverityReasonCount
				items = exactSeverityItemCount
				summaries = append(summaries, limitClassDigestHiddenStrategySummary{name: strategyName, mode: mode, priority: priority, hiddenCount: hidden, hiddenItems: items, score: score, eligible: eligible})
			}
		case "min_severity":
			active = shape.truncatedReasonBucketMinSeverity != ""
			if active {
				mode := limitClassDigestHiddenStrategyDominantModeForStrategy(shape, strategyName)
				score, contributions := limitClassDigestHiddenStrategyScore(shape, strategyName, priority, minSeverityReasonCount, minSeverityItemCount)
				eligible := limitClassDigestHiddenStrategyEligible(shape, strategyName, minSeverityReasonCount, minSeverityItemCount)
				strategy = map[string]interface{}{
					"active":                    true,
					"dominant_mode":             mode,
					"priority":                  priority,
					"score":                     score,
					"score_contributions":       contributions,
					"eligible_for_dominance":    eligible,
					"eligibility_thresholds":    limitClassDigestHiddenStrategyEligibilityThresholds(shape, strategyName),
					"min_severity":              shape.truncatedReasonBucketMinSeverity,
					"hidden_reason_count":       minSeverityReasonCount,
					"hidden_bucket_class_count": minSeverityClassCount,
					"hidden_" + itemField:       minSeverityItemCount,
				}
				hidden = minSeverityReasonCount
				items = minSeverityItemCount
				summaries = append(summaries, limitClassDigestHiddenStrategySummary{name: strategyName, mode: mode, priority: priority, hiddenCount: hidden, hiddenItems: items, score: score, eligible: eligible})
			}
		case "max_reasons":
			active = shape.truncatedReasonBucketMaxReasons > 0
			if active {
				mode := limitClassDigestHiddenStrategyDominantModeForStrategy(shape, strategyName)
				score, contributions := limitClassDigestHiddenStrategyScore(shape, strategyName, priority, maxReasonsReasonCount, maxReasonsItemCount)
				eligible := limitClassDigestHiddenStrategyEligible(shape, strategyName, maxReasonsReasonCount, maxReasonsItemCount)
				strategy = map[string]interface{}{
					"active":                    true,
					"dominant_mode":             mode,
					"priority":                  priority,
					"score":                     score,
					"score_contributions":       contributions,
					"eligible_for_dominance":    eligible,
					"eligibility_thresholds":    limitClassDigestHiddenStrategyEligibilityThresholds(shape, strategyName),
					"max_reasons":               shape.truncatedReasonBucketMaxReasons,
					"item_field":                itemField,
					"hidden_reason_count":       maxReasonsReasonCount,
					"hidden_bucket_class_count": maxReasonsClassCount,
					"hidden_" + itemField:       maxReasonsItemCount,
				}
				hidden = maxReasonsReasonCount
				items = maxReasonsItemCount
				summaries = append(summaries, limitClassDigestHiddenStrategySummary{name: strategyName, mode: mode, priority: priority, hiddenCount: hidden, hiddenItems: items, score: score, eligible: eligible})
			}
		}
		if !active {
			continue
		}
		strategy["affected"] = hidden > 0
		strategies[strategyName] = strategy
		order = append(order, strategyName)
		priority++
	}
	dominant := limitClassDigestDominantHiddenStrategyName(summaries)
	return strategies, order, dominant
}

func limitClassDigestDominantHiddenStrategyName(strategies []limitClassDigestHiddenStrategySummary) string {
	eligible := make([]limitClassDigestHiddenStrategySummary, 0, len(strategies))
	for _, strategy := range strategies {
		if strategy.eligible {
			eligible = append(eligible, strategy)
		}
	}
	if len(eligible) == 0 {
		return ""
	}
	best := eligible[0]
	for _, candidate := range eligible[1:] {
		if limitClassDigestHiddenStrategyDominanceValue(candidate) > limitClassDigestHiddenStrategyDominanceValue(best) ||
			(limitClassDigestHiddenStrategyDominanceValue(candidate) == limitClassDigestHiddenStrategyDominanceValue(best) && candidate.priority < best.priority) {
			best = candidate
		}
	}
	return best.name
}

func limitClassDigestHiddenStrategyDominanceValue(strategy limitClassDigestHiddenStrategySummary) int {
	switch strategy.mode {
	case "most_hidden_reasons":
		return strategy.hiddenCount
	case "most_hidden_items":
		return strategy.hiddenItems
	case "weighted_score":
		return strategy.score
	default:
		return 1000000 - strategy.priority
	}
}

func limitClassDigestHiddenStrategyDominantModeForStrategy(shape limitClassDigestReceiverShape, strategyName string) string {
	switch strategyName {
	case "exact_severity":
		if strings.TrimSpace(shape.truncatedReasonBucketExactSeverityDominantMode) != "" {
			return shape.truncatedReasonBucketExactSeverityDominantMode
		}
	case "min_severity":
		if strings.TrimSpace(shape.truncatedReasonBucketMinSeverityDominantMode) != "" {
			return shape.truncatedReasonBucketMinSeverityDominantMode
		}
	case "max_reasons":
		if strings.TrimSpace(shape.truncatedReasonBucketMaxReasonsDominantMode) != "" {
			return shape.truncatedReasonBucketMaxReasonsDominantMode
		}
	}
	return shape.truncatedReasonBucketHiddenStrategyDominantMode
}

func limitClassDigestHiddenStrategyEligible(shape limitClassDigestReceiverShape, strategyName string, hiddenReasonCount int, hiddenItemCount int) bool {
	thresholds := limitClassDigestHiddenStrategyEligibilityThresholds(shape, strategyName)
	if hiddenReasonCount < intValue(thresholds["min_reasons"]) {
		return false
	}
	if hiddenItemCount < intValue(thresholds["min_items"]) {
		return false
	}
	return true
}

func limitClassDigestHiddenStrategyEligibilityThresholds(shape limitClassDigestReceiverShape, strategyName string) map[string]interface{} {
	minReasons := shape.truncatedReasonBucketHiddenStrategyMinReasons
	minItems := shape.truncatedReasonBucketHiddenStrategyMinItems
	switch strategyName {
	case "exact_severity":
		if shape.truncatedReasonBucketExactSeverityMinReasons > 0 {
			minReasons = shape.truncatedReasonBucketExactSeverityMinReasons
		}
		if shape.truncatedReasonBucketExactSeverityMinItems > 0 {
			minItems = shape.truncatedReasonBucketExactSeverityMinItems
		}
	case "min_severity":
		if shape.truncatedReasonBucketMinSeverityMinReasons > 0 {
			minReasons = shape.truncatedReasonBucketMinSeverityMinReasons
		}
		if shape.truncatedReasonBucketMinSeverityMinItems > 0 {
			minItems = shape.truncatedReasonBucketMinSeverityMinItems
		}
	case "max_reasons":
		if shape.truncatedReasonBucketMaxReasonsMinReasons > 0 {
			minReasons = shape.truncatedReasonBucketMaxReasonsMinReasons
		}
		if shape.truncatedReasonBucketMaxReasonsMinItems > 0 {
			minItems = shape.truncatedReasonBucketMaxReasonsMinItems
		}
	}
	return map[string]interface{}{
		"min_reasons": minReasons,
		"min_items":   minItems,
	}
}

func limitClassDigestHiddenStrategyScore(shape limitClassDigestReceiverShape, strategyName string, priority int, hiddenReasonCount int, hiddenItemCount int) (int, map[string]interface{}) {
	orderBonus := len(limitClassDigestEffectiveTruncatedReasonBucketHiddenStrategyOrder(shape)) - priority + 1
	if orderBonus < 0 {
		orderBonus = 0
	}
	priorityWeight, reasonWeight, itemWeight := limitClassDigestHiddenStrategyWeightsForStrategy(shape, strategyName)
	priorityCap, reasonCap, itemCap := limitClassDigestHiddenStrategyCapsForStrategy(shape, strategyName)
	cappedPriority := limitClassDigestCappedWeightValue(orderBonus, priorityCap)
	cappedReasons := limitClassDigestCappedWeightValue(hiddenReasonCount, reasonCap)
	cappedItems := limitClassDigestCappedWeightValue(hiddenItemCount, itemCap)
	contributions := map[string]interface{}{
		"strategy":              strategyName,
		"priority_value":        orderBonus,
		"priority_capped_value": cappedPriority,
		"priority_weight":       priorityWeight,
		"priority_cap":          priorityCap,
		"reason_value":          hiddenReasonCount,
		"reason_capped_value":   cappedReasons,
		"reason_weight":         reasonWeight,
		"reason_cap":            reasonCap,
		"item_value":            hiddenItemCount,
		"item_capped_value":     cappedItems,
		"item_weight":           itemWeight,
		"item_cap":              itemCap,
	}
	score := cappedPriority*priorityWeight +
		cappedReasons*reasonWeight +
		cappedItems*itemWeight
	return score, contributions
}

func limitClassDigestHiddenStrategyWeightsForStrategy(shape limitClassDigestReceiverShape, strategyName string) (int, int, int) {
	priorityWeight := shape.truncatedReasonBucketHiddenStrategyPriorityWeight
	reasonWeight := shape.truncatedReasonBucketHiddenStrategyReasonWeight
	itemWeight := shape.truncatedReasonBucketHiddenStrategyItemWeight
	switch strategyName {
	case "exact_severity":
		if shape.truncatedReasonBucketExactSeverityPriorityWeight > 0 {
			priorityWeight = shape.truncatedReasonBucketExactSeverityPriorityWeight
		}
		if shape.truncatedReasonBucketExactSeverityReasonWeight > 0 {
			reasonWeight = shape.truncatedReasonBucketExactSeverityReasonWeight
		}
		if shape.truncatedReasonBucketExactSeverityItemWeight > 0 {
			itemWeight = shape.truncatedReasonBucketExactSeverityItemWeight
		}
	case "min_severity":
		if shape.truncatedReasonBucketMinSeverityPriorityWeight > 0 {
			priorityWeight = shape.truncatedReasonBucketMinSeverityPriorityWeight
		}
		if shape.truncatedReasonBucketMinSeverityReasonWeight > 0 {
			reasonWeight = shape.truncatedReasonBucketMinSeverityReasonWeight
		}
		if shape.truncatedReasonBucketMinSeverityItemWeight > 0 {
			itemWeight = shape.truncatedReasonBucketMinSeverityItemWeight
		}
	case "max_reasons":
		if shape.truncatedReasonBucketMaxReasonsPriorityWeight > 0 {
			priorityWeight = shape.truncatedReasonBucketMaxReasonsPriorityWeight
		}
		if shape.truncatedReasonBucketMaxReasonsReasonWeight > 0 {
			reasonWeight = shape.truncatedReasonBucketMaxReasonsReasonWeight
		}
		if shape.truncatedReasonBucketMaxReasonsItemWeight > 0 {
			itemWeight = shape.truncatedReasonBucketMaxReasonsItemWeight
		}
	}
	return priorityWeight, reasonWeight, itemWeight
}

func limitClassDigestHiddenStrategyCapsForStrategy(shape limitClassDigestReceiverShape, strategyName string) (int, int, int) {
	priorityCap := shape.truncatedReasonBucketHiddenStrategyPriorityCap
	reasonCap := shape.truncatedReasonBucketHiddenStrategyReasonCap
	itemCap := shape.truncatedReasonBucketHiddenStrategyItemCap
	switch strategyName {
	case "exact_severity":
		if shape.truncatedReasonBucketExactSeverityPriorityCap > 0 {
			priorityCap = shape.truncatedReasonBucketExactSeverityPriorityCap
		}
		if shape.truncatedReasonBucketExactSeverityReasonCap > 0 {
			reasonCap = shape.truncatedReasonBucketExactSeverityReasonCap
		}
		if shape.truncatedReasonBucketExactSeverityItemCap > 0 {
			itemCap = shape.truncatedReasonBucketExactSeverityItemCap
		}
	case "min_severity":
		if shape.truncatedReasonBucketMinSeverityPriorityCap > 0 {
			priorityCap = shape.truncatedReasonBucketMinSeverityPriorityCap
		}
		if shape.truncatedReasonBucketMinSeverityReasonCap > 0 {
			reasonCap = shape.truncatedReasonBucketMinSeverityReasonCap
		}
		if shape.truncatedReasonBucketMinSeverityItemCap > 0 {
			itemCap = shape.truncatedReasonBucketMinSeverityItemCap
		}
	case "max_reasons":
		if shape.truncatedReasonBucketMaxReasonsPriorityCap > 0 {
			priorityCap = shape.truncatedReasonBucketMaxReasonsPriorityCap
		}
		if shape.truncatedReasonBucketMaxReasonsReasonCap > 0 {
			reasonCap = shape.truncatedReasonBucketMaxReasonsReasonCap
		}
		if shape.truncatedReasonBucketMaxReasonsItemCap > 0 {
			itemCap = shape.truncatedReasonBucketMaxReasonsItemCap
		}
	}
	return priorityCap, reasonCap, itemCap
}

func limitClassDigestCappedWeightValue(value int, cap int) int {
	if cap > 0 && value > cap {
		return cap
	}
	return value
}

func limitClassDigestOverflowReasonStatsFromRows(rows []interface{}, visibleReasons map[string]limitClassDigestOverflowReasonStat, labels map[string]string, groups map[string]string) map[string]limitClassDigestOverflowReasonStat {
	if len(rows) == 0 || len(visibleReasons) == 0 {
		return nil
	}
	allowedDisplayReasons := make(map[string]struct{}, len(rows))
	for _, rowValue := range rows {
		row, _ := rowValue.(map[string]interface{})
		allowedDisplayReasons[strings.TrimSpace(fmt.Sprint(row["reason"]))] = struct{}{}
	}
	filtered := make(map[string]limitClassDigestOverflowReasonStat)
	for rawReason, stat := range visibleReasons {
		displayReason := limitClassDigestDisplayOverflowReasonGroup(labels, groups, rawReason)
		if _, ok := allowedDisplayReasons[displayReason]; ok {
			filtered[rawReason] = stat
		}
	}
	if len(filtered) == 0 {
		return nil
	}
	return filtered
}

func limitClassDigestOverflowReasonEntries(otherReasons map[string]limitClassDigestOverflowReasonStat, itemField string, labels map[string]string, groups map[string]string) []interface{} {
	if len(otherReasons) == 0 {
		return []interface{}{}
	}
	order := []string{"low_severity", "low_priority", "low_count", "max_summary_budget"}
	grouped := make([]map[string]interface{}, 0, len(otherReasons))
	indexByReason := make(map[string]int, len(otherReasons))
	for _, reason := range order {
		stat, ok := otherReasons[reason]
		if !ok {
			continue
		}
		displayReason := limitClassDigestDisplayOverflowReasonGroup(labels, groups, reason)
		if idx, ok := indexByReason[displayReason]; ok {
			row := grouped[idx]
			row["bucket_class_count"] = intValue(row["bucket_class_count"]) + stat.ClassCount
			row[itemField] = intValue(row[itemField]) + stat.ItemCount
			row["severity"] = strongerSeverity(fmt.Sprint(row["severity"]), stat.MaxSeverity)
			row["raw_reasons"] = append(row["raw_reasons"].([]string), reason)
			continue
		}
		indexByReason[displayReason] = len(grouped)
		grouped = append(grouped, map[string]interface{}{
			"reason":             displayReason,
			"raw_reason":         reason,
			"raw_reasons":        []string{reason},
			"bucket_class_count": stat.ClassCount,
			itemField:            stat.ItemCount,
			"severity":           stat.MaxSeverity,
		})
	}
	rows := make([]interface{}, 0, len(grouped))
	for _, row := range grouped {
		rows = append(rows, row)
	}
	return rows
}

func limitClassDigestVisibleOverflowReasons(allowed map[string]struct{}, otherReasons map[string]limitClassDigestOverflowReasonStat) map[string]limitClassDigestOverflowReasonStat {
	if len(allowed) == 0 || len(otherReasons) == 0 {
		return otherReasons
	}
	filtered := make(map[string]limitClassDigestOverflowReasonStat, len(otherReasons))
	for reason, stat := range otherReasons {
		if _, ok := allowed[reason]; ok {
			filtered[reason] = stat
		}
	}
	return filtered
}

func limitClassDigestVisibleOverflowReasonEntries(allowed map[string]struct{}, otherReasons map[string]limitClassDigestOverflowReasonStat, itemField string) ([]interface{}, int, int, int) {
	visibleReasons := limitClassDigestVisibleOverflowReasons(allowed, otherReasons)
	rows := limitClassDigestOverflowReasonEntries(visibleReasons, itemField, nil, nil)
	hiddenReasonCount := 0
	hiddenClassCount := 0
	hiddenItemCount := 0
	for reason, stat := range otherReasons {
		if _, ok := visibleReasons[reason]; ok {
			continue
		}
		hiddenReasonCount++
		hiddenClassCount += stat.ClassCount
		hiddenItemCount += stat.ItemCount
	}
	return rows, hiddenReasonCount, hiddenClassCount, hiddenItemCount
}

func limitClassDigestVisibleOverflowReasonEntriesWithLabels(allowed map[string]struct{}, otherReasons map[string]limitClassDigestOverflowReasonStat, itemField string, labels map[string]string, groups map[string]string, order []string) ([]interface{}, int, int, int) {
	visibleReasons := limitClassDigestVisibleOverflowReasons(allowed, otherReasons)
	rows := limitClassDigestOverflowReasonEntries(visibleReasons, itemField, labels, groups)
	sortLimitClassDigestOverflowReasonRows(rows, order)
	hiddenReasonCount := 0
	hiddenClassCount := 0
	hiddenItemCount := 0
	for reason, stat := range otherReasons {
		if _, ok := visibleReasons[reason]; ok {
			continue
		}
		hiddenReasonCount++
		hiddenClassCount += stat.ClassCount
		hiddenItemCount += stat.ItemCount
	}
	return rows, hiddenReasonCount, hiddenClassCount, hiddenItemCount
}

func sortLimitClassDigestOverflowReasonRows(rows []interface{}, order []string) {
	if len(rows) <= 1 || len(order) == 0 {
		return
	}
	rank := make(map[string]int, len(order))
	for idx, label := range order {
		rank[strings.TrimSpace(label)] = idx
	}
	sort.SliceStable(rows, func(i, j int) bool {
		left, _ := rows[i].(map[string]interface{})
		right, _ := rows[j].(map[string]interface{})
		leftReason := strings.TrimSpace(fmt.Sprint(left["reason"]))
		rightReason := strings.TrimSpace(fmt.Sprint(right["reason"]))
		leftRank, leftOK := rank[leftReason]
		rightRank, rightOK := rank[rightReason]
		switch {
		case leftOK && rightOK:
			return leftRank < rightRank
		case leftOK:
			return true
		case rightOK:
			return false
		default:
			return leftReason < rightReason
		}
	})
}

func sortLimitClassDigestOverflowReasonRowsForNestedBucket(rows []interface{}, order []string, sortMode string) {
	if len(rows) <= 1 {
		return
	}
	switch normalizedLimitClassDigestTruncatedReasonBucketSortMode(sortMode) {
	case "severity_first":
		sort.SliceStable(rows, func(i, j int) bool {
			left, _ := rows[i].(map[string]interface{})
			right, _ := rows[j].(map[string]interface{})
			leftSeverity := slaBreachTierRank(normalizeSLABreachTier(fmt.Sprint(left["severity"])))
			rightSeverity := slaBreachTierRank(normalizeSLABreachTier(fmt.Sprint(right["severity"])))
			if leftSeverity != rightSeverity {
				return leftSeverity > rightSeverity
			}
			if orderLess, decided := limitClassDigestOverflowReasonRowOrderLess(left, right, order); decided {
				return orderLess
			}
			leftCount := intValue(left["bucket_class_count"])
			rightCount := intValue(right["bucket_class_count"])
			if leftCount != rightCount {
				return leftCount > rightCount
			}
			return strings.TrimSpace(fmt.Sprint(left["reason"])) < strings.TrimSpace(fmt.Sprint(right["reason"]))
		})
	case "count_first":
		sort.SliceStable(rows, func(i, j int) bool {
			left, _ := rows[i].(map[string]interface{})
			right, _ := rows[j].(map[string]interface{})
			leftCount := intValue(left["bucket_class_count"])
			rightCount := intValue(right["bucket_class_count"])
			if leftCount != rightCount {
				return leftCount > rightCount
			}
			if orderLess, decided := limitClassDigestOverflowReasonRowOrderLess(left, right, order); decided {
				return orderLess
			}
			leftSeverity := slaBreachTierRank(normalizeSLABreachTier(fmt.Sprint(left["severity"])))
			rightSeverity := slaBreachTierRank(normalizeSLABreachTier(fmt.Sprint(right["severity"])))
			if leftSeverity != rightSeverity {
				return leftSeverity > rightSeverity
			}
			return strings.TrimSpace(fmt.Sprint(left["reason"])) < strings.TrimSpace(fmt.Sprint(right["reason"]))
		})
	default:
		if len(order) > 0 {
			sortLimitClassDigestOverflowReasonRows(rows, order)
		}
	}
}

func limitClassDigestOverflowReasonRowOrderLess(left, right map[string]interface{}, order []string) (bool, bool) {
	if len(order) == 0 {
		return false, false
	}
	rank := make(map[string]int, len(order))
	for idx, label := range order {
		rank[strings.TrimSpace(label)] = idx
	}
	leftReason := strings.TrimSpace(fmt.Sprint(left["reason"]))
	rightReason := strings.TrimSpace(fmt.Sprint(right["reason"]))
	leftRank, leftOK := rank[leftReason]
	rightRank, rightOK := rank[rightReason]
	switch {
	case leftOK && rightOK:
		return leftRank < rightRank, true
	case leftOK:
		return true, true
	case rightOK:
		return false, true
	default:
		return false, false
	}
}

func limitClassDigestOverflowDominantReason(otherReasons map[string]limitClassDigestOverflowReasonStat) string {
	return limitClassDigestOverflowDominantReasonWithStrategy(otherReasons, "default")
}

func limitClassDigestOverflowDominantReasonWithStrategy(otherReasons map[string]limitClassDigestOverflowReasonStat, strategy string) string {
	bestReason := ""
	bestItems := -1
	bestClasses := -1
	bestSeverity := -1
	order := []string{"low_severity", "low_priority", "low_count", "max_summary_budget"}
	for _, reason := range order {
		stat, ok := otherReasons[reason]
		if !ok {
			continue
		}
		severityRank := slaBreachTierRank(normalizeSLABreachTier(stat.MaxSeverity))
		switch normalizedLimitClassDigestTruncatedReasonBucketDominantReasonStrategy(strategy) {
		case "severity_first":
			if severityRank > bestSeverity ||
				(severityRank == bestSeverity && stat.ItemCount > bestItems) ||
				(severityRank == bestSeverity && stat.ItemCount == bestItems && stat.ClassCount > bestClasses) {
				bestReason = reason
				bestSeverity = severityRank
				bestItems = stat.ItemCount
				bestClasses = stat.ClassCount
			}
		case "count_first":
			if stat.ClassCount > bestClasses ||
				(stat.ClassCount == bestClasses && stat.ItemCount > bestItems) ||
				(stat.ClassCount == bestClasses && stat.ItemCount == bestItems && severityRank > bestSeverity) {
				bestReason = reason
				bestSeverity = severityRank
				bestItems = stat.ItemCount
				bestClasses = stat.ClassCount
			}
		default:
			if stat.ItemCount > bestItems || (stat.ItemCount == bestItems && stat.ClassCount > bestClasses) {
				bestReason = reason
				bestSeverity = severityRank
				bestItems = stat.ItemCount
				bestClasses = stat.ClassCount
			}
		}
	}
	return bestReason
}

func limitClassDigestDisplayOverflowReason(labels map[string]string, rawReason string) string {
	if label := strings.TrimSpace(labels[rawReason]); label != "" {
		return label
	}
	return rawReason
}

func limitClassDigestDisplayOverflowReasonGroup(labels map[string]string, groups map[string]string, rawReason string) string {
	if group := strings.TrimSpace(groups[rawReason]); group != "" {
		return group
	}
	return limitClassDigestDisplayOverflowReason(labels, rawReason)
}
