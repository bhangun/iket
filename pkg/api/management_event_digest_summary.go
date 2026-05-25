package api

import (
	"fmt"
	"sort"
	"strings"
)

type limitClassDigestSummaryStat struct {
	Count       int
	MaxSeverity string
}

type limitClassDigestOverflowReasonStat struct {
	ClassCount  int
	ItemCount   int
	MaxSeverity string
}

func (api *ManagementAPI) limitClassDigestAllItemsByClass(items []interface{}) map[string]limitClassDigestSummaryStat {
	counts := make(map[string]limitClassDigestSummaryStat)
	for _, item := range items {
		entry, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		bucketClass := notificationPayloadBucketClass(entry)
		api.bumpLimitClassDigestSummaryStat(counts, bucketClass, normalizeSLABreachTier(fmt.Sprint(entry["severity"])))
	}
	return counts
}

func (api *ManagementAPI) limitClassDigestSummaryEntriesWithBudget(counts map[string]limitClassDigestSummaryStat, minSummarySeverity string, minSummaryPriority, minSummaryCount, maxSummaryClasses int, sortMode string) ([]interface{}, int, int, map[string]limitClassDigestOverflowReasonStat) {
	summary := api.limitClassDigestReceiverSummaryEntries(counts, sortMode)
	filtered := make([]map[string]interface{}, 0, len(summary))
	otherClassCount := 0
	otherItemCount := 0
	otherReasons := make(map[string]limitClassDigestOverflowReasonStat)
	for _, entry := range summary {
		if reasons := limitClassDigestSummaryOverflowReasons(entry, minSummarySeverity, minSummaryPriority, minSummaryCount); len(reasons) > 0 {
			otherClassCount, otherItemCount = addLimitClassDigestOverflowEntry(otherReasons, reasons, entry, otherClassCount, otherItemCount)
			continue
		}
		filtered = append(filtered, entry)
	}
	if maxSummaryClasses <= 0 || len(filtered) <= maxSummaryClasses {
		return notificationPayloadRows(filtered), otherClassCount, otherItemCount, otherReasons
	}
	for _, entry := range filtered[maxSummaryClasses:] {
		otherClassCount, otherItemCount = addLimitClassDigestOverflowEntry(otherReasons, []string{"max_summary_budget"}, entry, otherClassCount, otherItemCount)
	}
	return notificationPayloadRows(filtered[:maxSummaryClasses]), otherClassCount, otherItemCount, otherReasons
}

func limitClassDigestSummaryOverflowReasons(entry map[string]interface{}, minSummarySeverity string, minSummaryPriority, minSummaryCount int) []string {
	reasons := make([]string, 0, 3)
	if limitClassDigestSummaryEntryBelowSeverity(entry, minSummarySeverity) {
		reasons = append(reasons, "low_severity")
	}
	if minSummaryPriority > 0 && intValue(entry["priority"]) < minSummaryPriority {
		reasons = append(reasons, "low_priority")
	}
	if minSummaryCount > 0 && intValue(entry["count"]) < minSummaryCount {
		reasons = append(reasons, "low_count")
	}
	return reasons
}

func limitClassDigestSummaryEntryBelowSeverity(entry map[string]interface{}, minSummarySeverity string) bool {
	if minSummarySeverity == "" {
		return false
	}
	severity := normalizeSLABreachTier(fmt.Sprint(entry["severity"]))
	return slaBreachTierRank(severity) < slaBreachTierRank(minSummarySeverity)
}

func (api *ManagementAPI) bumpLimitClassDigestSummaryStat(counts map[string]limitClassDigestSummaryStat, bucketClass, severity string) {
	stat := counts[bucketClass]
	stat.Count++
	stat.MaxSeverity = strongerSeverity(stat.MaxSeverity, severity)
	counts[bucketClass] = stat
}

func strongerSeverity(current, candidate string) string {
	if slaBreachTierRank(candidate) > slaBreachTierRank(current) {
		return candidate
	}
	return current
}

func (api *ManagementAPI) limitClassDigestReceiverSummaryEntries(counts map[string]limitClassDigestSummaryStat, sortMode string) []map[string]interface{} {
	summary := make([]map[string]interface{}, 0, len(counts))
	for bucketClass, stat := range counts {
		summary = append(summary, map[string]interface{}{
			"bucket_class": bucketClass,
			"count":        stat.Count,
			"priority":     api.limitAlertBucketClassPriority(bucketClass),
			"severity":     stat.MaxSeverity,
		})
	}
	sortMode = normalizedLimitClassDigestSummarySortMode(sortMode)
	sort.Slice(summary, func(i, j int) bool {
		return limitClassDigestSummaryEntryLess(summary[i], summary[j], sortMode)
	})
	return summary
}

type limitClassDigestSummarySortKey func(left, right map[string]interface{}) int

var limitClassDigestSummarySortModes = map[string][]limitClassDigestSummarySortKey{
	"priority_first": {
		compareLimitClassDigestSummaryPriority,
		compareLimitClassDigestSummarySeverity,
		compareLimitClassDigestSummaryCount,
	},
	"severity_first": {
		compareLimitClassDigestSummarySeverity,
		compareLimitClassDigestSummaryPriority,
		compareLimitClassDigestSummaryCount,
	},
	"count_first": {
		compareLimitClassDigestSummaryCount,
		compareLimitClassDigestSummaryPriority,
		compareLimitClassDigestSummarySeverity,
	},
}

func limitClassDigestSummaryEntryLess(left, right map[string]interface{}, sortMode string) bool {
	for _, sortKey := range limitClassDigestSummarySortKeys(sortMode) {
		if comparison := sortKey(left, right); comparison != 0 {
			return comparison > 0
		}
	}
	return limitClassDigestSummaryBucketClass(left) < limitClassDigestSummaryBucketClass(right)
}

func limitClassDigestSummarySortKeys(sortMode string) []limitClassDigestSummarySortKey {
	keys := limitClassDigestSummarySortModes[normalizedLimitClassDigestSummarySortMode(sortMode)]
	if len(keys) == 0 {
		return limitClassDigestSummarySortModes["priority_first"]
	}
	return keys
}

func compareLimitClassDigestSummaryPriority(left, right map[string]interface{}) int {
	return intValue(left["priority"]) - intValue(right["priority"])
}

func compareLimitClassDigestSummarySeverity(left, right map[string]interface{}) int {
	leftSeverity := slaBreachTierRank(normalizeSLABreachTier(fmt.Sprint(left["severity"])))
	rightSeverity := slaBreachTierRank(normalizeSLABreachTier(fmt.Sprint(right["severity"])))
	return leftSeverity - rightSeverity
}

func compareLimitClassDigestSummaryCount(left, right map[string]interface{}) int {
	return intValue(left["count"]) - intValue(right["count"])
}

func limitClassDigestSummaryBucketClass(entry map[string]interface{}) string {
	return strings.TrimSpace(fmt.Sprint(entry["bucket_class"]))
}

func addLimitClassDigestOverflowEntry(otherReasons map[string]limitClassDigestOverflowReasonStat, reasons []string, entry map[string]interface{}, otherClassCount, otherItemCount int) (int, int) {
	itemCount := intValue(entry["count"])
	severity := normalizeSLABreachTier(fmt.Sprint(entry["severity"]))
	otherClassCount++
	otherItemCount += itemCount
	for _, reason := range reasons {
		addLimitClassDigestOverflowReason(otherReasons, reason, itemCount, severity)
	}
	return otherClassCount, otherItemCount
}

func addLimitClassDigestOverflowReason(otherReasons map[string]limitClassDigestOverflowReasonStat, reason string, itemCount int, severity string) {
	stat := otherReasons[reason]
	stat.ClassCount++
	stat.ItemCount += itemCount
	stat.MaxSeverity = strongerSeverity(stat.MaxSeverity, severity)
	otherReasons[reason] = stat
}
