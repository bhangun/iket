package api

import (
	"fmt"
	"sort"
	"strings"

	"github.com/bhangun/iket/pkg/core/gateway"
)

func (api *ManagementAPI) splitLimitClassAlertDigestRows(alerts []gateway.RouteLimitClassAlert, minPriority, maxClasses int) ([]gateway.RouteLimitClassAlert, []map[string]interface{}) {
	eligibleByClass := make(map[string]int)
	for _, alert := range alerts {
		if api.limitClassPriorityIncludedInDigest(alert.BucketClass, minPriority) {
			eligibleByClass[normalizedLimitClassBucketClass(alert.BucketClass)]++
		}
	}

	allowedDetailedClasses := api.limitClassAllowedDetailedClasses(eligibleByClass, maxClasses)
	detailed := make([]gateway.RouteLimitClassAlert, 0, len(alerts))
	summarizedByClass := make(map[string]int)
	for _, alert := range alerts {
		bucketClass := normalizedLimitClassBucketClass(alert.BucketClass)
		if !api.limitClassPriorityIncludedInDigest(alert.BucketClass, minPriority) {
			summarizedByClass[bucketClass]++
			continue
		}
		if !limitClassDigestDetailedClassAllowed(bucketClass, allowedDetailedClasses) {
			summarizedByClass[bucketClass]++
			continue
		}
		detailed = append(detailed, alert)
	}
	return detailed, api.limitClassDigestSummaryEntries(summarizedByClass)
}

func (api *ManagementAPI) splitLimitClassSnoozeDigestRows(snoozes []map[string]interface{}, minPriority, maxClasses int) ([]map[string]interface{}, []map[string]interface{}) {
	eligibleByClass := make(map[string]int)
	for _, snooze := range snoozes {
		bucketClass := normalizedLimitClassBucketClass(fmt.Sprint(snooze["bucket_class"]))
		if api.limitClassSnoozeIncludedInDigest(bucketClass) && api.limitClassPriorityIncludedInDigest(bucketClass, minPriority) {
			eligibleByClass[bucketClass]++
		}
	}

	allowedDetailedClasses := api.limitClassAllowedDetailedClasses(eligibleByClass, maxClasses)
	detailed := make([]map[string]interface{}, 0, len(snoozes))
	summarizedByClass := make(map[string]int)
	for _, snooze := range snoozes {
		bucketClass := normalizedLimitClassBucketClass(fmt.Sprint(snooze["bucket_class"]))
		if !api.limitClassSnoozeIncludedInDigest(bucketClass) || !api.limitClassPriorityIncludedInDigest(bucketClass, minPriority) {
			summarizedByClass[bucketClass]++
			continue
		}
		if !limitClassDigestDetailedClassAllowed(bucketClass, allowedDetailedClasses) {
			summarizedByClass[bucketClass]++
			continue
		}
		detailed = append(detailed, snooze)
	}
	return detailed, api.limitClassDigestSummaryEntries(summarizedByClass)
}

func (api *ManagementAPI) limitAlertBucketClassPriority(bucketClass string) int {
	if api == nil || api.gateway == nil {
		return 0
	}
	cfg := api.gateway.GetConfig()
	if cfg == nil {
		return 0
	}
	classConfig, ok := cfg.Security.LimitAlertBucketClasses[strings.TrimSpace(bucketClass)]
	if !ok {
		return 0
	}
	return classConfig.Priority
}

func (api *ManagementAPI) limitClassPriorityIncludedInDigest(bucketClass string, minPriority int) bool {
	if minPriority <= 0 {
		return true
	}
	return api.limitAlertBucketClassPriority(bucketClass) >= minPriority
}

func (api *ManagementAPI) limitClassAllowedDetailedClasses(counts map[string]int, maxClasses int) map[string]struct{} {
	if maxClasses <= 0 || len(counts) == 0 {
		return nil
	}
	summary := api.limitClassDigestSummaryEntries(counts)
	if len(summary) <= maxClasses {
		return nil
	}
	allowed := make(map[string]struct{}, maxClasses)
	for i, entry := range summary {
		if i >= maxClasses {
			break
		}
		allowed[strings.TrimSpace(fmt.Sprint(entry["bucket_class"]))] = struct{}{}
	}
	return allowed
}

func (api *ManagementAPI) limitClassDigestSummaryEntries(counts map[string]int) []map[string]interface{} {
	summary := make([]map[string]interface{}, 0, len(counts))
	for bucketClass, count := range counts {
		summary = append(summary, map[string]interface{}{
			"bucket_class": bucketClass,
			"count":        count,
			"priority":     api.limitAlertBucketClassPriority(bucketClass),
		})
	}
	sort.Slice(summary, func(i, j int) bool {
		leftPriority := intValue(summary[i]["priority"])
		rightPriority := intValue(summary[j]["priority"])
		if leftPriority != rightPriority {
			return leftPriority > rightPriority
		}
		leftCount := intValue(summary[i]["count"])
		rightCount := intValue(summary[j]["count"])
		if leftCount == rightCount {
			return strings.TrimSpace(fmt.Sprint(summary[i]["bucket_class"])) < strings.TrimSpace(fmt.Sprint(summary[j]["bucket_class"]))
		}
		return leftCount > rightCount
	})
	return summary
}

func limitClassDigestDetailedClassAllowed(bucketClass string, allowedDetailedClasses map[string]struct{}) bool {
	if len(allowedDetailedClasses) == 0 {
		return true
	}
	_, ok := allowedDetailedClasses[bucketClass]
	return ok
}

func normalizedLimitClassBucketClass(bucketClass string) string {
	normalized := strings.TrimSpace(bucketClass)
	if normalized == "" {
		return "unknown"
	}
	return normalized
}
