package api

import (
	"fmt"
	"strings"
)

func (api *ManagementAPI) filterLimitClassDigestItems(items []interface{}, shape limitClassDigestReceiverShape) ([]interface{}, map[string]limitClassDigestSummaryStat) {
	eligibleByClass := api.limitClassDigestEligibleDetailedCounts(items, shape)
	allowedDetailedClasses := api.limitClassAllowedDetailedClasses(eligibleByClass, shape.maxClasses)

	filtered := make([]interface{}, 0, len(items))
	summarizedByClass := make(map[string]limitClassDigestSummaryStat)
	for _, item := range items {
		entry, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		bucketClass := notificationPayloadBucketClass(entry)
		if !api.limitClassDigestItemIncluded(entry, bucketClass, shape, allowedDetailedClasses) {
			api.bumpLimitClassDigestSummaryStat(summarizedByClass, bucketClass, normalizeSLABreachTier(fmt.Sprint(entry["severity"])))
			continue
		}
		filtered = append(filtered, item)
	}
	return filtered, summarizedByClass
}

func (api *ManagementAPI) limitClassDigestEligibleDetailedCounts(items []interface{}, shape limitClassDigestReceiverShape) map[string]int {
	eligibleByClass := make(map[string]int)
	for _, item := range items {
		entry, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		bucketClass := notificationPayloadBucketClass(entry)
		if !notificationPayloadMeetsSeverityFilters(entry, shape) {
			continue
		}
		if !api.limitClassPriorityIncludedInDigest(bucketClass, shape.minPriority) {
			continue
		}
		eligibleByClass[bucketClass]++
	}
	return eligibleByClass
}

func (api *ManagementAPI) limitClassDigestItemIncluded(entry map[string]interface{}, bucketClass string, shape limitClassDigestReceiverShape, allowedDetailedClasses map[string]struct{}) bool {
	if !notificationPayloadMeetsSeverityFilters(entry, shape) {
		return false
	}
	if !api.limitClassPriorityIncludedInDigest(bucketClass, shape.minPriority) {
		return false
	}
	if len(allowedDetailedClasses) == 0 {
		return true
	}
	_, ok := allowedDetailedClasses[bucketClass]
	return ok
}

func notificationPayloadBucketClass(entry map[string]interface{}) string {
	bucketClass := strings.TrimSpace(fmt.Sprint(entry["bucket_class"]))
	if bucketClass == "" {
		return "unknown"
	}
	return bucketClass
}

func notificationPayloadMeetsSeverityFilters(entry map[string]interface{}, shape limitClassDigestReceiverShape) bool {
	severity := normalizeSLABreachTier(fmt.Sprint(entry["severity"]))
	if len(shape.allowedSeverities) > 0 {
		if _, ok := shape.allowedSeverities[severity]; !ok {
			return false
		}
	}
	if shape.minSeverity == "" {
		return true
	}
	return slaBreachTierRank(severity) >= slaBreachTierRank(shape.minSeverity)
}
