package api

import (
	"strings"

	"github.com/bhangun/iket/pkg/config"
)

type limitClassDigestReceiverShape struct {
	digestType                                         string
	allowedDigestTypes                                 map[string]struct{}
	allowedDigestTypeList                              []string
	summaryOnlyDigestTypeList                          []string
	minSeverity                                        string
	allowedSeverities                                  map[string]struct{}
	allowedSeverityList                                []string
	minPriority                                        int
	maxClasses                                         int
	minSummarySeverity                                 string
	minSummaryPriority                                 int
	summarySortMode                                    string
	minSummaryCount                                    int
	otherBucketLabel                                   string
	allowedOverflowReasons                             map[string]struct{}
	allowedOverflowReasonList                          []string
	overflowReasonLabels                               map[string]string
	overflowReasonGroups                               map[string][]string
	overflowReasonGroupByRaw                           map[string]string
	overflowReasonOrder                                []string
	maxOverflowReasons                                 int
	truncatedReasonBucketLabel                         string
	truncatedReasonBucketMode                          string
	truncatedReasonBucketMaxReasons                    int
	truncatedReasonBucketReasonOrder                   []string
	truncatedReasonBucketMinSeverity                   string
	truncatedReasonBucketSeverities                    map[string]struct{}
	truncatedReasonBucketSeverityList                  []string
	truncatedReasonBucketSortMode                      string
	truncatedReasonBucketDominantReasonStrategy        string
	truncatedReasonBucketHiddenStrategyOrder           []string
	truncatedReasonBucketHiddenStrategyDominantMode    string
	truncatedReasonBucketHiddenStrategyPriorityWeight  int
	truncatedReasonBucketHiddenStrategyReasonWeight    int
	truncatedReasonBucketHiddenStrategyItemWeight      int
	truncatedReasonBucketHiddenStrategyPriorityCap     int
	truncatedReasonBucketHiddenStrategyReasonCap       int
	truncatedReasonBucketHiddenStrategyItemCap         int
	truncatedReasonBucketHiddenStrategyMinReasons      int
	truncatedReasonBucketHiddenStrategyMinItems        int
	truncatedReasonBucketExactSeverityPriorityCap      int
	truncatedReasonBucketExactSeverityReasonCap        int
	truncatedReasonBucketExactSeverityItemCap          int
	truncatedReasonBucketExactSeverityPriorityWeight   int
	truncatedReasonBucketExactSeverityReasonWeight     int
	truncatedReasonBucketExactSeverityItemWeight       int
	truncatedReasonBucketExactSeverityDominantMode     string
	truncatedReasonBucketExactSeverityMinReasons       int
	truncatedReasonBucketExactSeverityMinItems         int
	truncatedReasonBucketMinSeverityPriorityCap        int
	truncatedReasonBucketMinSeverityReasonCap          int
	truncatedReasonBucketMinSeverityItemCap            int
	truncatedReasonBucketMinSeverityPriorityWeight     int
	truncatedReasonBucketMinSeverityReasonWeight       int
	truncatedReasonBucketMinSeverityItemWeight         int
	truncatedReasonBucketMinSeverityDominantMode       string
	truncatedReasonBucketMinSeverityMinReasons         int
	truncatedReasonBucketMinSeverityMinItems           int
	truncatedReasonBucketMaxReasonsPriorityCap         int
	truncatedReasonBucketMaxReasonsReasonCap           int
	truncatedReasonBucketMaxReasonsItemCap             int
	truncatedReasonBucketMaxReasonsPriorityWeight      int
	truncatedReasonBucketMaxReasonsReasonWeight        int
	truncatedReasonBucketMaxReasonsItemWeight          int
	truncatedReasonBucketMaxReasonsDominantMode        string
	truncatedReasonBucketMaxReasonsMinReasons          int
	truncatedReasonBucketMaxReasonsMinItems            int
	hasTruncatedReasonBucketLabel                      bool
	hasTruncatedReasonBucketMode                       bool
	hasTruncatedReasonBucketSortMode                   bool
	hasTruncatedReasonBucketDominantReasonStrategy     bool
	hasTruncatedReasonBucketHiddenStrategyOrder        bool
	hasTruncatedReasonBucketHiddenStrategyDominantMode bool
	maxSummaryClasses                                  int
	summaryOnly                                        bool
}

func newLimitClassDigestReceiverShape(webhook config.NotificationWebhook, event string) limitClassDigestReceiverShape {
	digestType := limitClassDigestTypeFromEvent(event)
	summaryOnlyDigestTypes := normalizedLimitClassDigestTypes(webhook.LimitClassDigestSummaryOnlyTypes)
	_, summaryOnly := summaryOnlyDigestTypes[digestType]
	return limitClassDigestReceiverShape{
		digestType:                                         digestType,
		allowedDigestTypes:                                 normalizedLimitClassDigestTypes(webhook.LimitClassDigestTypes),
		allowedDigestTypeList:                              normalizedLimitClassDigestTypeList(webhook.LimitClassDigestTypes),
		summaryOnlyDigestTypeList:                          normalizedLimitClassDigestTypeList(webhook.LimitClassDigestSummaryOnlyTypes),
		minSeverity:                                        normalizeSLABreachTier(webhook.LimitClassDigestMinSeverity),
		allowedSeverities:                                  normalizedLimitClassDigestSeverities(webhook.LimitClassDigestSeverities),
		allowedSeverityList:                                normalizedLimitClassDigestSeverityList(webhook.LimitClassDigestSeverities),
		minPriority:                                        webhook.LimitClassDigestMinBucketClassPriority,
		maxClasses:                                         webhook.LimitClassDigestMaxBucketClasses,
		minSummarySeverity:                                 normalizeSLABreachTier(webhook.LimitClassDigestMinSummarySeverity),
		minSummaryPriority:                                 webhook.LimitClassDigestMinSummaryBucketClassPriority,
		summarySortMode:                                    normalizedLimitClassDigestSummarySortMode(webhook.LimitClassDigestSummarySortMode),
		minSummaryCount:                                    webhook.LimitClassDigestMinSummaryCount,
		otherBucketLabel:                                   normalizedLimitClassDigestOtherBucketLabel(webhook.LimitClassDigestOtherBucketLabel),
		allowedOverflowReasons:                             normalizedLimitClassDigestOverflowReasons(webhook.LimitClassDigestOverflowReasons),
		allowedOverflowReasonList:                          normalizedLimitClassDigestOverflowReasonList(webhook.LimitClassDigestOverflowReasons),
		overflowReasonLabels:                               normalizedLimitClassDigestOverflowReasonLabels(webhook.LimitClassDigestOverflowReasonLabels),
		overflowReasonGroups:                               normalizedLimitClassDigestOverflowReasonGroups(webhook.LimitClassDigestOverflowReasonGroups),
		overflowReasonGroupByRaw:                           normalizedLimitClassDigestOverflowReasonGroupByRaw(webhook.LimitClassDigestOverflowReasonGroups),
		overflowReasonOrder:                                normalizedLimitClassDigestOverflowReasonOrder(webhook.LimitClassDigestOverflowReasonOrder),
		maxOverflowReasons:                                 webhook.LimitClassDigestMaxOverflowReasons,
		truncatedReasonBucketLabel:                         normalizedLimitClassDigestTruncatedReasonBucketLabel(webhook.LimitClassDigestTruncatedReasonBucketLabel),
		truncatedReasonBucketMode:                          normalizedLimitClassDigestTruncatedReasonBucketMode(webhook.LimitClassDigestTruncatedReasonBucketMode),
		truncatedReasonBucketMaxReasons:                    webhook.LimitClassDigestTruncatedReasonBucketMaxReasons,
		truncatedReasonBucketReasonOrder:                   normalizedLimitClassDigestOverflowReasonOrder(webhook.LimitClassDigestTruncatedReasonBucketReasonOrder),
		truncatedReasonBucketMinSeverity:                   normalizeSLABreachTier(webhook.LimitClassDigestTruncatedReasonBucketMinSeverity),
		truncatedReasonBucketSeverities:                    normalizedLimitClassDigestSeverities(webhook.LimitClassDigestTruncatedReasonBucketSeverities),
		truncatedReasonBucketSeverityList:                  normalizedLimitClassDigestSeverityList(webhook.LimitClassDigestTruncatedReasonBucketSeverities),
		truncatedReasonBucketSortMode:                      normalizedLimitClassDigestTruncatedReasonBucketSortMode(webhook.LimitClassDigestTruncatedReasonBucketSortMode),
		truncatedReasonBucketDominantReasonStrategy:        normalizedLimitClassDigestTruncatedReasonBucketDominantReasonStrategy(webhook.LimitClassDigestTruncatedReasonBucketDominantReasonStrategy),
		truncatedReasonBucketHiddenStrategyOrder:           normalizedLimitClassDigestTruncatedReasonBucketHiddenStrategyOrder(webhook.LimitClassDigestTruncatedReasonBucketHiddenStrategyOrder),
		truncatedReasonBucketHiddenStrategyDominantMode:    normalizedLimitClassDigestTruncatedReasonBucketHiddenStrategyDominantMode(webhook.LimitClassDigestTruncatedReasonBucketHiddenStrategyDominantMode),
		truncatedReasonBucketHiddenStrategyPriorityWeight:  normalizedLimitClassDigestTruncatedReasonBucketHiddenStrategyWeight(webhook.LimitClassDigestTruncatedReasonBucketHiddenStrategyPriorityWeight),
		truncatedReasonBucketHiddenStrategyReasonWeight:    normalizedLimitClassDigestTruncatedReasonBucketHiddenStrategyWeight(webhook.LimitClassDigestTruncatedReasonBucketHiddenStrategyReasonWeight),
		truncatedReasonBucketHiddenStrategyItemWeight:      normalizedLimitClassDigestTruncatedReasonBucketHiddenStrategyWeight(webhook.LimitClassDigestTruncatedReasonBucketHiddenStrategyItemWeight),
		truncatedReasonBucketHiddenStrategyPriorityCap:     normalizedLimitClassDigestTruncatedReasonBucketHiddenStrategyWeight(webhook.LimitClassDigestTruncatedReasonBucketHiddenStrategyPriorityCap),
		truncatedReasonBucketHiddenStrategyReasonCap:       normalizedLimitClassDigestTruncatedReasonBucketHiddenStrategyWeight(webhook.LimitClassDigestTruncatedReasonBucketHiddenStrategyReasonCap),
		truncatedReasonBucketHiddenStrategyItemCap:         normalizedLimitClassDigestTruncatedReasonBucketHiddenStrategyWeight(webhook.LimitClassDigestTruncatedReasonBucketHiddenStrategyItemCap),
		truncatedReasonBucketHiddenStrategyMinReasons:      normalizedLimitClassDigestTruncatedReasonBucketHiddenStrategyWeight(webhook.LimitClassDigestTruncatedReasonBucketHiddenStrategyMinReasons),
		truncatedReasonBucketHiddenStrategyMinItems:        normalizedLimitClassDigestTruncatedReasonBucketHiddenStrategyWeight(webhook.LimitClassDigestTruncatedReasonBucketHiddenStrategyMinItems),
		truncatedReasonBucketExactSeverityPriorityCap:      resolvedLimitClassDigestHiddenStrategyPolicyInt(webhook.LimitClassDigestTruncatedReasonBucketExactSeverityPolicy, webhook.LimitClassDigestTruncatedReasonBucketExactSeverityPriorityCap, "priorityCap"),
		truncatedReasonBucketExactSeverityReasonCap:        resolvedLimitClassDigestHiddenStrategyPolicyInt(webhook.LimitClassDigestTruncatedReasonBucketExactSeverityPolicy, webhook.LimitClassDigestTruncatedReasonBucketExactSeverityReasonCap, "reasonCap"),
		truncatedReasonBucketExactSeverityItemCap:          resolvedLimitClassDigestHiddenStrategyPolicyInt(webhook.LimitClassDigestTruncatedReasonBucketExactSeverityPolicy, webhook.LimitClassDigestTruncatedReasonBucketExactSeverityItemCap, "itemCap"),
		truncatedReasonBucketExactSeverityPriorityWeight:   resolvedLimitClassDigestHiddenStrategyPolicyInt(webhook.LimitClassDigestTruncatedReasonBucketExactSeverityPolicy, webhook.LimitClassDigestTruncatedReasonBucketExactSeverityPriorityWeight, "priorityWeight"),
		truncatedReasonBucketExactSeverityReasonWeight:     resolvedLimitClassDigestHiddenStrategyPolicyInt(webhook.LimitClassDigestTruncatedReasonBucketExactSeverityPolicy, webhook.LimitClassDigestTruncatedReasonBucketExactSeverityReasonWeight, "reasonWeight"),
		truncatedReasonBucketExactSeverityItemWeight:       resolvedLimitClassDigestHiddenStrategyPolicyInt(webhook.LimitClassDigestTruncatedReasonBucketExactSeverityPolicy, webhook.LimitClassDigestTruncatedReasonBucketExactSeverityItemWeight, "itemWeight"),
		truncatedReasonBucketExactSeverityDominantMode:     resolvedLimitClassDigestHiddenStrategyPolicyMode(webhook.LimitClassDigestTruncatedReasonBucketExactSeverityPolicy, webhook.LimitClassDigestTruncatedReasonBucketExactSeverityDominantMode),
		truncatedReasonBucketExactSeverityMinReasons:       resolvedLimitClassDigestHiddenStrategyPolicyInt(webhook.LimitClassDigestTruncatedReasonBucketExactSeverityPolicy, webhook.LimitClassDigestTruncatedReasonBucketExactSeverityMinReasons, "minReasons"),
		truncatedReasonBucketExactSeverityMinItems:         resolvedLimitClassDigestHiddenStrategyPolicyInt(webhook.LimitClassDigestTruncatedReasonBucketExactSeverityPolicy, webhook.LimitClassDigestTruncatedReasonBucketExactSeverityMinItems, "minItems"),
		truncatedReasonBucketMinSeverityPriorityCap:        resolvedLimitClassDigestHiddenStrategyPolicyInt(webhook.LimitClassDigestTruncatedReasonBucketMinSeverityPolicy, webhook.LimitClassDigestTruncatedReasonBucketMinSeverityPriorityCap, "priorityCap"),
		truncatedReasonBucketMinSeverityReasonCap:          resolvedLimitClassDigestHiddenStrategyPolicyInt(webhook.LimitClassDigestTruncatedReasonBucketMinSeverityPolicy, webhook.LimitClassDigestTruncatedReasonBucketMinSeverityReasonCap, "reasonCap"),
		truncatedReasonBucketMinSeverityItemCap:            resolvedLimitClassDigestHiddenStrategyPolicyInt(webhook.LimitClassDigestTruncatedReasonBucketMinSeverityPolicy, webhook.LimitClassDigestTruncatedReasonBucketMinSeverityItemCap, "itemCap"),
		truncatedReasonBucketMinSeverityPriorityWeight:     resolvedLimitClassDigestHiddenStrategyPolicyInt(webhook.LimitClassDigestTruncatedReasonBucketMinSeverityPolicy, webhook.LimitClassDigestTruncatedReasonBucketMinSeverityPriorityWeight, "priorityWeight"),
		truncatedReasonBucketMinSeverityReasonWeight:       resolvedLimitClassDigestHiddenStrategyPolicyInt(webhook.LimitClassDigestTruncatedReasonBucketMinSeverityPolicy, webhook.LimitClassDigestTruncatedReasonBucketMinSeverityReasonWeight, "reasonWeight"),
		truncatedReasonBucketMinSeverityItemWeight:         resolvedLimitClassDigestHiddenStrategyPolicyInt(webhook.LimitClassDigestTruncatedReasonBucketMinSeverityPolicy, webhook.LimitClassDigestTruncatedReasonBucketMinSeverityItemWeight, "itemWeight"),
		truncatedReasonBucketMinSeverityDominantMode:       resolvedLimitClassDigestHiddenStrategyPolicyMode(webhook.LimitClassDigestTruncatedReasonBucketMinSeverityPolicy, webhook.LimitClassDigestTruncatedReasonBucketMinSeverityDominantMode),
		truncatedReasonBucketMinSeverityMinReasons:         resolvedLimitClassDigestHiddenStrategyPolicyInt(webhook.LimitClassDigestTruncatedReasonBucketMinSeverityPolicy, webhook.LimitClassDigestTruncatedReasonBucketMinSeverityMinReasons, "minReasons"),
		truncatedReasonBucketMinSeverityMinItems:           resolvedLimitClassDigestHiddenStrategyPolicyInt(webhook.LimitClassDigestTruncatedReasonBucketMinSeverityPolicy, webhook.LimitClassDigestTruncatedReasonBucketMinSeverityMinItems, "minItems"),
		truncatedReasonBucketMaxReasonsPriorityCap:         resolvedLimitClassDigestHiddenStrategyPolicyInt(webhook.LimitClassDigestTruncatedReasonBucketMaxReasonsPolicy, webhook.LimitClassDigestTruncatedReasonBucketMaxReasonsPriorityCap, "priorityCap"),
		truncatedReasonBucketMaxReasonsReasonCap:           resolvedLimitClassDigestHiddenStrategyPolicyInt(webhook.LimitClassDigestTruncatedReasonBucketMaxReasonsPolicy, webhook.LimitClassDigestTruncatedReasonBucketMaxReasonsReasonCap, "reasonCap"),
		truncatedReasonBucketMaxReasonsItemCap:             resolvedLimitClassDigestHiddenStrategyPolicyInt(webhook.LimitClassDigestTruncatedReasonBucketMaxReasonsPolicy, webhook.LimitClassDigestTruncatedReasonBucketMaxReasonsItemCap, "itemCap"),
		truncatedReasonBucketMaxReasonsPriorityWeight:      resolvedLimitClassDigestHiddenStrategyPolicyInt(webhook.LimitClassDigestTruncatedReasonBucketMaxReasonsPolicy, webhook.LimitClassDigestTruncatedReasonBucketMaxReasonsPriorityWeight, "priorityWeight"),
		truncatedReasonBucketMaxReasonsReasonWeight:        resolvedLimitClassDigestHiddenStrategyPolicyInt(webhook.LimitClassDigestTruncatedReasonBucketMaxReasonsPolicy, webhook.LimitClassDigestTruncatedReasonBucketMaxReasonsReasonWeight, "reasonWeight"),
		truncatedReasonBucketMaxReasonsItemWeight:          resolvedLimitClassDigestHiddenStrategyPolicyInt(webhook.LimitClassDigestTruncatedReasonBucketMaxReasonsPolicy, webhook.LimitClassDigestTruncatedReasonBucketMaxReasonsItemWeight, "itemWeight"),
		truncatedReasonBucketMaxReasonsDominantMode:        resolvedLimitClassDigestHiddenStrategyPolicyMode(webhook.LimitClassDigestTruncatedReasonBucketMaxReasonsPolicy, webhook.LimitClassDigestTruncatedReasonBucketMaxReasonsDominantMode),
		truncatedReasonBucketMaxReasonsMinReasons:          resolvedLimitClassDigestHiddenStrategyPolicyInt(webhook.LimitClassDigestTruncatedReasonBucketMaxReasonsPolicy, webhook.LimitClassDigestTruncatedReasonBucketMaxReasonsMinReasons, "minReasons"),
		truncatedReasonBucketMaxReasonsMinItems:            resolvedLimitClassDigestHiddenStrategyPolicyInt(webhook.LimitClassDigestTruncatedReasonBucketMaxReasonsPolicy, webhook.LimitClassDigestTruncatedReasonBucketMaxReasonsMinItems, "minItems"),
		hasTruncatedReasonBucketLabel:                      strings.TrimSpace(webhook.LimitClassDigestTruncatedReasonBucketLabel) != "",
		hasTruncatedReasonBucketMode:                       strings.TrimSpace(webhook.LimitClassDigestTruncatedReasonBucketMode) != "",
		hasTruncatedReasonBucketSortMode:                   strings.TrimSpace(webhook.LimitClassDigestTruncatedReasonBucketSortMode) != "",
		hasTruncatedReasonBucketDominantReasonStrategy:     strings.TrimSpace(webhook.LimitClassDigestTruncatedReasonBucketDominantReasonStrategy) != "",
		hasTruncatedReasonBucketHiddenStrategyOrder:        len(webhook.LimitClassDigestTruncatedReasonBucketHiddenStrategyOrder) > 0,
		hasTruncatedReasonBucketHiddenStrategyDominantMode: strings.TrimSpace(webhook.LimitClassDigestTruncatedReasonBucketHiddenStrategyDominantMode) != "",
		maxSummaryClasses:                                  webhook.LimitClassDigestMaxSummaryBucketClasses,
		summaryOnly:                                        summaryOnly,
	}
}

func (shape limitClassDigestReceiverShape) matchesDigestType() bool {
	if len(shape.allowedDigestTypes) == 0 {
		return true
	}
	_, ok := shape.allowedDigestTypes[shape.digestType]
	return ok
}

func (shape limitClassDigestReceiverShape) shapesPayload() bool {
	return shape.summaryOnly ||
		shape.minSeverity != "" ||
		len(shape.allowedSeverities) > 0 ||
		shape.minPriority > 0 ||
		shape.maxClasses > 0 ||
		shape.minSummarySeverity != "" ||
		shape.minSummaryPriority > 0 ||
		shape.minSummaryCount > 0 ||
		len(shape.allowedOverflowReasons) > 0 ||
		len(shape.overflowReasonLabels) > 0 ||
		len(shape.overflowReasonGroups) > 0 ||
		len(shape.overflowReasonOrder) > 0 ||
		shape.maxOverflowReasons > 0 ||
		shape.hasTruncatedReasonBucketLabel ||
		shape.hasTruncatedReasonBucketMode ||
		shape.truncatedReasonBucketMaxReasons > 0 ||
		len(shape.truncatedReasonBucketReasonOrder) > 0 ||
		shape.truncatedReasonBucketMinSeverity != "" ||
		len(shape.truncatedReasonBucketSeverities) > 0 ||
		shape.hasTruncatedReasonBucketSortMode ||
		shape.hasTruncatedReasonBucketDominantReasonStrategy ||
		shape.hasTruncatedReasonBucketHiddenStrategyOrder ||
		shape.hasTruncatedReasonBucketHiddenStrategyDominantMode ||
		shape.maxSummaryClasses > 0
}

func (shape limitClassDigestReceiverShape) applyReceiverMetadata(data map[string]interface{}) {
	data["receiver_detailed_digest_types"] = shape.allowedDigestTypeList
	data["receiver_summary_only_digest_types"] = shape.summaryOnlyDigestTypeList
	data["receiver_detailed_min_severity"] = shape.minSeverity
	data["receiver_detailed_severities"] = shape.allowedSeverityList
	data["receiver_detailed_min_bucket_class_priority"] = shape.minPriority
	data["receiver_detailed_max_bucket_classes"] = shape.maxClasses
	data["receiver_detailed_min_summary_severity"] = shape.minSummarySeverity
	data["receiver_detailed_min_summary_bucket_class_priority"] = shape.minSummaryPriority
	data["receiver_detailed_summary_sort_mode"] = shape.summarySortMode
	data["receiver_detailed_min_summary_count"] = shape.minSummaryCount
	data["receiver_detailed_other_bucket_label"] = shape.otherBucketLabel
	data["receiver_detailed_overflow_reasons"] = shape.allowedOverflowReasonList
	data["receiver_detailed_overflow_reason_labels"] = shape.overflowReasonLabels
	data["receiver_detailed_overflow_reason_groups"] = shape.overflowReasonGroups
	data["receiver_detailed_overflow_reason_order"] = shape.overflowReasonOrder
	data["receiver_detailed_max_overflow_reasons"] = shape.maxOverflowReasons
	data["receiver_detailed_truncated_reason_bucket_label"] = shape.truncatedReasonBucketLabel
	data["receiver_detailed_truncated_reason_bucket_mode"] = shape.truncatedReasonBucketMode
	data["receiver_detailed_truncated_reason_bucket_max_reasons"] = shape.truncatedReasonBucketMaxReasons
	data["receiver_detailed_truncated_reason_bucket_reason_order"] = shape.truncatedReasonBucketReasonOrder
	data["receiver_detailed_truncated_reason_bucket_min_severity"] = shape.truncatedReasonBucketMinSeverity
	data["receiver_detailed_truncated_reason_bucket_severities"] = shape.truncatedReasonBucketSeverityList
	data["receiver_detailed_truncated_reason_bucket_sort_mode"] = shape.truncatedReasonBucketSortMode
	data["receiver_detailed_truncated_reason_bucket_dominant_reason_strategy"] = shape.truncatedReasonBucketDominantReasonStrategy
	data["receiver_detailed_truncated_reason_bucket_hidden_strategy_order"] = limitClassDigestEffectiveTruncatedReasonBucketHiddenStrategyOrder(shape)
	data["receiver_detailed_truncated_reason_bucket_hidden_strategy_dominant_mode"] = shape.truncatedReasonBucketHiddenStrategyDominantMode
	data["receiver_detailed_truncated_reason_bucket_hidden_strategy_priority_weight"] = shape.truncatedReasonBucketHiddenStrategyPriorityWeight
	data["receiver_detailed_truncated_reason_bucket_hidden_strategy_reason_weight"] = shape.truncatedReasonBucketHiddenStrategyReasonWeight
	data["receiver_detailed_truncated_reason_bucket_hidden_strategy_item_weight"] = shape.truncatedReasonBucketHiddenStrategyItemWeight
	data["receiver_detailed_truncated_reason_bucket_hidden_strategy_priority_cap"] = shape.truncatedReasonBucketHiddenStrategyPriorityCap
	data["receiver_detailed_truncated_reason_bucket_hidden_strategy_reason_cap"] = shape.truncatedReasonBucketHiddenStrategyReasonCap
	data["receiver_detailed_truncated_reason_bucket_hidden_strategy_item_cap"] = shape.truncatedReasonBucketHiddenStrategyItemCap
	data["receiver_detailed_truncated_reason_bucket_hidden_strategy_min_reasons"] = shape.truncatedReasonBucketHiddenStrategyMinReasons
	data["receiver_detailed_truncated_reason_bucket_hidden_strategy_min_items"] = shape.truncatedReasonBucketHiddenStrategyMinItems
	data["receiver_detailed_truncated_reason_bucket_exact_severity_priority_cap"] = shape.truncatedReasonBucketExactSeverityPriorityCap
	data["receiver_detailed_truncated_reason_bucket_exact_severity_reason_cap"] = shape.truncatedReasonBucketExactSeverityReasonCap
	data["receiver_detailed_truncated_reason_bucket_exact_severity_item_cap"] = shape.truncatedReasonBucketExactSeverityItemCap
	data["receiver_detailed_truncated_reason_bucket_exact_severity_priority_weight"] = shape.truncatedReasonBucketExactSeverityPriorityWeight
	data["receiver_detailed_truncated_reason_bucket_exact_severity_reason_weight"] = shape.truncatedReasonBucketExactSeverityReasonWeight
	data["receiver_detailed_truncated_reason_bucket_exact_severity_item_weight"] = shape.truncatedReasonBucketExactSeverityItemWeight
	data["receiver_detailed_truncated_reason_bucket_exact_severity_dominant_mode"] = shape.truncatedReasonBucketExactSeverityDominantMode
	data["receiver_detailed_truncated_reason_bucket_exact_severity_min_reasons"] = shape.truncatedReasonBucketExactSeverityMinReasons
	data["receiver_detailed_truncated_reason_bucket_exact_severity_min_items"] = shape.truncatedReasonBucketExactSeverityMinItems
	data["receiver_detailed_truncated_reason_bucket_min_severity_priority_cap"] = shape.truncatedReasonBucketMinSeverityPriorityCap
	data["receiver_detailed_truncated_reason_bucket_min_severity_reason_cap"] = shape.truncatedReasonBucketMinSeverityReasonCap
	data["receiver_detailed_truncated_reason_bucket_min_severity_item_cap"] = shape.truncatedReasonBucketMinSeverityItemCap
	data["receiver_detailed_truncated_reason_bucket_min_severity_priority_weight"] = shape.truncatedReasonBucketMinSeverityPriorityWeight
	data["receiver_detailed_truncated_reason_bucket_min_severity_reason_weight"] = shape.truncatedReasonBucketMinSeverityReasonWeight
	data["receiver_detailed_truncated_reason_bucket_min_severity_item_weight"] = shape.truncatedReasonBucketMinSeverityItemWeight
	data["receiver_detailed_truncated_reason_bucket_min_severity_dominant_mode"] = shape.truncatedReasonBucketMinSeverityDominantMode
	data["receiver_detailed_truncated_reason_bucket_min_severity_min_reasons"] = shape.truncatedReasonBucketMinSeverityMinReasons
	data["receiver_detailed_truncated_reason_bucket_min_severity_min_items"] = shape.truncatedReasonBucketMinSeverityMinItems
	data["receiver_detailed_truncated_reason_bucket_max_reasons_priority_cap"] = shape.truncatedReasonBucketMaxReasonsPriorityCap
	data["receiver_detailed_truncated_reason_bucket_max_reasons_reason_cap"] = shape.truncatedReasonBucketMaxReasonsReasonCap
	data["receiver_detailed_truncated_reason_bucket_max_reasons_item_cap"] = shape.truncatedReasonBucketMaxReasonsItemCap
	data["receiver_detailed_truncated_reason_bucket_max_reasons_priority_weight"] = shape.truncatedReasonBucketMaxReasonsPriorityWeight
	data["receiver_detailed_truncated_reason_bucket_max_reasons_reason_weight"] = shape.truncatedReasonBucketMaxReasonsReasonWeight
	data["receiver_detailed_truncated_reason_bucket_max_reasons_item_weight"] = shape.truncatedReasonBucketMaxReasonsItemWeight
	data["receiver_detailed_truncated_reason_bucket_max_reasons_dominant_mode"] = shape.truncatedReasonBucketMaxReasonsDominantMode
	data["receiver_detailed_truncated_reason_bucket_max_reasons_min_reasons"] = shape.truncatedReasonBucketMaxReasonsMinReasons
	data["receiver_detailed_truncated_reason_bucket_max_reasons_min_items"] = shape.truncatedReasonBucketMaxReasonsMinItems
	data["receiver_detailed_max_summary_bucket_classes"] = shape.maxSummaryClasses
}

func normalizedLimitClassDigestOtherBucketLabel(value string) string {
	label := strings.TrimSpace(value)
	if label == "" {
		return "other"
	}
	return label
}

func normalizedLimitClassDigestTruncatedReasonBucketLabel(value string) string {
	label := strings.TrimSpace(value)
	if label == "" {
		return "other_reasons"
	}
	return label
}

func normalizedLimitClassDigestTruncatedReasonBucketMode(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "detailed":
		return "detailed"
	default:
		return "summary"
	}
}

func normalizedLimitClassDigestTruncatedReasonBucketHiddenStrategyOrder(values []string) []string {
	order := []string{"exact_severity", "min_severity", "max_reasons"}
	if len(values) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(values))
	normalized := make([]string, 0, len(order))
	for _, value := range values {
		switch strategy := strings.ToLower(strings.TrimSpace(value)); strategy {
		case "exact_severity", "min_severity", "max_reasons":
			if _, ok := seen[strategy]; ok {
				continue
			}
			seen[strategy] = struct{}{}
			normalized = append(normalized, strategy)
		}
	}
	if len(normalized) == 0 {
		return nil
	}
	for _, strategy := range order {
		if _, ok := seen[strategy]; ok {
			continue
		}
		normalized = append(normalized, strategy)
	}
	return normalized
}

func normalizedLimitClassDigestTruncatedReasonBucketHiddenStrategyDominantMode(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "most_hidden_reasons":
		return "most_hidden_reasons"
	case "most_hidden_items":
		return "most_hidden_items"
	case "weighted_score":
		return "weighted_score"
	default:
		return "order_first"
	}
}

func resolvedLimitClassDigestHiddenStrategyPolicyInt(policy *config.LimitClassDigestHiddenStrategyPolicy, fallback int, field string) int {
	if policy == nil {
		return normalizedLimitClassDigestTruncatedReasonBucketHiddenStrategyWeight(fallback)
	}
	switch field {
	case "priorityCap":
		if policy.PriorityCap > 0 {
			return normalizedLimitClassDigestTruncatedReasonBucketHiddenStrategyWeight(policy.PriorityCap)
		}
	case "reasonCap":
		if policy.ReasonCap > 0 {
			return normalizedLimitClassDigestTruncatedReasonBucketHiddenStrategyWeight(policy.ReasonCap)
		}
	case "itemCap":
		if policy.ItemCap > 0 {
			return normalizedLimitClassDigestTruncatedReasonBucketHiddenStrategyWeight(policy.ItemCap)
		}
	case "priorityWeight":
		if policy.PriorityWeight > 0 {
			return normalizedLimitClassDigestTruncatedReasonBucketHiddenStrategyWeight(policy.PriorityWeight)
		}
	case "reasonWeight":
		if policy.ReasonWeight > 0 {
			return normalizedLimitClassDigestTruncatedReasonBucketHiddenStrategyWeight(policy.ReasonWeight)
		}
	case "itemWeight":
		if policy.ItemWeight > 0 {
			return normalizedLimitClassDigestTruncatedReasonBucketHiddenStrategyWeight(policy.ItemWeight)
		}
	case "minReasons":
		if policy.MinReasons > 0 {
			return normalizedLimitClassDigestTruncatedReasonBucketHiddenStrategyWeight(policy.MinReasons)
		}
	case "minItems":
		if policy.MinItems > 0 {
			return normalizedLimitClassDigestTruncatedReasonBucketHiddenStrategyWeight(policy.MinItems)
		}
	}
	return normalizedLimitClassDigestTruncatedReasonBucketHiddenStrategyWeight(fallback)
}

func resolvedLimitClassDigestHiddenStrategyPolicyMode(policy *config.LimitClassDigestHiddenStrategyPolicy, fallback string) string {
	if policy != nil && strings.TrimSpace(policy.DominantMode) != "" {
		return normalizedLimitClassDigestTruncatedReasonBucketHiddenStrategyDominantMode(policy.DominantMode)
	}
	return normalizedLimitClassDigestTruncatedReasonBucketHiddenStrategyDominantMode(fallback)
}

func normalizedLimitClassDigestTruncatedReasonBucketHiddenStrategyWeight(value int) int {
	if value < 0 {
		return 0
	}
	return value
}

func limitClassDigestEffectiveTruncatedReasonBucketHiddenStrategyOrder(shape limitClassDigestReceiverShape) []string {
	if len(shape.truncatedReasonBucketHiddenStrategyOrder) > 0 {
		return append([]string(nil), shape.truncatedReasonBucketHiddenStrategyOrder...)
	}
	return []string{"exact_severity", "min_severity", "max_reasons"}
}

func normalizedLimitClassDigestOverflowReasons(values []string) map[string]struct{} {
	if len(values) == 0 {
		return nil
	}
	normalized := make(map[string]struct{}, len(values))
	for _, value := range values {
		switch strings.ToLower(strings.TrimSpace(value)) {
		case "low_severity", "low_priority", "low_count", "max_summary_budget":
			normalized[strings.ToLower(strings.TrimSpace(value))] = struct{}{}
		}
	}
	if len(normalized) == 0 {
		return nil
	}
	return normalized
}

func normalizedLimitClassDigestOverflowReasonList(values []string) []string {
	normalized := normalizedLimitClassDigestOverflowReasons(values)
	if len(normalized) == 0 {
		return nil
	}
	order := []string{"low_severity", "low_priority", "low_count", "max_summary_budget"}
	list := make([]string, 0, len(normalized))
	for _, reason := range order {
		if _, ok := normalized[reason]; ok {
			list = append(list, reason)
		}
	}
	return list
}

func normalizedLimitClassDigestOverflowReasonLabels(values map[string]string) map[string]string {
	if len(values) == 0 {
		return nil
	}
	normalized := make(map[string]string, len(values))
	for rawReason, label := range values {
		reason := strings.ToLower(strings.TrimSpace(rawReason))
		switch reason {
		case "low_severity", "low_priority", "low_count", "max_summary_budget":
			if strings.TrimSpace(label) != "" {
				normalized[reason] = strings.TrimSpace(label)
			}
		}
	}
	if len(normalized) == 0 {
		return nil
	}
	return normalized
}

func normalizedLimitClassDigestOverflowReasonGroups(values map[string][]string) map[string][]string {
	if len(values) == 0 {
		return nil
	}
	normalized := make(map[string][]string, len(values))
	for rawLabel, reasons := range values {
		groupLabel := strings.TrimSpace(rawLabel)
		if groupLabel == "" || len(reasons) == 0 {
			continue
		}
		collected := make([]string, 0, len(reasons))
		seen := make(map[string]struct{}, len(reasons))
		for _, rawReason := range reasons {
			reason := strings.ToLower(strings.TrimSpace(rawReason))
			switch reason {
			case "low_severity", "low_priority", "low_count", "max_summary_budget":
				if _, ok := seen[reason]; ok {
					continue
				}
				seen[reason] = struct{}{}
				collected = append(collected, reason)
			}
		}
		if len(collected) > 0 {
			normalized[groupLabel] = collected
		}
	}
	if len(normalized) == 0 {
		return nil
	}
	return normalized
}

func normalizedLimitClassDigestOverflowReasonGroupByRaw(values map[string][]string) map[string]string {
	groups := normalizedLimitClassDigestOverflowReasonGroups(values)
	if len(groups) == 0 {
		return nil
	}
	order := []string{"low_severity", "low_priority", "low_count", "max_summary_budget"}
	groupByRaw := make(map[string]string, len(order))
	for _, reason := range order {
		for groupLabel, reasons := range groups {
			for _, candidate := range reasons {
				if candidate == reason {
					groupByRaw[reason] = groupLabel
					break
				}
			}
			if _, ok := groupByRaw[reason]; ok {
				break
			}
		}
	}
	if len(groupByRaw) == 0 {
		return nil
	}
	return groupByRaw
}

func normalizedLimitClassDigestOverflowReasonOrder(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	order := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		label := strings.TrimSpace(value)
		if label == "" {
			continue
		}
		if _, ok := seen[label]; ok {
			continue
		}
		seen[label] = struct{}{}
		order = append(order, label)
	}
	if len(order) == 0 {
		return nil
	}
	return order
}
