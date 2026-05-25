package config

// SecurityConfig represents security configuration
type SecurityConfig struct {
	TLS                                                TLSConfig                                                    `yaml:"tls"`
	EnableBasicAuth                                    bool                                                         `yaml:"enableBasicAuth"`
	BasicAuthUsers                                     map[string]string                                            `yaml:"basicAuthUsers"`
	IPWhitelist                                        []string                                                     `yaml:"ipWhitelist"`
	Headers                                            map[string]string                                            `yaml:"headers"`
	Clients                                            map[string]string                                            `yaml:"clients"` // clientID: clientSecret
	Jwt                                                JWTConfig                                                    `yaml:"jwt"`
	MutationPolicy                                     MutationPolicy                                               `yaml:"mutationPolicy,omitempty"`
	LimitAlertBucketClasses                            map[string]LimitAlertBucketClassConfig                       `yaml:"limitAlertBucketClasses,omitempty" json:"limitAlertBucketClasses,omitempty"`
	LimiterClassPresets                                map[string]LimiterClassPolicyPreset                          `yaml:"limiterClassPresets,omitempty" json:"limiterClassPresets,omitempty"`
	LimitClassDigestHiddenStrategyPolicyPresets        map[string]LimitClassDigestHiddenStrategyPolicy              `yaml:"limitClassDigestHiddenStrategyPolicyPresets,omitempty" json:"limitClassDigestHiddenStrategyPolicyPresets,omitempty"`
	LimitClassDigestProfiles                           map[string]LimitAlertRecipientProfile                        `yaml:"limitClassDigestProfiles,omitempty" json:"limitClassDigestProfiles,omitempty"`
	LimitClassDigestExplainBundles                     map[string]LimitClassDigestExplainBundle                     `yaml:"limitClassDigestExplainBundles,omitempty" json:"limitClassDigestExplainBundles,omitempty"`
	LimitClassDigestAssertionExplainBundles            map[string]LimitClassDigestAssertionExplainBundle            `yaml:"limitClassDigestAssertionExplainBundles,omitempty" json:"limitClassDigestAssertionExplainBundles,omitempty"`
	LimitClassDigestAssertionGroupPresetExplainBundles map[string]LimitClassDigestAssertionGroupPresetExplainBundle `yaml:"limitClassDigestAssertionGroupPresetExplainBundles,omitempty" json:"limitClassDigestAssertionGroupPresetExplainBundles,omitempty"`
	LimitClassDigestAssertionGroupPresets              map[string]LimitClassDigestAssertionGroupPreset              `yaml:"limitClassDigestAssertionGroupPresets,omitempty" json:"limitClassDigestAssertionGroupPresets,omitempty"`
	LimitClassDigestAssertionPresets                   map[string]LimitClassDigestAssertionPreset                   `yaml:"limitClassDigestAssertionPresets,omitempty" json:"limitClassDigestAssertionPresets,omitempty"`
	LimitClassDigestAssertionExplainDiffProfiles       map[string]LimitClassDigestAssertionExplainDiffProfile       `yaml:"limitClassDigestAssertionExplainDiffProfiles,omitempty" json:"limitClassDigestAssertionExplainDiffProfiles,omitempty"`
	LimitClassDigestExplainDiffProfiles                map[string]LimitClassDigestExplainDiffProfile                `yaml:"limitClassDigestExplainDiffProfiles,omitempty" json:"limitClassDigestExplainDiffProfiles,omitempty"`
	LimitAlertProfiles                                 map[string]LimitAlertRecipientProfile                        `yaml:"limitAlertProfiles,omitempty" json:"limitAlertProfiles,omitempty"`
	NotificationWebhooks                               []NotificationWebhook                                        `yaml:"notificationWebhooks,omitempty"`
}

type MutationPolicy struct {
	Enabled                                                     bool                          `yaml:"enabled,omitempty" json:"enabled,omitempty"`
	EnforcedScopes                                              []string                      `yaml:"enforcedScopes,omitempty" json:"enforcedScopes,omitempty"`
	RequireLabel                                                bool                          `yaml:"requireLabel,omitempty" json:"requireLabel,omitempty"`
	RequireNoteForHighImpact                                    bool                          `yaml:"requireNoteForHighImpact,omitempty" json:"requireNoteForHighImpact,omitempty"`
	RequireChangeRefForHighImpact                               bool                          `yaml:"requireChangeRefForHighImpact,omitempty" json:"requireChangeRefForHighImpact,omitempty"`
	RequireDifferentReviewerForProposals                        bool                          `yaml:"requireDifferentReviewerForProposals,omitempty" json:"requireDifferentReviewerForProposals,omitempty"`
	MinApproversForHighImpactProposals                          int                           `yaml:"minApproversForHighImpactProposals,omitempty" json:"minApproversForHighImpactProposals,omitempty"`
	RequireNotBeforeForHighImpactProposals                      bool                          `yaml:"requireNotBeforeForHighImpactProposals,omitempty" json:"requireNotBeforeForHighImpactProposals,omitempty"`
	RequireVerificationForPromotedHighImpactProposals           bool                          `yaml:"requireVerificationForPromotedHighImpactProposals,omitempty" json:"requireVerificationForPromotedHighImpactProposals,omitempty"`
	RequireShadowEvaluationForPromotedHighImpactProposals       bool                          `yaml:"requireShadowEvaluationForPromotedHighImpactProposals,omitempty" json:"requireShadowEvaluationForPromotedHighImpactProposals,omitempty"`
	MinShadowHealthyVerificationsForPromotedHighImpactProposals int                           `yaml:"minShadowHealthyVerificationsForPromotedHighImpactProposals,omitempty" json:"minShadowHealthyVerificationsForPromotedHighImpactProposals,omitempty"`
	MaxProposalAge                                              string                        `yaml:"maxProposalAge,omitempty" json:"maxProposalAge,omitempty"`
	MaxApprovalAge                                              string                        `yaml:"maxApprovalAge,omitempty" json:"maxApprovalAge,omitempty"`
	BlockedApplyWindows                                         []MutationApplyWindow         `yaml:"blockedApplyWindows,omitempty" json:"blockedApplyWindows,omitempty"`
	ProposalQueue                                               ProposalQueuePolicy           `yaml:"proposalQueue,omitempty" json:"proposalQueue,omitempty"`
	PolicyAlertNotifications                                    PolicyAlertNotificationPolicy `yaml:"policyAlertNotifications,omitempty" json:"policyAlertNotifications,omitempty"`
	LimitAlertNotifications                                     PolicyAlertNotificationPolicy `yaml:"limitAlertNotifications,omitempty" json:"limitAlertNotifications,omitempty"`
	LimitClassAlertNotifications                                PolicyAlertNotificationPolicy `yaml:"limitClassAlertNotifications,omitempty" json:"limitClassAlertNotifications,omitempty"`
	LimitClassSnoozeNotifications                               PolicyAlertNotificationPolicy `yaml:"limitClassSnoozeNotifications,omitempty" json:"limitClassSnoozeNotifications,omitempty"`
}

type ProposalQueuePolicy struct {
	DefaultUrgency     ProposalQueueUrgencyThresholds            `yaml:"defaultUrgency,omitempty" json:"defaultUrgency,omitempty"`
	EnvironmentUrgency map[string]ProposalQueueUrgencyThresholds `yaml:"environmentUrgency,omitempty" json:"environmentUrgency,omitempty"`
	Notifications      ProposalQueueNotificationPolicy           `yaml:"notifications,omitempty" json:"notifications,omitempty"`
}

type ProposalQueueUrgencyThresholds struct {
	ReadyAgingAfter     string `yaml:"readyAgingAfter,omitempty" json:"readyAgingAfter,omitempty"`
	ReadyOverdueAfter   string `yaml:"readyOverdueAfter,omitempty" json:"readyOverdueAfter,omitempty"`
	BlockedAgingAfter   string `yaml:"blockedAgingAfter,omitempty" json:"blockedAgingAfter,omitempty"`
	BlockedOverdueAfter string `yaml:"blockedOverdueAfter,omitempty" json:"blockedOverdueAfter,omitempty"`
}

type ProposalQueueNotificationPolicy struct {
	Enabled                 bool     `yaml:"enabled,omitempty" json:"enabled,omitempty"`
	Interval                string   `yaml:"interval,omitempty" json:"interval,omitempty"`
	MinNotificationInterval string   `yaml:"minNotificationInterval,omitempty" json:"minNotificationInterval,omitempty"`
	OnlyOnSLABreach         bool     `yaml:"onlyOnSLABreach,omitempty" json:"onlyOnSLABreach,omitempty"`
	OnlyOnChange            bool     `yaml:"onlyOnChange,omitempty" json:"onlyOnChange,omitempty"`
	Environments            []string `yaml:"environments,omitempty" json:"environments,omitempty"`
}

type PolicyAlertNotificationPolicy struct {
	Enabled                        bool                            `yaml:"enabled,omitempty" json:"enabled,omitempty"`
	Interval                       string                          `yaml:"interval,omitempty" json:"interval,omitempty"`
	MinNotificationInterval        string                          `yaml:"minNotificationInterval,omitempty" json:"minNotificationInterval,omitempty"`
	OnlyOnChange                   bool                            `yaml:"onlyOnChange,omitempty" json:"onlyOnChange,omitempty"`
	Window                         string                          `yaml:"window,omitempty" json:"window,omitempty"`
	DetailedMinBucketClassPriority int                             `yaml:"detailedMinBucketClassPriority,omitempty" json:"detailedMinBucketClassPriority,omitempty"`
	DetailedMaxBucketClasses       int                             `yaml:"detailedMaxBucketClasses,omitempty" json:"detailedMaxBucketClasses,omitempty"`
	SnoozeElevatedWithin           string                          `yaml:"snoozeElevatedWithin,omitempty" json:"snoozeElevatedWithin,omitempty"`
	SnoozeCriticalWithin           string                          `yaml:"snoozeCriticalWithin,omitempty" json:"snoozeCriticalWithin,omitempty"`
	MinCount                       int                             `yaml:"minCount,omitempty" json:"minCount,omitempty"`
	MinSeverity                    string                          `yaml:"minSeverity,omitempty" json:"minSeverity,omitempty"`
	LimitTypePolicies              map[string]LimitAlertTypePolicy `yaml:"limitTypePolicies,omitempty" json:"limitTypePolicies,omitempty"`
}

type LimitAlertTypePolicy struct {
	WarningCount  int `yaml:"warningCount,omitempty" json:"warningCount,omitempty"`
	ElevatedCount int `yaml:"elevatedCount,omitempty" json:"elevatedCount,omitempty"`
	CriticalCount int `yaml:"criticalCount,omitempty" json:"criticalCount,omitempty"`
}

type LimitClassDigestHiddenStrategyPolicy struct {
	DominantMode   string `yaml:"dominantMode,omitempty" json:"dominantMode,omitempty"`
	MinReasons     int    `yaml:"minReasons,omitempty" json:"minReasons,omitempty"`
	MinItems       int    `yaml:"minItems,omitempty" json:"minItems,omitempty"`
	PriorityWeight int    `yaml:"priorityWeight,omitempty" json:"priorityWeight,omitempty"`
	ReasonWeight   int    `yaml:"reasonWeight,omitempty" json:"reasonWeight,omitempty"`
	ItemWeight     int    `yaml:"itemWeight,omitempty" json:"itemWeight,omitempty"`
	PriorityCap    int    `yaml:"priorityCap,omitempty" json:"priorityCap,omitempty"`
	ReasonCap      int    `yaml:"reasonCap,omitempty" json:"reasonCap,omitempty"`
	ItemCap        int    `yaml:"itemCap,omitempty" json:"itemCap,omitempty"`
}

type LimitClassDigestExplainBundle struct {
	Fields []string `yaml:"fields,omitempty" json:"fields,omitempty"`
}

type LimitClassDigestAssertionExplainBundle struct {
	Kinds []string `yaml:"kinds,omitempty" json:"kinds,omitempty"`
}

type LimitClassDigestAssertionGroupPresetExplainBundle struct {
	Presets []string `yaml:"presets,omitempty" json:"presets,omitempty"`
}

type LimitClassDigestAssertionGroup struct {
	Operator string                           `yaml:"operator,omitempty" json:"operator,omitempty"`
	Rules    []string                         `yaml:"rules,omitempty" json:"rules,omitempty"`
	Groups   []LimitClassDigestAssertionGroup `yaml:"groups,omitempty" json:"groups,omitempty"`
}

type LimitClassDigestAssertionPreset struct {
	PresetChain []string                         `yaml:"presetChain,omitempty" json:"presetChain,omitempty"`
	Rules       []string                         `yaml:"rules,omitempty" json:"rules,omitempty"`
	Groups      []LimitClassDigestAssertionGroup `yaml:"groups,omitempty" json:"groups,omitempty"`
}

type LimitClassDigestAssertionGroupPreset struct {
	PresetChain []string                         `yaml:"presetChain,omitempty" json:"presetChain,omitempty"`
	Groups      []LimitClassDigestAssertionGroup `yaml:"groups,omitempty" json:"groups,omitempty"`
}

type LimitClassDigestExplainDiffProfile struct {
	FromRole             string                                      `yaml:"fromRole,omitempty" json:"fromRole,omitempty"`
	ToRole               string                                      `yaml:"toRole,omitempty" json:"toRole,omitempty"`
	Bundles              []string                                    `yaml:"bundles,omitempty" json:"bundles,omitempty"`
	Fields               []string                                    `yaml:"fields,omitempty" json:"fields,omitempty"`
	AllowedChangedFields []string                                    `yaml:"allowedChangedFields,omitempty" json:"allowedChangedFields,omitempty"`
	ExpectedFromValues   map[string]string                           `yaml:"expectedFromValues,omitempty" json:"expectedFromValues,omitempty"`
	ExpectedToValues     map[string]string                           `yaml:"expectedToValues,omitempty" json:"expectedToValues,omitempty"`
	AssertFromPresets    map[string][]string                         `yaml:"assertFromPresets,omitempty" json:"assertFromPresets,omitempty"`
	AssertToPresets      map[string][]string                         `yaml:"assertToPresets,omitempty" json:"assertToPresets,omitempty"`
	AssertFromRules      map[string][]string                         `yaml:"assertFromRules,omitempty" json:"assertFromRules,omitempty"`
	AssertToRules        map[string][]string                         `yaml:"assertToRules,omitempty" json:"assertToRules,omitempty"`
	AssertFromGroups     map[string][]LimitClassDigestAssertionGroup `yaml:"assertFromGroups,omitempty" json:"assertFromGroups,omitempty"`
	AssertToGroups       map[string][]LimitClassDigestAssertionGroup `yaml:"assertToGroups,omitempty" json:"assertToGroups,omitempty"`
}

type LimitClassDigestAssertionExplainDiffProfile struct {
	Bundles                []string                                    `yaml:"bundles,omitempty" json:"bundles,omitempty"`
	Kinds                  []string                                    `yaml:"kinds,omitempty" json:"kinds,omitempty"`
	AllowedChangedKinds    []string                                    `yaml:"allowedChangedKinds,omitempty" json:"allowedChangedKinds,omitempty"`
	ExpectedFromValues     map[string]string                           `yaml:"expectedFromValues,omitempty" json:"expectedFromValues,omitempty"`
	ExpectedToValues       map[string]string                           `yaml:"expectedToValues,omitempty" json:"expectedToValues,omitempty"`
	AssertFromGroupPresets map[string][]string                         `yaml:"assertFromGroupPresets,omitempty" json:"assertFromGroupPresets,omitempty"`
	AssertToGroupPresets   map[string][]string                         `yaml:"assertToGroupPresets,omitempty" json:"assertToGroupPresets,omitempty"`
	AssertFromRules        map[string][]string                         `yaml:"assertFromRules,omitempty" json:"assertFromRules,omitempty"`
	AssertToRules          map[string][]string                         `yaml:"assertToRules,omitempty" json:"assertToRules,omitempty"`
	AssertFromGroups       map[string][]LimitClassDigestAssertionGroup `yaml:"assertFromGroups,omitempty" json:"assertFromGroups,omitempty"`
	AssertToGroups         map[string][]LimitClassDigestAssertionGroup `yaml:"assertToGroups,omitempty" json:"assertToGroups,omitempty"`
}

type LimitAlertBucketClassConfig struct {
	KeyType                 string   `yaml:"keyType,omitempty" json:"keyType,omitempty"`
	BucketRegex             string   `yaml:"bucketRegex,omitempty" json:"bucketRegex,omitempty"`
	Priority                int      `yaml:"priority,omitempty" json:"priority,omitempty"`
	SnoozeElevatedWithin    string   `yaml:"snoozeElevatedWithin,omitempty" json:"snoozeElevatedWithin,omitempty"`
	SnoozeCriticalWithin    string   `yaml:"snoozeCriticalWithin,omitempty" json:"snoozeCriticalWithin,omitempty"`
	SnoozeEventTypes        []string `yaml:"snoozeEventTypes,omitempty" json:"snoozeEventTypes,omitempty"`
	SnoozeExcludeFromDigest bool     `yaml:"snoozeExcludeFromDigest,omitempty" json:"snoozeExcludeFromDigest,omitempty"`
}

type LimiterClassPolicyPreset struct {
	BucketClass              string                          `yaml:"bucketClass,omitempty" json:"bucketClass,omitempty"`
	RateRequestsPerSecond    float64                         `yaml:"rateRequestsPerSecond,omitempty" json:"rateRequestsPerSecond,omitempty"`
	RateBurst                int                             `yaml:"rateBurst,omitempty" json:"rateBurst,omitempty"`
	ConcurrencyMaxInFlight   int                             `yaml:"concurrencyMaxInFlight,omitempty" json:"concurrencyMaxInFlight,omitempty"`
	ConcurrencyQueueTimeout  string                          `yaml:"concurrencyQueueTimeout,omitempty" json:"concurrencyQueueTimeout,omitempty"`
	ConcurrencyMaxQueueDepth int                             `yaml:"concurrencyMaxQueueDepth,omitempty" json:"concurrencyMaxQueueDepth,omitempty"`
	AlertMinCount            int                             `yaml:"alertMinCount,omitempty" json:"alertMinCount,omitempty"`
	AlertMinSeverity         string                          `yaml:"alertMinSeverity,omitempty" json:"alertMinSeverity,omitempty"`
	AlertLimitTypePolicies   map[string]LimitAlertTypePolicy `yaml:"alertLimitTypePolicies,omitempty" json:"alertLimitTypePolicies,omitempty"`
}

type RouteLimitAlertPolicyConfig struct {
	MinCount          int                             `yaml:"minCount,omitempty" json:"minCount,omitempty"`
	MinSeverity       string                          `yaml:"minSeverity,omitempty" json:"minSeverity,omitempty"`
	GroupBy           string                          `yaml:"groupBy,omitempty" json:"groupBy,omitempty"`
	LimitTypePolicies map[string]LimitAlertTypePolicy `yaml:"limitTypePolicies,omitempty" json:"limitTypePolicies,omitempty"`
	BucketPolicies    []LimitAlertBucketPolicyConfig  `yaml:"bucketPolicies,omitempty" json:"bucketPolicies,omitempty"`
}

type LimitAlertBucketPolicyConfig struct {
	Preset            string                          `yaml:"preset,omitempty" json:"preset,omitempty"`
	BucketClass       string                          `yaml:"bucketClass,omitempty" json:"bucketClass,omitempty"`
	KeyType           string                          `yaml:"keyType,omitempty" json:"keyType,omitempty"`
	BucketRegex       string                          `yaml:"bucketRegex,omitempty" json:"bucketRegex,omitempty"`
	MinCount          int                             `yaml:"minCount,omitempty" json:"minCount,omitempty"`
	MinSeverity       string                          `yaml:"minSeverity,omitempty" json:"minSeverity,omitempty"`
	LimitTypePolicies map[string]LimitAlertTypePolicy `yaml:"limitTypePolicies,omitempty" json:"limitTypePolicies,omitempty"`
}

type MutationApplyWindow struct {
	Name     string   `yaml:"name,omitempty" json:"name,omitempty"`
	Days     []string `yaml:"days,omitempty" json:"days,omitempty"`
	Start    string   `yaml:"start" json:"start"`
	End      string   `yaml:"end" json:"end"`
	Timezone string   `yaml:"timezone,omitempty" json:"timezone,omitempty"`
	Scopes   []string `yaml:"scopes,omitempty" json:"scopes,omitempty"`
}

type NotificationWebhook struct {
	Name                                                                string                                `yaml:"name,omitempty" json:"name,omitempty"`
	URL                                                                 string                                `yaml:"url" json:"url"`
	Format                                                              string                                `yaml:"format,omitempty" json:"format,omitempty"`
	Events                                                              []string                              `yaml:"events,omitempty" json:"events,omitempty"`
	Environments                                                        []string                              `yaml:"environments,omitempty" json:"environments,omitempty"`
	MinSLABreachCount                                                   int                                   `yaml:"minSLABreachCount,omitempty" json:"minSLABreachCount,omitempty"`
	MinConsecutiveSLABreaches                                           int                                   `yaml:"minConsecutiveSLABreaches,omitempty" json:"minConsecutiveSLABreaches,omitempty"`
	MinSLABreachDuration                                                string                                `yaml:"minSLABreachDuration,omitempty" json:"minSLABreachDuration,omitempty"`
	MinSLABreachTier                                                    string                                `yaml:"minSLABreachTier,omitempty" json:"minSLABreachTier,omitempty"`
	SLABreachCooldown                                                   string                                `yaml:"slaBreachCooldown,omitempty" json:"slaBreachCooldown,omitempty"`
	LimitAlertProfile                                                   string                                `yaml:"limitAlertProfile,omitempty" json:"limitAlertProfile,omitempty"`
	LimitClassDigestProfileChain                                        []string                              `yaml:"limitClassDigestProfileChain,omitempty" json:"limitClassDigestProfileChain,omitempty"`
	LimitClassDigestProfile                                             string                                `yaml:"limitClassDigestProfile,omitempty" json:"limitClassDigestProfile,omitempty"`
	MinLimitAlertSeverity                                               string                                `yaml:"minLimitAlertSeverity,omitempty" json:"minLimitAlertSeverity,omitempty"`
	MinLimitAlertBucketClassPriority                                    int                                   `yaml:"minLimitAlertBucketClassPriority,omitempty" json:"minLimitAlertBucketClassPriority,omitempty"`
	LimitClassDigestTypes                                               []string                              `yaml:"limitClassDigestTypes,omitempty" json:"limitClassDigestTypes,omitempty"`
	LimitClassDigestSummaryOnlyTypes                                    []string                              `yaml:"limitClassDigestSummaryOnlyTypes,omitempty" json:"limitClassDigestSummaryOnlyTypes,omitempty"`
	LimitClassDigestMinSeverity                                         string                                `yaml:"limitClassDigestMinSeverity,omitempty" json:"limitClassDigestMinSeverity,omitempty"`
	LimitClassDigestSeverities                                          []string                              `yaml:"limitClassDigestSeverities,omitempty" json:"limitClassDigestSeverities,omitempty"`
	LimitClassDigestMinBucketClassPriority                              int                                   `yaml:"limitClassDigestMinBucketClassPriority,omitempty" json:"limitClassDigestMinBucketClassPriority,omitempty"`
	LimitClassDigestMaxBucketClasses                                    int                                   `yaml:"limitClassDigestMaxBucketClasses,omitempty" json:"limitClassDigestMaxBucketClasses,omitempty"`
	LimitClassDigestMinSummarySeverity                                  string                                `yaml:"limitClassDigestMinSummarySeverity,omitempty" json:"limitClassDigestMinSummarySeverity,omitempty"`
	LimitClassDigestMinSummaryBucketClassPriority                       int                                   `yaml:"limitClassDigestMinSummaryBucketClassPriority,omitempty" json:"limitClassDigestMinSummaryBucketClassPriority,omitempty"`
	LimitClassDigestSummarySortMode                                     string                                `yaml:"limitClassDigestSummarySortMode,omitempty" json:"limitClassDigestSummarySortMode,omitempty"`
	LimitClassDigestMinSummaryCount                                     int                                   `yaml:"limitClassDigestMinSummaryCount,omitempty" json:"limitClassDigestMinSummaryCount,omitempty"`
	LimitClassDigestOtherBucketLabel                                    string                                `yaml:"limitClassDigestOtherBucketLabel,omitempty" json:"limitClassDigestOtherBucketLabel,omitempty"`
	LimitClassDigestOverflowReasons                                     []string                              `yaml:"limitClassDigestOverflowReasons,omitempty" json:"limitClassDigestOverflowReasons,omitempty"`
	LimitClassDigestOverflowReasonLabels                                map[string]string                     `yaml:"limitClassDigestOverflowReasonLabels,omitempty" json:"limitClassDigestOverflowReasonLabels,omitempty"`
	LimitClassDigestOverflowReasonGroups                                map[string][]string                   `yaml:"limitClassDigestOverflowReasonGroups,omitempty" json:"limitClassDigestOverflowReasonGroups,omitempty"`
	LimitClassDigestOverflowReasonOrder                                 []string                              `yaml:"limitClassDigestOverflowReasonOrder,omitempty" json:"limitClassDigestOverflowReasonOrder,omitempty"`
	LimitClassDigestMaxOverflowReasons                                  int                                   `yaml:"limitClassDigestMaxOverflowReasons,omitempty" json:"limitClassDigestMaxOverflowReasons,omitempty"`
	LimitClassDigestTruncatedReasonBucketLabel                          string                                `yaml:"limitClassDigestTruncatedReasonBucketLabel,omitempty" json:"limitClassDigestTruncatedReasonBucketLabel,omitempty"`
	LimitClassDigestTruncatedReasonBucketMode                           string                                `yaml:"limitClassDigestTruncatedReasonBucketMode,omitempty" json:"limitClassDigestTruncatedReasonBucketMode,omitempty"`
	LimitClassDigestTruncatedReasonBucketMaxReasons                     int                                   `yaml:"limitClassDigestTruncatedReasonBucketMaxReasons,omitempty" json:"limitClassDigestTruncatedReasonBucketMaxReasons,omitempty"`
	LimitClassDigestTruncatedReasonBucketReasonOrder                    []string                              `yaml:"limitClassDigestTruncatedReasonBucketReasonOrder,omitempty" json:"limitClassDigestTruncatedReasonBucketReasonOrder,omitempty"`
	LimitClassDigestTruncatedReasonBucketMinSeverity                    string                                `yaml:"limitClassDigestTruncatedReasonBucketMinSeverity,omitempty" json:"limitClassDigestTruncatedReasonBucketMinSeverity,omitempty"`
	LimitClassDigestTruncatedReasonBucketSeverities                     []string                              `yaml:"limitClassDigestTruncatedReasonBucketSeverities,omitempty" json:"limitClassDigestTruncatedReasonBucketSeverities,omitempty"`
	LimitClassDigestTruncatedReasonBucketSortMode                       string                                `yaml:"limitClassDigestTruncatedReasonBucketSortMode,omitempty" json:"limitClassDigestTruncatedReasonBucketSortMode,omitempty"`
	LimitClassDigestTruncatedReasonBucketDominantReasonStrategy         string                                `yaml:"limitClassDigestTruncatedReasonBucketDominantReasonStrategy,omitempty" json:"limitClassDigestTruncatedReasonBucketDominantReasonStrategy,omitempty"`
	LimitClassDigestTruncatedReasonBucketHiddenStrategyOrder            []string                              `yaml:"limitClassDigestTruncatedReasonBucketHiddenStrategyOrder,omitempty" json:"limitClassDigestTruncatedReasonBucketHiddenStrategyOrder,omitempty"`
	LimitClassDigestTruncatedReasonBucketHiddenStrategyDominantMode     string                                `yaml:"limitClassDigestTruncatedReasonBucketHiddenStrategyDominantMode,omitempty" json:"limitClassDigestTruncatedReasonBucketHiddenStrategyDominantMode,omitempty"`
	LimitClassDigestTruncatedReasonBucketHiddenStrategyPriorityWeight   int                                   `yaml:"limitClassDigestTruncatedReasonBucketHiddenStrategyPriorityWeight,omitempty" json:"limitClassDigestTruncatedReasonBucketHiddenStrategyPriorityWeight,omitempty"`
	LimitClassDigestTruncatedReasonBucketHiddenStrategyReasonWeight     int                                   `yaml:"limitClassDigestTruncatedReasonBucketHiddenStrategyReasonWeight,omitempty" json:"limitClassDigestTruncatedReasonBucketHiddenStrategyReasonWeight,omitempty"`
	LimitClassDigestTruncatedReasonBucketHiddenStrategyItemWeight       int                                   `yaml:"limitClassDigestTruncatedReasonBucketHiddenStrategyItemWeight,omitempty" json:"limitClassDigestTruncatedReasonBucketHiddenStrategyItemWeight,omitempty"`
	LimitClassDigestTruncatedReasonBucketHiddenStrategyPriorityCap      int                                   `yaml:"limitClassDigestTruncatedReasonBucketHiddenStrategyPriorityCap,omitempty" json:"limitClassDigestTruncatedReasonBucketHiddenStrategyPriorityCap,omitempty"`
	LimitClassDigestTruncatedReasonBucketHiddenStrategyReasonCap        int                                   `yaml:"limitClassDigestTruncatedReasonBucketHiddenStrategyReasonCap,omitempty" json:"limitClassDigestTruncatedReasonBucketHiddenStrategyReasonCap,omitempty"`
	LimitClassDigestTruncatedReasonBucketHiddenStrategyItemCap          int                                   `yaml:"limitClassDigestTruncatedReasonBucketHiddenStrategyItemCap,omitempty" json:"limitClassDigestTruncatedReasonBucketHiddenStrategyItemCap,omitempty"`
	LimitClassDigestTruncatedReasonBucketHiddenStrategyMinReasons       int                                   `yaml:"limitClassDigestTruncatedReasonBucketHiddenStrategyMinReasons,omitempty" json:"limitClassDigestTruncatedReasonBucketHiddenStrategyMinReasons,omitempty"`
	LimitClassDigestTruncatedReasonBucketHiddenStrategyMinItems         int                                   `yaml:"limitClassDigestTruncatedReasonBucketHiddenStrategyMinItems,omitempty" json:"limitClassDigestTruncatedReasonBucketHiddenStrategyMinItems,omitempty"`
	LimitClassDigestTruncatedReasonBucketExactSeverityPolicyPresetChain []string                              `yaml:"limitClassDigestTruncatedReasonBucketExactSeverityPolicyPresetChain,omitempty" json:"limitClassDigestTruncatedReasonBucketExactSeverityPolicyPresetChain,omitempty"`
	LimitClassDigestTruncatedReasonBucketExactSeverityPolicyPreset      string                                `yaml:"limitClassDigestTruncatedReasonBucketExactSeverityPolicyPreset,omitempty" json:"limitClassDigestTruncatedReasonBucketExactSeverityPolicyPreset,omitempty"`
	LimitClassDigestTruncatedReasonBucketExactSeverityPolicy            *LimitClassDigestHiddenStrategyPolicy `yaml:"limitClassDigestTruncatedReasonBucketExactSeverityPolicy,omitempty" json:"limitClassDigestTruncatedReasonBucketExactSeverityPolicy,omitempty"`
	LimitClassDigestTruncatedReasonBucketExactSeverityPriorityCap       int                                   `yaml:"limitClassDigestTruncatedReasonBucketExactSeverityPriorityCap,omitempty" json:"limitClassDigestTruncatedReasonBucketExactSeverityPriorityCap,omitempty"`
	LimitClassDigestTruncatedReasonBucketExactSeverityReasonCap         int                                   `yaml:"limitClassDigestTruncatedReasonBucketExactSeverityReasonCap,omitempty" json:"limitClassDigestTruncatedReasonBucketExactSeverityReasonCap,omitempty"`
	LimitClassDigestTruncatedReasonBucketExactSeverityItemCap           int                                   `yaml:"limitClassDigestTruncatedReasonBucketExactSeverityItemCap,omitempty" json:"limitClassDigestTruncatedReasonBucketExactSeverityItemCap,omitempty"`
	LimitClassDigestTruncatedReasonBucketExactSeverityPriorityWeight    int                                   `yaml:"limitClassDigestTruncatedReasonBucketExactSeverityPriorityWeight,omitempty" json:"limitClassDigestTruncatedReasonBucketExactSeverityPriorityWeight,omitempty"`
	LimitClassDigestTruncatedReasonBucketExactSeverityReasonWeight      int                                   `yaml:"limitClassDigestTruncatedReasonBucketExactSeverityReasonWeight,omitempty" json:"limitClassDigestTruncatedReasonBucketExactSeverityReasonWeight,omitempty"`
	LimitClassDigestTruncatedReasonBucketExactSeverityItemWeight        int                                   `yaml:"limitClassDigestTruncatedReasonBucketExactSeverityItemWeight,omitempty" json:"limitClassDigestTruncatedReasonBucketExactSeverityItemWeight,omitempty"`
	LimitClassDigestTruncatedReasonBucketExactSeverityDominantMode      string                                `yaml:"limitClassDigestTruncatedReasonBucketExactSeverityDominantMode,omitempty" json:"limitClassDigestTruncatedReasonBucketExactSeverityDominantMode,omitempty"`
	LimitClassDigestTruncatedReasonBucketExactSeverityMinReasons        int                                   `yaml:"limitClassDigestTruncatedReasonBucketExactSeverityMinReasons,omitempty" json:"limitClassDigestTruncatedReasonBucketExactSeverityMinReasons,omitempty"`
	LimitClassDigestTruncatedReasonBucketExactSeverityMinItems          int                                   `yaml:"limitClassDigestTruncatedReasonBucketExactSeverityMinItems,omitempty" json:"limitClassDigestTruncatedReasonBucketExactSeverityMinItems,omitempty"`
	LimitClassDigestTruncatedReasonBucketMinSeverityPolicyPresetChain   []string                              `yaml:"limitClassDigestTruncatedReasonBucketMinSeverityPolicyPresetChain,omitempty" json:"limitClassDigestTruncatedReasonBucketMinSeverityPolicyPresetChain,omitempty"`
	LimitClassDigestTruncatedReasonBucketMinSeverityPolicyPreset        string                                `yaml:"limitClassDigestTruncatedReasonBucketMinSeverityPolicyPreset,omitempty" json:"limitClassDigestTruncatedReasonBucketMinSeverityPolicyPreset,omitempty"`
	LimitClassDigestTruncatedReasonBucketMinSeverityPolicy              *LimitClassDigestHiddenStrategyPolicy `yaml:"limitClassDigestTruncatedReasonBucketMinSeverityPolicy,omitempty" json:"limitClassDigestTruncatedReasonBucketMinSeverityPolicy,omitempty"`
	LimitClassDigestTruncatedReasonBucketMinSeverityPriorityCap         int                                   `yaml:"limitClassDigestTruncatedReasonBucketMinSeverityPriorityCap,omitempty" json:"limitClassDigestTruncatedReasonBucketMinSeverityPriorityCap,omitempty"`
	LimitClassDigestTruncatedReasonBucketMinSeverityReasonCap           int                                   `yaml:"limitClassDigestTruncatedReasonBucketMinSeverityReasonCap,omitempty" json:"limitClassDigestTruncatedReasonBucketMinSeverityReasonCap,omitempty"`
	LimitClassDigestTruncatedReasonBucketMinSeverityItemCap             int                                   `yaml:"limitClassDigestTruncatedReasonBucketMinSeverityItemCap,omitempty" json:"limitClassDigestTruncatedReasonBucketMinSeverityItemCap,omitempty"`
	LimitClassDigestTruncatedReasonBucketMinSeverityPriorityWeight      int                                   `yaml:"limitClassDigestTruncatedReasonBucketMinSeverityPriorityWeight,omitempty" json:"limitClassDigestTruncatedReasonBucketMinSeverityPriorityWeight,omitempty"`
	LimitClassDigestTruncatedReasonBucketMinSeverityReasonWeight        int                                   `yaml:"limitClassDigestTruncatedReasonBucketMinSeverityReasonWeight,omitempty" json:"limitClassDigestTruncatedReasonBucketMinSeverityReasonWeight,omitempty"`
	LimitClassDigestTruncatedReasonBucketMinSeverityItemWeight          int                                   `yaml:"limitClassDigestTruncatedReasonBucketMinSeverityItemWeight,omitempty" json:"limitClassDigestTruncatedReasonBucketMinSeverityItemWeight,omitempty"`
	LimitClassDigestTruncatedReasonBucketMinSeverityDominantMode        string                                `yaml:"limitClassDigestTruncatedReasonBucketMinSeverityDominantMode,omitempty" json:"limitClassDigestTruncatedReasonBucketMinSeverityDominantMode,omitempty"`
	LimitClassDigestTruncatedReasonBucketMinSeverityMinReasons          int                                   `yaml:"limitClassDigestTruncatedReasonBucketMinSeverityMinReasons,omitempty" json:"limitClassDigestTruncatedReasonBucketMinSeverityMinReasons,omitempty"`
	LimitClassDigestTruncatedReasonBucketMinSeverityMinItems            int                                   `yaml:"limitClassDigestTruncatedReasonBucketMinSeverityMinItems,omitempty" json:"limitClassDigestTruncatedReasonBucketMinSeverityMinItems,omitempty"`
	LimitClassDigestTruncatedReasonBucketMaxReasonsPolicyPresetChain    []string                              `yaml:"limitClassDigestTruncatedReasonBucketMaxReasonsPolicyPresetChain,omitempty" json:"limitClassDigestTruncatedReasonBucketMaxReasonsPolicyPresetChain,omitempty"`
	LimitClassDigestTruncatedReasonBucketMaxReasonsPolicyPreset         string                                `yaml:"limitClassDigestTruncatedReasonBucketMaxReasonsPolicyPreset,omitempty" json:"limitClassDigestTruncatedReasonBucketMaxReasonsPolicyPreset,omitempty"`
	LimitClassDigestTruncatedReasonBucketMaxReasonsPolicy               *LimitClassDigestHiddenStrategyPolicy `yaml:"limitClassDigestTruncatedReasonBucketMaxReasonsPolicy,omitempty" json:"limitClassDigestTruncatedReasonBucketMaxReasonsPolicy,omitempty"`
	LimitClassDigestTruncatedReasonBucketMaxReasonsPriorityCap          int                                   `yaml:"limitClassDigestTruncatedReasonBucketMaxReasonsPriorityCap,omitempty" json:"limitClassDigestTruncatedReasonBucketMaxReasonsPriorityCap,omitempty"`
	LimitClassDigestTruncatedReasonBucketMaxReasonsReasonCap            int                                   `yaml:"limitClassDigestTruncatedReasonBucketMaxReasonsReasonCap,omitempty" json:"limitClassDigestTruncatedReasonBucketMaxReasonsReasonCap,omitempty"`
	LimitClassDigestTruncatedReasonBucketMaxReasonsItemCap              int                                   `yaml:"limitClassDigestTruncatedReasonBucketMaxReasonsItemCap,omitempty" json:"limitClassDigestTruncatedReasonBucketMaxReasonsItemCap,omitempty"`
	LimitClassDigestTruncatedReasonBucketMaxReasonsPriorityWeight       int                                   `yaml:"limitClassDigestTruncatedReasonBucketMaxReasonsPriorityWeight,omitempty" json:"limitClassDigestTruncatedReasonBucketMaxReasonsPriorityWeight,omitempty"`
	LimitClassDigestTruncatedReasonBucketMaxReasonsReasonWeight         int                                   `yaml:"limitClassDigestTruncatedReasonBucketMaxReasonsReasonWeight,omitempty" json:"limitClassDigestTruncatedReasonBucketMaxReasonsReasonWeight,omitempty"`
	LimitClassDigestTruncatedReasonBucketMaxReasonsItemWeight           int                                   `yaml:"limitClassDigestTruncatedReasonBucketMaxReasonsItemWeight,omitempty" json:"limitClassDigestTruncatedReasonBucketMaxReasonsItemWeight,omitempty"`
	LimitClassDigestTruncatedReasonBucketMaxReasonsDominantMode         string                                `yaml:"limitClassDigestTruncatedReasonBucketMaxReasonsDominantMode,omitempty" json:"limitClassDigestTruncatedReasonBucketMaxReasonsDominantMode,omitempty"`
	LimitClassDigestTruncatedReasonBucketMaxReasonsMinReasons           int                                   `yaml:"limitClassDigestTruncatedReasonBucketMaxReasonsMinReasons,omitempty" json:"limitClassDigestTruncatedReasonBucketMaxReasonsMinReasons,omitempty"`
	LimitClassDigestTruncatedReasonBucketMaxReasonsMinItems             int                                   `yaml:"limitClassDigestTruncatedReasonBucketMaxReasonsMinItems,omitempty" json:"limitClassDigestTruncatedReasonBucketMaxReasonsMinItems,omitempty"`
	LimitClassDigestMaxSummaryBucketClasses                             int                                   `yaml:"limitClassDigestMaxSummaryBucketClasses,omitempty" json:"limitClassDigestMaxSummaryBucketClasses,omitempty"`
	LimitAlertTypes                                                     []string                              `yaml:"limitAlertTypes,omitempty" json:"limitAlertTypes,omitempty"`
	LimitAlertKeyTypes                                                  []string                              `yaml:"limitAlertKeyTypes,omitempty" json:"limitAlertKeyTypes,omitempty"`
	LimitAlertBucketClasses                                             []string                              `yaml:"limitAlertBucketClasses,omitempty" json:"limitAlertBucketClasses,omitempty"`
	LimitAlertBucketIDRegex                                             string                                `yaml:"limitAlertBucketIDRegex,omitempty" json:"limitAlertBucketIDRegex,omitempty"`
	LimitAlertCooldown                                                  string                                `yaml:"limitAlertCooldown,omitempty" json:"limitAlertCooldown,omitempty"`
	LimitClassSnoozeExpiryCooldown                                      string                                `yaml:"limitClassSnoozeExpiryCooldown,omitempty" json:"limitClassSnoozeExpiryCooldown,omitempty"`
	LimitClassSnoozeExpiryWithin                                        string                                `yaml:"limitClassSnoozeExpiryWithin,omitempty" json:"limitClassSnoozeExpiryWithin,omitempty"`
	LimitClassSnoozeExpiryStages                                        []string                              `yaml:"limitClassSnoozeExpiryStages,omitempty" json:"limitClassSnoozeExpiryStages,omitempty"`
	LimitClassSnoozeEventTypes                                          []string                              `yaml:"limitClassSnoozeEventTypes,omitempty" json:"limitClassSnoozeEventTypes,omitempty"`
	Headers                                                             map[string]string                     `yaml:"headers,omitempty" json:"headers,omitempty"`
	Timeout                                                             string                                `yaml:"timeout,omitempty" json:"timeout,omitempty"`
	RetryCount                                                          int                                   `yaml:"retryCount,omitempty" json:"retryCount,omitempty"`
	RetryBackoff                                                        string                                `yaml:"retryBackoff,omitempty" json:"retryBackoff,omitempty"`
	SigningSecret                                                       string                                `yaml:"signingSecret,omitempty" json:"signingSecret,omitempty"`
	SignatureHeader                                                     string                                `yaml:"signatureHeader,omitempty" json:"signatureHeader,omitempty"`
	TimestampHeader                                                     string                                `yaml:"timestampHeader,omitempty" json:"timestampHeader,omitempty"`
	InsecureSkipVerify                                                  bool                                  `yaml:"insecureSkipVerify,omitempty" json:"insecureSkipVerify,omitempty"`
}

type LimitAlertRecipientProfile struct {
	MinLimitAlertSeverity                                               string                                `yaml:"minLimitAlertSeverity,omitempty" json:"minLimitAlertSeverity,omitempty"`
	MinLimitAlertBucketClassPriority                                    int                                   `yaml:"minLimitAlertBucketClassPriority,omitempty" json:"minLimitAlertBucketClassPriority,omitempty"`
	LimitClassDigestTypes                                               []string                              `yaml:"limitClassDigestTypes,omitempty" json:"limitClassDigestTypes,omitempty"`
	LimitClassDigestSummaryOnlyTypes                                    []string                              `yaml:"limitClassDigestSummaryOnlyTypes,omitempty" json:"limitClassDigestSummaryOnlyTypes,omitempty"`
	LimitClassDigestMinSeverity                                         string                                `yaml:"limitClassDigestMinSeverity,omitempty" json:"limitClassDigestMinSeverity,omitempty"`
	LimitClassDigestSeverities                                          []string                              `yaml:"limitClassDigestSeverities,omitempty" json:"limitClassDigestSeverities,omitempty"`
	LimitClassDigestMinBucketClassPriority                              int                                   `yaml:"limitClassDigestMinBucketClassPriority,omitempty" json:"limitClassDigestMinBucketClassPriority,omitempty"`
	LimitClassDigestMaxBucketClasses                                    int                                   `yaml:"limitClassDigestMaxBucketClasses,omitempty" json:"limitClassDigestMaxBucketClasses,omitempty"`
	LimitClassDigestMinSummarySeverity                                  string                                `yaml:"limitClassDigestMinSummarySeverity,omitempty" json:"limitClassDigestMinSummarySeverity,omitempty"`
	LimitClassDigestMinSummaryBucketClassPriority                       int                                   `yaml:"limitClassDigestMinSummaryBucketClassPriority,omitempty" json:"limitClassDigestMinSummaryBucketClassPriority,omitempty"`
	LimitClassDigestSummarySortMode                                     string                                `yaml:"limitClassDigestSummarySortMode,omitempty" json:"limitClassDigestSummarySortMode,omitempty"`
	LimitClassDigestMinSummaryCount                                     int                                   `yaml:"limitClassDigestMinSummaryCount,omitempty" json:"limitClassDigestMinSummaryCount,omitempty"`
	LimitClassDigestOtherBucketLabel                                    string                                `yaml:"limitClassDigestOtherBucketLabel,omitempty" json:"limitClassDigestOtherBucketLabel,omitempty"`
	LimitClassDigestOverflowReasons                                     []string                              `yaml:"limitClassDigestOverflowReasons,omitempty" json:"limitClassDigestOverflowReasons,omitempty"`
	LimitClassDigestOverflowReasonLabels                                map[string]string                     `yaml:"limitClassDigestOverflowReasonLabels,omitempty" json:"limitClassDigestOverflowReasonLabels,omitempty"`
	LimitClassDigestOverflowReasonGroups                                map[string][]string                   `yaml:"limitClassDigestOverflowReasonGroups,omitempty" json:"limitClassDigestOverflowReasonGroups,omitempty"`
	LimitClassDigestOverflowReasonOrder                                 []string                              `yaml:"limitClassDigestOverflowReasonOrder,omitempty" json:"limitClassDigestOverflowReasonOrder,omitempty"`
	LimitClassDigestMaxOverflowReasons                                  int                                   `yaml:"limitClassDigestMaxOverflowReasons,omitempty" json:"limitClassDigestMaxOverflowReasons,omitempty"`
	LimitClassDigestTruncatedReasonBucketLabel                          string                                `yaml:"limitClassDigestTruncatedReasonBucketLabel,omitempty" json:"limitClassDigestTruncatedReasonBucketLabel,omitempty"`
	LimitClassDigestTruncatedReasonBucketMode                           string                                `yaml:"limitClassDigestTruncatedReasonBucketMode,omitempty" json:"limitClassDigestTruncatedReasonBucketMode,omitempty"`
	LimitClassDigestTruncatedReasonBucketMaxReasons                     int                                   `yaml:"limitClassDigestTruncatedReasonBucketMaxReasons,omitempty" json:"limitClassDigestTruncatedReasonBucketMaxReasons,omitempty"`
	LimitClassDigestTruncatedReasonBucketReasonOrder                    []string                              `yaml:"limitClassDigestTruncatedReasonBucketReasonOrder,omitempty" json:"limitClassDigestTruncatedReasonBucketReasonOrder,omitempty"`
	LimitClassDigestTruncatedReasonBucketMinSeverity                    string                                `yaml:"limitClassDigestTruncatedReasonBucketMinSeverity,omitempty" json:"limitClassDigestTruncatedReasonBucketMinSeverity,omitempty"`
	LimitClassDigestTruncatedReasonBucketSeverities                     []string                              `yaml:"limitClassDigestTruncatedReasonBucketSeverities,omitempty" json:"limitClassDigestTruncatedReasonBucketSeverities,omitempty"`
	LimitClassDigestTruncatedReasonBucketSortMode                       string                                `yaml:"limitClassDigestTruncatedReasonBucketSortMode,omitempty" json:"limitClassDigestTruncatedReasonBucketSortMode,omitempty"`
	LimitClassDigestTruncatedReasonBucketDominantReasonStrategy         string                                `yaml:"limitClassDigestTruncatedReasonBucketDominantReasonStrategy,omitempty" json:"limitClassDigestTruncatedReasonBucketDominantReasonStrategy,omitempty"`
	LimitClassDigestTruncatedReasonBucketHiddenStrategyOrder            []string                              `yaml:"limitClassDigestTruncatedReasonBucketHiddenStrategyOrder,omitempty" json:"limitClassDigestTruncatedReasonBucketHiddenStrategyOrder,omitempty"`
	LimitClassDigestTruncatedReasonBucketHiddenStrategyDominantMode     string                                `yaml:"limitClassDigestTruncatedReasonBucketHiddenStrategyDominantMode,omitempty" json:"limitClassDigestTruncatedReasonBucketHiddenStrategyDominantMode,omitempty"`
	LimitClassDigestTruncatedReasonBucketHiddenStrategyPriorityWeight   int                                   `yaml:"limitClassDigestTruncatedReasonBucketHiddenStrategyPriorityWeight,omitempty" json:"limitClassDigestTruncatedReasonBucketHiddenStrategyPriorityWeight,omitempty"`
	LimitClassDigestTruncatedReasonBucketHiddenStrategyReasonWeight     int                                   `yaml:"limitClassDigestTruncatedReasonBucketHiddenStrategyReasonWeight,omitempty" json:"limitClassDigestTruncatedReasonBucketHiddenStrategyReasonWeight,omitempty"`
	LimitClassDigestTruncatedReasonBucketHiddenStrategyItemWeight       int                                   `yaml:"limitClassDigestTruncatedReasonBucketHiddenStrategyItemWeight,omitempty" json:"limitClassDigestTruncatedReasonBucketHiddenStrategyItemWeight,omitempty"`
	LimitClassDigestTruncatedReasonBucketHiddenStrategyPriorityCap      int                                   `yaml:"limitClassDigestTruncatedReasonBucketHiddenStrategyPriorityCap,omitempty" json:"limitClassDigestTruncatedReasonBucketHiddenStrategyPriorityCap,omitempty"`
	LimitClassDigestTruncatedReasonBucketHiddenStrategyReasonCap        int                                   `yaml:"limitClassDigestTruncatedReasonBucketHiddenStrategyReasonCap,omitempty" json:"limitClassDigestTruncatedReasonBucketHiddenStrategyReasonCap,omitempty"`
	LimitClassDigestTruncatedReasonBucketHiddenStrategyItemCap          int                                   `yaml:"limitClassDigestTruncatedReasonBucketHiddenStrategyItemCap,omitempty" json:"limitClassDigestTruncatedReasonBucketHiddenStrategyItemCap,omitempty"`
	LimitClassDigestTruncatedReasonBucketHiddenStrategyMinReasons       int                                   `yaml:"limitClassDigestTruncatedReasonBucketHiddenStrategyMinReasons,omitempty" json:"limitClassDigestTruncatedReasonBucketHiddenStrategyMinReasons,omitempty"`
	LimitClassDigestTruncatedReasonBucketHiddenStrategyMinItems         int                                   `yaml:"limitClassDigestTruncatedReasonBucketHiddenStrategyMinItems,omitempty" json:"limitClassDigestTruncatedReasonBucketHiddenStrategyMinItems,omitempty"`
	LimitClassDigestTruncatedReasonBucketExactSeverityPolicyPresetChain []string                              `yaml:"limitClassDigestTruncatedReasonBucketExactSeverityPolicyPresetChain,omitempty" json:"limitClassDigestTruncatedReasonBucketExactSeverityPolicyPresetChain,omitempty"`
	LimitClassDigestTruncatedReasonBucketExactSeverityPolicyPreset      string                                `yaml:"limitClassDigestTruncatedReasonBucketExactSeverityPolicyPreset,omitempty" json:"limitClassDigestTruncatedReasonBucketExactSeverityPolicyPreset,omitempty"`
	LimitClassDigestTruncatedReasonBucketExactSeverityPolicy            *LimitClassDigestHiddenStrategyPolicy `yaml:"limitClassDigestTruncatedReasonBucketExactSeverityPolicy,omitempty" json:"limitClassDigestTruncatedReasonBucketExactSeverityPolicy,omitempty"`
	LimitClassDigestTruncatedReasonBucketExactSeverityPriorityCap       int                                   `yaml:"limitClassDigestTruncatedReasonBucketExactSeverityPriorityCap,omitempty" json:"limitClassDigestTruncatedReasonBucketExactSeverityPriorityCap,omitempty"`
	LimitClassDigestTruncatedReasonBucketExactSeverityReasonCap         int                                   `yaml:"limitClassDigestTruncatedReasonBucketExactSeverityReasonCap,omitempty" json:"limitClassDigestTruncatedReasonBucketExactSeverityReasonCap,omitempty"`
	LimitClassDigestTruncatedReasonBucketExactSeverityItemCap           int                                   `yaml:"limitClassDigestTruncatedReasonBucketExactSeverityItemCap,omitempty" json:"limitClassDigestTruncatedReasonBucketExactSeverityItemCap,omitempty"`
	LimitClassDigestTruncatedReasonBucketExactSeverityPriorityWeight    int                                   `yaml:"limitClassDigestTruncatedReasonBucketExactSeverityPriorityWeight,omitempty" json:"limitClassDigestTruncatedReasonBucketExactSeverityPriorityWeight,omitempty"`
	LimitClassDigestTruncatedReasonBucketExactSeverityReasonWeight      int                                   `yaml:"limitClassDigestTruncatedReasonBucketExactSeverityReasonWeight,omitempty" json:"limitClassDigestTruncatedReasonBucketExactSeverityReasonWeight,omitempty"`
	LimitClassDigestTruncatedReasonBucketExactSeverityItemWeight        int                                   `yaml:"limitClassDigestTruncatedReasonBucketExactSeverityItemWeight,omitempty" json:"limitClassDigestTruncatedReasonBucketExactSeverityItemWeight,omitempty"`
	LimitClassDigestTruncatedReasonBucketExactSeverityDominantMode      string                                `yaml:"limitClassDigestTruncatedReasonBucketExactSeverityDominantMode,omitempty" json:"limitClassDigestTruncatedReasonBucketExactSeverityDominantMode,omitempty"`
	LimitClassDigestTruncatedReasonBucketExactSeverityMinReasons        int                                   `yaml:"limitClassDigestTruncatedReasonBucketExactSeverityMinReasons,omitempty" json:"limitClassDigestTruncatedReasonBucketExactSeverityMinReasons,omitempty"`
	LimitClassDigestTruncatedReasonBucketExactSeverityMinItems          int                                   `yaml:"limitClassDigestTruncatedReasonBucketExactSeverityMinItems,omitempty" json:"limitClassDigestTruncatedReasonBucketExactSeverityMinItems,omitempty"`
	LimitClassDigestTruncatedReasonBucketMinSeverityPolicyPresetChain   []string                              `yaml:"limitClassDigestTruncatedReasonBucketMinSeverityPolicyPresetChain,omitempty" json:"limitClassDigestTruncatedReasonBucketMinSeverityPolicyPresetChain,omitempty"`
	LimitClassDigestTruncatedReasonBucketMinSeverityPolicyPreset        string                                `yaml:"limitClassDigestTruncatedReasonBucketMinSeverityPolicyPreset,omitempty" json:"limitClassDigestTruncatedReasonBucketMinSeverityPolicyPreset,omitempty"`
	LimitClassDigestTruncatedReasonBucketMinSeverityPolicy              *LimitClassDigestHiddenStrategyPolicy `yaml:"limitClassDigestTruncatedReasonBucketMinSeverityPolicy,omitempty" json:"limitClassDigestTruncatedReasonBucketMinSeverityPolicy,omitempty"`
	LimitClassDigestTruncatedReasonBucketMinSeverityPriorityCap         int                                   `yaml:"limitClassDigestTruncatedReasonBucketMinSeverityPriorityCap,omitempty" json:"limitClassDigestTruncatedReasonBucketMinSeverityPriorityCap,omitempty"`
	LimitClassDigestTruncatedReasonBucketMinSeverityReasonCap           int                                   `yaml:"limitClassDigestTruncatedReasonBucketMinSeverityReasonCap,omitempty" json:"limitClassDigestTruncatedReasonBucketMinSeverityReasonCap,omitempty"`
	LimitClassDigestTruncatedReasonBucketMinSeverityItemCap             int                                   `yaml:"limitClassDigestTruncatedReasonBucketMinSeverityItemCap,omitempty" json:"limitClassDigestTruncatedReasonBucketMinSeverityItemCap,omitempty"`
	LimitClassDigestTruncatedReasonBucketMinSeverityPriorityWeight      int                                   `yaml:"limitClassDigestTruncatedReasonBucketMinSeverityPriorityWeight,omitempty" json:"limitClassDigestTruncatedReasonBucketMinSeverityPriorityWeight,omitempty"`
	LimitClassDigestTruncatedReasonBucketMinSeverityReasonWeight        int                                   `yaml:"limitClassDigestTruncatedReasonBucketMinSeverityReasonWeight,omitempty" json:"limitClassDigestTruncatedReasonBucketMinSeverityReasonWeight,omitempty"`
	LimitClassDigestTruncatedReasonBucketMinSeverityItemWeight          int                                   `yaml:"limitClassDigestTruncatedReasonBucketMinSeverityItemWeight,omitempty" json:"limitClassDigestTruncatedReasonBucketMinSeverityItemWeight,omitempty"`
	LimitClassDigestTruncatedReasonBucketMinSeverityDominantMode        string                                `yaml:"limitClassDigestTruncatedReasonBucketMinSeverityDominantMode,omitempty" json:"limitClassDigestTruncatedReasonBucketMinSeverityDominantMode,omitempty"`
	LimitClassDigestTruncatedReasonBucketMinSeverityMinReasons          int                                   `yaml:"limitClassDigestTruncatedReasonBucketMinSeverityMinReasons,omitempty" json:"limitClassDigestTruncatedReasonBucketMinSeverityMinReasons,omitempty"`
	LimitClassDigestTruncatedReasonBucketMinSeverityMinItems            int                                   `yaml:"limitClassDigestTruncatedReasonBucketMinSeverityMinItems,omitempty" json:"limitClassDigestTruncatedReasonBucketMinSeverityMinItems,omitempty"`
	LimitClassDigestTruncatedReasonBucketMaxReasonsPolicyPresetChain    []string                              `yaml:"limitClassDigestTruncatedReasonBucketMaxReasonsPolicyPresetChain,omitempty" json:"limitClassDigestTruncatedReasonBucketMaxReasonsPolicyPresetChain,omitempty"`
	LimitClassDigestTruncatedReasonBucketMaxReasonsPolicyPreset         string                                `yaml:"limitClassDigestTruncatedReasonBucketMaxReasonsPolicyPreset,omitempty" json:"limitClassDigestTruncatedReasonBucketMaxReasonsPolicyPreset,omitempty"`
	LimitClassDigestTruncatedReasonBucketMaxReasonsPolicy               *LimitClassDigestHiddenStrategyPolicy `yaml:"limitClassDigestTruncatedReasonBucketMaxReasonsPolicy,omitempty" json:"limitClassDigestTruncatedReasonBucketMaxReasonsPolicy,omitempty"`
	LimitClassDigestTruncatedReasonBucketMaxReasonsPriorityCap          int                                   `yaml:"limitClassDigestTruncatedReasonBucketMaxReasonsPriorityCap,omitempty" json:"limitClassDigestTruncatedReasonBucketMaxReasonsPriorityCap,omitempty"`
	LimitClassDigestTruncatedReasonBucketMaxReasonsReasonCap            int                                   `yaml:"limitClassDigestTruncatedReasonBucketMaxReasonsReasonCap,omitempty" json:"limitClassDigestTruncatedReasonBucketMaxReasonsReasonCap,omitempty"`
	LimitClassDigestTruncatedReasonBucketMaxReasonsItemCap              int                                   `yaml:"limitClassDigestTruncatedReasonBucketMaxReasonsItemCap,omitempty" json:"limitClassDigestTruncatedReasonBucketMaxReasonsItemCap,omitempty"`
	LimitClassDigestTruncatedReasonBucketMaxReasonsPriorityWeight       int                                   `yaml:"limitClassDigestTruncatedReasonBucketMaxReasonsPriorityWeight,omitempty" json:"limitClassDigestTruncatedReasonBucketMaxReasonsPriorityWeight,omitempty"`
	LimitClassDigestTruncatedReasonBucketMaxReasonsReasonWeight         int                                   `yaml:"limitClassDigestTruncatedReasonBucketMaxReasonsReasonWeight,omitempty" json:"limitClassDigestTruncatedReasonBucketMaxReasonsReasonWeight,omitempty"`
	LimitClassDigestTruncatedReasonBucketMaxReasonsItemWeight           int                                   `yaml:"limitClassDigestTruncatedReasonBucketMaxReasonsItemWeight,omitempty" json:"limitClassDigestTruncatedReasonBucketMaxReasonsItemWeight,omitempty"`
	LimitClassDigestTruncatedReasonBucketMaxReasonsDominantMode         string                                `yaml:"limitClassDigestTruncatedReasonBucketMaxReasonsDominantMode,omitempty" json:"limitClassDigestTruncatedReasonBucketMaxReasonsDominantMode,omitempty"`
	LimitClassDigestTruncatedReasonBucketMaxReasonsMinReasons           int                                   `yaml:"limitClassDigestTruncatedReasonBucketMaxReasonsMinReasons,omitempty" json:"limitClassDigestTruncatedReasonBucketMaxReasonsMinReasons,omitempty"`
	LimitClassDigestTruncatedReasonBucketMaxReasonsMinItems             int                                   `yaml:"limitClassDigestTruncatedReasonBucketMaxReasonsMinItems,omitempty" json:"limitClassDigestTruncatedReasonBucketMaxReasonsMinItems,omitempty"`
	LimitClassDigestMaxSummaryBucketClasses                             int                                   `yaml:"limitClassDigestMaxSummaryBucketClasses,omitempty" json:"limitClassDigestMaxSummaryBucketClasses,omitempty"`
	LimitAlertTypes                                                     []string                              `yaml:"limitAlertTypes,omitempty" json:"limitAlertTypes,omitempty"`
	LimitAlertKeyTypes                                                  []string                              `yaml:"limitAlertKeyTypes,omitempty" json:"limitAlertKeyTypes,omitempty"`
	LimitAlertBucketClasses                                             []string                              `yaml:"limitAlertBucketClasses,omitempty" json:"limitAlertBucketClasses,omitempty"`
	LimitAlertBucketIDRegex                                             string                                `yaml:"limitAlertBucketIDRegex,omitempty" json:"limitAlertBucketIDRegex,omitempty"`
	LimitAlertCooldown                                                  string                                `yaml:"limitAlertCooldown,omitempty" json:"limitAlertCooldown,omitempty"`
	LimitClassSnoozeExpiryCooldown                                      string                                `yaml:"limitClassSnoozeExpiryCooldown,omitempty" json:"limitClassSnoozeExpiryCooldown,omitempty"`
	LimitClassSnoozeExpiryWithin                                        string                                `yaml:"limitClassSnoozeExpiryWithin,omitempty" json:"limitClassSnoozeExpiryWithin,omitempty"`
	LimitClassSnoozeExpiryStages                                        []string                              `yaml:"limitClassSnoozeExpiryStages,omitempty" json:"limitClassSnoozeExpiryStages,omitempty"`
	LimitClassSnoozeEventTypes                                          []string                              `yaml:"limitClassSnoozeEventTypes,omitempty" json:"limitClassSnoozeEventTypes,omitempty"`
}

// JWTConfig holds JWT auth settings
type JWTConfig struct {
	Enabled       bool     `yaml:"enabled"`
	Secret        string   `yaml:"secret"`
	Algorithms    []string `yaml:"algorithms"`
	PublicKeyFile string   `yaml:"publicKeyFile"`
	Required      bool     `yaml:"required"`
}
