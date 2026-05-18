package config

// SecurityConfig represents security configuration
type SecurityConfig struct {
	TLS                     TLSConfig                              `yaml:"tls"`
	EnableBasicAuth         bool                                   `yaml:"enableBasicAuth"`
	BasicAuthUsers          map[string]string                      `yaml:"basicAuthUsers"`
	IPWhitelist             []string                               `yaml:"ipWhitelist"`
	Headers                 map[string]string                      `yaml:"headers"`
	Clients                 map[string]string                      `yaml:"clients"` // clientID: clientSecret
	Jwt                     JWTConfig                              `yaml:"jwt"`
	MutationPolicy          MutationPolicy                         `yaml:"mutationPolicy,omitempty"`
	LimitAlertBucketClasses map[string]LimitAlertBucketClassConfig `yaml:"limitAlertBucketClasses,omitempty" json:"limitAlertBucketClasses,omitempty"`
	LimiterClassPresets     map[string]LimiterClassPolicyPreset    `yaml:"limiterClassPresets,omitempty" json:"limiterClassPresets,omitempty"`
	LimitAlertProfiles      map[string]LimitAlertRecipientProfile  `yaml:"limitAlertProfiles,omitempty" json:"limitAlertProfiles,omitempty"`
	NotificationWebhooks    []NotificationWebhook                  `yaml:"notificationWebhooks,omitempty"`
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
	Enabled                 bool                            `yaml:"enabled,omitempty" json:"enabled,omitempty"`
	Interval                string                          `yaml:"interval,omitempty" json:"interval,omitempty"`
	MinNotificationInterval string                          `yaml:"minNotificationInterval,omitempty" json:"minNotificationInterval,omitempty"`
	OnlyOnChange            bool                            `yaml:"onlyOnChange,omitempty" json:"onlyOnChange,omitempty"`
	Window                  string                          `yaml:"window,omitempty" json:"window,omitempty"`
	MinCount                int                             `yaml:"minCount,omitempty" json:"minCount,omitempty"`
	MinSeverity             string                          `yaml:"minSeverity,omitempty" json:"minSeverity,omitempty"`
	LimitTypePolicies       map[string]LimitAlertTypePolicy `yaml:"limitTypePolicies,omitempty" json:"limitTypePolicies,omitempty"`
}

type LimitAlertTypePolicy struct {
	WarningCount  int `yaml:"warningCount,omitempty" json:"warningCount,omitempty"`
	ElevatedCount int `yaml:"elevatedCount,omitempty" json:"elevatedCount,omitempty"`
	CriticalCount int `yaml:"criticalCount,omitempty" json:"criticalCount,omitempty"`
}

type LimitAlertBucketClassConfig struct {
	KeyType     string `yaml:"keyType,omitempty" json:"keyType,omitempty"`
	BucketRegex string `yaml:"bucketRegex,omitempty" json:"bucketRegex,omitempty"`
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
	Name                      string            `yaml:"name,omitempty" json:"name,omitempty"`
	URL                       string            `yaml:"url" json:"url"`
	Format                    string            `yaml:"format,omitempty" json:"format,omitempty"`
	Events                    []string          `yaml:"events,omitempty" json:"events,omitempty"`
	Environments              []string          `yaml:"environments,omitempty" json:"environments,omitempty"`
	MinSLABreachCount         int               `yaml:"minSLABreachCount,omitempty" json:"minSLABreachCount,omitempty"`
	MinConsecutiveSLABreaches int               `yaml:"minConsecutiveSLABreaches,omitempty" json:"minConsecutiveSLABreaches,omitempty"`
	MinSLABreachDuration      string            `yaml:"minSLABreachDuration,omitempty" json:"minSLABreachDuration,omitempty"`
	MinSLABreachTier          string            `yaml:"minSLABreachTier,omitempty" json:"minSLABreachTier,omitempty"`
	SLABreachCooldown         string            `yaml:"slaBreachCooldown,omitempty" json:"slaBreachCooldown,omitempty"`
	LimitAlertProfile         string            `yaml:"limitAlertProfile,omitempty" json:"limitAlertProfile,omitempty"`
	MinLimitAlertSeverity     string            `yaml:"minLimitAlertSeverity,omitempty" json:"minLimitAlertSeverity,omitempty"`
	LimitAlertTypes           []string          `yaml:"limitAlertTypes,omitempty" json:"limitAlertTypes,omitempty"`
	LimitAlertKeyTypes        []string          `yaml:"limitAlertKeyTypes,omitempty" json:"limitAlertKeyTypes,omitempty"`
	LimitAlertBucketClasses   []string          `yaml:"limitAlertBucketClasses,omitempty" json:"limitAlertBucketClasses,omitempty"`
	LimitAlertBucketIDRegex   string            `yaml:"limitAlertBucketIDRegex,omitempty" json:"limitAlertBucketIDRegex,omitempty"`
	LimitAlertCooldown        string            `yaml:"limitAlertCooldown,omitempty" json:"limitAlertCooldown,omitempty"`
	Headers                   map[string]string `yaml:"headers,omitempty" json:"headers,omitempty"`
	Timeout                   string            `yaml:"timeout,omitempty" json:"timeout,omitempty"`
	RetryCount                int               `yaml:"retryCount,omitempty" json:"retryCount,omitempty"`
	RetryBackoff              string            `yaml:"retryBackoff,omitempty" json:"retryBackoff,omitempty"`
	SigningSecret             string            `yaml:"signingSecret,omitempty" json:"signingSecret,omitempty"`
	SignatureHeader           string            `yaml:"signatureHeader,omitempty" json:"signatureHeader,omitempty"`
	TimestampHeader           string            `yaml:"timestampHeader,omitempty" json:"timestampHeader,omitempty"`
	InsecureSkipVerify        bool              `yaml:"insecureSkipVerify,omitempty" json:"insecureSkipVerify,omitempty"`
}

type LimitAlertRecipientProfile struct {
	MinLimitAlertSeverity   string   `yaml:"minLimitAlertSeverity,omitempty" json:"minLimitAlertSeverity,omitempty"`
	LimitAlertTypes         []string `yaml:"limitAlertTypes,omitempty" json:"limitAlertTypes,omitempty"`
	LimitAlertKeyTypes      []string `yaml:"limitAlertKeyTypes,omitempty" json:"limitAlertKeyTypes,omitempty"`
	LimitAlertBucketClasses []string `yaml:"limitAlertBucketClasses,omitempty" json:"limitAlertBucketClasses,omitempty"`
	LimitAlertBucketIDRegex string   `yaml:"limitAlertBucketIDRegex,omitempty" json:"limitAlertBucketIDRegex,omitempty"`
	LimitAlertCooldown      string   `yaml:"limitAlertCooldown,omitempty" json:"limitAlertCooldown,omitempty"`
}

// JWTConfig holds JWT auth settings
type JWTConfig struct {
	Enabled       bool     `yaml:"enabled"`
	Secret        string   `yaml:"secret"`
	Algorithms    []string `yaml:"algorithms"`
	PublicKeyFile string   `yaml:"publicKeyFile"`
	Required      bool     `yaml:"required"`
}
