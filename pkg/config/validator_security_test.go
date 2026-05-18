package config

import (
	"strings"
	"testing"
)

func TestSecurityConfigRuleRejectsNegativeEnrollmentMaxActive(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Security: SecurityConfig{
			TLS: TLSConfig{
				Enabled:             true,
				CertFile:            "server.crt",
				KeyFile:             "server.key",
				EnrollmentMaxActive: -1,
			},
		},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "enrollmentMaxActive") {
		t.Fatalf("expected enrollmentMaxActive validation error, got %v", err)
	}
}

func TestSecurityConfigRuleRejectsHTTP3WithoutTLS(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Security: SecurityConfig{
			TLS: TLSConfig{
				Enabled:      false,
				HTTP3Enabled: true,
			},
		},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "http3Enabled") {
		t.Fatalf("expected http3Enabled validation error, got %v", err)
	}
}

func TestSecurityConfigRuleAllowsHTTP3WithTLS(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Security: SecurityConfig{
			TLS: TLSConfig{
				Enabled:      true,
				Port:         8443,
				HTTP3Enabled: true,
				HTTP3Port:    8443,
				CertFile:     "server.crt",
				KeyFile:      "server.key",
			},
		},
	}

	if err := NewConfigValidator().Validate(cfg); err != nil {
		t.Fatalf("expected http3 tls config to validate, got %v", err)
	}
}

func TestSecurityConfigRuleRejectsDisabledMutationPolicyRequirements(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Security: SecurityConfig{
			MutationPolicy: MutationPolicy{
				Enabled:                  false,
				RequireNoteForHighImpact: true,
			},
		},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "mutationPolicy.enabled") {
		t.Fatalf("expected mutationPolicy.enabled validation error, got %v", err)
	}
}

func TestSecurityConfigRuleRejectsInvalidMutationPolicyScope(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Security: SecurityConfig{
			MutationPolicy: MutationPolicy{
				Enabled:        true,
				EnforcedScopes: []string{"banana"},
			},
		},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "mutationPolicy.enforcedScopes") {
		t.Fatalf("expected mutationPolicy.enforcedScopes validation error, got %v", err)
	}
}

func TestSecurityConfigRuleAllowsKnownMutationPolicyScopes(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Security: SecurityConfig{
			MutationPolicy: MutationPolicy{
				Enabled:        true,
				EnforcedScopes: []string{"services", "high_impact"},
			},
		},
	}

	if err := NewConfigValidator().Validate(cfg); err != nil {
		t.Fatalf("expected known mutation policy scopes to validate, got %v", err)
	}
}

func TestSecurityConfigRuleRejectsInvalidProposalQueueUrgencyThreshold(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Security: SecurityConfig{
			MutationPolicy: MutationPolicy{
				ProposalQueue: ProposalQueuePolicy{
					DefaultUrgency: ProposalQueueUrgencyThresholds{
						ReadyAgingAfter: "later",
					},
				},
			},
		},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "proposalQueue.defaultUrgency.readyAgingAfter") {
		t.Fatalf("expected proposal queue urgency validation error, got %v", err)
	}
}

func TestSecurityConfigRuleRejectsInvalidProposalQueueUrgencyOrdering(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Security: SecurityConfig{
			MutationPolicy: MutationPolicy{
				ProposalQueue: ProposalQueuePolicy{
					EnvironmentUrgency: map[string]ProposalQueueUrgencyThresholds{
						"prod": {
							BlockedAgingAfter:   "4h",
							BlockedOverdueAfter: "1h",
						},
					},
				},
			},
		},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "proposalQueue.environmentUrgency.prod") {
		t.Fatalf("expected proposal queue urgency ordering validation error, got %v", err)
	}
}

func TestSecurityConfigRuleRejectsInvalidPolicyAlertNotificationSeverity(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Security: SecurityConfig{
			MutationPolicy: MutationPolicy{
				PolicyAlertNotifications: PolicyAlertNotificationPolicy{
					Enabled:     true,
					MinSeverity: "banana",
				},
			},
		},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "policyAlertNotifications.minSeverity") {
		t.Fatalf("expected policy alert notification severity validation error, got %v", err)
	}
}

func TestSecurityConfigRuleRejectsInvalidLimitAlertNotificationSeverity(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Security: SecurityConfig{
			MutationPolicy: MutationPolicy{
				LimitAlertNotifications: PolicyAlertNotificationPolicy{
					Enabled:     true,
					MinSeverity: "banana",
				},
			},
		},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "limitAlertNotifications.minSeverity") {
		t.Fatalf("expected limit alert notification severity validation error, got %v", err)
	}
}

func TestSecurityConfigRuleRejectsInvalidLimitClassAlertNotificationSeverity(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Security: SecurityConfig{
			MutationPolicy: MutationPolicy{
				LimitClassAlertNotifications: PolicyAlertNotificationPolicy{
					Enabled:     true,
					MinSeverity: "banana",
				},
			},
		},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "limitClassAlertNotifications.minSeverity") {
		t.Fatalf("expected limit class alert notification severity validation error, got %v", err)
	}
}

func TestSecurityConfigRuleRejectsInvalidLimitAlertTypePolicyOrdering(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Security: SecurityConfig{
			MutationPolicy: MutationPolicy{
				LimitAlertNotifications: PolicyAlertNotificationPolicy{
					Enabled: true,
					LimitTypePolicies: map[string]LimitAlertTypePolicy{
						"concurrency_queue_full": {
							WarningCount:  3,
							ElevatedCount: 2,
						},
					},
				},
			},
		},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "limitTypePolicies") {
		t.Fatalf("expected limit alert type policy ordering validation error, got %v", err)
	}
}

func TestSecurityConfigRuleRejectsInvalidProposalQueueNotificationInterval(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Security: SecurityConfig{
			MutationPolicy: MutationPolicy{
				ProposalQueue: ProposalQueuePolicy{
					Notifications: ProposalQueueNotificationPolicy{
						Enabled:  true,
						Interval: "whenever",
					},
				},
			},
		},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "proposalQueue.notifications.interval") {
		t.Fatalf("expected proposal queue notification interval validation error, got %v", err)
	}
}

func TestSecurityConfigRuleRejectsInvalidNotificationWebhookURL(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Security: SecurityConfig{
			NotificationWebhooks: []NotificationWebhook{
				{URL: "ftp://example.com/hook"},
			},
		},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "notificationWebhooks[0].url") {
		t.Fatalf("expected notification webhook url validation error, got %v", err)
	}
}

func TestSecurityConfigRuleRejectsInvalidNotificationWebhookFormat(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Security: SecurityConfig{
			NotificationWebhooks: []NotificationWebhook{
				{URL: "https://example.com/hook", Format: "discord"},
			},
		},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "notificationWebhooks[0].format") {
		t.Fatalf("expected notification webhook format validation error, got %v", err)
	}
}

func TestSecurityConfigRuleRejectsSignatureHeaderWithoutSecret(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Security: SecurityConfig{
			NotificationWebhooks: []NotificationWebhook{
				{
					URL:             "https://example.com/hook",
					SignatureHeader: "X-Iket-Signature",
				},
			},
		},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "notificationWebhooks[0].signingSecret") {
		t.Fatalf("expected notification webhook signing secret validation error, got %v", err)
	}
}

func TestSecurityConfigRuleRejectsNegativeNotificationWebhookRetryCount(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Security: SecurityConfig{
			NotificationWebhooks: []NotificationWebhook{
				{URL: "https://example.com/hook", RetryCount: -1},
			},
		},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "notificationWebhooks[0].retryCount") {
		t.Fatalf("expected notification webhook retryCount validation error, got %v", err)
	}
}

func TestSecurityConfigRuleRejectsInvalidNotificationWebhookRetryBackoff(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Security: SecurityConfig{
			NotificationWebhooks: []NotificationWebhook{
				{URL: "https://example.com/hook", RetryBackoff: "later"},
			},
		},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "notificationWebhooks[0].retryBackoff") {
		t.Fatalf("expected notification webhook retryBackoff validation error, got %v", err)
	}
}

func TestSecurityConfigRuleRejectsNegativeNotificationWebhookSLABreachThreshold(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Security: SecurityConfig{
			NotificationWebhooks: []NotificationWebhook{
				{URL: "https://example.com/hook", MinSLABreachCount: -1},
			},
		},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "notificationWebhooks[0].minSLABreachCount") {
		t.Fatalf("expected notification webhook minSLABreachCount validation error, got %v", err)
	}
}

func TestSecurityConfigRuleRejectsNegativeNotificationWebhookConsecutiveSLABreachThreshold(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Security: SecurityConfig{
			NotificationWebhooks: []NotificationWebhook{
				{URL: "https://example.com/hook", MinConsecutiveSLABreaches: -1},
			},
		},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "notificationWebhooks[0].minConsecutiveSLABreaches") {
		t.Fatalf("expected notification webhook minConsecutiveSLABreaches validation error, got %v", err)
	}
}

func TestSecurityConfigRuleRejectsInvalidNotificationWebhookSLABreachDuration(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Security: SecurityConfig{
			NotificationWebhooks: []NotificationWebhook{
				{URL: "https://example.com/hook", MinSLABreachDuration: "later"},
			},
		},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "notificationWebhooks[0].minSLABreachDuration") {
		t.Fatalf("expected notification webhook minSLABreachDuration validation error, got %v", err)
	}
}

func TestSecurityConfigRuleRejectsInvalidNotificationWebhookSLABreachTier(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Security: SecurityConfig{
			NotificationWebhooks: []NotificationWebhook{
				{URL: "https://example.com/hook", MinSLABreachTier: "urgent"},
			},
		},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "notificationWebhooks[0].minSLABreachTier") {
		t.Fatalf("expected notification webhook minSLABreachTier validation error, got %v", err)
	}
}

func TestSecurityConfigRuleRejectsInvalidNotificationWebhookSLABreachCooldown(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Security: SecurityConfig{
			NotificationWebhooks: []NotificationWebhook{
				{URL: "https://example.com/hook", SLABreachCooldown: "soon"},
			},
		},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "notificationWebhooks[0].slaBreachCooldown") {
		t.Fatalf("expected notification webhook slaBreachCooldown validation error, got %v", err)
	}
}

func TestSecurityConfigRuleRejectsInvalidNotificationWebhookLimitAlertSeverity(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Security: SecurityConfig{
			NotificationWebhooks: []NotificationWebhook{
				{URL: "https://example.com/hook", MinLimitAlertSeverity: "urgent"},
			},
		},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "notificationWebhooks[0].minLimitAlertSeverity") {
		t.Fatalf("expected notification webhook minLimitAlertSeverity validation error, got %v", err)
	}
}

func TestSecurityConfigRuleRejectsInvalidNotificationWebhookLimitAlertType(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Security: SecurityConfig{
			NotificationWebhooks: []NotificationWebhook{
				{URL: "https://example.com/hook", LimitAlertTypes: []string{"udp_flood"}},
			},
		},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "notificationWebhooks[0].limitAlertTypes") {
		t.Fatalf("expected notification webhook limitAlertTypes validation error, got %v", err)
	}
}

func TestSecurityConfigRuleRejectsInvalidNotificationWebhookLimitAlertCooldown(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Security: SecurityConfig{
			NotificationWebhooks: []NotificationWebhook{
				{URL: "https://example.com/hook", LimitAlertCooldown: "soon"},
			},
		},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "notificationWebhooks[0].limitAlertCooldown") {
		t.Fatalf("expected notification webhook limitAlertCooldown validation error, got %v", err)
	}
}

func TestSecurityConfigRuleRejectsInvalidNotificationWebhookLimitAlertKeyType(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Security: SecurityConfig{
			NotificationWebhooks: []NotificationWebhook{
				{URL: "https://example.com/hook", LimitAlertKeyTypes: []string{"tenant"}},
			},
		},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "notificationWebhooks[0].limitAlertKeyTypes") {
		t.Fatalf("expected notification webhook limitAlertKeyTypes validation error, got %v", err)
	}
}

func TestSecurityConfigRuleRejectsInvalidNotificationWebhookLimitAlertBucketIDRegex(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Security: SecurityConfig{
			NotificationWebhooks: []NotificationWebhook{
				{URL: "https://example.com/hook", LimitAlertBucketIDRegex: "["},
			},
		},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "notificationWebhooks[0].limitAlertBucketIDRegex") {
		t.Fatalf("expected notification webhook limitAlertBucketIDRegex validation error, got %v", err)
	}
}

func TestSecurityConfigRuleRejectsUnknownNotificationWebhookLimitAlertProfile(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Security: SecurityConfig{
			NotificationWebhooks: []NotificationWebhook{
				{URL: "https://example.com/hook", LimitAlertProfile: "vip"},
			},
		},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "notificationWebhooks[0].limitAlertProfile") {
		t.Fatalf("expected notification webhook limitAlertProfile validation error, got %v", err)
	}
}

func TestSecurityConfigRuleRejectsUnknownNotificationWebhookLimitAlertBucketClass(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Security: SecurityConfig{
			LimitAlertBucketClasses: map[string]LimitAlertBucketClassConfig{
				"vip-jwt": {
					KeyType:     "jwt_sub",
					BucketRegex: "^vip-",
				},
			},
			NotificationWebhooks: []NotificationWebhook{
				{URL: "https://example.com/hook", LimitAlertBucketClasses: []string{"missing"}},
			},
		},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "notificationWebhooks[0].limitAlertBucketClasses") {
		t.Fatalf("expected notification webhook limitAlertBucketClasses validation error, got %v", err)
	}
}

func TestSecurityConfigRuleRejectsLimiterClassPresetWithUnknownBucketClass(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Security: SecurityConfig{
			LimiterClassPresets: map[string]LimiterClassPolicyPreset{
				"vip": {
					BucketClass:           "missing",
					RateRequestsPerSecond: 20,
					RateBurst:             40,
				},
			},
		},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "limiterClassPresets.vip.bucketClass") {
		t.Fatalf("expected limiterClassPresets bucketClass validation error, got %v", err)
	}
}

func TestSecurityConfigRuleRejectsDisabledDifferentReviewerPolicy(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Security: SecurityConfig{
			MutationPolicy: MutationPolicy{
				Enabled:                              false,
				RequireDifferentReviewerForProposals: true,
			},
		},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "mutationPolicy.enabled") {
		t.Fatalf("expected mutationPolicy.enabled validation error, got %v", err)
	}
}

func TestSecurityConfigRuleRejectsNegativeProposalApproverRequirement(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Security: SecurityConfig{
			MutationPolicy: MutationPolicy{
				Enabled:                            true,
				MinApproversForHighImpactProposals: -1,
			},
		},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "minApproversForHighImpactProposals") {
		t.Fatalf("expected min approvers validation error, got %v", err)
	}
}

func TestSecurityConfigRuleRejectsDisabledProposalScheduleRequirement(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Security: SecurityConfig{
			MutationPolicy: MutationPolicy{
				Enabled:                                false,
				RequireNotBeforeForHighImpactProposals: true,
			},
		},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "mutationPolicy.enabled") {
		t.Fatalf("expected mutationPolicy.enabled validation error, got %v", err)
	}
}

func TestSecurityConfigRuleRejectsDisabledPromotedProposalVerificationRequirement(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Security: SecurityConfig{
			MutationPolicy: MutationPolicy{
				Enabled: false,
				RequireVerificationForPromotedHighImpactProposals: true,
			},
		},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "mutationPolicy.enabled") {
		t.Fatalf("expected mutationPolicy.enabled validation error, got %v", err)
	}
}

func TestSecurityConfigRuleRejectsDisabledPromotedProposalShadowEvaluationRequirement(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Security: SecurityConfig{
			MutationPolicy: MutationPolicy{
				Enabled: false,
				RequireShadowEvaluationForPromotedHighImpactProposals: true,
			},
		},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "mutationPolicy.enabled") {
		t.Fatalf("expected mutationPolicy.enabled validation error, got %v", err)
	}
}

func TestSecurityConfigRuleRejectsDisabledShadowVerificationStreakRequirement(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Security: SecurityConfig{
			MutationPolicy: MutationPolicy{
				Enabled: false,
				MinShadowHealthyVerificationsForPromotedHighImpactProposals: 2,
			},
		},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "mutationPolicy.enabled") {
		t.Fatalf("expected mutationPolicy.enabled validation error, got %v", err)
	}
}

func TestSecurityConfigRuleRejectsDisabledBlockedApplyWindows(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Security: SecurityConfig{
			MutationPolicy: MutationPolicy{
				Enabled: false,
				BlockedApplyWindows: []MutationApplyWindow{
					{Name: "freeze", Start: "22:00", End: "23:00"},
				},
			},
		},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "mutationPolicy.enabled") {
		t.Fatalf("expected mutationPolicy.enabled validation error, got %v", err)
	}
}

func TestSecurityConfigRuleRejectsDisabledProposalAgeLimits(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Security: SecurityConfig{
			MutationPolicy: MutationPolicy{
				Enabled:        false,
				MaxProposalAge: "24h",
			},
		},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "mutationPolicy.enabled") {
		t.Fatalf("expected mutationPolicy.enabled validation error, got %v", err)
	}
}

func TestSecurityConfigRuleRejectsInvalidProposalAgeLimits(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Security: SecurityConfig{
			MutationPolicy: MutationPolicy{
				Enabled:        true,
				MaxProposalAge: "tomorrow",
			},
		},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "maxProposalAge") {
		t.Fatalf("expected maxProposalAge validation error, got %v", err)
	}
}

func TestSecurityConfigRuleAllowsValidProposalAgeLimits(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Security: SecurityConfig{
			MutationPolicy: MutationPolicy{
				Enabled:        true,
				MaxProposalAge: "72h",
				MaxApprovalAge: "12h",
			},
		},
	}

	if err := NewConfigValidator().Validate(cfg); err != nil {
		t.Fatalf("expected valid proposal age limits to validate, got %v", err)
	}
}

func TestSecurityConfigRuleRejectsInvalidBlockedApplyWindow(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Security: SecurityConfig{
			MutationPolicy: MutationPolicy{
				Enabled: true,
				BlockedApplyWindows: []MutationApplyWindow{
					{Name: "freeze", Days: []string{"noday"}, Start: "22:00", End: "22:00", Timezone: "Mars/Phobos"},
				},
			},
		},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "blockedApplyWindows") {
		t.Fatalf("expected blocked apply window validation error, got %v", err)
	}
}

func TestSecurityConfigRuleAllowsValidBlockedApplyWindow(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Security: SecurityConfig{
			MutationPolicy: MutationPolicy{
				Enabled: true,
				BlockedApplyWindows: []MutationApplyWindow{
					{
						Name:     "weekend-freeze",
						Days:     []string{"sat", "sun"},
						Start:    "00:00",
						End:      "06:00",
						Timezone: "UTC",
						Scopes:   []string{"high_impact"},
					},
				},
			},
		},
	}

	if err := NewConfigValidator().Validate(cfg); err != nil {
		t.Fatalf("expected valid blocked apply window to validate, got %v", err)
	}
}
