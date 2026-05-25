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

func TestSecurityConfigRuleRejectsInvalidLimitClassSnoozeNotificationWindow(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Security: SecurityConfig{
			MutationPolicy: MutationPolicy{
				LimitClassSnoozeNotifications: PolicyAlertNotificationPolicy{
					Enabled: true,
					Window:  "banana",
				},
			},
		},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "limitClassSnoozeNotifications.window") {
		t.Fatalf("expected limit class snooze notification window validation error, got %v", err)
	}
}

func TestSecurityConfigRuleRejectsNegativeLimitClassSnoozeNotificationDetailedMinBucketClassPriority(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Security: SecurityConfig{
			MutationPolicy: MutationPolicy{
				LimitClassSnoozeNotifications: PolicyAlertNotificationPolicy{
					Enabled:                        true,
					DetailedMinBucketClassPriority: -1,
				},
			},
		},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "limitClassSnoozeNotifications.detailedMinBucketClassPriority") {
		t.Fatalf("expected detailedMinBucketClassPriority validation error, got %v", err)
	}
}

func TestSecurityConfigRuleRejectsNegativeLimitClassSnoozeNotificationDetailedMaxBucketClasses(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Security: SecurityConfig{
			MutationPolicy: MutationPolicy{
				LimitClassSnoozeNotifications: PolicyAlertNotificationPolicy{
					Enabled:                  true,
					DetailedMaxBucketClasses: -1,
				},
			},
		},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "limitClassSnoozeNotifications.detailedMaxBucketClasses") {
		t.Fatalf("expected detailedMaxBucketClasses validation error, got %v", err)
	}
}

func TestSecurityConfigRuleRejectsInvalidLimitClassSnoozeNotificationStageThresholdOrdering(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Security: SecurityConfig{
			MutationPolicy: MutationPolicy{
				LimitClassSnoozeNotifications: PolicyAlertNotificationPolicy{
					Enabled:              true,
					SnoozeElevatedWithin: "5m",
					SnoozeCriticalWithin: "10m",
				},
			},
		},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "limitClassSnoozeNotifications.snoozeCriticalWithin") {
		t.Fatalf("expected limit class snooze notification stage threshold ordering validation error, got %v", err)
	}
}

func TestSecurityConfigRuleRejectsInvalidLimitAlertBucketClassSnoozeThresholdOrdering(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Security: SecurityConfig{
			LimitAlertBucketClasses: map[string]LimitAlertBucketClassConfig{
				"vip-jwt": {
					KeyType:              "jwt_sub",
					BucketRegex:          "^vip-",
					SnoozeElevatedWithin: "5m",
					SnoozeCriticalWithin: "10m",
				},
			},
		},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "security.limitAlertBucketClasses.vip-jwt.snoozeCriticalWithin") {
		t.Fatalf("expected limit alert bucket class snooze threshold ordering validation error, got %v", err)
	}
}

func TestSecurityConfigRuleRejectsInvalidLimitAlertBucketClassSnoozeEventType(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Security: SecurityConfig{
			LimitAlertBucketClasses: map[string]LimitAlertBucketClassConfig{
				"vip-jwt": {
					KeyType:          "jwt_sub",
					BucketRegex:      "^vip-",
					SnoozeEventTypes: []string{"digest"},
				},
			},
		},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "security.limitAlertBucketClasses.vip-jwt.snoozeEventTypes") {
		t.Fatalf("expected limit alert bucket class snooze event types validation error, got %v", err)
	}
}

func TestSecurityConfigRuleRejectsNegativeLimitAlertBucketClassPriority(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Security: SecurityConfig{
			LimitAlertBucketClasses: map[string]LimitAlertBucketClassConfig{
				"vip-jwt": {
					KeyType:     "jwt_sub",
					BucketRegex: "^vip-",
					Priority:    -1,
				},
			},
		},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "security.limitAlertBucketClasses.vip-jwt.priority") {
		t.Fatalf("expected limit alert bucket class priority validation error, got %v", err)
	}
}

func TestSecurityConfigRuleRejectsInvalidLimitClassSnoozeExpiryCooldown(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Security: SecurityConfig{
			NotificationWebhooks: []NotificationWebhook{{
				URL:                            "https://example.com/hook",
				Events:                         []string{"gateway.limit_class_snooze_expiring"},
				LimitClassSnoozeExpiryCooldown: "banana",
			}},
		},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "limitClassSnoozeExpiryCooldown") {
		t.Fatalf("expected limit class snooze expiry cooldown validation error, got %v", err)
	}
}

func TestSecurityConfigRuleRejectsInvalidLimitClassSnoozeExpiryWithin(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Security: SecurityConfig{
			NotificationWebhooks: []NotificationWebhook{{
				URL:                          "https://example.com/hook",
				Events:                       []string{"gateway.limit_class_snooze_expiring"},
				LimitClassSnoozeExpiryWithin: "0m",
			}},
		},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "limitClassSnoozeExpiryWithin") {
		t.Fatalf("expected limit class snooze expiry within validation error, got %v", err)
	}
}

func TestSecurityConfigRuleRejectsInvalidLimitClassSnoozeExpiryStage(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Security: SecurityConfig{
			NotificationWebhooks: []NotificationWebhook{{
				URL:                          "https://example.com/hook",
				Events:                       []string{"gateway.limit_class_snooze_expiring"},
				LimitClassSnoozeExpiryStages: []string{"urgent"},
			}},
		},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "limitClassSnoozeExpiryStages") {
		t.Fatalf("expected limit class snooze expiry stages validation error, got %v", err)
	}
}

func TestSecurityConfigRuleRejectsInvalidLimitClassSnoozeEventType(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Security: SecurityConfig{
			NotificationWebhooks: []NotificationWebhook{{
				URL:                        "https://example.com/hook",
				Events:                     []string{"gateway.limit_class_snooze_resumed"},
				LimitClassSnoozeEventTypes: []string{"wake_up"},
			}},
		},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "limitClassSnoozeEventTypes") {
		t.Fatalf("expected limit class snooze event types validation error, got %v", err)
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

func TestSecurityConfigRuleRejectsNegativeNotificationWebhookLimitAlertBucketClassPriority(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Security: SecurityConfig{
			NotificationWebhooks: []NotificationWebhook{
				{URL: "https://example.com/hook", MinLimitAlertBucketClassPriority: -1},
			},
		},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "notificationWebhooks[0].minLimitAlertBucketClassPriority") {
		t.Fatalf("expected notification webhook minLimitAlertBucketClassPriority validation error, got %v", err)
	}
}

func TestSecurityConfigRuleRejectsNegativeNotificationWebhookLimitClassDigestMaxBucketClasses(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Security: SecurityConfig{
			NotificationWebhooks: []NotificationWebhook{
				{URL: "https://example.com/hook", LimitClassDigestMaxBucketClasses: -1},
			},
		},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "notificationWebhooks[0].limitClassDigestMaxBucketClasses") {
		t.Fatalf("expected notification webhook limitClassDigestMaxBucketClasses validation error, got %v", err)
	}
}

func TestSecurityConfigRuleRejectsInvalidNotificationWebhookLimitClassDigestMinSeverity(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Security: SecurityConfig{
			NotificationWebhooks: []NotificationWebhook{
				{URL: "https://example.com/hook", LimitClassDigestMinSeverity: "urgent"},
			},
		},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "notificationWebhooks[0].limitClassDigestMinSeverity") {
		t.Fatalf("expected notification webhook limitClassDigestMinSeverity validation error, got %v", err)
	}
}

func TestSecurityConfigRuleRejectsInvalidNotificationWebhookLimitClassDigestSeverities(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Security: SecurityConfig{
			NotificationWebhooks: []NotificationWebhook{
				{URL: "https://example.com/hook", LimitClassDigestSeverities: []string{"critical", "urgent"}},
			},
		},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "notificationWebhooks[0].limitClassDigestSeverities") {
		t.Fatalf("expected notification webhook limitClassDigestSeverities validation error, got %v", err)
	}
}

func TestSecurityConfigRuleRejectsInvalidNotificationWebhookLimitClassDigestTypes(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Security: SecurityConfig{
			NotificationWebhooks: []NotificationWebhook{
				{URL: "https://example.com/hook", LimitClassDigestTypes: []string{"alert", "digest"}},
			},
		},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "notificationWebhooks[0].limitClassDigestTypes") {
		t.Fatalf("expected notification webhook limitClassDigestTypes validation error, got %v", err)
	}
}

func TestSecurityConfigRuleRejectsInvalidNotificationWebhookLimitClassDigestSummaryOnlyTypes(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Security: SecurityConfig{
			NotificationWebhooks: []NotificationWebhook{
				{URL: "https://example.com/hook", LimitClassDigestSummaryOnlyTypes: []string{"snooze", "digest"}},
			},
		},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "notificationWebhooks[0].limitClassDigestSummaryOnlyTypes") {
		t.Fatalf("expected notification webhook limitClassDigestSummaryOnlyTypes validation error, got %v", err)
	}
}

func TestSecurityConfigRuleRejectsNegativeNotificationWebhookLimitClassDigestMaxSummaryBucketClasses(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Security: SecurityConfig{
			NotificationWebhooks: []NotificationWebhook{
				{URL: "https://example.com/hook", LimitClassDigestMaxSummaryBucketClasses: -1},
			},
		},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "notificationWebhooks[0].limitClassDigestMaxSummaryBucketClasses") {
		t.Fatalf("expected notification webhook limitClassDigestMaxSummaryBucketClasses validation error, got %v", err)
	}
}

func TestSecurityConfigRuleRejectsNegativeNotificationWebhookLimitClassDigestMinSummaryBucketClassPriority(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Security: SecurityConfig{
			NotificationWebhooks: []NotificationWebhook{
				{URL: "https://example.com/hook", LimitClassDigestMinSummaryBucketClassPriority: -1},
			},
		},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "notificationWebhooks[0].limitClassDigestMinSummaryBucketClassPriority") {
		t.Fatalf("expected notification webhook limitClassDigestMinSummaryBucketClassPriority validation error, got %v", err)
	}
}

func TestSecurityConfigRuleRejectsInvalidNotificationWebhookLimitClassDigestMinSummarySeverity(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Security: SecurityConfig{
			NotificationWebhooks: []NotificationWebhook{
				{URL: "https://example.com/hook", LimitClassDigestMinSummarySeverity: "urgent"},
			},
		},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "notificationWebhooks[0].limitClassDigestMinSummarySeverity") {
		t.Fatalf("expected notification webhook limitClassDigestMinSummarySeverity validation error, got %v", err)
	}
}

func TestSecurityConfigRuleRejectsInvalidNotificationWebhookLimitClassDigestSummarySortMode(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Security: SecurityConfig{
			NotificationWebhooks: []NotificationWebhook{
				{URL: "https://example.com/hook", LimitClassDigestSummarySortMode: "severity_only"},
			},
		},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "notificationWebhooks[0].limitClassDigestSummarySortMode") {
		t.Fatalf("expected notification webhook limitClassDigestSummarySortMode validation error, got %v", err)
	}
}

func TestSecurityConfigRuleRejectsNegativeNotificationWebhookLimitClassDigestMinSummaryCount(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Security: SecurityConfig{
			NotificationWebhooks: []NotificationWebhook{
				{URL: "https://example.com/hook", LimitClassDigestMinSummaryCount: -1},
			},
		},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "notificationWebhooks[0].limitClassDigestMinSummaryCount") {
		t.Fatalf("expected notification webhook limitClassDigestMinSummaryCount validation error, got %v", err)
	}
}

func TestSecurityConfigRuleRejectsInvalidNotificationWebhookLimitClassDigestOverflowReasons(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Security: SecurityConfig{
			NotificationWebhooks: []NotificationWebhook{
				{URL: "https://example.com/hook", LimitClassDigestOverflowReasons: []string{"banana"}},
			},
		},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "notificationWebhooks[0].limitClassDigestOverflowReasons") {
		t.Fatalf("expected notification webhook limitClassDigestOverflowReasons validation error, got %v", err)
	}
}

func TestSecurityConfigRuleRejectsInvalidNotificationWebhookLimitClassDigestOverflowReasonLabels(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Security: SecurityConfig{
			NotificationWebhooks: []NotificationWebhook{
				{URL: "https://example.com/hook", LimitClassDigestOverflowReasonLabels: map[string]string{"banana": "friendly"}},
			},
		},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "notificationWebhooks[0].limitClassDigestOverflowReasonLabels") {
		t.Fatalf("expected notification webhook limitClassDigestOverflowReasonLabels validation error, got %v", err)
	}
}

func TestSecurityConfigRuleRejectsInvalidNotificationWebhookLimitClassDigestOverflowReasonGroups(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Security: SecurityConfig{
			NotificationWebhooks: []NotificationWebhook{
				{URL: "https://example.com/hook", LimitClassDigestOverflowReasonGroups: map[string][]string{"policy_filtered": []string{"banana"}}},
			},
		},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "notificationWebhooks[0].limitClassDigestOverflowReasonGroups") {
		t.Fatalf("expected notification webhook limitClassDigestOverflowReasonGroups validation error, got %v", err)
	}
}

func TestSecurityConfigRuleRejectsEmptyNotificationWebhookLimitClassDigestOverflowReasonOrder(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Security: SecurityConfig{
			NotificationWebhooks: []NotificationWebhook{
				{URL: "https://example.com/hook", LimitClassDigestOverflowReasonOrder: []string{"policy_filtered", ""}},
			},
		},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "notificationWebhooks[0].limitClassDigestOverflowReasonOrder") {
		t.Fatalf("expected notification webhook limitClassDigestOverflowReasonOrder validation error, got %v", err)
	}
}

func TestSecurityConfigRuleRejectsNegativeNotificationWebhookLimitClassDigestMaxOverflowReasons(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Security: SecurityConfig{
			NotificationWebhooks: []NotificationWebhook{
				{URL: "https://example.com/hook", LimitClassDigestMaxOverflowReasons: -1},
			},
		},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "notificationWebhooks[0].limitClassDigestMaxOverflowReasons") {
		t.Fatalf("expected limitClassDigestMaxOverflowReasons validation error, got %v", err)
	}
}

func TestSecurityConfigRuleRejectsInvalidNotificationWebhookLimitClassDigestTruncatedReasonBucketMode(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Security: SecurityConfig{
			NotificationWebhooks: []NotificationWebhook{
				{URL: "https://example.com/hook", LimitClassDigestTruncatedReasonBucketMode: "verbose"},
			},
		},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "notificationWebhooks[0].limitClassDigestTruncatedReasonBucketMode") {
		t.Fatalf("expected notification webhook limitClassDigestTruncatedReasonBucketMode validation error, got %v", err)
	}
}

func TestSecurityConfigRuleRejectsNegativeNotificationWebhookLimitClassDigestTruncatedReasonBucketMaxReasons(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Security: SecurityConfig{
			NotificationWebhooks: []NotificationWebhook{
				{URL: "https://example.com/hook", LimitClassDigestTruncatedReasonBucketMaxReasons: -1},
			},
		},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "notificationWebhooks[0].limitClassDigestTruncatedReasonBucketMaxReasons") {
		t.Fatalf("expected notification webhook limitClassDigestTruncatedReasonBucketMaxReasons validation error, got %v", err)
	}
}

func TestSecurityConfigRuleRejectsEmptyNotificationWebhookLimitClassDigestTruncatedReasonBucketReasonOrderValue(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Security: SecurityConfig{
			NotificationWebhooks: []NotificationWebhook{
				{URL: "https://example.com/hook", LimitClassDigestTruncatedReasonBucketReasonOrder: []string{"priority_floor", "  "}},
			},
		},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "notificationWebhooks[0].limitClassDigestTruncatedReasonBucketReasonOrder") {
		t.Fatalf("expected notification webhook limitClassDigestTruncatedReasonBucketReasonOrder validation error, got %v", err)
	}
}

func TestSecurityConfigRuleRejectsInvalidNotificationWebhookLimitClassDigestTruncatedReasonBucketMinSeverity(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Security: SecurityConfig{
			NotificationWebhooks: []NotificationWebhook{
				{URL: "https://example.com/hook", LimitClassDigestTruncatedReasonBucketMinSeverity: "urgent"},
			},
		},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "notificationWebhooks[0].limitClassDigestTruncatedReasonBucketMinSeverity") {
		t.Fatalf("expected notification webhook limitClassDigestTruncatedReasonBucketMinSeverity validation error, got %v", err)
	}
}

func TestSecurityConfigRuleRejectsInvalidNotificationWebhookLimitClassDigestTruncatedReasonBucketSeverities(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Security: SecurityConfig{
			NotificationWebhooks: []NotificationWebhook{
				{URL: "https://example.com/hook", LimitClassDigestTruncatedReasonBucketSeverities: []string{"critical", "urgent"}},
			},
		},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "notificationWebhooks[0].limitClassDigestTruncatedReasonBucketSeverities") {
		t.Fatalf("expected notification webhook limitClassDigestTruncatedReasonBucketSeverities validation error, got %v", err)
	}
}

func TestSecurityConfigRuleRejectsInvalidNotificationWebhookLimitClassDigestTruncatedReasonBucketSortMode(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Security: SecurityConfig{
			NotificationWebhooks: []NotificationWebhook{
				{URL: "https://example.com/hook", LimitClassDigestTruncatedReasonBucketSortMode: "priority_first"},
			},
		},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "notificationWebhooks[0].limitClassDigestTruncatedReasonBucketSortMode") {
		t.Fatalf("expected notification webhook limitClassDigestTruncatedReasonBucketSortMode validation error, got %v", err)
	}
}

func TestSecurityConfigRuleRejectsInvalidNotificationWebhookLimitClassDigestTruncatedReasonBucketDominantReasonStrategy(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Security: SecurityConfig{
			NotificationWebhooks: []NotificationWebhook{
				{URL: "https://example.com/hook", LimitClassDigestTruncatedReasonBucketDominantReasonStrategy: "raw_frequency"},
			},
		},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "notificationWebhooks[0].limitClassDigestTruncatedReasonBucketDominantReasonStrategy") {
		t.Fatalf("expected notification webhook limitClassDigestTruncatedReasonBucketDominantReasonStrategy validation error, got %v", err)
	}
}

func TestSecurityConfigRuleRejectsInvalidNotificationWebhookLimitClassDigestTruncatedReasonBucketHiddenStrategyOrder(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Security: SecurityConfig{
			NotificationWebhooks: []NotificationWebhook{
				{URL: "https://example.com/hook", LimitClassDigestTruncatedReasonBucketHiddenStrategyOrder: []string{"exact_severity", "raw_frequency"}},
			},
		},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "notificationWebhooks[0].limitClassDigestTruncatedReasonBucketHiddenStrategyOrder") {
		t.Fatalf("expected notification webhook limitClassDigestTruncatedReasonBucketHiddenStrategyOrder validation error, got %v", err)
	}
}

func TestSecurityConfigRuleRejectsInvalidNotificationWebhookLimitClassDigestTruncatedReasonBucketHiddenStrategyDominantMode(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Security: SecurityConfig{
			NotificationWebhooks: []NotificationWebhook{
				{URL: "https://example.com/hook", LimitClassDigestTruncatedReasonBucketHiddenStrategyDominantMode: "largest_hidden"},
			},
		},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "notificationWebhooks[0].limitClassDigestTruncatedReasonBucketHiddenStrategyDominantMode") {
		t.Fatalf("expected notification webhook limitClassDigestTruncatedReasonBucketHiddenStrategyDominantMode validation error, got %v", err)
	}
}

func TestSecurityConfigRuleRejectsInvalidNotificationWebhookLimitClassDigestTruncatedReasonBucketExactSeverityDominantMode(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Security: SecurityConfig{
			NotificationWebhooks: []NotificationWebhook{
				{URL: "https://example.com/hook", LimitClassDigestTruncatedReasonBucketExactSeverityDominantMode: "largest_hidden"},
			},
		},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "notificationWebhooks[0].limitClassDigestTruncatedReasonBucketExactSeverityDominantMode") {
		t.Fatalf("expected notification webhook limitClassDigestTruncatedReasonBucketExactSeverityDominantMode validation error, got %v", err)
	}
}

func TestSecurityConfigRuleRejectsInvalidNotificationWebhookLimitClassDigestTruncatedReasonBucketExactSeverityPolicy(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Security: SecurityConfig{
			NotificationWebhooks: []NotificationWebhook{
				{URL: "https://example.com/hook", LimitClassDigestTruncatedReasonBucketExactSeverityPolicy: &LimitClassDigestHiddenStrategyPolicy{DominantMode: "largest_hidden"}},
			},
		},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "notificationWebhooks[0].limitClassDigestTruncatedReasonBucketExactSeverityPolicy.dominantMode") {
		t.Fatalf("expected notification webhook limitClassDigestTruncatedReasonBucketExactSeverityPolicy validation error, got %v", err)
	}
}

func TestSecurityConfigRuleRejectsUnknownNotificationWebhookLimitClassDigestTruncatedReasonBucketExactSeverityPolicyPreset(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Security: SecurityConfig{
			NotificationWebhooks: []NotificationWebhook{
				{URL: "https://example.com/hook", LimitClassDigestTruncatedReasonBucketExactSeverityPolicyPreset: "shared-exact"},
			},
		},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "notificationWebhooks[0].limitClassDigestTruncatedReasonBucketExactSeverityPolicyPreset") {
		t.Fatalf("expected notification webhook limitClassDigestTruncatedReasonBucketExactSeverityPolicyPreset validation error, got %v", err)
	}
}

func TestSecurityConfigRuleRejectsUnknownNotificationWebhookLimitClassDigestTruncatedReasonBucketExactSeverityPolicyPresetChainEntry(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Security: SecurityConfig{
			LimitClassDigestHiddenStrategyPolicyPresets: map[string]LimitClassDigestHiddenStrategyPolicy{
				"base": {DominantMode: "weighted_score"},
			},
			NotificationWebhooks: []NotificationWebhook{
				{URL: "https://example.com/hook", LimitClassDigestTruncatedReasonBucketExactSeverityPolicyPresetChain: []string{"base", "missing"}},
			},
		},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "notificationWebhooks[0].limitClassDigestTruncatedReasonBucketExactSeverityPolicyPresetChain") {
		t.Fatalf("expected notification webhook limitClassDigestTruncatedReasonBucketExactSeverityPolicyPresetChain validation error, got %v", err)
	}
}

func TestSecurityConfigRuleRejectsUnknownNotificationWebhookLimitClassDigestProfile(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Security: SecurityConfig{
			NotificationWebhooks: []NotificationWebhook{
				{URL: "https://example.com/hook", LimitClassDigestProfile: "shared-digest"},
			},
		},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "notificationWebhooks[0].limitClassDigestProfile") {
		t.Fatalf("expected notification webhook limitClassDigestProfile validation error, got %v", err)
	}
}

func TestSecurityConfigRuleRejectsUnknownNotificationWebhookLimitClassDigestProfileChainEntry(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Security: SecurityConfig{
			LimitClassDigestProfiles: map[string]LimitAlertRecipientProfile{
				"base": {LimitClassDigestMinSeverity: "warning"},
			},
			NotificationWebhooks: []NotificationWebhook{
				{URL: "https://example.com/hook", LimitClassDigestProfileChain: []string{"base", "missing"}},
			},
		},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "notificationWebhooks[0].limitClassDigestProfileChain") {
		t.Fatalf("expected notification webhook limitClassDigestProfileChain validation error, got %v", err)
	}
}

func TestSecurityConfigRuleRejectsEmptyLimitClassDigestExplainBundleFields(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Security: SecurityConfig{
			LimitClassDigestExplainBundles: map[string]LimitClassDigestExplainBundle{
				"ops-core": {},
			},
		},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "security.limitClassDigestExplainBundles.ops-core.fields") {
		t.Fatalf("expected limit class digest explain bundle fields validation error, got %v", err)
	}
}

func TestSecurityConfigRuleRejectsEmptyLimitClassDigestExplainBundleFieldEntry(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Security: SecurityConfig{
			LimitClassDigestExplainBundles: map[string]LimitClassDigestExplainBundle{
				"ops-core": {Fields: []string{"limitClassDigestMinSeverity", " "}},
			},
		},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "security.limitClassDigestExplainBundles.ops-core.fields") {
		t.Fatalf("expected limit class digest explain bundle empty field validation error, got %v", err)
	}
}

func TestSecurityConfigRuleRejectsUnknownLimitClassDigestExplainDiffProfileBundle(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Security: SecurityConfig{
			LimitClassDigestExplainDiffProfiles: map[string]LimitClassDigestExplainDiffProfile{
				"pager-audit": {Bundles: []string{"missing"}},
			},
		},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "security.limitClassDigestExplainDiffProfiles.pager-audit.bundles") {
		t.Fatalf("expected limit class digest explain diff profile bundle validation error, got %v", err)
	}
}

func TestSecurityConfigRuleRejectsEmptyLimitClassDigestAssertionExplainBundleKinds(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Security: SecurityConfig{
			LimitClassDigestAssertionExplainBundles: map[string]LimitClassDigestAssertionExplainBundle{
				"core": {},
			},
		},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "security.limitClassDigestAssertionExplainBundles.core.kinds") {
		t.Fatalf("expected limit class digest assertion explain bundle kinds validation error, got %v", err)
	}
}

func TestSecurityConfigRuleRejectsInvalidLimitClassDigestAssertionExplainBundleKind(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Security: SecurityConfig{
			LimitClassDigestAssertionExplainBundles: map[string]LimitClassDigestAssertionExplainBundle{
				"core": {Kinds: []string{"rules", "fields"}},
			},
		},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "security.limitClassDigestAssertionExplainBundles.core.kinds") {
		t.Fatalf("expected limit class digest assertion explain bundle kind validation error, got %v", err)
	}
}

func TestSecurityConfigRuleRejectsUnknownLimitClassDigestAssertionExplainDiffProfileBundle(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Security: SecurityConfig{
			LimitClassDigestAssertionExplainDiffProfiles: map[string]LimitClassDigestAssertionExplainDiffProfile{
				"preset-audit": {Bundles: []string{"missing"}},
			},
		},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "security.limitClassDigestAssertionExplainDiffProfiles.preset-audit.bundles") {
		t.Fatalf("expected limit class digest assertion explain diff profile bundle validation error, got %v", err)
	}
}

func TestSecurityConfigRuleRejectsInvalidLimitClassDigestAssertionExplainDiffProfileExpectedValueKey(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Security: SecurityConfig{
			LimitClassDigestAssertionExplainDiffProfiles: map[string]LimitClassDigestAssertionExplainDiffProfile{
				"preset-audit": {ExpectedFromValues: map[string]string{"fields": "[]"}},
			},
		},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "security.limitClassDigestAssertionExplainDiffProfiles.preset-audit.expectedFromValues") {
		t.Fatalf("expected limit class digest assertion explain diff profile expectedFromValues validation error, got %v", err)
	}
}

func TestSecurityConfigRuleRejectsInvalidLimitClassDigestAssertionExplainDiffProfileRuleKey(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Security: SecurityConfig{
			LimitClassDigestAssertionExplainDiffProfiles: map[string]LimitClassDigestAssertionExplainDiffProfile{
				"preset-audit": {AssertFromRules: map[string][]string{"fields": {"exists"}}},
			},
		},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "security.limitClassDigestAssertionExplainDiffProfiles.preset-audit.assertFromRules") {
		t.Fatalf("expected limit class digest assertion explain diff profile assertFromRules validation error, got %v", err)
	}
}

func TestSecurityConfigRuleRejectsInvalidLimitClassDigestAssertionExplainDiffProfileGroupKey(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Security: SecurityConfig{
			LimitClassDigestAssertionExplainDiffProfiles: map[string]LimitClassDigestAssertionExplainDiffProfile{
				"preset-audit": {AssertFromGroups: map[string][]LimitClassDigestAssertionGroup{"fields": {{Operator: "allOf", Rules: []string{"exists"}}}}},
			},
		},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "security.limitClassDigestAssertionExplainDiffProfiles.preset-audit.assertFromGroups") {
		t.Fatalf("expected limit class digest assertion explain diff profile assertFromGroups validation error, got %v", err)
	}
}

func TestSecurityConfigRuleRejectsUnknownLimitClassDigestAssertionExplainDiffProfileGroupPreset(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Security: SecurityConfig{
			LimitClassDigestAssertionExplainDiffProfiles: map[string]LimitClassDigestAssertionExplainDiffProfile{
				"preset-audit": {AssertFromGroupPresets: map[string][]string{"rules": {"missing"}}},
			},
		},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "security.limitClassDigestAssertionExplainDiffProfiles.preset-audit.assertFromGroupPresets.rules") {
		t.Fatalf("expected limit class digest assertion explain diff profile assertFromGroupPresets validation error, got %v", err)
	}
}

func TestSecurityConfigRuleRejectsUnknownLimitClassDigestAssertionGroupPresetExplainBundlePreset(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Security: SecurityConfig{
			LimitClassDigestAssertionGroupPresetExplainBundles: map[string]LimitClassDigestAssertionGroupPresetExplainBundle{
				"core": {Presets: []string{"missing"}},
			},
		},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "security.limitClassDigestAssertionGroupPresetExplainBundles.core.presets") {
		t.Fatalf("expected limit class digest assertion group preset explain bundle validation error, got %v", err)
	}
}

func TestSecurityConfigRuleRejectsHalfDefinedLimitClassDigestExplainDiffProfileRoles(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Security: SecurityConfig{
			LimitClassDigestExplainDiffProfiles: map[string]LimitClassDigestExplainDiffProfile{
				"pager-audit": {FromRole: "baseline"},
			},
		},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "security.limitClassDigestExplainDiffProfiles.pager-audit") {
		t.Fatalf("expected limit class digest explain diff profile role validation error, got %v", err)
	}
}

func TestSecurityConfigRuleRejectsEmptyLimitClassDigestExplainDiffProfileExpectedFromField(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Security: SecurityConfig{
			LimitClassDigestExplainDiffProfiles: map[string]LimitClassDigestExplainDiffProfile{
				"pager-audit": {ExpectedFromValues: map[string]string{" ": "critical"}},
			},
		},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "security.limitClassDigestExplainDiffProfiles.pager-audit.expectedFromValues") {
		t.Fatalf("expected limit class digest explain diff profile expectedFromValues validation error, got %v", err)
	}
}

func TestSecurityConfigRuleRejectsInvalidLimitClassDigestExplainDiffProfileAssertionRule(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Security: SecurityConfig{
			LimitClassDigestExplainDiffProfiles: map[string]LimitClassDigestExplainDiffProfile{
				"pager-audit": {AssertFromRules: map[string][]string{"limitClassDigestTypes": {"invalid:rule"}}},
			},
		},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "security.limitClassDigestExplainDiffProfiles.pager-audit.assertFromRules.limitClassDigestTypes") {
		t.Fatalf("expected limit class digest explain diff profile assertFromRules validation error, got %v", err)
	}
}

func TestSecurityConfigRuleRejectsInvalidLimitClassDigestExplainDiffProfileAssertionRegex(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Security: SecurityConfig{
			LimitClassDigestExplainDiffProfiles: map[string]LimitClassDigestExplainDiffProfile{
				"pager-audit": {AssertToRules: map[string][]string{"limitClassDigestMinSeverity": {"regex:["}}},
			},
		},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "security.limitClassDigestExplainDiffProfiles.pager-audit.assertToRules.limitClassDigestMinSeverity") {
		t.Fatalf("expected limit class digest explain diff profile assertToRules regex validation error, got %v", err)
	}
}

func TestSecurityConfigRuleAllowsLimitClassDigestExplainDiffProfileNoneOfAssertionGroup(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Security: SecurityConfig{
			LimitClassDigestExplainDiffProfiles: map[string]LimitClassDigestExplainDiffProfile{
				"pager-audit": {
					AssertFromGroups: map[string][]LimitClassDigestAssertionGroup{
						"limitClassDigestTypes": {{
							Operator: "noneOf",
							Rules:    []string{"exists"},
						}},
					},
				},
			},
		},
	}

	err := NewConfigValidator().Validate(cfg)
	if err != nil {
		t.Fatalf("expected noneOf assertion group to validate, got %v", err)
	}
}

func TestSecurityConfigRuleRejectsEmptyNestedLimitClassDigestExplainAssertionGroup(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Security: SecurityConfig{
			LimitClassDigestExplainDiffProfiles: map[string]LimitClassDigestExplainDiffProfile{
				"pager-audit": {
					AssertToGroups: map[string][]LimitClassDigestAssertionGroup{
						"limitClassDigestTypes": {{
							Operator: "allOf",
							Groups: []LimitClassDigestAssertionGroup{{
								Operator: "anyOf",
							}},
						}},
					},
				},
			},
		},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "security.limitClassDigestExplainDiffProfiles.pager-audit.assertToGroups.limitClassDigestTypes[0].groups[0]") {
		t.Fatalf("expected nested limit class digest explain assertion group validation error, got %v", err)
	}
}

func TestSecurityConfigRuleRejectsUnknownLimitClassDigestAssertionPresetRef(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Security: SecurityConfig{
			LimitClassDigestExplainDiffProfiles: map[string]LimitClassDigestExplainDiffProfile{
				"pager-audit": {
					AssertFromPresets: map[string][]string{
						"limitClassDigestTypes": {"missing"},
					},
				},
			},
		},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "security.limitClassDigestExplainDiffProfiles.pager-audit.assertFromPresets.limitClassDigestTypes") {
		t.Fatalf("expected limit class digest assertion preset ref validation error, got %v", err)
	}
}

func TestSecurityConfigRuleRejectsLimitClassDigestAssertionPresetCycle(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Security: SecurityConfig{
			LimitClassDigestAssertionPresets: map[string]LimitClassDigestAssertionPreset{
				"base":  {PresetChain: []string{"child"}},
				"child": {PresetChain: []string{"base"}},
			},
		},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || (!strings.Contains(err.Error(), "security.limitClassDigestAssertionPresets.child.presetChain") && !strings.Contains(err.Error(), "security.limitClassDigestAssertionPresets.base.presetChain")) {
		t.Fatalf("expected limit class digest assertion preset cycle validation error, got %v", err)
	}
}

func TestSecurityConfigRuleRejectsNegativeNotificationWebhookLimitClassDigestTruncatedReasonBucketHiddenStrategyWeight(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Security: SecurityConfig{
			NotificationWebhooks: []NotificationWebhook{
				{URL: "https://example.com/hook", LimitClassDigestTruncatedReasonBucketHiddenStrategyReasonWeight: -1},
			},
		},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "notificationWebhooks[0].limitClassDigestTruncatedReasonBucketHiddenStrategyReasonWeight") {
		t.Fatalf("expected notification webhook limitClassDigestTruncatedReasonBucketHiddenStrategyReasonWeight validation error, got %v", err)
	}
}

func TestSecurityConfigRuleRejectsNegativeNotificationWebhookLimitClassDigestTruncatedReasonBucketExactSeverityWeight(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Security: SecurityConfig{
			NotificationWebhooks: []NotificationWebhook{
				{URL: "https://example.com/hook", LimitClassDigestTruncatedReasonBucketExactSeverityReasonWeight: -1},
			},
		},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "notificationWebhooks[0].limitClassDigestTruncatedReasonBucketExactSeverityReasonWeight") {
		t.Fatalf("expected notification webhook limitClassDigestTruncatedReasonBucketExactSeverityReasonWeight validation error, got %v", err)
	}
}

func TestSecurityConfigRuleRejectsNegativeNotificationWebhookLimitClassDigestTruncatedReasonBucketHiddenStrategyCap(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Security: SecurityConfig{
			NotificationWebhooks: []NotificationWebhook{
				{URL: "https://example.com/hook", LimitClassDigestTruncatedReasonBucketHiddenStrategyItemCap: -1},
			},
		},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "notificationWebhooks[0].limitClassDigestTruncatedReasonBucketHiddenStrategyItemCap") {
		t.Fatalf("expected notification webhook limitClassDigestTruncatedReasonBucketHiddenStrategyItemCap validation error, got %v", err)
	}
}

func TestSecurityConfigRuleRejectsNegativeNotificationWebhookLimitClassDigestTruncatedReasonBucketExactSeverityCap(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Security: SecurityConfig{
			NotificationWebhooks: []NotificationWebhook{
				{URL: "https://example.com/hook", LimitClassDigestTruncatedReasonBucketExactSeverityItemCap: -1},
			},
		},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "notificationWebhooks[0].limitClassDigestTruncatedReasonBucketExactSeverityItemCap") {
		t.Fatalf("expected notification webhook limitClassDigestTruncatedReasonBucketExactSeverityItemCap validation error, got %v", err)
	}
}

func TestSecurityConfigRuleRejectsNegativeNotificationWebhookLimitClassDigestTruncatedReasonBucketHiddenStrategyMinimum(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Security: SecurityConfig{
			NotificationWebhooks: []NotificationWebhook{
				{URL: "https://example.com/hook", LimitClassDigestTruncatedReasonBucketHiddenStrategyMinItems: -1},
			},
		},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "notificationWebhooks[0].limitClassDigestTruncatedReasonBucketHiddenStrategyMinItems") {
		t.Fatalf("expected notification webhook limitClassDigestTruncatedReasonBucketHiddenStrategyMinItems validation error, got %v", err)
	}
}

func TestSecurityConfigRuleRejectsNegativeNotificationWebhookLimitClassDigestTruncatedReasonBucketPerStrategyMinimum(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Security: SecurityConfig{
			NotificationWebhooks: []NotificationWebhook{
				{URL: "https://example.com/hook", LimitClassDigestTruncatedReasonBucketExactSeverityMinReasons: -1},
			},
		},
	}

	err := NewConfigValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "notificationWebhooks[0].limitClassDigestTruncatedReasonBucketExactSeverityMinReasons") {
		t.Fatalf("expected notification webhook limitClassDigestTruncatedReasonBucketExactSeverityMinReasons validation error, got %v", err)
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
