package api

import "time"

type managementWebhookEvent struct {
	Event       string                 `json:"event"`
	OccurredAt  time.Time              `json:"occurred_at"`
	ProposalID  string                 `json:"proposal_id,omitempty"`
	Action      string                 `json:"action,omitempty"`
	Status      string                 `json:"status,omitempty"`
	Environment string                 `json:"environment,omitempty"`
	Reviewer    string                 `json:"reviewer,omitempty"`
	ReviewNote  string                 `json:"review_note,omitempty"`
	Label       string                 `json:"label,omitempty"`
	Note        string                 `json:"note,omitempty"`
	ChangeRef   string                 `json:"change_ref,omitempty"`
	Data        map[string]interface{} `json:"data,omitempty"`
}

type proposalQueueSLABreachState struct {
	IncidentID          string
	ConsecutiveBreaches int
	FirstBreachedAt     time.Time
	LastBreachedAt      time.Time
}

type proposalQueueSLABreachEscalationState struct {
	LastSentAt time.Time
	LastTier   string
}

type gatewayPolicyAlertIncidentState struct {
	IncidentID  string
	Severity    string
	ServiceName string
	RoutePath   string
	Reason      string
	FirstSeenAt time.Time
	LastSeenAt  time.Time
	LastCount   int
}

type gatewayLimitAlertIncidentState struct {
	IncidentID  string
	Severity    string
	ServiceName string
	RoutePath   string
	LimitType   string
	KeyType     string
	BucketID    string
	BucketClass string
	FirstSeenAt time.Time
	LastSeenAt  time.Time
	LastCount   int
}

type gatewayLimitClassAlertIncidentState struct {
	IncidentID      string
	Severity        string
	ServiceName     string
	RoutePath       string
	LimitType       string
	KeyType         string
	BucketClass     string
	FirstSeenAt     time.Time
	LastSeenAt      time.Time
	LastCount       int
	AcknowledgedAt  time.Time
	AcknowledgedBy  string
	AcknowledgeNote string
	SnoozedUntil    time.Time
	SnoozedBy       string
	SnoozeNote      string
}
