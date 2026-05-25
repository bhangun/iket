package config

import (
	"strconv"
	"strings"
)

func validateRouteRateLimitPolicy(ctx serviceValidationContext) error {
	route := ctx.route
	if route.RateLimit != nil && *route.RateLimit <= 0 {
		return validationError(ctx.routeField("rateLimit"), "rateLimit must be positive")
	}
	if route.RateLimitPolicy == nil {
		return nil
	}

	policy := route.RateLimitPolicy
	if policy.RequestsPerSecond <= 0 {
		return validationError(ctx.routeField("rateLimitPolicy.requestsPerSecond"), "requestsPerSecond must be positive")
	}
	if policy.Burst <= 0 {
		return validationError(ctx.routeField("rateLimitPolicy.burst"), "burst must be positive")
	}
	if err := validateLimitKeyPolicy(ctx.routeField("rateLimitPolicy"), policy.KeyBy, policy.KeyHeader); err != nil {
		return err
	}
	if err := validateNonEmptyStringSlice(ctx.routeField("rateLimitPolicy.exemptMethods"), policy.ExemptMethods, "exemptMethods must not contain empty values"); err != nil {
		return err
	}
	return validateLimiterClassRatePolicies(ctx, *policy)
}

func validateRouteConcurrencyLimitPolicy(ctx serviceValidationContext) error {
	route := ctx.route
	if strings.TrimSpace(route.ConcurrentCalls) != "" {
		maxInFlight, err := strconv.Atoi(strings.TrimSpace(route.ConcurrentCalls))
		if err != nil || maxInFlight <= 0 {
			return validationError(ctx.routeField("concurrent_calls"), "concurrent_calls must be a positive integer")
		}
	}
	if route.ConcurrencyLimitPolicy == nil {
		if route.LimitAlertPolicy != nil {
			return validateRouteLimitAlertPolicy(ctx.routeField("limitAlertPolicy"), *route.LimitAlertPolicy)
		}
		return nil
	}

	policy := route.ConcurrencyLimitPolicy
	if policy.MaxInFlight <= 0 {
		return validationError(ctx.routeField("concurrencyLimitPolicy.maxInFlight"), "maxInFlight must be positive")
	}
	if policy.MaxQueueDepth < 0 {
		return validationError(ctx.routeField("concurrencyLimitPolicy.maxQueueDepth"), "maxQueueDepth must be zero or positive")
	}
	if err := validateLimitKeyPolicy(ctx.routeField("concurrencyLimitPolicy"), policy.KeyBy, policy.KeyHeader); err != nil {
		return err
	}
	if err := validateOptionalPositiveDuration(ctx.routeField("concurrencyLimitPolicy.queueTimeout"), policy.QueueTimeout, "queueTimeout must use a valid positive duration format"); err != nil {
		return err
	}
	if err := validateNonEmptyStringSlice(ctx.routeField("concurrencyLimitPolicy.exemptMethods"), policy.ExemptMethods, "exemptMethods must not contain empty values"); err != nil {
		return err
	}
	if err := validateLimiterClassConcurrencyPolicies(ctx, *policy); err != nil {
		return err
	}
	if route.LimitAlertPolicy != nil {
		return validateRouteLimitAlertPolicy(ctx.routeField("limitAlertPolicy"), *route.LimitAlertPolicy)
	}
	return nil
}

func validateLimitKeyPolicy(fieldPrefix, keyBy, keyHeader string) error {
	if !IsRouteLimitKeyBy(keyBy) {
		return validationError(fieldPrefix+".keyBy", "keyBy must be one of "+SupportedRouteLimitKeyByValues)
	}
	if strings.EqualFold(strings.TrimSpace(keyBy), "header") && strings.TrimSpace(keyHeader) == "" {
		return validationError(fieldPrefix+".keyHeader", "keyHeader is required when keyBy is header")
	}
	return nil
}

func validateLimiterClassRatePolicies(ctx serviceValidationContext, policy RateLimitPolicyConfig) error {
	if len(policy.ClassPolicies) == 0 {
		return nil
	}
	keyBy := NormalizeLimitKeyType(policy.KeyBy)
	if !IsBucketedLimitKeyType(keyBy) {
		return validationError(ctx.routeField("rateLimitPolicy.classPolicies"), "classPolicies require a bucketed keyBy such as "+SupportedBucketedLimitKeyTypeValues)
	}
	for i, classPolicy := range policy.ClassPolicies {
		prefix := ctx.routeField("rateLimitPolicy.classPolicies") + "[" + strconv.Itoa(i) + "]"
		preset, err := resolveLimiterClassPresetForRatePolicy(ctx, classPolicy, prefix)
		if err != nil {
			return err
		}
		bucketClass := strings.TrimSpace(classPolicy.BucketClass)
		if bucketClass == "" {
			bucketClass = strings.TrimSpace(preset.BucketClass)
		}
		if bucketClass == "" {
			return validationError(prefix+".bucketClass", "bucketClass is required")
		}
		classConfig, ok := ctx.cfg.Security.LimitAlertBucketClasses[bucketClass]
		if !ok {
			return validationError(prefix+".bucketClass", "bucketClass must reference a defined security.limitAlertBucketClasses entry")
		}
		if NormalizeLimitKeyType(classConfig.KeyType) != keyBy {
			return validationError(prefix+".bucketClass", "bucketClass keyType must match the route rateLimitPolicy keyBy")
		}
		requestsPerSecond := classPolicy.RequestsPerSecond
		if requestsPerSecond <= 0 {
			requestsPerSecond = preset.RateRequestsPerSecond
		}
		burst := classPolicy.Burst
		if burst <= 0 {
			burst = preset.RateBurst
		}
		if requestsPerSecond <= 0 {
			return validationError(prefix+".requestsPerSecond", "requestsPerSecond must be positive")
		}
		if burst <= 0 {
			return validationError(prefix+".burst", "burst must be positive")
		}
	}
	return nil
}

func validateLimiterClassConcurrencyPolicies(ctx serviceValidationContext, policy ConcurrencyLimitPolicyConfig) error {
	if len(policy.ClassPolicies) == 0 {
		return nil
	}
	keyBy := NormalizeLimitKeyType(policy.KeyBy)
	if !IsBucketedLimitKeyType(keyBy) {
		return validationError(ctx.routeField("concurrencyLimitPolicy.classPolicies"), "classPolicies require a bucketed keyBy such as "+SupportedBucketedLimitKeyTypeValues)
	}
	for i, classPolicy := range policy.ClassPolicies {
		prefix := ctx.routeField("concurrencyLimitPolicy.classPolicies") + "[" + strconv.Itoa(i) + "]"
		preset, err := resolveLimiterClassPresetForConcurrencyPolicy(ctx, classPolicy, prefix)
		if err != nil {
			return err
		}
		bucketClass := strings.TrimSpace(classPolicy.BucketClass)
		if bucketClass == "" {
			bucketClass = strings.TrimSpace(preset.BucketClass)
		}
		if bucketClass == "" {
			return validationError(prefix+".bucketClass", "bucketClass is required")
		}
		classConfig, ok := ctx.cfg.Security.LimitAlertBucketClasses[bucketClass]
		if !ok {
			return validationError(prefix+".bucketClass", "bucketClass must reference a defined security.limitAlertBucketClasses entry")
		}
		if NormalizeLimitKeyType(classConfig.KeyType) != keyBy {
			return validationError(prefix+".bucketClass", "bucketClass keyType must match the route concurrencyLimitPolicy keyBy")
		}
		maxInFlight := classPolicy.MaxInFlight
		if maxInFlight <= 0 {
			maxInFlight = preset.ConcurrencyMaxInFlight
		}
		maxQueueDepth := classPolicy.MaxQueueDepth
		if maxQueueDepth == 0 && preset.ConcurrencyMaxQueueDepth > 0 {
			maxQueueDepth = preset.ConcurrencyMaxQueueDepth
		}
		queueTimeout := classPolicy.QueueTimeout
		if strings.TrimSpace(queueTimeout) == "" {
			queueTimeout = preset.ConcurrencyQueueTimeout
		}
		if maxInFlight <= 0 {
			return validationError(prefix+".maxInFlight", "maxInFlight must be positive")
		}
		if maxQueueDepth < 0 {
			return validationError(prefix+".maxQueueDepth", "maxQueueDepth must be zero or positive")
		}
		if err := validateOptionalPositiveDuration(prefix+".queueTimeout", queueTimeout, "queueTimeout must use a valid positive duration format"); err != nil {
			return err
		}
	}
	return nil
}

func resolveLimiterClassPresetForRatePolicy(ctx serviceValidationContext, classPolicy LimiterClassRatePolicyConfig, prefix string) (LimiterClassPolicyPreset, error) {
	if strings.TrimSpace(classPolicy.Preset) == "" {
		return LimiterClassPolicyPreset{}, nil
	}
	preset, ok := ctx.cfg.Security.LimiterClassPresets[strings.TrimSpace(classPolicy.Preset)]
	if !ok {
		return LimiterClassPolicyPreset{}, validationError(prefix+".preset", "preset must reference a defined security.limiterClassPresets entry")
	}
	return preset, nil
}

func resolveLimiterClassPresetForConcurrencyPolicy(ctx serviceValidationContext, classPolicy LimiterClassConcurrencyPolicyConfig, prefix string) (LimiterClassPolicyPreset, error) {
	if strings.TrimSpace(classPolicy.Preset) == "" {
		return LimiterClassPolicyPreset{}, nil
	}
	preset, ok := ctx.cfg.Security.LimiterClassPresets[strings.TrimSpace(classPolicy.Preset)]
	if !ok {
		return LimiterClassPolicyPreset{}, validationError(prefix+".preset", "preset must reference a defined security.limiterClassPresets entry")
	}
	return preset, nil
}
