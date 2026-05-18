package gateway

import (
	"testing"

	"github.com/bhangun/iket/pkg/config"
)

func TestEffectiveLimiterClassRatePolicyAppliesPreset(t *testing.T) {
	cfg := &config.Config{
		Security: config.SecurityConfig{
			LimiterClassPresets: map[string]config.LimiterClassPolicyPreset{
				"vip": {
					BucketClass:           "vip-jwt",
					RateRequestsPerSecond: 20,
					RateBurst:             40,
				},
			},
		},
	}

	effective := effectiveLimiterClassRatePolicy(cfg, config.LimiterClassRatePolicyConfig{
		Preset: "vip",
	})

	if effective.BucketClass != "vip-jwt" || effective.RequestsPerSecond != 20 || effective.Burst != 40 {
		t.Fatalf("expected preset-backed rate policy, got %+v", effective)
	}
}

func TestEffectiveLimiterClassConcurrencyPolicyAppliesPreset(t *testing.T) {
	cfg := &config.Config{
		Security: config.SecurityConfig{
			LimiterClassPresets: map[string]config.LimiterClassPolicyPreset{
				"vip": {
					BucketClass:              "vip-jwt",
					ConcurrencyMaxInFlight:   16,
					ConcurrencyQueueTimeout:  "250ms",
					ConcurrencyMaxQueueDepth: 32,
				},
			},
		},
	}

	effective := effectiveLimiterClassConcurrencyPolicy(cfg, config.LimiterClassConcurrencyPolicyConfig{
		Preset: "vip",
	})

	if effective.BucketClass != "vip-jwt" || effective.MaxInFlight != 16 || effective.QueueTimeout != "250ms" || effective.MaxQueueDepth != 32 {
		t.Fatalf("expected preset-backed concurrency policy, got %+v", effective)
	}
}
