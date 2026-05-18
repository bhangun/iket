package gateway

import (
	"time"

	"github.com/bhangun/iket/pkg/config"
)

func (g *Gateway) RecordBackendSuccessForTest(route config.RouterConfig, backend config.Backend, destination string, statusCode int, latency time.Duration, now time.Time) {
	g.recordBackendSuccessWithStatus(route, backend, destination, statusCode, latency, now)
}

func (g *Gateway) RecordShadowResultForTest(route config.RouterConfig, backend config.Backend, destination string, statusCode int, latency time.Duration, shadowErr error) {
	g.recordShadowResult(route, backend, destination, statusCode, latency, shadowErr)
}

func (g *Gateway) RecordPolicyHitForTest(route config.RouterConfig, reason string, occurredAt time.Time) {
	g.recordPolicyHitAt(route, reason, occurredAt)
}

func (g *Gateway) RecordRouteLimitHitForTest(route config.RouterConfig, limitType string, keyType string, wait time.Duration, occurredAt time.Time) {
	g.recordRouteLimitHitAt(route, limitType, keyType, "", wait, occurredAt)
}

func (g *Gateway) RecordRouteLimitHitForBucketTest(route config.RouterConfig, limitType string, keyType string, bucketKey string, wait time.Duration, occurredAt time.Time) {
	g.recordRouteLimitHitAt(route, limitType, keyType, bucketKey, wait, occurredAt)
}
