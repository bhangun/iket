package gateway

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
	"time"

	"github.com/bhangun/iket/pkg/config"
)

type routeLimitHitRuntimeState struct {
	Total     int
	ByType    map[string]int
	ByRoute   map[string]routeLimitHitRouteRuntimeEntry
	Events    []routeLimitHitEvent
	UpdatedAt time.Time
}

type routeLimitHitRouteRuntimeEntry struct {
	ServiceName         string
	RoutePath           string
	Total               int
	ByType              map[string]int
	ByKeyType           map[string]int
	QueuedAdmissions    int
	QueueFullRejections int
	QueueWaitTotalMs    int64
	QueueWaitMaxMs      int64
}

type routeLimitHitEvent struct {
	ServiceName string
	RoutePath   string
	LimitType   string
	KeyType     string
	BucketKey   string
	BucketID    string
	QueueWaitMs int64
	OccurredAt  time.Time
}

type RouteLimitHitTypeSummary struct {
	Type  string `json:"type"`
	Count int    `json:"count"`
}

type RouteLimitHitRouteSummary struct {
	ServiceName         string         `json:"service_name,omitempty"`
	RoutePath           string         `json:"route_path"`
	Total               int            `json:"total"`
	ByType              map[string]int `json:"by_type,omitempty"`
	ByKeyType           map[string]int `json:"by_key_type,omitempty"`
	QueuedAdmissions    int            `json:"queued_admissions,omitempty"`
	QueueFullRejections int            `json:"queue_full_rejections,omitempty"`
	AverageQueueWaitMs  int64          `json:"average_queue_wait_ms,omitempty"`
	MaxQueueWaitMs      int64          `json:"max_queue_wait_ms,omitempty"`
	CurrentInFlight     int            `json:"current_in_flight,omitempty"`
	CurrentQueued       int            `json:"current_queued,omitempty"`
}

type RouteLimitHitSummary struct {
	Total     int                         `json:"total"`
	Types     []RouteLimitHitTypeSummary  `json:"types,omitempty"`
	Routes    []RouteLimitHitRouteSummary `json:"routes,omitempty"`
	UpdatedAt time.Time                   `json:"updated_at,omitempty"`
}

type RouteLimitHitWindowSummary struct {
	Window         string                      `json:"window"`
	WindowSeconds  int64                       `json:"window_seconds"`
	Total          int                         `json:"total"`
	Types          []RouteLimitHitTypeSummary  `json:"types,omitempty"`
	Routes         []RouteLimitHitRouteSummary `json:"routes,omitempty"`
	Since          time.Time                   `json:"since,omitempty"`
	TopType        string                      `json:"top_type,omitempty"`
	TopRoutePath   string                      `json:"top_route_path,omitempty"`
	TopServiceName string                      `json:"top_service_name,omitempty"`
}

type RouteLimitAlert struct {
	Severity            string    `json:"severity"`
	ServiceName         string    `json:"service_name,omitempty"`
	RoutePath           string    `json:"route_path"`
	LimitType           string    `json:"limit_type"`
	KeyType             string    `json:"key_type,omitempty"`
	BucketID            string    `json:"bucket_id,omitempty"`
	BucketClass         string    `json:"bucket_class,omitempty"`
	RawBucketKey        string    `json:"-"`
	Count               int       `json:"count"`
	QueuedAdmissions    int       `json:"queued_admissions,omitempty"`
	QueueFullRejections int       `json:"queue_full_rejections,omitempty"`
	AverageQueueWaitMs  int64     `json:"average_queue_wait_ms,omitempty"`
	MaxQueueWaitMs      int64     `json:"max_queue_wait_ms,omitempty"`
	Since               time.Time `json:"since,omitempty"`
}

type RouteLimitAlertSummary struct {
	Window        string            `json:"window"`
	WindowSeconds int64             `json:"window_seconds"`
	MinCount      int               `json:"min_count"`
	TotalAlerts   int               `json:"total_alerts"`
	BySeverity    map[string]int    `json:"by_severity,omitempty"`
	Alerts        []RouteLimitAlert `json:"alerts,omitempty"`
}

type RouteLimitBucketSummaryEntry struct {
	ServiceName         string    `json:"service_name,omitempty"`
	RoutePath           string    `json:"route_path"`
	LimitType           string    `json:"limit_type"`
	KeyType             string    `json:"key_type"`
	BucketID            string    `json:"bucket_id"`
	Count               int       `json:"count"`
	QueuedAdmissions    int       `json:"queued_admissions,omitempty"`
	QueueFullRejections int       `json:"queue_full_rejections,omitempty"`
	AverageQueueWaitMs  int64     `json:"average_queue_wait_ms,omitempty"`
	MaxQueueWaitMs      int64     `json:"max_queue_wait_ms,omitempty"`
	Since               time.Time `json:"since,omitempty"`
}

type RouteLimitBucketSummary struct {
	Window        string                         `json:"window"`
	WindowSeconds int64                          `json:"window_seconds"`
	MinCount      int                            `json:"min_count"`
	TotalBuckets  int                            `json:"total_buckets"`
	TopBucketID   string                         `json:"top_bucket_id,omitempty"`
	Entries       []RouteLimitBucketSummaryEntry `json:"entries,omitempty"`
}

type RouteLimitClassSummaryEntry struct {
	ServiceName         string    `json:"service_name,omitempty"`
	RoutePath           string    `json:"route_path"`
	LimitType           string    `json:"limit_type"`
	KeyType             string    `json:"key_type"`
	BucketClass         string    `json:"bucket_class"`
	Count               int       `json:"count"`
	QueuedAdmissions    int       `json:"queued_admissions,omitempty"`
	QueueFullRejections int       `json:"queue_full_rejections,omitempty"`
	AverageQueueWaitMs  int64     `json:"average_queue_wait_ms,omitempty"`
	MaxQueueWaitMs      int64     `json:"max_queue_wait_ms,omitempty"`
	Since               time.Time `json:"since,omitempty"`
}

type RouteLimitClassSummary struct {
	Window         string                        `json:"window"`
	WindowSeconds  int64                         `json:"window_seconds"`
	MinCount       int                           `json:"min_count"`
	TotalClasses   int                           `json:"total_classes"`
	TopBucketClass string                        `json:"top_bucket_class,omitempty"`
	Entries        []RouteLimitClassSummaryEntry `json:"entries,omitempty"`
}

type RouteLimitClassAlert struct {
	Severity            string    `json:"severity"`
	ServiceName         string    `json:"service_name,omitempty"`
	RoutePath           string    `json:"route_path"`
	LimitType           string    `json:"limit_type"`
	KeyType             string    `json:"key_type"`
	BucketClass         string    `json:"bucket_class"`
	Count               int       `json:"count"`
	QueuedAdmissions    int       `json:"queued_admissions,omitempty"`
	QueueFullRejections int       `json:"queue_full_rejections,omitempty"`
	AverageQueueWaitMs  int64     `json:"average_queue_wait_ms,omitempty"`
	MaxQueueWaitMs      int64     `json:"max_queue_wait_ms,omitempty"`
	Since               time.Time `json:"since,omitempty"`
}

type RouteLimitClassAlertSummary struct {
	Window         string                 `json:"window"`
	WindowSeconds  int64                  `json:"window_seconds"`
	MinCount       int                    `json:"min_count"`
	TotalAlerts    int                    `json:"total_alerts"`
	TopBucketClass string                 `json:"top_bucket_class,omitempty"`
	BySeverity     map[string]int         `json:"by_severity,omitempty"`
	Alerts         []RouteLimitClassAlert `json:"alerts,omitempty"`
}

func (g *Gateway) RecordRouteLimitHit(route config.RouterConfig, limitType string, keyType string) {
	g.recordRouteLimitHitAt(route, limitType, keyType, "", 0, time.Now().UTC())
}

func (g *Gateway) RecordRouteLimitHitWithWait(route config.RouterConfig, limitType string, keyType string, wait time.Duration) {
	g.recordRouteLimitHitAt(route, limitType, keyType, "", wait, time.Now().UTC())
}

func (g *Gateway) RecordRouteLimitHitForBucket(route config.RouterConfig, limitType string, keyType string, bucketKey string) {
	g.recordRouteLimitHitAt(route, limitType, keyType, bucketKey, 0, time.Now().UTC())
}

func (g *Gateway) RecordRouteLimitHitWithBucketAndWait(route config.RouterConfig, limitType string, keyType string, bucketKey string, wait time.Duration) {
	g.recordRouteLimitHitAt(route, limitType, keyType, bucketKey, wait, time.Now().UTC())
}

func (g *Gateway) recordRouteLimitHitAt(route config.RouterConfig, limitType string, keyType string, bucketKey string, wait time.Duration, occurredAt time.Time) {
	limitType = strings.TrimSpace(limitType)
	keyType = strings.TrimSpace(keyType)
	if limitType == "" {
		return
	}
	if keyType == "" {
		keyType = "global"
	}
	waitMs := int64(0)
	if wait > 0 {
		waitMs = wait.Milliseconds()
		if waitMs == 0 {
			waitMs = 1
		}
	}
	serviceName := strings.TrimSpace(route.ServiceName)
	routePath := strings.TrimSpace(route.Path)
	if routePath == "" {
		routePath = "/"
	}
	bucketID := limitBucketID(keyType, bucketKey)
	routeKey := serviceName + "|" + routePath

	g.limitHitStateMu.Lock()
	defer g.limitHitStateMu.Unlock()

	if g.limitHitState.ByType == nil {
		g.limitHitState.ByType = make(map[string]int)
	}
	if g.limitHitState.ByRoute == nil {
		g.limitHitState.ByRoute = make(map[string]routeLimitHitRouteRuntimeEntry)
	}
	g.limitHitState.Total++
	g.limitHitState.ByType[limitType]++
	entry := g.limitHitState.ByRoute[routeKey]
	if entry.ByType == nil {
		entry.ByType = make(map[string]int)
	}
	if entry.ByKeyType == nil {
		entry.ByKeyType = make(map[string]int)
	}
	entry.ServiceName = serviceName
	entry.RoutePath = routePath
	entry.Total++
	entry.ByType[limitType]++
	entry.ByKeyType[keyType]++
	switch limitType {
	case "concurrency_queued":
		entry.QueuedAdmissions++
		entry.QueueWaitTotalMs += waitMs
		if waitMs > entry.QueueWaitMaxMs {
			entry.QueueWaitMaxMs = waitMs
		}
	case "concurrency_queue_full":
		entry.QueueFullRejections++
	}
	g.limitHitState.ByRoute[routeKey] = entry
	g.limitHitState.Events = append(g.limitHitState.Events, routeLimitHitEvent{
		ServiceName: serviceName,
		RoutePath:   routePath,
		LimitType:   limitType,
		KeyType:     keyType,
		BucketKey:   bucketKey,
		BucketID:    bucketID,
		QueueWaitMs: waitMs,
		OccurredAt:  occurredAt,
	})
	g.trimRouteLimitHitEventsLocked(occurredAt)
	g.limitHitState.UpdatedAt = occurredAt
}

func (g *Gateway) RouteLimitHitSummary() RouteLimitHitSummary {
	g.limitHitStateMu.RLock()
	defer g.limitHitStateMu.RUnlock()
	concurrencySnapshots := g.currentRouteConcurrencySnapshots()

	summary := RouteLimitHitSummary{
		Total:     g.limitHitState.Total,
		UpdatedAt: g.limitHitState.UpdatedAt,
	}
	for limitType, count := range g.limitHitState.ByType {
		summary.Types = append(summary.Types, RouteLimitHitTypeSummary{Type: limitType, Count: count})
	}
	sort.Slice(summary.Types, func(i, j int) bool {
		if summary.Types[i].Count == summary.Types[j].Count {
			return summary.Types[i].Type < summary.Types[j].Type
		}
		return summary.Types[i].Count > summary.Types[j].Count
	})
	for _, entry := range g.limitHitState.ByRoute {
		copyTypes := make(map[string]int, len(entry.ByType))
		for limitType, count := range entry.ByType {
			copyTypes[limitType] = count
		}
		copyKeyTypes := make(map[string]int, len(entry.ByKeyType))
		for keyType, count := range entry.ByKeyType {
			copyKeyTypes[keyType] = count
		}
		summary.Routes = append(summary.Routes, RouteLimitHitRouteSummary{
			ServiceName:         entry.ServiceName,
			RoutePath:           entry.RoutePath,
			Total:               entry.Total,
			ByType:              copyTypes,
			ByKeyType:           copyKeyTypes,
			QueuedAdmissions:    entry.QueuedAdmissions,
			QueueFullRejections: entry.QueueFullRejections,
			AverageQueueWaitMs:  averageQueueWaitMs(entry.QueueWaitTotalMs, entry.QueuedAdmissions),
			MaxQueueWaitMs:      entry.QueueWaitMaxMs,
			CurrentInFlight:     concurrencySnapshots[entry.ServiceName+"|"+entry.RoutePath].inFlight,
			CurrentQueued:       concurrencySnapshots[entry.ServiceName+"|"+entry.RoutePath].queued,
		})
	}
	sort.Slice(summary.Routes, func(i, j int) bool {
		if summary.Routes[i].Total == summary.Routes[j].Total {
			if summary.Routes[i].ServiceName == summary.Routes[j].ServiceName {
				return summary.Routes[i].RoutePath < summary.Routes[j].RoutePath
			}
			return summary.Routes[i].ServiceName < summary.Routes[j].ServiceName
		}
		return summary.Routes[i].Total > summary.Routes[j].Total
	})
	return summary
}

func (g *Gateway) RouteLimitHitWindowSummary(window time.Duration) RouteLimitHitWindowSummary {
	g.limitHitStateMu.RLock()
	defer g.limitHitStateMu.RUnlock()
	concurrencySnapshots := g.currentRouteConcurrencySnapshots()

	if window <= 0 {
		window = 5 * time.Minute
	}
	now := time.Now().UTC()
	since := now.Add(-window)
	summary := RouteLimitHitWindowSummary{
		Window:        window.String(),
		WindowSeconds: int64(window.Seconds()),
		Since:         since,
	}
	types := make(map[string]int)
	routes := make(map[string]RouteLimitHitRouteSummary)
	for _, event := range g.limitHitState.Events {
		if event.OccurredAt.Before(since) {
			continue
		}
		summary.Total++
		types[event.LimitType]++
		key := event.ServiceName + "|" + event.RoutePath
		entry := routes[key]
		if entry.ByType == nil {
			entry.ByType = make(map[string]int)
		}
		if entry.ByKeyType == nil {
			entry.ByKeyType = make(map[string]int)
		}
		entry.ServiceName = event.ServiceName
		entry.RoutePath = event.RoutePath
		entry.Total++
		entry.ByType[event.LimitType]++
		entry.ByKeyType[event.KeyType]++
		switch event.LimitType {
		case "concurrency_queued":
			entry.QueuedAdmissions++
			entry.AverageQueueWaitMs += event.QueueWaitMs
			if event.QueueWaitMs > entry.MaxQueueWaitMs {
				entry.MaxQueueWaitMs = event.QueueWaitMs
			}
		case "concurrency_queue_full":
			entry.QueueFullRejections++
		}
		routes[key] = entry
	}
	for limitType, count := range types {
		summary.Types = append(summary.Types, RouteLimitHitTypeSummary{Type: limitType, Count: count})
	}
	sort.Slice(summary.Types, func(i, j int) bool {
		if summary.Types[i].Count == summary.Types[j].Count {
			return summary.Types[i].Type < summary.Types[j].Type
		}
		return summary.Types[i].Count > summary.Types[j].Count
	})
	if len(summary.Types) > 0 {
		summary.TopType = summary.Types[0].Type
	}
	for _, entry := range routes {
		snapshot := concurrencySnapshots[entry.ServiceName+"|"+entry.RoutePath]
		if entry.QueuedAdmissions > 0 {
			entry.AverageQueueWaitMs = averageQueueWaitMs(entry.AverageQueueWaitMs, entry.QueuedAdmissions)
		}
		entry.CurrentInFlight = snapshot.inFlight
		entry.CurrentQueued = snapshot.queued
		summary.Routes = append(summary.Routes, entry)
	}
	sort.Slice(summary.Routes, func(i, j int) bool {
		if summary.Routes[i].Total == summary.Routes[j].Total {
			if summary.Routes[i].ServiceName == summary.Routes[j].ServiceName {
				return summary.Routes[i].RoutePath < summary.Routes[j].RoutePath
			}
			return summary.Routes[i].ServiceName < summary.Routes[j].ServiceName
		}
		return summary.Routes[i].Total > summary.Routes[j].Total
	})
	if len(summary.Routes) > 0 {
		summary.TopRoutePath = summary.Routes[0].RoutePath
		summary.TopServiceName = summary.Routes[0].ServiceName
	}
	return summary
}

func (g *Gateway) RouteLimitAlertSummary(window time.Duration, minCount int) RouteLimitAlertSummary {
	return g.RouteLimitAlertSummaryAt(time.Now().UTC(), window, minCount)
}

func (g *Gateway) RouteLimitBucketSummary(window time.Duration, minCount int) RouteLimitBucketSummary {
	g.limitHitStateMu.RLock()
	defer g.limitHitStateMu.RUnlock()

	if window <= 0 {
		window = 5 * time.Minute
	}
	if minCount <= 0 {
		minCount = 1
	}
	now := time.Now().UTC()
	since := now.Add(-window)
	type counter struct {
		serviceName         string
		routePath           string
		limitType           string
		keyType             string
		bucketID            string
		count               int
		queuedAdmissions    int
		queueFullRejections int
		queueWaitTotalMs    int64
		queueWaitMaxMs      int64
	}
	grouped := make(map[string]*counter)
	for _, event := range g.limitHitState.Events {
		if event.OccurredAt.Before(since) || strings.TrimSpace(event.BucketID) == "" {
			continue
		}
		key := strings.Join([]string{
			event.ServiceName,
			event.RoutePath,
			event.LimitType,
			event.KeyType,
			event.BucketID,
		}, "|")
		entry := grouped[key]
		if entry == nil {
			entry = &counter{
				serviceName: event.ServiceName,
				routePath:   event.RoutePath,
				limitType:   event.LimitType,
				keyType:     event.KeyType,
				bucketID:    event.BucketID,
			}
			grouped[key] = entry
		}
		entry.count++
		switch event.LimitType {
		case "concurrency_queued":
			entry.queuedAdmissions++
			entry.queueWaitTotalMs += event.QueueWaitMs
			if event.QueueWaitMs > entry.queueWaitMaxMs {
				entry.queueWaitMaxMs = event.QueueWaitMs
			}
		case "concurrency_queue_full":
			entry.queueFullRejections++
		}
	}

	summary := RouteLimitBucketSummary{
		Window:        window.String(),
		WindowSeconds: int64(window.Seconds()),
		MinCount:      minCount,
	}
	for _, entry := range grouped {
		if entry.count < minCount {
			continue
		}
		summary.Entries = append(summary.Entries, RouteLimitBucketSummaryEntry{
			ServiceName:         entry.serviceName,
			RoutePath:           entry.routePath,
			LimitType:           entry.limitType,
			KeyType:             entry.keyType,
			BucketID:            entry.bucketID,
			Count:               entry.count,
			QueuedAdmissions:    entry.queuedAdmissions,
			QueueFullRejections: entry.queueFullRejections,
			AverageQueueWaitMs:  averageQueueWaitMs(entry.queueWaitTotalMs, entry.queuedAdmissions),
			MaxQueueWaitMs:      entry.queueWaitMaxMs,
			Since:               since,
		})
	}
	sort.Slice(summary.Entries, func(i, j int) bool {
		if summary.Entries[i].Count == summary.Entries[j].Count {
			if summary.Entries[i].ServiceName == summary.Entries[j].ServiceName {
				if summary.Entries[i].RoutePath == summary.Entries[j].RoutePath {
					if summary.Entries[i].LimitType == summary.Entries[j].LimitType {
						return summary.Entries[i].BucketID < summary.Entries[j].BucketID
					}
					return summary.Entries[i].LimitType < summary.Entries[j].LimitType
				}
				return summary.Entries[i].RoutePath < summary.Entries[j].RoutePath
			}
			return summary.Entries[i].ServiceName < summary.Entries[j].ServiceName
		}
		return summary.Entries[i].Count > summary.Entries[j].Count
	})
	summary.TotalBuckets = len(summary.Entries)
	if len(summary.Entries) > 0 {
		summary.TopBucketID = summary.Entries[0].BucketID
	}
	return summary
}

func (g *Gateway) RouteLimitClassSummary(window time.Duration, minCount int) RouteLimitClassSummary {
	g.limitHitStateMu.RLock()
	defer g.limitHitStateMu.RUnlock()

	if window <= 0 {
		window = 5 * time.Minute
	}
	if minCount <= 0 {
		minCount = 1
	}
	now := time.Now().UTC()
	since := now.Add(-window)
	cfg := g.GetConfig()

	type counter struct {
		serviceName         string
		routePath           string
		limitType           string
		keyType             string
		bucketClass         string
		count               int
		queuedAdmissions    int
		queueFullRejections int
		queueWaitTotalMs    int64
		queueWaitMaxMs      int64
	}

	grouped := make(map[string]*counter)
	for _, event := range g.limitHitState.Events {
		if event.OccurredAt.Before(since) {
			continue
		}
		bucketClass := ResolveLimiterBucketClass(cfg, event.KeyType, event.BucketKey)
		if strings.TrimSpace(bucketClass) == "" {
			continue
		}
		key := event.ServiceName + "|" + event.RoutePath + "|" + event.LimitType + "|" + event.KeyType + "|" + bucketClass
		entry := grouped[key]
		if entry == nil {
			entry = &counter{
				serviceName: event.ServiceName,
				routePath:   event.RoutePath,
				limitType:   event.LimitType,
				keyType:     event.KeyType,
				bucketClass: bucketClass,
			}
			grouped[key] = entry
		}
		entry.count++
		switch event.LimitType {
		case "concurrency_queued":
			entry.queuedAdmissions++
			entry.queueWaitTotalMs += event.QueueWaitMs
			if event.QueueWaitMs > entry.queueWaitMaxMs {
				entry.queueWaitMaxMs = event.QueueWaitMs
			}
		case "concurrency_queue_full":
			entry.queueFullRejections++
		}
	}

	summary := RouteLimitClassSummary{
		Window:        window.String(),
		WindowSeconds: int64(window.Seconds()),
		MinCount:      minCount,
	}
	for _, entry := range grouped {
		if entry.count < minCount {
			continue
		}
		summary.Entries = append(summary.Entries, RouteLimitClassSummaryEntry{
			ServiceName:         entry.serviceName,
			RoutePath:           entry.routePath,
			LimitType:           entry.limitType,
			KeyType:             entry.keyType,
			BucketClass:         entry.bucketClass,
			Count:               entry.count,
			QueuedAdmissions:    entry.queuedAdmissions,
			QueueFullRejections: entry.queueFullRejections,
			AverageQueueWaitMs:  averageQueueWaitMs(entry.queueWaitTotalMs, entry.queuedAdmissions),
			MaxQueueWaitMs:      entry.queueWaitMaxMs,
			Since:               since,
		})
	}
	sort.Slice(summary.Entries, func(i, j int) bool {
		if summary.Entries[i].Count == summary.Entries[j].Count {
			if summary.Entries[i].BucketClass == summary.Entries[j].BucketClass {
				if summary.Entries[i].RoutePath == summary.Entries[j].RoutePath {
					return summary.Entries[i].LimitType < summary.Entries[j].LimitType
				}
				return summary.Entries[i].RoutePath < summary.Entries[j].RoutePath
			}
			return summary.Entries[i].BucketClass < summary.Entries[j].BucketClass
		}
		return summary.Entries[i].Count > summary.Entries[j].Count
	})
	summary.TotalClasses = len(summary.Entries)
	if len(summary.Entries) > 0 {
		summary.TopBucketClass = summary.Entries[0].BucketClass
	}
	return summary
}

func (g *Gateway) RouteLimitClassAlertSummary(window time.Duration, minCount int) RouteLimitClassAlertSummary {
	return g.RouteLimitClassAlertSummaryAt(time.Now().UTC(), window, minCount)
}

func (g *Gateway) RouteLimitClassAlertSummaryAt(now time.Time, window time.Duration, minCount int) RouteLimitClassAlertSummary {
	g.limitHitStateMu.RLock()
	defer g.limitHitStateMu.RUnlock()

	if window <= 0 {
		window = 5 * time.Minute
	}
	if minCount <= 0 {
		minCount = 3
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	since := now.Add(-window)
	cfg := g.GetConfig()

	type counter struct {
		serviceName         string
		routePath           string
		limitType           string
		keyType             string
		bucketClass         string
		count               int
		queuedAdmissions    int
		queueFullRejections int
		queueWaitTotalMs    int64
		queueWaitMaxMs      int64
	}

	grouped := make(map[string]*counter)
	for _, event := range g.limitHitState.Events {
		if event.OccurredAt.Before(since) {
			continue
		}
		bucketClass := ResolveLimiterBucketClass(cfg, event.KeyType, event.BucketKey)
		if strings.TrimSpace(bucketClass) == "" {
			continue
		}
		key := event.ServiceName + "|" + event.RoutePath + "|" + event.LimitType + "|" + event.KeyType + "|" + bucketClass
		entry := grouped[key]
		if entry == nil {
			entry = &counter{
				serviceName: event.ServiceName,
				routePath:   event.RoutePath,
				limitType:   event.LimitType,
				keyType:     event.KeyType,
				bucketClass: bucketClass,
			}
			grouped[key] = entry
		}
		entry.count++
		switch event.LimitType {
		case "concurrency_queued":
			entry.queuedAdmissions++
			entry.queueWaitTotalMs += event.QueueWaitMs
			if event.QueueWaitMs > entry.queueWaitMaxMs {
				entry.queueWaitMaxMs = event.QueueWaitMs
			}
		case "concurrency_queue_full":
			entry.queueFullRejections++
		}
	}

	summary := RouteLimitClassAlertSummary{
		Window:        window.String(),
		WindowSeconds: int64(window.Seconds()),
		MinCount:      minCount,
		BySeverity:    map[string]int{"warning": 0, "elevated": 0, "critical": 0},
	}
	for _, entry := range grouped {
		if entry.count < minCount {
			continue
		}
		severity := "warning"
		if entry.limitType == "concurrency_queue_full" && entry.count >= minCount {
			severity = "elevated"
		}
		if entry.count >= maxInt(minCount*4, 12) {
			severity = "critical"
		} else if severity != "elevated" && entry.count >= maxInt(minCount*2, 6) {
			severity = "elevated"
		}
		summary.Alerts = append(summary.Alerts, RouteLimitClassAlert{
			Severity:            severity,
			ServiceName:         entry.serviceName,
			RoutePath:           entry.routePath,
			LimitType:           entry.limitType,
			KeyType:             entry.keyType,
			BucketClass:         entry.bucketClass,
			Count:               entry.count,
			QueuedAdmissions:    entry.queuedAdmissions,
			QueueFullRejections: entry.queueFullRejections,
			AverageQueueWaitMs:  averageQueueWaitMs(entry.queueWaitTotalMs, entry.queuedAdmissions),
			MaxQueueWaitMs:      entry.queueWaitMaxMs,
			Since:               since,
		})
		summary.BySeverity[severity]++
	}
	sort.Slice(summary.Alerts, func(i, j int) bool {
		if summary.Alerts[i].Count == summary.Alerts[j].Count {
			if summary.Alerts[i].Severity == summary.Alerts[j].Severity {
				if summary.Alerts[i].BucketClass == summary.Alerts[j].BucketClass {
					if summary.Alerts[i].RoutePath == summary.Alerts[j].RoutePath {
						return summary.Alerts[i].LimitType < summary.Alerts[j].LimitType
					}
					return summary.Alerts[i].RoutePath < summary.Alerts[j].RoutePath
				}
				return summary.Alerts[i].BucketClass < summary.Alerts[j].BucketClass
			}
			return summary.Alerts[i].Severity > summary.Alerts[j].Severity
		}
		return summary.Alerts[i].Count > summary.Alerts[j].Count
	})
	summary.TotalAlerts = len(summary.Alerts)
	if len(summary.Alerts) > 0 {
		summary.TopBucketClass = summary.Alerts[0].BucketClass
	}
	return summary
}

func (g *Gateway) RouteLimitAlertSummaryAt(now time.Time, window time.Duration, minCount int) RouteLimitAlertSummary {
	g.limitHitStateMu.RLock()
	defer g.limitHitStateMu.RUnlock()

	if window <= 0 {
		window = 5 * time.Minute
	}
	if minCount <= 0 {
		minCount = 3
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	since := now.Add(-window)
	type counter struct {
		serviceName         string
		routePath           string
		limitType           string
		keyType             string
		rawBucketKey        string
		bucketID            string
		count               int
		queuedAdmissions    int
		queueFullRejections int
		queueWaitTotalMs    int64
		queueWaitMaxMs      int64
	}
	grouped := make(map[string]*counter)
	for _, event := range g.limitHitState.Events {
		if event.OccurredAt.Before(since) {
			continue
		}
		key := event.ServiceName + "|" + event.RoutePath + "|" + event.LimitType
		if g.routeLimitAlertGroupByBucket(event.ServiceName, event.RoutePath) && strings.TrimSpace(event.BucketID) != "" {
			key += "|" + strings.TrimSpace(event.KeyType) + "|" + strings.TrimSpace(event.BucketID)
		}
		entry := grouped[key]
		if entry == nil {
			entry = &counter{
				serviceName:  event.ServiceName,
				routePath:    event.RoutePath,
				limitType:    event.LimitType,
				keyType:      event.KeyType,
				rawBucketKey: event.BucketKey,
				bucketID:     event.BucketID,
			}
			grouped[key] = entry
		}
		entry.count++
		switch event.LimitType {
		case "concurrency_queued":
			entry.queuedAdmissions++
			entry.queueWaitTotalMs += event.QueueWaitMs
			if event.QueueWaitMs > entry.queueWaitMaxMs {
				entry.queueWaitMaxMs = event.QueueWaitMs
			}
		case "concurrency_queue_full":
			entry.queueFullRejections++
		}
	}

	summary := RouteLimitAlertSummary{
		Window:        window.String(),
		WindowSeconds: int64(window.Seconds()),
		MinCount:      minCount,
		BySeverity:    map[string]int{"warning": 0, "elevated": 0, "critical": 0},
	}
	for _, entry := range grouped {
		if entry.count < minCount {
			continue
		}
		severity := "warning"
		if entry.limitType == "concurrency_queue_full" && entry.count >= minCount {
			severity = "elevated"
		}
		if entry.count >= maxInt(minCount*4, 12) {
			severity = "critical"
		} else if severity != "elevated" && entry.count >= maxInt(minCount*2, 6) {
			severity = "elevated"
		}
		summary.Alerts = append(summary.Alerts, RouteLimitAlert{
			Severity:            severity,
			ServiceName:         entry.serviceName,
			RoutePath:           entry.routePath,
			LimitType:           entry.limitType,
			KeyType:             entry.keyType,
			BucketID:            entry.bucketID,
			RawBucketKey:        entry.rawBucketKey,
			Count:               entry.count,
			QueuedAdmissions:    entry.queuedAdmissions,
			QueueFullRejections: entry.queueFullRejections,
			AverageQueueWaitMs:  averageQueueWaitMs(entry.queueWaitTotalMs, entry.queuedAdmissions),
			MaxQueueWaitMs:      entry.queueWaitMaxMs,
			Since:               since,
		})
		summary.BySeverity[severity]++
	}
	sort.Slice(summary.Alerts, func(i, j int) bool {
		if summary.Alerts[i].Count == summary.Alerts[j].Count {
			if summary.Alerts[i].Severity == summary.Alerts[j].Severity {
				if summary.Alerts[i].ServiceName == summary.Alerts[j].ServiceName {
					if summary.Alerts[i].RoutePath == summary.Alerts[j].RoutePath {
						if summary.Alerts[i].LimitType == summary.Alerts[j].LimitType {
							return summary.Alerts[i].BucketID < summary.Alerts[j].BucketID
						}
						return summary.Alerts[i].LimitType < summary.Alerts[j].LimitType
					}
					return summary.Alerts[i].RoutePath < summary.Alerts[j].RoutePath
				}
				return summary.Alerts[i].ServiceName < summary.Alerts[j].ServiceName
			}
			return summary.Alerts[i].Severity > summary.Alerts[j].Severity
		}
		return summary.Alerts[i].Count > summary.Alerts[j].Count
	})
	summary.TotalAlerts = len(summary.Alerts)
	return summary
}

type routeConcurrencySnapshot struct {
	inFlight int
	queued   int
}

func (g *Gateway) currentRouteConcurrencySnapshots() map[string]routeConcurrencySnapshot {
	g.concurrencyStateMu.Lock()
	defer g.concurrencyStateMu.Unlock()

	snapshots := make(map[string]routeConcurrencySnapshot, len(g.concurrencyState))
	for routeKey, bucket := range g.concurrencyState {
		serviceName, routePath := routeIdentityFromStateKey(routeKey)
		if routePath == "" {
			continue
		}
		bucket.mu.Lock()
		snapshots[serviceName+"|"+routePath] = routeConcurrencySnapshot{
			inFlight: bucket.inFlight,
			queued:   bucket.queued,
		}
		bucket.mu.Unlock()
	}
	return snapshots
}

func routeIdentityFromStateKey(routeKey string) (string, string) {
	parts := strings.SplitN(routeKey, "|", 4)
	if len(parts) < 2 {
		return "", ""
	}
	return parts[0], parts[1]
}

func (g *Gateway) trimRouteLimitHitEventsLocked(now time.Time) {
	cutoff := now.Add(-24 * time.Hour)
	trimIndex := 0
	for trimIndex < len(g.limitHitState.Events) && g.limitHitState.Events[trimIndex].OccurredAt.Before(cutoff) {
		trimIndex++
	}
	if trimIndex > 0 {
		g.limitHitState.Events = append([]routeLimitHitEvent(nil), g.limitHitState.Events[trimIndex:]...)
	}
}

func averageQueueWaitMs(totalMs int64, count int) int64 {
	if totalMs <= 0 || count <= 0 {
		return 0
	}
	return totalMs / int64(count)
}

func (g *Gateway) routeLimitAlertGroupByBucket(serviceName, routePath string) bool {
	cfg := g.GetConfig()
	if cfg == nil {
		return false
	}
	serviceName = strings.TrimSpace(serviceName)
	routePath = strings.TrimSpace(routePath)
	for _, serviceConfig := range cfg.Services {
		for _, service := range serviceConfig.Services {
			for _, route := range service.Routes {
				if strings.TrimSpace(service.Name) != serviceName || strings.TrimSpace(route.Path) != routePath {
					continue
				}
				if route.LimitAlertPolicy == nil {
					return false
				}
				return strings.EqualFold(strings.TrimSpace(route.LimitAlertPolicy.GroupBy), "bucket")
			}
		}
	}
	return false
}

func limitBucketID(keyType, bucketKey string) string {
	keyType = strings.ToLower(strings.TrimSpace(keyType))
	bucketKey = strings.TrimSpace(bucketKey)
	if keyType == "" || keyType == "global" || bucketKey == "" {
		return ""
	}
	if bucketKey == "__missing__" {
		return keyType + ":missing"
	}
	sum := sha256.Sum256([]byte(bucketKey))
	return keyType + ":" + hex.EncodeToString(sum[:6])
}
