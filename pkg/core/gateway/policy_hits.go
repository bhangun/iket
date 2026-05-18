package gateway

import (
	"sort"
	"strings"
	"time"

	"github.com/bhangun/iket/pkg/config"
)

type policyHitRuntimeState struct {
	Total     int
	ByReason  map[string]int
	ByRoute   map[string]policyHitRouteRuntimeState
	Events    []policyHitEvent
	UpdatedAt time.Time
}

type policyHitRouteRuntimeState struct {
	ServiceName string
	RoutePath   string
	Total       int
	ByReason    map[string]int
}

type policyHitEvent struct {
	ServiceName string
	RoutePath   string
	Reason      string
	OccurredAt  time.Time
}

type PolicyHitReasonSummary struct {
	Reason string `json:"reason"`
	Count  int    `json:"count"`
}

type PolicyHitRouteSummary struct {
	ServiceName string         `json:"service_name,omitempty"`
	RoutePath   string         `json:"route_path"`
	Total       int            `json:"total"`
	ByReason    map[string]int `json:"by_reason,omitempty"`
}

type PolicyHitSummary struct {
	Total     int                      `json:"total"`
	Reasons   []PolicyHitReasonSummary `json:"reasons,omitempty"`
	Routes    []PolicyHitRouteSummary  `json:"routes,omitempty"`
	UpdatedAt time.Time                `json:"updated_at,omitempty"`
}

type PolicyHitWindowSummary struct {
	Window         string                   `json:"window"`
	WindowSeconds  int64                    `json:"window_seconds"`
	Total          int                      `json:"total"`
	Reasons        []PolicyHitReasonSummary `json:"reasons,omitempty"`
	Routes         []PolicyHitRouteSummary  `json:"routes,omitempty"`
	Since          time.Time                `json:"since,omitempty"`
	TopReason      string                   `json:"top_reason,omitempty"`
	TopRoutePath   string                   `json:"top_route_path,omitempty"`
	TopServiceName string                   `json:"top_service_name,omitempty"`
}

type PolicyAlert struct {
	Severity    string    `json:"severity"`
	ServiceName string    `json:"service_name,omitempty"`
	RoutePath   string    `json:"route_path"`
	Reason      string    `json:"reason"`
	Count       int       `json:"count"`
	Since       time.Time `json:"since,omitempty"`
}

type PolicyAlertSummary struct {
	Window        string         `json:"window"`
	WindowSeconds int64          `json:"window_seconds"`
	MinCount      int            `json:"min_count"`
	TotalAlerts   int            `json:"total_alerts"`
	BySeverity    map[string]int `json:"by_severity,omitempty"`
	Alerts        []PolicyAlert  `json:"alerts,omitempty"`
}

func (g *Gateway) RecordPolicyHit(route config.RouterConfig, reason string) {
	g.recordPolicyHitAt(route, reason, time.Now().UTC())
}

func (g *Gateway) recordPolicyHitAt(route config.RouterConfig, reason string, occurredAt time.Time) {
	reason = strings.TrimSpace(reason)
	if reason == "" {
		return
	}
	serviceName := strings.TrimSpace(route.ServiceName)
	routePath := strings.TrimSpace(route.Path)
	if routePath == "" {
		routePath = "/"
	}
	routeKey := serviceName + "|" + routePath

	g.policyStateMu.Lock()
	defer g.policyStateMu.Unlock()

	if g.policyState.ByReason == nil {
		g.policyState.ByReason = make(map[string]int)
	}
	if g.policyState.ByRoute == nil {
		g.policyState.ByRoute = make(map[string]policyHitRouteRuntimeState)
	}
	g.policyState.Total++
	g.policyState.ByReason[reason]++
	entry := g.policyState.ByRoute[routeKey]
	if entry.ByReason == nil {
		entry.ByReason = make(map[string]int)
	}
	entry.ServiceName = serviceName
	entry.RoutePath = routePath
	entry.Total++
	entry.ByReason[reason]++
	g.policyState.ByRoute[routeKey] = entry
	g.policyState.Events = append(g.policyState.Events, policyHitEvent{
		ServiceName: serviceName,
		RoutePath:   routePath,
		Reason:      reason,
		OccurredAt:  occurredAt,
	})
	g.trimPolicyHitEventsLocked(occurredAt)
	g.policyState.UpdatedAt = occurredAt
}

func (g *Gateway) PolicyHitSummary() PolicyHitSummary {
	g.policyStateMu.RLock()
	defer g.policyStateMu.RUnlock()

	summary := PolicyHitSummary{
		Total:     g.policyState.Total,
		UpdatedAt: g.policyState.UpdatedAt,
	}
	for reason, count := range g.policyState.ByReason {
		summary.Reasons = append(summary.Reasons, PolicyHitReasonSummary{
			Reason: reason,
			Count:  count,
		})
	}
	sort.Slice(summary.Reasons, func(i, j int) bool {
		if summary.Reasons[i].Count == summary.Reasons[j].Count {
			return summary.Reasons[i].Reason < summary.Reasons[j].Reason
		}
		return summary.Reasons[i].Count > summary.Reasons[j].Count
	})
	for _, entry := range g.policyState.ByRoute {
		copyReasons := make(map[string]int, len(entry.ByReason))
		for reason, count := range entry.ByReason {
			copyReasons[reason] = count
		}
		summary.Routes = append(summary.Routes, PolicyHitRouteSummary{
			ServiceName: entry.ServiceName,
			RoutePath:   entry.RoutePath,
			Total:       entry.Total,
			ByReason:    copyReasons,
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

func (g *Gateway) PolicyHitWindowSummary(window time.Duration) PolicyHitWindowSummary {
	g.policyStateMu.RLock()
	defer g.policyStateMu.RUnlock()

	if window <= 0 {
		window = 5 * time.Minute
	}
	now := time.Now().UTC()
	since := now.Add(-window)
	summary := PolicyHitWindowSummary{
		Window:        window.String(),
		WindowSeconds: int64(window.Seconds()),
		Since:         since,
	}
	reasons := make(map[string]int)
	routes := make(map[string]PolicyHitRouteSummary)
	for _, event := range g.policyState.Events {
		if event.OccurredAt.Before(since) {
			continue
		}
		summary.Total++
		reasons[event.Reason]++
		key := event.ServiceName + "|" + event.RoutePath
		entry := routes[key]
		if entry.ByReason == nil {
			entry.ByReason = make(map[string]int)
		}
		entry.ServiceName = event.ServiceName
		entry.RoutePath = event.RoutePath
		entry.Total++
		entry.ByReason[event.Reason]++
		routes[key] = entry
	}
	for reason, count := range reasons {
		summary.Reasons = append(summary.Reasons, PolicyHitReasonSummary{Reason: reason, Count: count})
	}
	sort.Slice(summary.Reasons, func(i, j int) bool {
		if summary.Reasons[i].Count == summary.Reasons[j].Count {
			return summary.Reasons[i].Reason < summary.Reasons[j].Reason
		}
		return summary.Reasons[i].Count > summary.Reasons[j].Count
	})
	if len(summary.Reasons) > 0 {
		summary.TopReason = summary.Reasons[0].Reason
	}
	for _, entry := range routes {
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

func (g *Gateway) PolicyAlertSummary(window time.Duration, minCount int) PolicyAlertSummary {
	return g.PolicyAlertSummaryAt(time.Now().UTC(), window, minCount)
}

func (g *Gateway) PolicyAlertSummaryAt(now time.Time, window time.Duration, minCount int) PolicyAlertSummary {
	g.policyStateMu.RLock()
	defer g.policyStateMu.RUnlock()

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
		serviceName string
		routePath   string
		reason      string
		count       int
	}
	grouped := make(map[string]*counter)
	for _, event := range g.policyState.Events {
		if event.OccurredAt.Before(since) {
			continue
		}
		key := event.ServiceName + "|" + event.RoutePath + "|" + event.Reason
		entry := grouped[key]
		if entry == nil {
			entry = &counter{
				serviceName: event.ServiceName,
				routePath:   event.RoutePath,
				reason:      event.Reason,
			}
			grouped[key] = entry
		}
		entry.count++
	}
	summary := PolicyAlertSummary{
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
		if entry.count >= maxInt(minCount*4, 12) {
			severity = "critical"
		} else if entry.count >= maxInt(minCount*2, 6) {
			severity = "elevated"
		}
		summary.Alerts = append(summary.Alerts, PolicyAlert{
			Severity:    severity,
			ServiceName: entry.serviceName,
			RoutePath:   entry.routePath,
			Reason:      entry.reason,
			Count:       entry.count,
			Since:       since,
		})
		summary.BySeverity[severity]++
	}
	sort.Slice(summary.Alerts, func(i, j int) bool {
		if summary.Alerts[i].Count == summary.Alerts[j].Count {
			if summary.Alerts[i].Severity == summary.Alerts[j].Severity {
				if summary.Alerts[i].ServiceName == summary.Alerts[j].ServiceName {
					if summary.Alerts[i].RoutePath == summary.Alerts[j].RoutePath {
						return summary.Alerts[i].Reason < summary.Alerts[j].Reason
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

func (g *Gateway) trimPolicyHitEventsLocked(now time.Time) {
	const maxPolicyHitRetention = 24 * time.Hour
	if len(g.policyState.Events) == 0 {
		return
	}
	cutoff := now.Add(-maxPolicyHitRetention)
	trim := 0
	for trim < len(g.policyState.Events) && g.policyState.Events[trim].OccurredAt.Before(cutoff) {
		trim++
	}
	if trim > 0 {
		g.policyState.Events = append([]policyHitEvent(nil), g.policyState.Events[trim:]...)
	}
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
