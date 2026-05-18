package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

type cliLogEntry struct {
	Timestamp string                 `json:"timestamp"`
	Level     string                 `json:"level"`
	Message   string                 `json:"message"`
	Fields    map[string]interface{} `json:"fields"`
}

func initLogsCmd(rootCmd *cobra.Command) {
	logsCmd := &cobra.Command{
		Use:   "logs",
		Short: "Read remote gateway logs",
	}

	var (
		listLimit     int
		listLevel     string
		listFormat    string
		listService   string
		listRoute     string
		listRequestID string
	)
	listCmd := &cobra.Command{
		Use:   "list",
		Short: "Fetch recent logs",
		RunE: func(cmd *cobra.Command, args []string) error {
			apiPath := fmt.Sprintf("/api/v1/logs?limit=%d", listLimit)
			if listLevel != "" {
				apiPath += "&level=" + url.QueryEscape(listLevel)
			}
			if listService != "" {
				apiPath += "&service=" + url.QueryEscape(listService)
			}
			if listRoute != "" {
				apiPath += "&route=" + url.QueryEscape(listRoute)
			}
			if listRequestID != "" {
				apiPath += "&request_id=" + url.QueryEscape(listRequestID)
			}
			resp, err := apiClient.Do("GET", apiPath, nil)
			if err != nil {
				return err
			}
			if listFormat == "json" {
				fmt.Println(string(resp))
				return nil
			}

			var payload struct {
				Logs []cliLogEntry `json:"logs"`
			}
			if err := json.Unmarshal(resp, &payload); err != nil {
				return err
			}
			for _, entry := range payload.Logs {
				fmt.Println(formatHumanLog(entry))
			}
			return nil
		},
	}
	listCmd.Flags().IntVar(&listLimit, "limit", 50, "Number of recent log lines")
	listCmd.Flags().StringVar(&listLevel, "level", "", "Filter by level")
	listCmd.Flags().StringVar(&listService, "service", "", "Filter by service_name")
	listCmd.Flags().StringVar(&listRoute, "route", "", "Filter by route_name")
	listCmd.Flags().StringVar(&listRequestID, "request-id", "", "Filter by request_id")
	listCmd.Flags().StringVar(&listFormat, "format", "human", "Output format: human or json")

	var (
		tailLevel     string
		tailFormat    string
		tailBacklog   int
		tailPoll      time.Duration
		tailService   string
		tailRoute     string
		tailRequestID string
	)
	tailCmd := &cobra.Command{
		Use:     "tail",
		Aliases: []string{"stream"},
		Short:   "Stream logs in real time",
		RunE: func(cmd *cobra.Command, args []string) error {
			return streamOrPollLogs(tailBacklog, tailLevel, tailService, tailRoute, tailRequestID, tailFormat, tailPoll)
		},
	}
	tailCmd.Flags().StringVar(&tailLevel, "level", "", "Filter by level")
	tailCmd.Flags().StringVar(&tailService, "service", "", "Filter by service_name")
	tailCmd.Flags().StringVar(&tailRoute, "route", "", "Filter by route_name")
	tailCmd.Flags().StringVar(&tailRequestID, "request-id", "", "Filter by request_id")
	tailCmd.Flags().StringVar(&tailFormat, "format", "human", "Output format: human or json")
	tailCmd.Flags().IntVar(&tailBacklog, "backlog", 20, "Recent log lines to print before following")
	tailCmd.Flags().DurationVar(&tailPoll, "poll-interval", 3*time.Second, "Polling interval when live streaming is unavailable")

	var (
		traceLimit   int
		traceLevel   string
		traceService string
		traceRoute   string
		traceFormat  string
		tracePoll    time.Duration
	)
	traceCmd := &cobra.Command{
		Use:   "trace",
		Short: "Find a recent request_id and follow only that request's logs",
		RunE: func(cmd *cobra.Command, args []string) error {
			entry, err := findLatestTraceableLog(traceLimit, traceLevel, traceService, traceRoute)
			if err != nil {
				return err
			}
			requestID := fieldValue(entry.Fields, "request_id")
			if summary, err := describeTraceRequest(requestID, traceLimit); err == nil && summary != "" {
				fmt.Println(summary)
			}
			fmt.Printf("Tracing request_id=%s", requestID)
			if svc := fieldValue(entry.Fields, "service_name"); svc != "" {
				fmt.Printf(" service=%s", svc)
			}
			if route := fieldValue(entry.Fields, "route_name"); route != "" {
				fmt.Printf(" route=%s", route)
			}
			fmt.Println()

			return streamOrPollLogs(traceLimit, traceLevel, traceService, traceRoute, requestID, traceFormat, tracePoll)
		},
	}
	traceCmd.Flags().IntVar(&traceLimit, "limit", 200, "How many recent logs to inspect while finding a request_id")
	traceCmd.Flags().StringVar(&traceLevel, "level", "", "Filter by level while discovering the request")
	traceCmd.Flags().StringVar(&traceService, "service", "", "Filter by service_name while discovering the request")
	traceCmd.Flags().StringVar(&traceRoute, "route", "", "Filter by route_name while discovering the request")
	traceCmd.Flags().StringVar(&traceFormat, "format", "human", "Output format: human or json")
	traceCmd.Flags().DurationVar(&tracePoll, "poll-interval", 3*time.Second, "Polling interval when live streaming is unavailable")

	logsCmd.AddCommand(listCmd, tailCmd, traceCmd)
	rootCmd.AddCommand(logsCmd)
}

func shouldFallbackToLogPolling(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "Streaming not supported") ||
		strings.Contains(msg, "text/event-stream") ||
		strings.Contains(msg, "http.Flusher")
}

func streamOrPollLogs(backlog int, level string, service string, route string, requestID string, format string, interval time.Duration) error {
	apiPath := fmt.Sprintf("/api/v1/logs/stream?backlog=%d", backlog)
	if level != "" {
		apiPath += "&level=" + url.QueryEscape(level)
	}
	if service != "" {
		apiPath += "&service=" + url.QueryEscape(service)
	}
	if route != "" {
		apiPath += "&route=" + url.QueryEscape(route)
	}
	if requestID != "" {
		apiPath += "&request_id=" + url.QueryEscape(requestID)
	}

	resp, err := apiClient.OpenStream(apiPath)
	if err != nil {
		if shouldFallbackToLogPolling(err) {
			fmt.Fprintf(os.Stderr, "Live log stream unavailable, falling back to polling every %s.\n", interval)
			return pollLogsTail(backlog, level, service, route, requestID, format, interval)
		}
		return err
	}
	defer resp.Body.Close()

	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		payload := strings.TrimPrefix(line, "data: ")
		if strings.Contains(payload, `"Connected to log stream"`) {
			continue
		}

		if format == "json" {
			fmt.Println(payload)
			continue
		}

		var entry cliLogEntry
		if err := json.Unmarshal([]byte(payload), &entry); err != nil {
			return err
		}
		fmt.Println(formatHumanLog(entry))
	}
	return scanner.Err()
}

func pollLogsTail(backlog int, level string, service string, route string, requestID string, format string, interval time.Duration) error {
	if interval <= 0 {
		interval = 3 * time.Second
	}

	seen := map[string]struct{}{}
	if err := pollLogsOnce(backlog, level, service, route, requestID, format, seen); err != nil {
		return err
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for range ticker.C {
		if err := pollLogsOnce(backlog, level, service, route, requestID, format, seen); err != nil {
			return err
		}
	}
	return nil
}

func findLatestTraceableLog(limit int, level string, service string, route string) (cliLogEntry, error) {
	apiPath := fmt.Sprintf("/api/v1/logs?limit=%d", limit)
	if level != "" {
		apiPath += "&level=" + url.QueryEscape(level)
	}
	if service != "" {
		apiPath += "&service=" + url.QueryEscape(service)
	}
	if route != "" {
		apiPath += "&route=" + url.QueryEscape(route)
	}
	resp, err := apiClient.Do("GET", apiPath, nil)
	if err != nil {
		return cliLogEntry{}, err
	}
	var payload struct {
		Logs []cliLogEntry `json:"logs"`
	}
	if err := json.Unmarshal(resp, &payload); err != nil {
		return cliLogEntry{}, err
	}
	for i := len(payload.Logs) - 1; i >= 0; i-- {
		entry := payload.Logs[i]
		if fieldValue(entry.Fields, "request_id") != "" {
			return entry, nil
		}
	}
	return cliLogEntry{}, fmt.Errorf("no recent logs with request_id found")
}

func describeTraceRequest(requestID string, limit int) (string, error) {
	apiPath := fmt.Sprintf("/api/v1/logs?limit=%d&request_id=%s", limit, url.QueryEscape(requestID))
	resp, err := apiClient.Do("GET", apiPath, nil)
	if err != nil {
		return "", err
	}

	var payload struct {
		Logs []cliLogEntry `json:"logs"`
	}
	if err := json.Unmarshal(resp, &payload); err != nil {
		return "", err
	}

	return summarizeTraceEntries(requestID, payload.Logs), nil
}

func summarizeTraceEntries(requestID string, entries []cliLogEntry) string {
	if len(entries) == 0 {
		return ""
	}

	var (
		method  string
		path    string
		status  string
		service string
		route   string
	)

	for _, entry := range entries {
		if method == "" {
			method = fieldValue(entry.Fields, "method")
		}
		if path == "" {
			path = fieldValue(entry.Fields, "path")
		}
		if service == "" {
			service = fieldValue(entry.Fields, "service_name")
		}
		if route == "" {
			route = fieldValue(entry.Fields, "route_name")
		}
		if code := fieldValue(entry.Fields, "status_code"); code != "" {
			status = code
		}
	}

	parts := make([]string, 0, 5)
	if method != "" || path != "" {
		parts = append(parts, strings.TrimSpace(method+" "+path))
	}
	if status != "" {
		parts = append(parts, "status="+status)
	}
	if service != "" {
		parts = append(parts, "service="+service)
	}
	if route != "" {
		parts = append(parts, "route="+route)
	}

	if len(parts) == 0 {
		return fmt.Sprintf("Trace summary: request_id=%s", requestID)
	}
	return fmt.Sprintf("Trace summary: request_id=%s | %s", requestID, strings.Join(parts, " "))
}

func pollLogsOnce(limit int, level string, service string, route string, requestID string, format string, seen map[string]struct{}) error {
	apiPath := fmt.Sprintf("/api/v1/logs?limit=%d", limit)
	if level != "" {
		apiPath += "&level=" + url.QueryEscape(level)
	}
	if service != "" {
		apiPath += "&service=" + url.QueryEscape(service)
	}
	if route != "" {
		apiPath += "&route=" + url.QueryEscape(route)
	}
	if requestID != "" {
		apiPath += "&request_id=" + url.QueryEscape(requestID)
	}

	resp, err := apiClient.Do("GET", apiPath, nil)
	if err != nil {
		return err
	}

	var payload struct {
		Logs []cliLogEntry `json:"logs"`
	}
	if err := json.Unmarshal(resp, &payload); err != nil {
		return err
	}

	for _, entry := range payload.Logs {
		key := logEntryKey(entry)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		if format == "json" {
			data, err := json.Marshal(entry)
			if err != nil {
				return err
			}
			fmt.Println(string(data))
			continue
		}
		fmt.Println(formatHumanLog(entry))
	}
	return nil
}

func logEntryKey(entry cliLogEntry) string {
	data, err := json.Marshal(entry)
	if err != nil {
		return entry.Timestamp + "|" + entry.Level + "|" + entry.Message
	}
	return string(data)
}

func fieldValue(fields map[string]interface{}, key string) string {
	if len(fields) == 0 {
		return ""
	}
	if value, ok := fields[key]; ok {
		return fmt.Sprint(value)
	}
	return ""
}

func formatHumanLog(entry cliLogEntry) string {
	ts := entry.Timestamp
	if parsed, err := time.Parse(time.RFC3339Nano, entry.Timestamp); err == nil {
		ts = parsed.Format("2006-01-02 15:04:05")
	}
	level := strings.ToUpper(entry.Level)
	if len(entry.Fields) == 0 {
		return fmt.Sprintf("%s %-5s %s", ts, level, entry.Message)
	}

	fieldPairs := make([]string, 0, len(entry.Fields))
	for key, value := range entry.Fields {
		fieldPairs = append(fieldPairs, fmt.Sprintf("%s=%v", key, value))
	}
	return fmt.Sprintf("%s %-5s %s | %s", ts, level, entry.Message, strings.Join(fieldPairs, " "))
}
