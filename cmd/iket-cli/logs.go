package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/url"
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
		listLimit  int
		listLevel  string
		listFormat string
	)
	listCmd := &cobra.Command{
		Use:   "list",
		Short: "Fetch recent logs",
		RunE: func(cmd *cobra.Command, args []string) error {
			apiPath := fmt.Sprintf("/api/v1/logs?limit=%d", listLimit)
			if listLevel != "" {
				apiPath += "&level=" + url.QueryEscape(listLevel)
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
	listCmd.Flags().StringVar(&listFormat, "format", "human", "Output format: human or json")

	var (
		tailLevel   string
		tailFormat  string
		tailBacklog int
	)
	tailCmd := &cobra.Command{
		Use:     "tail",
		Aliases: []string{"stream"},
		Short:   "Stream logs in real time",
		RunE: func(cmd *cobra.Command, args []string) error {
			apiPath := fmt.Sprintf("/api/v1/logs/stream?backlog=%d", tailBacklog)
			if tailLevel != "" {
				apiPath += "&level=" + url.QueryEscape(tailLevel)
			}

			resp, err := apiClient.OpenStream(apiPath)
			if err != nil {
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

				if tailFormat == "json" {
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
		},
	}
	tailCmd.Flags().StringVar(&tailLevel, "level", "", "Filter by level")
	tailCmd.Flags().StringVar(&tailFormat, "format", "human", "Output format: human or json")
	tailCmd.Flags().IntVar(&tailBacklog, "backlog", 20, "Recent log lines to print before following")

	logsCmd.AddCommand(listCmd, tailCmd)
	rootCmd.AddCommand(logsCmd)
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
