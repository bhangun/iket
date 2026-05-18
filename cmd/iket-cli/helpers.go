package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

func printResponse(resp []byte) {
	var pretty bytes.Buffer
	if err := json.Indent(&pretty, resp, "", "  "); err == nil {
		fmt.Println(pretty.String())
		return
	}
	fmt.Println(string(resp))
}

func loadStructuredFile(path string) (interface{}, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	if strings.HasSuffix(strings.ToLower(path), ".json") {
		var content interface{}
		if err := json.Unmarshal(data, &content); err != nil {
			return nil, fmt.Errorf("failed to parse json: %w", err)
		}
		return content, nil
	}

	var content interface{}
	if err := yaml.Unmarshal(data, &content); err != nil {
		return nil, fmt.Errorf("failed to parse file: %w", err)
	}
	return content, nil
}

func appendQueryParam(path, key, value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return path
	}
	separator := "?"
	if strings.Contains(path, "?") {
		separator = "&"
	}
	return path + separator + key + "=" + url.QueryEscape(value)
}

func appendMutationOptions(path string, preview bool) string {
	if preview {
		path = appendQueryParam(path, "dry_run", "true")
	}
	path = appendQueryParam(path, "label", revisionLabel)
	path = appendQueryParam(path, "note", revisionNote)
	path = appendQueryParam(path, "change_ref", changeRef)
	return path
}

func appendProposalReviewOptions(path, reviewer, reviewNote string) string {
	path = appendQueryParam(path, "reviewer", reviewer)
	path = appendQueryParam(path, "review_note", reviewNote)
	return path
}

func appendProposalPromoteOptions(path, proposer, environment, notBefore string) string {
	path = appendQueryParam(path, "proposer", proposer)
	path = appendQueryParam(path, "environment", environment)
	path = appendQueryParam(path, "not_before", notBefore)
	return path
}

func appendCanaryOptions(path string, canaryServices, canaryRoutes []string) string {
	for _, selector := range canaryServices {
		path = appendQueryParam(path, "canary_service", selector)
	}
	for _, selector := range canaryRoutes {
		path = appendQueryParam(path, "canary_route", selector)
	}
	return path
}

func appendCanaryHeaderOptions(path string, canaryHeaders []string) string {
	for _, selector := range canaryHeaders {
		path = appendQueryParam(path, "canary_header", selector)
	}
	return path
}

func appendCanaryStepOptions(path string, canarySteps []int) string {
	for _, step := range canarySteps {
		if step > 0 {
			path = appendQueryParam(path, "canary_step", fmt.Sprintf("%d", step))
		}
	}
	return path
}

func appendCanaryPercentOption(path string, canaryPercent int) string {
	if canaryPercent <= 0 {
		return path
	}
	return appendQueryParam(path, "canary_percent", fmt.Sprintf("%d", canaryPercent))
}

func appendCanaryGuardOptions(path string, canaryMinRequests int, canaryMaxErrorRate float64, canaryMaxP95Latency string) string {
	if canaryMinRequests > 0 {
		path = appendQueryParam(path, "canary_min_requests", fmt.Sprintf("%d", canaryMinRequests))
	}
	if canaryMaxErrorRate > 0 {
		path = appendQueryParam(path, "canary_max_error_rate", strconv.FormatFloat(canaryMaxErrorRate, 'f', -1, 64))
	}
	path = appendQueryParam(path, "canary_max_p95_latency", canaryMaxP95Latency)
	return path
}

func appendCanaryAutoOptions(path string, canaryAuto bool, canaryAutoInterval, canaryAutoReviewer string) string {
	if canaryAuto {
		path = appendQueryParam(path, "canary_auto", "true")
	}
	path = appendQueryParam(path, "canary_auto_interval", canaryAutoInterval)
	path = appendQueryParam(path, "canary_auto_reviewer", canaryAutoReviewer)
	return path
}
