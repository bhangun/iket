package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
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
