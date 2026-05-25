package api

import (
	"encoding/json"

	"github.com/bhangun/iket/pkg/config"
)

func buildGatewayConfigCandidate(current *config.Config, strategy string, input map[string]interface{}) (*config.Config, error) {
	if strategy == "merge" {
		return buildMergedGatewayConfigCandidate(current, input)
	}
	return decodeGatewayConfigInput(input)
}

func decodeGatewayConfigInput(input map[string]interface{}) (*config.Config, error) {
	data, err := json.Marshal(input)
	if err != nil {
		return nil, err
	}
	var candidate config.Config
	if err := json.Unmarshal(data, &candidate); err != nil {
		return nil, err
	}
	return &candidate, nil
}

func buildMergedGatewayConfigCandidate(current *config.Config, input map[string]interface{}) (*config.Config, error) {
	candidate, err := cloneConfig(current)
	if err != nil {
		return nil, err
	}

	currentMap := make(map[string]interface{})
	currentJSON, err := json.Marshal(candidate)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(currentJSON, &currentMap); err != nil {
		return nil, err
	}

	deepMergeGatewayConfigMap(currentMap, input)

	mergedJSON, err := json.Marshal(currentMap)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(mergedJSON, candidate); err != nil {
		return nil, err
	}
	return candidate, nil
}

func deepMergeGatewayConfigMap(dst, src map[string]interface{}) {
	for key, value := range src {
		srcMap, ok := value.(map[string]interface{})
		if !ok {
			dst[key] = value
			continue
		}
		dstMap, ok := dst[key].(map[string]interface{})
		if !ok {
			dst[key] = value
			continue
		}
		deepMergeGatewayConfigMap(dstMap, srcMap)
	}
}
