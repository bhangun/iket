package api

import "github.com/bhangun/iket/pkg/core/gateway"

func cloneNotificationPayloadMap(input map[string]interface{}) map[string]interface{} {
	if input == nil {
		return nil
	}
	cloned := make(map[string]interface{}, len(input))
	for key, value := range input {
		cloned[key] = cloneNotificationPayloadValue(value)
	}
	return cloned
}

func cloneNotificationPayloadValue(value interface{}) interface{} {
	switch typed := value.(type) {
	case []gateway.RouteLimitClassAlert:
		cloned := make([]interface{}, 0, len(typed))
		for _, item := range typed {
			cloned = append(cloned, map[string]interface{}{
				"severity":              item.Severity,
				"service_name":          item.ServiceName,
				"route_path":            item.RoutePath,
				"limit_type":            item.LimitType,
				"key_type":              item.KeyType,
				"bucket_class":          item.BucketClass,
				"count":                 item.Count,
				"queued_admissions":     item.QueuedAdmissions,
				"queue_full_rejections": item.QueueFullRejections,
				"average_queue_wait_ms": item.AverageQueueWaitMs,
				"max_queue_wait_ms":     item.MaxQueueWaitMs,
				"since":                 item.Since,
			})
		}
		return cloned
	case map[string]interface{}:
		return cloneNotificationPayloadMap(typed)
	case []interface{}:
		cloned := make([]interface{}, len(typed))
		for i, item := range typed {
			cloned[i] = cloneNotificationPayloadValue(item)
		}
		return cloned
	default:
		return value
	}
}

func notificationPayloadItems(value interface{}) []interface{} {
	switch typed := value.(type) {
	case []interface{}:
		return typed
	case []map[string]interface{}:
		items := make([]interface{}, 0, len(typed))
		for _, item := range typed {
			items = append(items, item)
		}
		return items
	default:
		return nil
	}
}

func notificationPayloadRows(rows []map[string]interface{}) []interface{} {
	if rows == nil {
		return nil
	}
	items := make([]interface{}, 0, len(rows))
	for _, row := range rows {
		items = append(items, row)
	}
	return items
}
