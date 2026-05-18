package gateway

import (
	"regexp"
	"sort"
	"strings"

	"github.com/bhangun/iket/pkg/config"
)

func ResolveLimiterBucketClass(cfg *config.Config, keyType string, rawBucketKey string) string {
	if cfg == nil {
		return ""
	}
	keyType = strings.ToLower(strings.TrimSpace(keyType))
	rawBucketKey = strings.TrimSpace(rawBucketKey)
	if keyType == "" || rawBucketKey == "" || len(cfg.Security.LimitAlertBucketClasses) == 0 {
		return ""
	}
	names := make([]string, 0, len(cfg.Security.LimitAlertBucketClasses))
	for name := range cfg.Security.LimitAlertBucketClasses {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		classConfig := cfg.Security.LimitAlertBucketClasses[name]
		if strings.ToLower(strings.TrimSpace(classConfig.KeyType)) != keyType {
			continue
		}
		re, err := regexp.Compile(strings.TrimSpace(classConfig.BucketRegex))
		if err != nil {
			continue
		}
		if re.MatchString(rawBucketKey) {
			return strings.TrimSpace(name)
		}
	}
	return ""
}
