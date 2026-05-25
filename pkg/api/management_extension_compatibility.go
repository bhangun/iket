package api

import (
	"fmt"
	"strconv"
	"strings"
)

type managementRouteExtensionComparableVersion struct {
	major int
	minor int
	patch int
}

func normalizeManagementRouteExtensionCompatibility(compatibility ManagementRouteExtensionCompatibility) ManagementRouteExtensionCompatibility {
	compatibility.MinimumIketVersion = strings.TrimSpace(compatibility.MinimumIketVersion)
	compatibility.MaximumIketVersion = strings.TrimSpace(compatibility.MaximumIketVersion)
	compatibility.Status = ""
	compatibility.Message = ""
	return compatibility
}

func validateManagementRouteExtensionCompatibility(compatibility ManagementRouteExtensionCompatibility) error {
	compatibility = normalizeManagementRouteExtensionCompatibility(compatibility)
	minimum, hasMinimum := parseManagementRouteExtensionComparableVersion(compatibility.MinimumIketVersion)
	maximum, hasMaximum := parseManagementRouteExtensionComparableVersion(compatibility.MaximumIketVersion)
	if compatibility.MinimumIketVersion != "" && !hasMinimum {
		return fmt.Errorf("management route extension minimum Iket version must be semver-like: %s", compatibility.MinimumIketVersion)
	}
	if compatibility.MaximumIketVersion != "" && !hasMaximum {
		return fmt.Errorf("management route extension maximum Iket version must be semver-like: %s", compatibility.MaximumIketVersion)
	}
	if hasMinimum && hasMaximum && compareManagementRouteExtensionVersions(minimum, maximum) > 0 {
		return fmt.Errorf("management route extension minimum Iket version must not be greater than maximum Iket version: %s > %s", compatibility.MinimumIketVersion, compatibility.MaximumIketVersion)
	}
	return nil
}

func isValidManagementRouteExtensionVersion(version string) bool {
	return !strings.ContainsAny(version, " \t\r\n")
}

func resolveManagementRouteExtensionCompatibility(info ManagementRouteExtensionInfo, currentIketVersion string) ManagementRouteExtensionInfo {
	compatibility := normalizeManagementRouteExtensionCompatibility(info.Compatibility)
	compatibility.Status, compatibility.Message = evaluateManagementRouteExtensionCompatibility(compatibility, currentIketVersion)
	info.Compatibility = compatibility
	return info
}

func evaluateManagementRouteExtensionCompatibility(compatibility ManagementRouteExtensionCompatibility, currentIketVersion string) (string, string) {
	compatibility = normalizeManagementRouteExtensionCompatibility(compatibility)
	if compatibility.MinimumIketVersion == "" && compatibility.MaximumIketVersion == "" {
		return ManagementRouteExtensionCompatibilityCompatible, ""
	}

	current, ok := parseManagementRouteExtensionComparableVersion(currentIketVersion)
	if !ok {
		return ManagementRouteExtensionCompatibilityUnknown, "Iket version " + strings.TrimSpace(currentIketVersion) + " cannot be compared with extension compatibility constraints."
	}

	if minimum, hasMinimum := parseManagementRouteExtensionComparableVersion(compatibility.MinimumIketVersion); hasMinimum && compareManagementRouteExtensionVersions(current, minimum) < 0 {
		return ManagementRouteExtensionCompatibilityIncompatible, fmt.Sprintf("Extension requires Iket >= %s (current %s).", compatibility.MinimumIketVersion, strings.TrimSpace(currentIketVersion))
	}
	if maximum, hasMaximum := parseManagementRouteExtensionComparableVersion(compatibility.MaximumIketVersion); hasMaximum && compareManagementRouteExtensionVersions(current, maximum) > 0 {
		return ManagementRouteExtensionCompatibilityIncompatible, fmt.Sprintf("Extension supports Iket <= %s (current %s).", compatibility.MaximumIketVersion, strings.TrimSpace(currentIketVersion))
	}
	return ManagementRouteExtensionCompatibilityCompatible, ""
}

func parseManagementRouteExtensionComparableVersion(version string) (managementRouteExtensionComparableVersion, bool) {
	version = strings.TrimSpace(version)
	version = strings.TrimPrefix(version, "v")
	if version == "" || strings.ContainsAny(version, " \t\r\n") {
		return managementRouteExtensionComparableVersion{}, false
	}
	if index := strings.IndexAny(version, "+-"); index >= 0 {
		version = version[:index]
	}
	parts := strings.Split(version, ".")
	if len(parts) == 0 || len(parts) > 3 {
		return managementRouteExtensionComparableVersion{}, false
	}

	numbers := [3]int{}
	for index, part := range parts {
		if part == "" {
			return managementRouteExtensionComparableVersion{}, false
		}
		for _, char := range part {
			if char < '0' || char > '9' {
				return managementRouteExtensionComparableVersion{}, false
			}
		}
		number, err := strconv.Atoi(part)
		if err != nil {
			return managementRouteExtensionComparableVersion{}, false
		}
		numbers[index] = number
	}
	return managementRouteExtensionComparableVersion{
		major: numbers[0],
		minor: numbers[1],
		patch: numbers[2],
	}, true
}

func compareManagementRouteExtensionVersions(left managementRouteExtensionComparableVersion, right managementRouteExtensionComparableVersion) int {
	if left.major != right.major {
		return left.major - right.major
	}
	if left.minor != right.minor {
		return left.minor - right.minor
	}
	return left.patch - right.patch
}
