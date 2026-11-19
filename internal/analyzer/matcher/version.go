package matcher

import (
	"strconv"
	"strings"
)

// CompareVersions compares two version strings (a and b).
// Returns -1 if a < b, 0 if a == b, and 1 if a > b.
func CompareVersions(a, b string) int {
	a = strings.TrimPrefix(strings.TrimSpace(a), "v")
	b = strings.TrimPrefix(strings.TrimSpace(b), "v")

	if a == b {
		return 0
	}
	if a == "" {
		return -1
	}
	if b == "" {
		return 1
	}

	// Split pre-release tags (e.g. 1.2.3-alpha.1)
	aParts := strings.SplitN(a, "-", 2)
	bParts := strings.SplitN(b, "-", 2)

	aNums := strings.Split(aParts[0], ".")
	bNums := strings.Split(bParts[0], ".")

	maxLen := len(aNums)
	if len(bNums) > maxLen {
		maxLen = len(bNums)
	}

	for i := 0; i < maxLen; i++ {
		var nA, nB int64
		if i < len(aNums) {
			nA, _ = strconv.ParseInt(aNums[i], 10, 64)
		}
		if i < len(bNums) {
			nB, _ = strconv.ParseInt(bNums[i], 10, 64)
		}

		if nA < nB {
			return -1
		}
		if nA > nB {
			return 1
		}
	}

	// Compare pre-release tags if main versions are equal
	if len(aParts) > 1 && len(bParts) == 1 {
		// e.g. 1.0.0-rc1 < 1.0.0
		return -1
	}
	if len(aParts) == 1 && len(bParts) > 1 {
		// e.g. 1.0.0 > 1.0.0-rc1
		return 1
	}
	if len(aParts) > 1 && len(bParts) > 1 {
		return strings.Compare(aParts[1], bParts[1])
	}

	return 0
}

// IsAffected checks if a given version falls inside the affected range:
// introduced <= version < fixed (or last_affected if fixed is empty).
func IsAffected(version, introduced, fixed string) bool {
	if version == "" {
		return false
	}

	// Check introduced boundary (inclusive)
	if introduced != "" && introduced != "0" {
		if CompareVersions(version, introduced) < 0 {
			return false
		}
	}

	// Check fixed boundary (exclusive)
	if fixed != "" {
		if CompareVersions(version, fixed) >= 0 {
			return false
		}
	}

	return true
}
