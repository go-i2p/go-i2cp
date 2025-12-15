package go_i2cp

import (
	"strconv"
	"strings"
)

type Version struct {
	major, minor, micro, qualifier uint16
	version                        string
}

// parseVersion parses a router version string into Version components.
// Handles I2P router version format: "major.minor.micro[.qualifier]"
//
// Examples:
//   - "0.9.67" → Version{major: 0, minor: 9, micro: 67, qualifier: 0}
//   - "2.10.0" → Version{major: 2, minor: 10, micro: 0, qualifier: 0}
//
// MINOR FIX: Gracefully handles malformed version strings
//   - Invalid segments default to 0 (e.g., "0.9.garbage" → Version{0, 9, 0, 0})
//   - Missing segments default to 0 (e.g., "0.9" → Version{0, 9, 0, 0})
//   - Logs warning for parsing failures to aid debugging
//
// Returns:
//
//	Version struct with parsed components (invalid segments set to 0)
func parseVersion(str string) Version {
	v := Version{version: str}
	segments := strings.Split(str, ".")
	parseVersionComponents(&v, segments, str)
	return v
}

// parseVersionSegment parses a single version segment string into a uint16.
// Returns 0 and logs a warning if parsing fails.
func parseVersionSegment(segment, segmentName, fullVersion string) uint16 {
	i, err := strconv.Atoi(segment)
	if err != nil {
		Warning("Invalid %s version '%s' in router version '%s', defaulting to 0", segmentName, segment, fullVersion)
		return 0
	}
	return uint16(i)
}

// parseVersionComponents parses all version segments (major, minor, micro, qualifier).
// Updates the provided Version struct in place.
func parseVersionComponents(v *Version, segments []string, fullVersion string) {
	n := len(segments)

	if n > 0 {
		v.major = parseVersionSegment(segments[0], "major", fullVersion)
	}

	if n > 1 {
		v.minor = parseVersionSegment(segments[1], "minor", fullVersion)
	}

	if n > 2 {
		v.micro = parseVersionSegment(segments[2], "micro", fullVersion)
	}

	if n > 3 {
		v.qualifier = parseVersionSegment(segments[3], "qualifier", fullVersion)
	}
}

func (v *Version) compare(other Version) int {
	if v.major != other.major {
		if (v.major - other.major) > 0 {
			return 1
		} else {
			return -1
		}
	}
	if v.minor != other.minor {
		if (v.minor - other.minor) > 0 {
			return 1
		} else {
			return -1
		}
	}
	if v.micro != other.micro {
		if (v.micro - other.micro) > 0 {
			return 1
		} else {
			return -1
		}
	}
	if v.qualifier != other.qualifier {
		if (v.qualifier - other.qualifier) > 0 {
			return 1
		} else {
			return -1
		}
	}
	return 0
}
