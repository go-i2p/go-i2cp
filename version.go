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
	n := len(segments)
	
	// Parse major version
	if n > 0 {
		i, err := strconv.Atoi(segments[0])
		if err != nil {
			Warning("Invalid major version '%s' in router version '%s', defaulting to 0", segments[0], str)
			v.major = 0
		} else {
			v.major = uint16(i)
		}
	}
	
	// Parse minor version
	if n > 1 {
		i, err := strconv.Atoi(segments[1])
		if err != nil {
			Warning("Invalid minor version '%s' in router version '%s', defaulting to 0", segments[1], str)
			v.minor = 0
		} else {
			v.minor = uint16(i)
		}
	}
	
	// Parse micro version
	if n > 2 {
		i, err := strconv.Atoi(segments[2])
		if err != nil {
			Warning("Invalid micro version '%s' in router version '%s', defaulting to 0", segments[2], str)
			v.micro = 0
		} else {
			v.micro = uint16(i)
		}
	}
	
	// Parse qualifier (optional)
	if n > 3 {
		i, err := strconv.Atoi(segments[3])
		if err != nil {
			Warning("Invalid qualifier '%s' in router version '%s', defaulting to 0", segments[3], str)
			v.qualifier = 0
		} else {
			v.qualifier = uint16(i)
		}
	}
	
	return v
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
