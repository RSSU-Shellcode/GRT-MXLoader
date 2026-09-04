package beacon

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
)

func parseVersion(version string) (uint8, uint8, error) {
	if version == "" {
		return 4, 0, nil // v4.0
	}
	sections := strings.Split(version, ".")
	if len(sections) != 2 {
		return 0, 0, fmt.Errorf("invalid version format: %s", version)
	}
	major, err := strconv.Atoi(sections[0])
	if err != nil {
		return 0, 0, fmt.Errorf("invalid major version format: %s", version)
	}
	if major > 0xFF {
		return 0, 0, fmt.Errorf("invalid major version: %d", major)
	}
	minor, err := strconv.Atoi(sections[1])
	if err != nil {
		return 0, 0, fmt.Errorf("invalid minor version format: %s", version)
	}
	if minor > 0xFF {
		return 0, 0, fmt.Errorf("invalid minor version: %d", minor)
	}
	return uint8(major), uint8(minor), nil // #nosec G115
}

func encodeVersion(version string) ([]byte, error) {
	major, minor, err := parseVersion(version)
	if err != nil {
		return nil, err
	}
	ver := uint16(major)<<8 | uint16(minor) // #nosec G115
	buf := make([]byte, 2)
	binary.LittleEndian.PutUint16(buf, ver)
	return buf, nil
}
