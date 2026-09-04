package beacon

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseVersion(t *testing.T) {
	t.Run("default", func(t *testing.T) {
		major, minor, err := parseVersion("")
		require.NoError(t, err)
		require.Equal(t, uint8(4), major)
		require.Equal(t, uint8(0), minor)
	})

	t.Run("v4.0", func(t *testing.T) {
		major, minor, err := parseVersion("4.0")
		require.NoError(t, err)
		require.Equal(t, uint8(4), major)
		require.Equal(t, uint8(0), minor)
	})

	t.Run("v4.5", func(t *testing.T) {
		major, minor, err := parseVersion("4.5")
		require.NoError(t, err)
		require.Equal(t, uint8(4), major)
		require.Equal(t, uint8(5), minor)
	})

	t.Run("zero", func(t *testing.T) {
		major, minor, err := parseVersion("0.0")
		require.NoError(t, err)
		require.Equal(t, uint8(0), major)
		require.Equal(t, uint8(0), minor)
	})

	t.Run("max", func(t *testing.T) {
		major, minor, err := parseVersion("255.255")
		require.NoError(t, err)
		require.Equal(t, uint8(255), major)
		require.Equal(t, uint8(255), minor)
	})

	t.Run("invalid format", func(t *testing.T) {
		major, minor, err := parseVersion("invalid")
		errStr := "invalid version format: invalid"
		require.EqualError(t, err, errStr)
		require.Zero(t, major)
		require.Zero(t, minor)
	})

	t.Run("multiple dots", func(t *testing.T) {
		major, minor, err := parseVersion("4.5.6")
		errStr := "invalid version format: 4.5.6"
		require.EqualError(t, err, errStr)
		require.Zero(t, major)
		require.Zero(t, minor)
	})

	t.Run("invalid major format", func(t *testing.T) {
		major, minor, err := parseVersion("a.5")
		errStr := "invalid major version format: a.5"
		require.EqualError(t, err, errStr)
		require.Zero(t, major)
		require.Zero(t, minor)
	})

	t.Run("invalid minor format", func(t *testing.T) {
		major, minor, err := parseVersion("4.a")
		errStr := "invalid minor version format: 4.a"
		require.EqualError(t, err, errStr)
		require.Zero(t, major)
		require.Zero(t, minor)
	})

	t.Run("major out of range", func(t *testing.T) {
		major, minor, err := parseVersion("256.0")
		errStr := "invalid major version: 256"
		require.EqualError(t, err, errStr)
		require.Zero(t, major)
		require.Zero(t, minor)
	})

	t.Run("minor out of range", func(t *testing.T) {
		major, minor, err := parseVersion("4.256")
		errStr := "invalid minor version: 256"
		require.EqualError(t, err, errStr)
		require.Zero(t, major)
		require.Zero(t, minor)
	})
}

func TestEncodeVersion(t *testing.T) {
	t.Run("common", func(t *testing.T) {
		tests := []struct {
			name     string
			version  string
			expected []byte
		}{
			{"default", "", []byte{0x00, 0x04}},
			{"v4.0", "4.0", []byte{0x00, 0x04}},
			{"v4.5", "4.5", []byte{0x05, 0x04}},
		}

		for _, item := range tests {
			version, err := encodeVersion(item.version)
			require.NoError(t, err)
			require.Equal(t, item.expected, version, item.name)
		}
	})

	t.Run("invalid version", func(t *testing.T) {
		ver, err := encodeVersion("invalid")
		require.EqualError(t, err, "invalid version format: invalid")
		require.Nil(t, ver)
	})
}
