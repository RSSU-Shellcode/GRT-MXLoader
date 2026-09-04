package beacon

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestExtractStage(t *testing.T) {
	t.Run("invalid version", func(t *testing.T) {
		stage, err := ExtractStage("invalid", nil)
		require.EqualError(t, err, "invalid version format: invalid")
		require.Nil(t, stage)
	})

	t.Run("unsupported version", func(t *testing.T) {
		stage, err := ExtractStage("255.0", nil)
		require.EqualError(t, err, "unsupported version")
		require.Nil(t, stage)
	})
}

func TestXOR(t *testing.T) {
	cipherData := []byte{0x12, 0x34, 0x56, 0x78}
	key := []byte{0xAC, 0x77}

	plainData := xor(cipherData, key)

	expected := []byte{0xBE, 0x43, 0xFA, 0x0F}
	require.Equal(t, expected, plainData)
}
