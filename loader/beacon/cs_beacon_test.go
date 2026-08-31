package loader

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestXOR(t *testing.T) {
	cipherData := []byte{0x12, 0x34, 0x56, 0x78}
	key := []byte{0xAC, 0x77}

	plainData := xor(cipherData, key)

	expected := []byte{0xBE, 0x43, 0xFA, 0x0F}
	require.Equal(t, expected, plainData)
}
