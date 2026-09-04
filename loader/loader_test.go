package loader

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBuildTemplate(t *testing.T) {
	boot := []byte{
		0xFF, 0xFF, 0xFF, 0xFF,
		0xCD, 0xAB, 0x26, 0x20, // size stub
		0xAA, 0xAA, 0xAA, 0xAA,
	}
	peLoader := []byte{0x12, 0x34, 0x56, 0x78}
	runtime := []byte{0x77, 0x88, 0x56, 0x78}

	t.Run("common", func(t *testing.T) {
		template, err := BuildTemplate(boot, peLoader, runtime)
		require.NoError(t, err)

		expected := []byte{
			// boot
			0xFF, 0xFF, 0xFF, 0xFF,
			0x04, 0x00, 0x00, 0x00, // size stub
			0xAA, 0xAA, 0xAA, 0xAA,

			// pe loader
			0x12, 0x34, 0x56, 0x78,

			// runtime
			0x77, 0x88, 0x56, 0x78,
		}
		require.Equal(t, expected, template)
	})

	t.Run("without pe loader", func(t *testing.T) {
		template, err := BuildTemplate(boot, nil, runtime)
		require.NoError(t, err)

		expected := []byte{
			// boot
			0xFF, 0xFF, 0xFF, 0xFF,
			0xCD, 0xAB, 0x26, 0x20,
			0xAA, 0xAA, 0xAA, 0xAA,

			// runtime
			0x77, 0x88, 0x56, 0x78,
		}
		require.Equal(t, expected, template)
	})

	t.Run("invalid boot", func(t *testing.T) {
		invalidBoot := []byte{0xFF, 0xFF, 0xFF, 0xFF}

		template, err := BuildTemplate(invalidBoot, peLoader, runtime)
		require.EqualError(t, err, "invalid boot that without size stub")
		require.Nil(t, template)
	})
}
