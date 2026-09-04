package loader

import (
	"testing"

	"github.com/davecgh/go-spew/spew"
	"github.com/stretchr/testify/require"
)

const testFilePath = "C:\\Windows\\System32\\cmd.exe"

func TestFile(t *testing.T) {
	t.Run("common", func(t *testing.T) {
		image := NewFile(testFilePath)

		config, err := image.Encode()
		require.NoError(t, err)

		spew.Dump(config)
	})

	t.Run("mode", func(t *testing.T) {
		image := NewFile(testFilePath)
		require.Equal(t, ModeFile, image.Mode())
	})
}
