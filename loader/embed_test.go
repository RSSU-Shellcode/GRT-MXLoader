package loader

import (
	"strings"
	"testing"

	"github.com/For-ACGN/LZSS"
	"github.com/davecgh/go-spew/spew"
	"github.com/stretchr/testify/require"
)

var testEmbedData = []byte("test embed data" + strings.Repeat("repeated data", 16))

func TestEmbed(t *testing.T) {
	t.Run("common", func(t *testing.T) {
		embed := NewEmbed(testEmbedData, nil)

		config, err := embed.Encode()
		require.NoError(t, err)
		require.Greater(t, len(config), len(testEmbedData))

		spew.Dump(config)
	})

	t.Run("mode", func(t *testing.T) {
		embed := NewEmbed(testEmbedData, nil)
		require.Equal(t, ModeEmbed, embed.Mode())
	})
}

func TestEmbedCompress(t *testing.T) {
	t.Run("common", func(t *testing.T) {
		opts := EmbedOptions{
			Compress:   true,
			WindowSize: lzss.MaximumWindowSize,
			ChainLen:   lzss.DefaultChainLen,
		}
		embed := NewEmbed(testEmbedData, &opts)

		config, err := embed.Encode()
		require.NoError(t, err)
		require.Less(t, len(config), len(testEmbedData))

		spew.Dump(config)
	})

	t.Run("invalid window size", func(t *testing.T) {
		opts := EmbedOptions{
			Compress:   true,
			WindowSize: 40960,
			ChainLen:   lzss.DefaultChainLen,
		}
		embed := NewEmbed(testEmbedData, &opts)

		config, err := embed.Encode()
		errStr := "failed to compress payload: invalid window size"
		require.EqualError(t, err, errStr)
		require.Nil(t, config)
	})
}

func TestEmbedPreCompressed(t *testing.T) {
	t.Run("common", func(t *testing.T) {
		windowSize := lzss.MaximumWindowSize
		chainLen := lzss.DefaultChainLen
		compressed, err := lzss.Compress(testEmbedData, windowSize, chainLen)
		require.NoError(t, err)

		opts := EmbedOptions{
			PreCompressed: true,
		}
		embed := NewEmbed(compressed, &opts)

		config, err := embed.Encode()
		require.NoError(t, err)
		require.Less(t, len(config), len(testEmbedData))

		spew.Dump(config)
	})

	t.Run("invalid compressed data", func(t *testing.T) {
		invalid := []byte{0x80, 0x00}
		opts := EmbedOptions{
			PreCompressed: true,
		}
		embed := NewEmbed(invalid, &opts)

		config, err := embed.Encode()
		errStr := "invalid precompressed payload: truncated match reference"
		require.EqualError(t, err, errStr)
		require.Nil(t, config)
	})
}
