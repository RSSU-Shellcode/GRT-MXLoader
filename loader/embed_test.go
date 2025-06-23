package loader

import (
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"

	"github.com/For-ACGN/LZSS"
	"github.com/davecgh/go-spew/spew"
	"github.com/stretchr/testify/require"
)

func TestEmbed(t *testing.T) {
	payload, err := os.ReadFile("testdata/executable.dat")
	require.NoError(t, err)

	t.Run("common", func(t *testing.T) {
		embed := NewEmbed(payload)

		config, err := embed.Encode()
		require.NoError(t, err)
		require.Greater(t, len(config), len(payload))

		spew.Dump(config)
	})

	t.Run("invalid payload", func(t *testing.T) {
		embed := NewEmbed([]byte{0x00, 0x01})

		config, err := embed.Encode()
		require.EqualError(t, err, "invalid payload: EOF")
		require.Nil(t, config)
	})

	t.Run("mode", func(t *testing.T) {
		embed := NewEmbed(payload)
		require.Equal(t, ModeEmbed, embed.Mode())
	})
}

func TestEmbedCompress(t *testing.T) {
	payload, err := os.ReadFile("testdata/executable.dat")
	require.NoError(t, err)

	t.Run("common", func(t *testing.T) {
		embed := NewEmbedCompress(payload, 4096)

		config, err := embed.Encode()
		require.NoError(t, err)
		require.Less(t, len(config), len(payload))

		spew.Dump(config)
	})

	t.Run("invalid window size", func(t *testing.T) {
		embed := NewEmbedCompress(payload, 40960)

		config, err := embed.Encode()
		errStr := "failed to compress payload: invalid window size"
		require.EqualError(t, err, errStr)
		require.Nil(t, config)
	})
}

func TestEmbedPreCompress(t *testing.T) {
	payload, err := os.ReadFile("testdata/executable.dat")
	require.NoError(t, err)

	t.Run("common", func(t *testing.T) {
		compressed, err := lzss.Compress(payload, 4096)
		require.NoError(t, err)

		embed := NewEmbedPreCompress(compressed)

		config, err := embed.Encode()
		require.NoError(t, err)
		require.Less(t, len(config), len(payload))

		spew.Dump(config)
	})
}

func TestEmbedInstance(t *testing.T) {
	if runtime.GOOS != "windows" {
		return
	}

	wg := sync.WaitGroup{}
	t.Run("x86", func(t *testing.T) {
		if runtime.GOARCH != "386" {
			return
		}

		for _, item := range payloads {
			path := filepath.Join("../test/payload/x86", item.path)
			payload, err := os.ReadFile(path)
			require.NoError(t, err)
			opts := &Options{
				ImageName:    "test.exe",
				CommandLine:  "-p1 123 -p2 \"hello\"",
				WaitMain:     item.wait,
				AllowSkipDLL: true,
			}

			preCompressed, err := lzss.Compress(payload, 2048)
			require.NoError(t, err)
			embed1 := NewEmbed(payload)
			embed2 := NewEmbedCompress(payload, 2048)
			embed3 := NewEmbedPreCompress(preCompressed)

			for _, img := range []Payload{
				embed1, embed2, embed3,
			} {
				wg.Add(1)
				go func(img Payload) {
					defer wg.Done()
					inst, err := CreateInstance(testLDRx86, 32, img, opts)
					require.NoError(t, err)

					addr := loadShellcode(t, inst)
					ret, _, _ := syscallN(addr)
					require.NotEqual(t, uintptr(0), ret)
				}(img)
			}
		}
	})

	t.Run("x64", func(t *testing.T) {
		if runtime.GOARCH != "amd64" {
			return
		}

		for _, item := range payloads {
			path := filepath.Join("../test/payload/x64", item.path)
			payload, err := os.ReadFile(path)
			require.NoError(t, err)
			opts := &Options{
				ImageName:    "test.exe",
				CommandLine:  "-p1 123 -p2 \"hello\"",
				WaitMain:     item.wait,
				AllowSkipDLL: true,
			}

			preCompressed, err := lzss.Compress(payload, 2048)
			require.NoError(t, err)
			embed1 := NewEmbed(payload)
			embed2 := NewEmbedCompress(payload, 2048)
			embed3 := NewEmbedPreCompress(preCompressed)

			for _, img := range []Payload{
				embed1, embed2, embed3,
			} {
				wg.Add(1)
				go func(img Payload) {
					defer wg.Done()
					inst, err := CreateInstance(testLDRx64, 64, img, opts)
					require.NoError(t, err)

					addr := loadShellcode(t, inst)
					ret, _, _ := syscallN(addr)
					require.NotEqual(t, uintptr(0), ret)
				}(img)
			}
		}
	})
	wg.Wait()
}
