package loader

import (
	"path/filepath"
	"runtime"
	"sync"
	"testing"

	"github.com/davecgh/go-spew/spew"
	"github.com/stretchr/testify/require"
)

const testFilePath = "C:\\Windows\\System32\\cmd.exe"

func TestFile(t *testing.T) {
	t.Run("common", func(t *testing.T) {
		payload := NewFile(testFilePath)

		config, err := payload.Encode()
		require.NoError(t, err)

		spew.Dump(config)
	})

	t.Run("mode", func(t *testing.T) {
		payload := NewFile(testFilePath)
		require.Equal(t, ModeFile, payload.Mode())
	})
}

func TestFileInstance(t *testing.T) {
	if runtime.GOOS != "windows" {
		return
	}

	wg := sync.WaitGroup{}
	t.Run("x86", func(t *testing.T) {
		if runtime.GOARCH != "386" {
			return
		}

		for _, item := range payloads {
			path, err := filepath.Abs(filepath.Join("../test/payload/x86", item.path))
			require.NoError(t, err)
			payload := NewFile(path)
			opts := &Options{
				ImageName:    "test.exe",
				CommandLine:  "-p1 123 -p2 \"hello\"",
				WaitMain:     item.wait,
				AllowSkipDLL: true,
			}

			wg.Add(1)
			go func() {
				defer wg.Done()
				inst, err := CreateInstance(testLDRx86, 32, payload, opts)
				require.NoError(t, err)

				addr := loadShellcode(t, inst)
				ret, _, _ := syscallN(addr)
				require.NotEqual(t, uintptr(0), ret)
			}()
		}
	})

	t.Run("x64", func(t *testing.T) {
		if runtime.GOARCH != "amd64" {
			return
		}

		for _, item := range payloads {
			path, err := filepath.Abs(filepath.Join("../test/payload/x64", item.path))
			require.NoError(t, err)
			payload := NewFile(path)
			opts := &Options{
				ImageName:    "test.exe",
				CommandLine:  "-p1 123 -p2 \"hello\"",
				WaitMain:     item.wait,
				AllowSkipDLL: true,
			}

			wg.Add(1)
			go func() {
				defer wg.Done()
				inst, err := CreateInstance(testLDRx64, 64, payload, opts)
				require.NoError(t, err)

				addr := loadShellcode(t, inst)
				ret, _, _ := syscallN(addr)
				require.NotEqual(t, uintptr(0), ret)
			}()
		}
	})
	wg.Wait()
}
