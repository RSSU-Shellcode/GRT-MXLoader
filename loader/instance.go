package loader

import (
	"encoding/binary"
	"fmt"
	"strings"
	"unicode/utf16"

	"github.com/RSSU-Shellcode/GRT-Develop/argument"
	"github.com/RSSU-Shellcode/GRT-Develop/option"
)

// load mode about payload source.
const (
	ModeEmbed = "embed"
	ModeFile  = "file"
	ModeHTTP  = "http"
)

// Payload contain various load mode.
type Payload interface {
	// Encode is used to encode payload config to binary.
	Encode() ([]byte, error)

	// Mode is used to get the payload load mode.
	Mode() string
}

// Options contains options about create instance.
type Options struct {
	// set the custom image name about the command line prefix.
	ImageName string

	// set the command line argument about the image.
	CommandLine string

	// wait main thread exit, if it is an exe image.
	WaitMain bool

	// if failed to load library, can continue it.
	AllowSkipDLL bool

	// set standard handles for hook GetStdHandle,
	// if them are NULL, call original GetStdHandle.
	StdInput  uint64
	StdOutput uint64
	StdError  uint64

	// set Gleam-RT options, usually keep the default value.
	Runtime option.Options
}

// CreateInstance is used to create instance from loader template.
func CreateInstance(tpl []byte, arch int, payload Payload, opts *Options) ([]byte, error) {
	if opts == nil {
		opts = new(Options)
	}
	// encode payload configuration
	config, err := payload.Encode()
	if err != nil {
		return nil, fmt.Errorf("invalid %s mode config: %s", payload.Mode(), err)
	}
	// process command line
	var (
		cmdLineA []byte
		cmdLineW []byte
	)
	cmdLine := opts.CommandLine
	if cmdLine != "" {
		imageName := opts.ImageName
		if imageName == "" {
			imageName = "GRT-PELoader.exe"
		}
		if strings.Contains(imageName, " ") {
			imageName = "\"" + imageName + "\""
		}
		imageName += " "
		cmdLine = imageName + cmdLine
		cmdLineA = []byte(cmdLine + "\x00")
		cmdLineW = []byte(stringToUTF16(cmdLine))
	}
	// process WaitMain
	waitMain := make([]byte, 1)
	if opts.WaitMain {
		waitMain[0] = 1
	}
	// process AllowSkipDLL
	allowSkipDLL := make([]byte, 1)
	if opts.AllowSkipDLL {
		allowSkipDLL[0] = 1
	}
	// process standard handle
	stdInput := binary.LittleEndian.AppendUint64(nil, opts.StdInput)
	stdOutput := binary.LittleEndian.AppendUint64(nil, opts.StdOutput)
	stdError := binary.LittleEndian.AppendUint64(nil, opts.StdError)
	switch arch {
	case 32:
		stdInput = stdInput[:4]
		stdOutput = stdOutput[:4]
		stdError = stdError[:4]
	case 64:
	default:
		return nil, fmt.Errorf("invalid architecture: %d", arch)
	}
	tpl, err = option.Set(tpl, &opts.Runtime)
	if err != nil {
		return nil, fmt.Errorf("failed to set runtime option: %s", err)
	}
	args := []*argument.Arg{
		{ID: 1, Data: config},
		{ID: 2, Data: cmdLineA},
		{ID: 3, Data: cmdLineW},
		{ID: 4, Data: waitMain},
		{ID: 5, Data: allowSkipDLL},
		{ID: 6, Data: stdInput},
		{ID: 7, Data: stdOutput},
		{ID: 8, Data: stdError},
	}
	stub, err := argument.Encode(args...)
	if err != nil {
		return nil, fmt.Errorf("failed to encode argument: %s", err)
	}
	return append(tpl, stub...), nil
}

func stringToUTF16(s string) string {
	w := utf16.Encode([]rune(s))
	output := make([]byte, len(w)*2+2)
	for i := 0; i < len(w); i++ {
		binary.LittleEndian.PutUint16(output[i*2:], w[i])
	}
	return string(output)
}
