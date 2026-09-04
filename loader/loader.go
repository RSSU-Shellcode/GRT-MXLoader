package loader

import (
	"bytes"
	"encoding/binary"
	"errors"
)

// load mode about payload source.
const (
	ModeEmbed = "embed"
	ModeFile  = "file"
	ModeHTTP  = "http"
)

// stub data for locate pe loader and runtime.
const stubPELoaderSize = 0x2026ABCD

// Payload contain various mode for load payload.
type Payload interface {
	// Encode is used to encode payload config to binary.
	Encode() ([]byte, error)

	// Mode is used to get the payload load mode.
	Mode() string
}

// BuildTemplate is used to build template for Pipeline mode.
// When use CreateInstance for Pipeline Node, must set IgnoreInstOpts true.
// peLoader can be empty when use some special boot.
func BuildTemplate(boot, peLoader, runtime []byte) ([]byte, error) {
	template := bytes.Buffer{}
	if len(peLoader) == 0 {
		template.Write(boot)
		template.Write(runtime)
	} else {
		// replace the size stub in the boot
		stub := binary.LittleEndian.AppendUint32(nil, stubPELoaderSize)
		idx := bytes.Index(boot, stub)
		if idx == -1 {
			return nil, errors.New("invalid boot that without size stub")
		}
		binary.LittleEndian.PutUint32(stub, uint32(len(peLoader)))
		boot = bytes.Clone(boot)
		copy(boot[idx:], stub)
		template.Write(boot)
		template.Write(peLoader)
		template.Write(runtime)
	}
	return template.Bytes(), nil
}
