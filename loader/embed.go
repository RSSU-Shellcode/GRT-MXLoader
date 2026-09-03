package loader

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/For-ACGN/LZSS"
)

// enable compression
// +-----------+----------+----------+-----------------+---------+
// | mode flag | compress | raw size | compressed size | payload |
// +-----------+----------+----------+-----------------+---------+
// |   byte    |   bool   |  uint32  |     uint32      |   var   |
// +-----------+----------+----------+-----------------+---------+

// disable compression
// +-----------+----------+--------+---------+
// | mode flag | compress |  size  | payload |
// +-----------+----------+--------+---------+
// |   byte    |   bool   | uint32 |   var   |
// +-----------+----------+--------+---------+

const modeEmbed = 1

const (
	enableCompression  = 1
	disableCompression = 0
)

// Embed is the embed mode.
type Embed struct {
	payload []byte
	opts    EmbedOptions
}

// EmbedOptions contains Embed mode options.
type EmbedOptions struct {
	Compress      bool `toml:"compress"       json:"compress"`
	WindowSize    int  `toml:"window_size"    json:"window_size"`
	ChainLen      int  `toml:"chain_len"      json:"chain_len"`
	PreCompressed bool `toml:"pre_compressed" json:"pre_compressed"`
}

// NewEmbed is used to create payload with embed mode.
func NewEmbed(payload []byte, opts *EmbedOptions) Payload {
	if opts == nil {
		opts = new(EmbedOptions)
	}
	return &Embed{payload: payload, opts: *opts}
}

// Encode implement Payload interface.
func (e *Embed) Encode() ([]byte, error) {
	// get raw payload size
	var err error
	payload := e.payload
	if e.opts.PreCompressed {
		payload, err = lzss.Decompress(payload)
		if err != nil {
			return nil, fmt.Errorf("invalid precompressed payload: %s", err)
		}
	}
	buffer := bytes.NewBuffer(make([]byte, 0, 16*1024))
	// write the mode
	buffer.WriteByte(modeEmbed)
	// disable compression
	if !e.opts.Compress && !e.opts.PreCompressed {
		size := binary.LittleEndian.AppendUint32(nil, uint32(len(e.payload))) // #nosec
		buffer.WriteByte(disableCompression)
		buffer.Write(size)
		buffer.Write(e.payload)
		return buffer.Bytes(), nil
	}
	// set the compressed flag
	buffer.WriteByte(enableCompression)
	// compress payload
	var compressed []byte
	if e.opts.PreCompressed {
		compressed = e.payload
	} else {
		compressed, err = lzss.Compress(e.payload, e.opts.WindowSize, e.opts.ChainLen)
		if err != nil {
			return nil, fmt.Errorf("failed to compress payload: %s", err)
		}
	}
	// write raw size
	size := binary.LittleEndian.AppendUint32(nil, uint32(len(payload))) // #nosec
	buffer.Write(size)
	// write compressed size
	size = binary.LittleEndian.AppendUint32(nil, uint32(len(compressed))) // #nosec
	buffer.Write(size)
	// write compressed payload
	buffer.Write(compressed)
	return buffer.Bytes(), nil
}

// Mode implement Payload interface.
func (e *Embed) Mode() string {
	return ModeEmbed
}
