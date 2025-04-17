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
	disableCompress = 0
	enableCompress  = 1
)

// Embed is the embed mode.
type Embed struct {
	payload []byte

	compress   bool
	windowSize int

	preCompress bool
}

// NewEmbed is used to create payload with embed mode.
func NewEmbed(payload []byte) Payload {
	return &Embed{payload: payload}
}

// NewEmbedCompress is used to create embed with compression.
func NewEmbedCompress(payload []byte, windowSize int) Payload {
	return &Embed{
		payload:    payload,
		compress:   true,
		windowSize: windowSize,
	}
}

// NewEmbedPreCompress is used to create embed with pre-compression.
func NewEmbedPreCompress(payload []byte) Payload {
	return &Embed{
		payload:     payload,
		compress:    true,
		preCompress: true,
	}
}

// Encode implement Payload interface.
func (e *Embed) Encode() ([]byte, error) {
	buffer := bytes.NewBuffer(make([]byte, 0, 16*1024))
	// write the mode
	buffer.WriteByte(modeEmbed)
	// need use compress mode
	if !e.compress {
		size := binary.LittleEndian.AppendUint32(nil, uint32(len(e.payload))) // #nosec
		buffer.WriteByte(disableCompress)
		buffer.Write(size)
		buffer.Write(e.payload)
		return buffer.Bytes(), nil
	}
	// set the compressed flag
	buffer.WriteByte(enableCompress)
	// compress payload
	var compressed []byte
	if !e.preCompress {
		output, err := lzss.Compress(e.payload, e.windowSize)
		if err != nil {
			return nil, fmt.Errorf("failed to compress payload: %s", err)
		}
		compressed = output
	} else {
		compressed = e.payload
	}
	// write payload raw size
	payload := e.payload
	if e.preCompress {
		payload = lzss.Decompress(payload)
	}
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
