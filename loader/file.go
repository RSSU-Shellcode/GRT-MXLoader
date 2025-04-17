package loader

import (
	"bytes"
)

// +-----------+-----------+
// | mode flag | file path |
// +-----------+-----------+
// |   byte    |    var    |
// +-----------+-----------+

const modeFile = 2

// File is the local file mode.
type File struct {
	Path string
}

// NewFile is used to create payload with local file mode.
func NewFile(path string) Payload {
	return &File{Path: path}
}

// Encode implement Payload interface.
func (f *File) Encode() ([]byte, error) {
	buffer := bytes.NewBuffer(make([]byte, 0, 128))
	// write the mode
	buffer.WriteByte(modeFile)
	// write the file path
	buffer.WriteString(stringToUTF16(f.Path))
	return buffer.Bytes(), nil
}

// Mode implement Payload interface.
func (f *File) Mode() string {
	return ModeFile
}
