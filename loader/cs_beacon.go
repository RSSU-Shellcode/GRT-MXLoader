package loader

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// ExtractBeaconStage is used to extract stage from Cobalt-Strike stageless beacon.
func ExtractBeaconStage(image []byte) ([]byte, error) {
	beaconPE, err := pe.NewFile(bytes.NewReader(image))
	if err != nil {
		return nil, fmt.Errorf("invalid PE image data: %s", err)
	}
	section := beaconPE.Section(".data")
	if section == nil {
		return nil, errors.New("failed to get data section that contains beacon stage")
	}
	data, err := io.ReadAll(section.Open())
	if err != nil {
		return nil, fmt.Errorf("failed to read data section: %s", err)
	}
	if len(data) < 64 {
		return nil, errors.New("invalid data section")
	}
	size := binary.LittleEndian.Uint32(data[4:])
	if size < 64*1024 || size > 4*1024*1024 {
		return nil, errors.New("invalid beacon stage image size")
	}
	cipherData := data[16 : 16+size]
	key := data[8 : 8+4]
	plainData := xor(cipherData, key)
	dll, err := pe.NewFile(bytes.NewReader(plainData))
	if err != nil {
		return nil, fmt.Errorf("invalid decrypted PE image: %s", err)
	}
	if (dll.Characteristics & pe.IMAGE_FILE_DLL) == 0 {
		return nil, errors.New("invalid beacon stage image")
	}
	return plainData, nil
}

func xor(cipherData, key []byte) []byte {
	plainData := make([]byte, len(cipherData))
	var keyIdx int
	for i := 0; i < len(cipherData); i++ {
		plainData[i] = cipherData[i] ^ key[keyIdx]
		keyIdx++
		if keyIdx >= len(key) {
			keyIdx = 0
		}
	}
	return plainData
}
