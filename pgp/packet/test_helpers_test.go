package packet

import (
	"bytes"
	"encoding/hex"
	"io"
)

// readerFromHex returns an io.Reader that decodes a hex string.
func readerFromHex(s string) io.Reader {
	data, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return bytes.NewReader(data)
}
