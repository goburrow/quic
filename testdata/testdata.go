package testdata

import (
	"bytes"
	"encoding/hex"
)

func removeSpaces(b []byte) []byte {
	for i := 0; i < len(b); {
		idx := bytes.IndexAny(b[i:], "\r\n\t ")
		if idx < 0 {
			break
		}
		i += idx
		copy(b[i:], b[i+1:])
		b = b[:len(b)-1]
	}
	return b
}

func DecodeHex(str string) []byte {
	data := removeSpaces([]byte(str))
	n, err := hex.Decode(data, data)
	if err != nil {
		panic(err)
	}
	return data[:n]
}
