package mattervault

import (
	"encoding/binary"
	"encoding/hex"
	"strings"
)

func toHex(b []byte) string { return "0x" + hex.EncodeToString(b) }

func fromHex(s string) ([]byte, error) {
	return hex.DecodeString(strings.TrimPrefix(s, "0x"))
}

// secretIDBytes renders a secret id as 16 big-endian bytes (the signing-payload form).
func secretIDBytes(id uint64) [16]byte {
	var b [16]byte
	binary.BigEndian.PutUint64(b[8:], id)
	return b
}

func secretIDHex(id uint64) string {
	b := secretIDBytes(id)
	return toHex(b[:])
}
