package mattervault

import (
	"encoding/hex"
	"strings"
)

func toHex(b []byte) string { return "0x" + hex.EncodeToString(b) }

func fromHex(s string) ([]byte, error) {
	return hex.DecodeString(strings.TrimPrefix(s, "0x"))
}
