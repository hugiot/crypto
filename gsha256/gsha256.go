package gsha256

import (
	"crypto/sha256"
	"encoding/hex"
)

// Sum returns a hexadecimal lowercase string
func Sum(data []byte) string {
	hash := sha256.New()
	hash.Write(data)
	b := hash.Sum(nil)
	return hex.EncodeToString(b)
}
