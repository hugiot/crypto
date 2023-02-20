package gmd5

import (
	"crypto/md5"
	"encoding/hex"
)

// Sum returns a hexadecimal lowercase string
func Sum(data []byte) string {
	hash := md5.New()
	hash.Write(data)
	b := hash.Sum(nil)
	return hex.EncodeToString(b)
}
