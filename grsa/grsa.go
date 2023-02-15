package grsa

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
)

type KeyFormat uint8 // 密钥格式
type KeyBits int     // 密钥位数

const (
	PKCS1 KeyFormat = iota // PKCS#1
	PKCS8                  // PKCS#8
)

const (
	Bits512  KeyBits = 512
	Bits1024 KeyBits = 1024
	Bits2048 KeyBits = 2048
	Bits3072 KeyBits = 3072
	Bits4096 KeyBits = 4096
)

var KeyFormatErr = errors.New("the key format must be PKCS#1 or PKCS#2")

// GenerateKey 生成公钥、私钥
func GenerateKey(bits KeyBits, format KeyFormat) (privateKey []byte, publicKey []byte, err error) {
	// private key
	priKey, err := rsa.GenerateKey(rand.Reader, int(bits))
	if err != nil {
		return
	}
	// format
	switch format {
	case PKCS1:
		privateKey = x509.MarshalPKCS1PrivateKey(priKey)
	case PKCS8:
		privateKey, err = x509.MarshalPKCS8PrivateKey(priKey)
		if err != nil {
			return
		}
	default:
		return nil, nil, KeyFormatErr
	}
	// public key
	pubKey := priKey.Public()
	publicKey, err = x509.MarshalPKIXPublicKey(pubKey)
	return
}

func GenerateStringKey(bits KeyBits, format KeyFormat) (privateKey string, publicKey string, err error) {
	priKey, pubKey, err := GenerateKey(bits, format)
	if err != nil {
		return
	}

	buf := bytes.NewBuffer([]byte(""))

	priBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: priKey,
	}
	err = pem.Encode(buf, priBlock)
	if err != nil {
		return
	}
	privateKey = buf.String()

	buf.Reset()
	pubBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKey,
	}
	err = pem.Encode(buf, pubBlock)
	if err != nil {
		return
	}
	publicKey = buf.String()

	return
}

// PublicKeyEncrypt 公钥加密
func PublicKeyEncrypt() {

}

// PrivateKeyEncrypt 私钥加密
func PrivateKeyEncrypt() {

}

// PrivateKeyDecrypt 私钥解密
func PrivateKeyDecrypt() {

}

// PublicKeyDecrypt 公钥解密
func PublicKeyDecrypt() {

}
