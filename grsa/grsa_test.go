package grsa

import (
	"path/filepath"
	"testing"
)

var plaintext string = "this is content"

func TestGenerateKeyToFile(t *testing.T) {
	err := GenerateKeyToFile(1024, PKCS8, ".")
	if err != nil {
		t.Error(err)
	}
}

func TestEncryptByPrivateKey(t *testing.T) {
	privateKey, err := GetPrivateKeyFromFile(filepath.Join(".", PrivateKeyFileName))
	if err != nil {
		t.Error(err)
		return
	}

	ciphertext, err := EncryptByPrivateKey(privateKey, []byte(plaintext))
	if err != nil {
		t.Error(err)
		return
	}

	publicKey, err := GetPublicKeyFromFile(filepath.Join(".", PublicKeyFileName))
	if err != nil {
		t.Error(err)
		return
	}

	data, err := DecryptByPublicKey(publicKey, ciphertext)
	if err != nil {
		t.Error(err)
		return
	}

	if plaintext != string(data) {
		t.Error("encrypt by private key is error")
	}
}

func TestEncryptByPublicKey(t *testing.T) {
	publicKey, err := GetPublicKeyFromFile(filepath.Join(".", PublicKeyFileName))
	if err != nil {
		t.Error(err)
		return
	}

	ciphertext, err := EncryptByPublicKey(publicKey, []byte(plaintext))
	if err != nil {
		t.Error(err)
		return
	}

	privateKey, err := GetPrivateKeyFromFile(filepath.Join(".", PrivateKeyFileName))
	if err != nil {
		t.Error(err)
		return
	}

	data, err := DecryptByPrivateKey(privateKey, ciphertext)
	if err != nil {
		t.Error(err)
		return
	}

	if plaintext != string(data) {
		t.Error("encrypt by public key is error")
	}
}
