package grsa

import (
	"testing"
)

var plaintext = []byte(`
this is long text this is long text this is long text
this is long text this is long text this is long text
this is long text this is long text this is long text
this is long text this is long text this is long text
this is long text this is long text this is long text
this is long text this is long text this is long text
this is long text this is long text this is long text
this is long text this is long text this is long text
this is long text this is long text this is long text
this is long text this is long text this is long text
this is long text this is long text this is long text
this is long text this is long text this is long text
this is long text this is long text this is long text
this is long text this is long text this is long text
this is long text this is long text this is long text
`)

func TestEncryptByPrivateKey(t *testing.T) {
	priKey, pubKey, err := GenerateKey(1024, PKCS8)
	if err != nil {
		t.Error(err)
		return
	}
	privateKey, err := ResolvePrivateKey(priKey)
	if err != nil {
		t.Error(err)
		return
	}
	publicKey, err := ResolvePublicKey(pubKey)
	if err != nil {
		t.Error(err)
		return
	}

	// 加密
	ciphertext, err := EncryptByPrivateKey(privateKey, plaintext)
	if err != nil {
		t.Error(err)
		return
	}

	// 解密
	data, err := DecryptByPublicKey(publicKey, ciphertext)
	if string(plaintext) != string(data) {
		if err != nil {
			t.Error("private key encrypt error")
			return
		}
	}
}

func TestEncryptByPublicKey(t *testing.T) {
	priKey, pubKey, err := GenerateKey(1024, PKCS8)
	if err != nil {
		t.Error(err)
		return
	}
	privateKey, err := ResolvePrivateKey(priKey)
	if err != nil {
		t.Error(err)
		return
	}
	publicKey, err := ResolvePublicKey(pubKey)
	if err != nil {
		t.Error(err)
		return
	}

	// 加密
	ciphertext, err := EncryptByPublicKey(publicKey, plaintext)
	if err != nil {
		t.Error(err)
		return
	}

	// 解密
	data, err := DecryptByPrivateKey(privateKey, ciphertext)
	if string(plaintext) != string(data) {
		if err != nil {
			t.Error("private key encrypt error")
			return
		}
	}
}

func BenchmarkEncryptByPrivateKey(b *testing.B) {
	priKey, _, err := GenerateKey(1024, PKCS8)
	if err != nil {
		b.Error(err)
		return
	}
	privateKey, err := ResolvePrivateKey(priKey)
	if err != nil {
		b.Error(err)
		return
	}
	b.ResetTimer()

	// 加密
	for i := 0; i < b.N; i++ {
		_, err = EncryptByPrivateKey(privateKey, plaintext)
		if err != nil {
			b.Error(err)
			return
		}
	}
}

func BenchmarkEncryptByPublicKey(b *testing.B) {
	_, pubKey, err := GenerateKey(1024, PKCS8)
	if err != nil {
		b.Error(err)
		return
	}
	publicKey, err := ResolvePublicKey(pubKey)
	if err != nil {
		b.Error(err)
		return
	}
	b.ResetTimer()

	// 加密
	for i := 0; i < b.N; i++ {
		_, err = EncryptByPublicKey(publicKey, plaintext)
		if err != nil {
			b.Error(err)
			return
		}
	}
}
