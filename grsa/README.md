# GRSA

## Getting started

**The key features of Gin are:**

- PKCS#1
- PKCS#8
- Support Bits：512、1024、2048、3072、4096
- Support Long Text


### Use GRSA

With [Go module](https://github.com/golang/go/wiki/Modules) support, simply add the following import

```
import "github.com/hugiot/crypto/grsa"
```

to your code, and then `go [build|run|test]` will automatically fetch the necessary dependencies.

Otherwise, run the following Go command to install the `grsa` package:

```sh
$ go get -u github.com/hugiot/crypto/grsa
```

### Generate Key

```go
package main

import (
	"github.com/hugiot/crypto/grsa"
	"log"
)

func main() {
	//privateKey, publicKey, err := grsa.GenerateKey(1024, grsa.PKCS8)
	//privateKeyString, publicKeyString, err := grsa.GenerateKeyToString(1024, grsa.PKCS8)
	if err := grsa.GenerateKeyToFile(1024, grsa.PKCS8, "."); err != nil {
		log.Fatal(err)
	}
}
```

### Get Key

```go
package main

import "github.com/hugiot/crypto/grsa"

func main() {
	//rsaPrivateKey, _ := grsa.ResolvePrivateKeyFromStr("")
	//rsaPublicKey, _ := grsa.ResolvePublicKeyFromFile("")
	rsaPrivateKey, _ := grsa.ResolvePrivateKeyFromFile("./private.key")
	rsaPublicKey, _ := grsa.ResolvePublicKeyFromFile("./Public.key")
}
```

### Encryption

```go
package main

import "github.com/hugiot/crypto/grsa"

func main() {
	// use private key
	privateKey, _ := grsa.ResolvePrivateKeyFromFile(grsa.PrivateKeyFileName)
	ciphertext, _ := grsa.EncryptByPrivateKey(privateKey, []byte("this is content"))
	// use public key
	publicKey, _ := grsa.ResolvePublicKeyFromFile(grsa.PublicKeyFileName)
	ciphertext, _ := grsa.EncryptByPublicKey(publicKey, []byte("this is content"))
}
```

### Decryption

```go
package main

import "github.com/hugiot/crypto/grsa"

func main() {
	// use private key
	privateKey, _ := grsa.ResolvePrivateKeyFromFile(grsa.PrivateKeyFileName)
	plaintext, _ := grsa.DecryptByPrivateKey(privateKey, []byte("xxx"))
	// use public key
	publicKey, _ := grsa.ResolvePublicKeyFromFile(grsa.PublicKeyFileName)
	plaintext, _ := grsa.DecryptByPublicKey(publicKey, []byte("xxx"))
}
```



