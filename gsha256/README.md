# GSHA256

## Getting started

### Use GSHA256

With [Go module](https://github.com/golang/go/wiki/Modules) support, simply add the following import

```
import "github.com/hugiot/crypto/gsha256"
```

to your code, and then `go [build|run|test]` will automatically fetch the necessary dependencies.

Otherwise, run the following Go command to install the `gsha256` package:

```sh
$ go get -u github.com/hugiot/crypto/gsha256
```

#### Demo

```go
package main

import (
	"github.com/hugiot/crypto/gsha256"
)

func main() {
	s := gsha256.Sum([]byte("this is content")) // 630a118958070c95a69efbcfb8a212a84167173a3bf6e8a334b0d45504b00bf5
}
```



