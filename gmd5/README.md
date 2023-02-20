# GMD5

## Getting started

### Use GMD5

With [Go module](https://github.com/golang/go/wiki/Modules) support, simply add the following import

```
import "github.com/hugiot/crypto/gmd5"
```

to your code, and then `go [build|run|test]` will automatically fetch the necessary dependencies.

Otherwise, run the following Go command to install the `gmd5` package:

```sh
$ go get -u github.com/hugiot/crypto/gmd5
```

#### Demo

```go
package main

import (
	"github.com/hugiot/crypto/gmd5"
)

func main() {
	s := gmd5.Sum([]byte("this is content")) // b7fcef7fe745f2a95560ff5f550e3b8f
}
```



