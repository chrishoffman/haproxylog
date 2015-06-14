# haproxylog [![Build Status](https://travis-ci.org/chrishoffman/haproxylog.png)](https://travis-ci.org/chrishoffman/haproxylog)

haproxylog is a go library that parses [haproxy](http://www.haproxy.org/) log messages.

## Installation

Standard `go get`:

```
$ go get github.com/chrishoffman/haproxylog
```

## Usage

```go
package main

import (
	"fmt"

	"github.com/chrishoffman/haproxy"
)

func main() {
	const rawLog = `192.168.9.185:56276 [29/May/2015:10:36:47.766] Service1 Service1/host-1 2/0/0 423 -- 282/36/0/0/0 0/0`

	log, err := haproxy.NewLog(rawLog)
	if err != nil {
		panic(err)
	}

	fmt.Println("Frontend Name: ", log.FrontendName)
	fmt.Println("Backend Name: ", log.BackendName)
	fmt.Println("Stat Tt: ", log.Tt)
}
```

See [GoDoc](http://godoc.org/github.com/chrishoffman/haproxylog) for complete documentation.
