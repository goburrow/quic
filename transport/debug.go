// +build debug

package transport

import "log"

// Use `go build -tags debug` to enable debugging in transport layer.
// This is to avoid heap escaping https://github.com/golang/go/issues/8618
var debug = log.Printf
