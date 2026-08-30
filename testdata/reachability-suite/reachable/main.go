package main

import (
	"crypto/md5"
	"fmt"
)

// The advisory for this case names crypto/md5. This build links it, so
// reachability is determined AND positive.
func main() { fmt.Printf("%x\n", md5.Sum([]byte("x"))) }
