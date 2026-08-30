package main

import (
	"crypto/sha256"
	"fmt"
)

// The advisory for this case names NO import paths — most ecosystems' advisories
// do not. Nothing can be concluded about which package is affected, so
// reachability is undetermined however completely the build was enumerated.
func main() { fmt.Printf("%x\n", sha256.Sum256([]byte("x"))) }
