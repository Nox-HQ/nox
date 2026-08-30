package main

import (
	"crypto/sha256"
	"fmt"
)

// The advisory for this case names crypto/md5. This build links sha256 and not
// md5, so reachability is determined AND negative — the only state in the whole
// suite that may justify suppressing a finding.
func main() { fmt.Printf("%x\n", sha256.Sum256([]byte("x"))) }
