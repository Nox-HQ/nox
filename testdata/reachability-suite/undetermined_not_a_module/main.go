package main

import "fmt"

// This directory holds Go source and NO go.mod, so `go list -deps` cannot
// enumerate anything. The linked set is unknown, which is a different statement
// from the linked set being empty — and the difference is the whole of Gate B.
func main() { fmt.Println("no module here") }
