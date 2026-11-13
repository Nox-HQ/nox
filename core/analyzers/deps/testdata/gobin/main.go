// Command gobin is a fixture: a real Go executable with a known dependency,
// built by the tests so its embedded build info does not depend on how the
// test binary itself was built (coverage builds record no modules).
package main

import "golang.org/x/sync/errgroup"

func main() {
	var g errgroup.Group
	_ = g.Wait()
}
