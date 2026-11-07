// Command gobin is a fixture: a Go executable that links a module, so its
// build info names one. core/image tests build it and put it in an image
// layer.
package main

import (
	"fmt"

	"gopkg.in/yaml.v3"
)

func main() {
	out, _ := yaml.Marshal(map[string]string{"fixture": "gobin"})
	fmt.Print(string(out))
}
