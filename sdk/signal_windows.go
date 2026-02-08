//go:build windows

package sdk

import "os"

func shutdownSignals() []os.Signal {
	return []os.Signal{os.Interrupt}
}
