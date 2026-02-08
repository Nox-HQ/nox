//go:build windows

package plugin

import "os"

func sigterm() os.Signal {
	return os.Kill
}
