//go:build !windows

package plugin

import (
	"os"
	"syscall"
)

func sigterm() os.Signal {
	return syscall.SIGTERM
}
