package testdata

import (
	"os"
	"os/exec"
)

func runUserCommand() {
	cmd := os.Getenv("USER_CMD")
	exec.Command("sh", "-c", cmd)
}
