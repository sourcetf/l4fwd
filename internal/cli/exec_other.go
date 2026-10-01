//go:build !windows

package cli

import (
	"os/exec"
)

// newCommand builds an exec.Cmd used by the restart path off Windows.
func newCommand(exe string, args ...string) *exec.Cmd {
	return exec.Command(exe, args...)
}
