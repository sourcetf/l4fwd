//go:build windows

package cli

import (
	"os/exec"
	"syscall"
)

// newCommand builds a detached, windowless exec.Cmd for the restart path.
func newCommand(exe string, args ...string) *exec.Cmd {
	cmd := exec.Command(exe, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: 0x00000008 | 0x08000000, // DETACHED_PROCESS | CREATE_NO_WINDOW
	}
	return cmd
}
