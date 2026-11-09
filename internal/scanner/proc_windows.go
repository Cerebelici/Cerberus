//go:build windows

package scanner

import (
	"os/exec"
	"syscall"
)

const (
	// CREATE_NO_WINDOW is a Windows process creation flag (0x08000000) that prevents
	// the system from creating a new console window for the child process.
	createNoWindow = 0x08000000
)

// configureProcessGroup configures Windows process creation flags to ensure external tools
// (such as Nmap and RustScan) run completely silently in the background without spawning
// visible command-prompt/console windows.
func configureProcessGroup(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.HideWindow = true
	cmd.SysProcAttr.CreationFlags |= createNoWindow
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		return cmd.Process.Kill()
	}
}
