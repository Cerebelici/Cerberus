//go:build !linux && !darwin && !windows

package scanner

import "os/exec"

func configureProcessGroup(cmd *exec.Cmd) {
	// No-op stub on other non-Unix, non-Windows platforms
}
