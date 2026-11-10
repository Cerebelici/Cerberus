//go:build !windows

package scanner

import "os"

// processIsElevated reports whether the current process has root privileges.
func processIsElevated() bool {
	return os.Geteuid() == 0
}

// hasNpcap is only meaningful on Windows; other platforms use their native capture stack.
func hasNpcap() bool {
	return false
}
