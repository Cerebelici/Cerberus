//go:build windows

package scanner

import (
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

// processIsElevated reports whether the current Windows process runs with an elevated
// administrator token. os.Geteuid() always returns -1 on Windows, so it cannot be used here.
func processIsElevated() bool {
	// The desktop app requests requireAdministrator in its manifest, so a normal launch is
	// elevated. Development builds may not be.
	return windows.GetCurrentProcessToken().IsElevated()
}

// hasNpcap reports whether the Npcap packet capture driver is installed. Nmap on Windows
// needs it for the raw/SYN scans this application requires; there is no connect-scan
// fallback.
func hasNpcap() bool {
	root := os.Getenv("SystemRoot")
	if root == "" {
		root = `C:\Windows`
	}
	candidates := []string{
		filepath.Join(root, "System32", "Npcap", "wpcap.dll"),
		filepath.Join(root, "System32", "wpcap.dll"),
		filepath.Join(root, "SysWOW64", "Npcap", "wpcap.dll"),
		filepath.Join(root, "SysWOW64", "wpcap.dll"),
	}
	for _, path := range candidates {
		if fi, err := os.Stat(path); err == nil && !fi.IsDir() {
			return true
		}
	}
	return false
}
