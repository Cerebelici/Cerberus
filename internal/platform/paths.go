package platform

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

// ToolPaths holds the resolved paths for bundled or system scanning binaries.
type ToolPaths struct {
	RustScanPath string
	NmapPath     string
	NmapDir      string // Value for NMAPDIR environment variable
}

// ResolveBundledTools locates bundled RustScan and Nmap binaries and data files,
// falling back to system PATH if bundled versions are not present.
func ResolveBundledTools() (*ToolPaths, error) {
	execPath, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("unable to determine executable path: %w", err)
	}
	execDir := filepath.Dir(execPath)

	paths := &ToolPaths{}

	switch runtime.GOOS {
	case "darwin":
		// Inside macOS App Bundle: /Applications/Cerberus.app/Contents/MacOS/cerberus
		// Target: /Applications/Cerberus.app/Contents/Resources/bin/
		bundleResources := filepath.Join(filepath.Dir(execDir), "Resources", "bin")
		paths.RustScanPath = filepath.Join(bundleResources, "rustscan")

		nestedNmap := filepath.Join(bundleResources, "nmap", "nmap")
		flatNmap := filepath.Join(bundleResources, "nmap")
		if fi, err := os.Stat(nestedNmap); err == nil && !fi.IsDir() {
			paths.NmapPath = nestedNmap
			paths.NmapDir = filepath.Join(bundleResources, "nmap")
		} else if fi, err := os.Stat(flatNmap); err == nil && !fi.IsDir() {
			paths.NmapPath = flatNmap
			paths.NmapDir = bundleResources
		} else {
			paths.NmapPath = nestedNmap
			paths.NmapDir = filepath.Join(bundleResources, "nmap")
		}

	case "windows":
		// Inside Windows Install Dir: C:\Program Files\Cerberus\cerberus.exe
		// Target: C:\Program Files\Cerberus\tools\
		toolsDir := filepath.Join(execDir, "tools")
		paths.RustScanPath = filepath.Join(toolsDir, "rustscan.exe")
		paths.NmapPath = filepath.Join(toolsDir, "nmap", "nmap.exe")
		paths.NmapDir = filepath.Join(toolsDir, "nmap")

	case "linux":
		// Target: relative tools/ or /opt/cerberus/bin
		toolsDir := filepath.Join(execDir, "tools")
		if fi, err := os.Stat(toolsDir); err != nil || !fi.IsDir() {
			toolsDir = "/opt/cerberus/bin"
		}
		paths.RustScanPath = filepath.Join(toolsDir, "rustscan")
		nestedNmap := filepath.Join(toolsDir, "nmap", "nmap")
		flatNmap := filepath.Join(toolsDir, "nmap")
		if fi, err := os.Stat(nestedNmap); err == nil && !fi.IsDir() {
			paths.NmapPath = nestedNmap
			paths.NmapDir = filepath.Join(toolsDir, "nmap")
		} else {
			paths.NmapPath = flatNmap
			paths.NmapDir = filepath.Join(toolsDir, "nmap")
		}
	}

	// Developer / System Fallback: If bundled binaries are missing or not executable, check system PATH
	if fi, err := os.Stat(paths.RustScanPath); err != nil || fi.IsDir() {
		if sysPath, err := exec.LookPath("rustscan"); err == nil {
			paths.RustScanPath = sysPath
		}
	}
	if fi, err := os.Stat(paths.NmapPath); err != nil || fi.IsDir() {
		if sysPath, err := exec.LookPath("nmap"); err == nil {
			paths.NmapPath = sysPath
			paths.NmapDir = "" // Use system default NMAPDIR
		}
	}

	return paths, nil
}
