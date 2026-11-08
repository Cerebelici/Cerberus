package platform

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

// Search paths by operating system for external scanning tools.
var toolSearchPaths = map[string][]string{
	"darwin": {
		"/opt/homebrew/bin",
		"/usr/local/bin",
		"/opt/local/bin",
		"/usr/bin",
		"/bin",
		"/usr/sbin",
	},
	"linux": {
		"/usr/bin",
		"/usr/local/bin",
		"/snap/bin",
		"/bin",
		"/usr/sbin",
		"/sbin",
	},
	"windows": {
		`C:\Program Files (x86)\Nmap`,
		`C:\Program Files\Nmap`,
		`C:\Program Files\RustScan`,
		`C:\ProgramData\chocolatey\bin`,
		`C:\Users\admin\scoop\shims`,
	},
}

// ResolveBinaryPath locates the named executable across PATH, common OS candidate directories,
// and adjacent to the current application bundle.
func ResolveBinaryPath(name string) string {
	if name == "" {
		return ""
	}

	// 1. Direct path exists check
	if fi, err := os.Stat(name); err == nil && !fi.IsDir() {
		return name
	}

	// 2. PATH resolution via exec.LookPath
	if path, err := exec.LookPath(name); err == nil {
		return path
	}

	// 3. Executable-relative paths (e.g. bundled resources)
	if execPath, err := os.Executable(); err == nil {
		execDir := filepath.Dir(execPath)
		candidates := []string{
			filepath.Join(execDir, name),
			filepath.Join(execDir, "bin", name),
			filepath.Join(execDir, "..", "Resources", "bin", name),
			filepath.Join(execDir, "..", "Resources", name),
		}
		if runtime.GOOS == "windows" {
			candidates = append(candidates,
				filepath.Join(execDir, name+".exe"),
				filepath.Join(execDir, "bin", name+".exe"),
			)
		}
		for _, cand := range candidates {
			if fi, err := os.Stat(cand); err == nil && !fi.IsDir() {
				return cand
			}
		}
	}

	// 4. OS standard candidate directories
	if paths, ok := toolSearchPaths[runtime.GOOS]; ok {
		binName := name
		for _, dir := range paths {
			cand := filepath.Join(dir, binName)
			if fi, err := os.Stat(cand); err == nil && !fi.IsDir() {
				return cand
			}
			if runtime.GOOS == "windows" {
				candExe := filepath.Join(dir, binName+".exe")
				if fi, err := os.Stat(candExe); err == nil && !fi.IsDir() {
					return candExe
				}
			}
		}
	}

	return name
}

// ResolveNmap returns the best path for nmap.
func ResolveNmap() string {
	return ResolveBinaryPath("nmap")
}

// ResolveRustScan returns the best path for rustscan, or empty string if not found.
func ResolveRustScan() string {
	p := ResolveBinaryPath("rustscan")
	if p == "rustscan" {
		if _, err := exec.LookPath("rustscan"); err != nil {
			return ""
		}
	}
	return p
}
