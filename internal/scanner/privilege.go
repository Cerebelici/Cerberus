package scanner

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/gr0gu/cerberus/internal/platform"
)

// Well-known candidate locations for the Nmap executable across operating systems.
var candidatePaths = map[string][]string{
	"darwin": {
		"/opt/homebrew/bin/nmap",
		"/usr/local/bin/nmap",
		"/opt/local/bin/nmap",
		"/usr/bin/nmap",
	},
	"linux": {
		"/usr/bin/nmap",
		"/usr/local/bin/nmap",
		"/snap/bin/nmap",
	},
	"windows": {
		`C:\Program Files (x86)\Nmap\nmap.exe`,
		`C:\Program Files\Nmap\nmap.exe`,
	},
}

// ResolveNmapBinary inspects the system to discover the Nmap binary.
// It prioritizes explicit custom paths, PATH lookups, and OS-specific standard installation directories.
func ResolveNmapBinary(customPath string) string {
	// 1. Explicit path check
	if customPath != "" {
		if fi, err := os.Stat(customPath); err == nil && !fi.IsDir() {
			return customPath
		}
		if p, err := exec.LookPath(customPath); err == nil {
			return p
		}
	}

	// 2. Standard LookPath in current PATH
	if p, err := exec.LookPath("nmap"); err == nil {
		return p
	}

	// 3. Check relative to current running executable (e.g. bundled app resources)
	if execPath, err := os.Executable(); err == nil {
		execDir := filepath.Dir(execPath)
		relativeCandidates := []string{
			filepath.Join(execDir, "nmap"),
			filepath.Join(execDir, "nmap.exe"),
			filepath.Join(execDir, "nmap", "bin", "nmap"),
			filepath.Join(execDir, "nmap", "nmap.exe"),
			filepath.Join(execDir, "..", "Resources", "nmap", "bin", "nmap"),
			filepath.Join(execDir, "..", "Resources", "bin", "nmap"),
		}
		for _, rel := range relativeCandidates {
			if fi, err := os.Stat(rel); err == nil && !fi.IsDir() {
				return rel
			}
		}
	}

	// 4. Standard OS filesystem paths
	if paths, ok := candidatePaths[runtime.GOOS]; ok {
		for _, p := range paths {
			if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
				return p
			}
		}
	}

	return "nmap"
}

// SetupPrivilegesOrInstall requests OS Administrator/Root privileges via native GUI dialogs
// to configure raw network capabilities or install Nmap if missing.
func SetupPrivilegesOrInstall(ctx context.Context, nmapPath string) error {
	resolved := ResolveNmapBinary(nmapPath)

	switch runtime.GOOS {
	case "linux":
		// On Linux, use pkexec to grant cap_net_raw on the real binary (setcap fails on symlinks)
		if _, err := os.Stat(resolved); err == nil {
			realPath := resolved
			if eval, err := filepath.EvalSymlinks(resolved); err == nil && eval != "" {
				realPath = eval
			}
			cmd := exec.CommandContext(ctx, "pkexec", "setcap", "cap_net_raw,cap_net_admin,cap_net_bind_service+eip", realPath)
			out, err := cmd.CombinedOutput()
			if err != nil {
				return fmt.Errorf("pkexec setcap failed: %w (output: %s)", err, string(out))
			}
			return nil
		}
		// If nmap does not exist, attempt apt-get install via pkexec
		cmd := exec.CommandContext(ctx, "pkexec", "sh", "-c", "apt-get update && apt-get install -y nmap && setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip $(realpath $(which nmap))")
		out, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("pkexec apt-get install nmap failed: %w (output: %s)", err, string(out))
		}
		return nil

	case "darwin":
		// Check if the privileged root helper daemon is already active and reachable
		helper := platform.NewHelperClient()
		if helper.IsHelperAvailable() {
			return nil
		}

		// Progressive enhancement: Attempt certified Touch ID / SMJobBless installation first
		if blessErr := platform.BlessPrivilegedHelper("com.cerberus.helper"); blessErr == nil {
			if helper.IsHelperAvailable() {
				return nil
			}
		}

		// Development fallback: prompt via osascript Administrator dialog
		var script string
		if _, err := os.Stat(resolved); err == nil {
			realPath := resolved
			if eval, err := filepath.EvalSymlinks(resolved); err == nil && eval != "" {
				realPath = eval
			}
			// On macOS, setuid root (chmod 4755) triggers an upstream Nmap bug in libnsock
			// (mksock_bind_addr(): Bind failed: Invalid argument (22)) during TCP version probes,
			// causing all ports to report as tcpwrapped.
			// Ensure standard chmod 0755 and grant /dev/bpf* permissions.
			script = fmt.Sprintf("do shell script \"chmod 0755 '%s' && (chmod o+rw /dev/bpf* 2>/dev/null || true)\" with administrator privileges", realPath)
		} else {
			// Check if bundled nmap-installer pkg is present in Resources
			execPath, _ := os.Executable()
			pkgPath := filepath.Join(filepath.Dir(execPath), "..", "Resources", "nmap-installer.mpkg")
			if fi, err := os.Stat(pkgPath); err == nil && !fi.IsDir() {
				script = fmt.Sprintf("do shell script \"installer -pkg '%s' -target /\" with administrator privileges", pkgPath)
			} else {
				// Fall back to brew install if Homebrew is available
				script = "do shell script \"if command -v brew >/dev/null; then brew install nmap; else true; fi\" with administrator privileges"
			}
		}

		cmd := exec.CommandContext(ctx, "osascript", "-e", script)
		out, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("macOS administrator elevation failed: %w (output: %s)", err, string(out))
		}
		return nil

	case "windows":
		// On Windows, if Nmap setup installer is bundled or present, launch it with elevation
		execPath, _ := os.Executable()
		installerPath := filepath.Join(filepath.Dir(execPath), "nmap-setup.exe")
		if _, err := os.Stat(installerPath); err == nil {
			// Execute powershell Start-Process -Verb runAs
			psCmd := fmt.Sprintf("Start-Process -FilePath '%s' -ArgumentList '/S' -Verb runAs -Wait", installerPath)
			cmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-Command", psCmd)
			out, err := cmd.CombinedOutput()
			if err != nil {
				return fmt.Errorf("windows elevated installation failed: %w (output: %s)", err, string(out))
			}
			return nil
		}
		return fmt.Errorf("Nmap is not installed and nmap-setup.exe was not found in %s", filepath.Dir(execPath))

	default:
		return fmt.Errorf("platform %s not supported for automated privilege elevation", runtime.GOOS)
	}
}

// IsSetuidRoot checks whether the target Nmap binary (following symlinks) has the setuid bit set and is owned by root (UID 0).
func IsSetuidRoot(resolvedNmapPath string) bool {
	if resolvedNmapPath == "" {
		return false
	}
	realPath := resolvedNmapPath
	if eval, err := filepath.EvalSymlinks(resolvedNmapPath); err == nil && eval != "" {
		realPath = eval
	}
	fi, err := os.Stat(realPath)
	if err != nil || fi.IsDir() {
		return false
	}
	if fi.Mode()&os.ModeSetuid == 0 {
		return false
	}

	switch runtime.GOOS {
	case "darwin":
		out, err := exec.Command("stat", "-f", "%u", realPath).Output()
		return err == nil && strings.TrimSpace(string(out)) == "0"
	case "linux":
		out, err := exec.Command("stat", "-c", "%u", realPath).Output()
		return err == nil && strings.TrimSpace(string(out)) == "0"
	default:
		return false
	}
}

// IsPrivilegedScanCapable checks if the current process or Nmap binary has raw-socket network permissions.
func IsPrivilegedScanCapable(resolvedNmapPath string) bool {
	if os.Geteuid() == 0 {
		return true
	}
	if IsSetuidRoot(resolvedNmapPath) {
		return true
	}
	if runtime.GOOS == "darwin" {
		if bpfFi, err := os.Stat("/dev/bpf0"); err == nil && bpfFi.Mode().Perm()&0006 != 0 {
			return true
		}
	}
	if runtime.GOOS == "linux" {
		realPath := resolvedNmapPath
		if eval, err := filepath.EvalSymlinks(resolvedNmapPath); err == nil && eval != "" {
			realPath = eval
		}
		getcapPath, err := exec.LookPath("getcap")
		if err == nil && getcapPath != "" {
			out, err := exec.Command(getcapPath, realPath).CombinedOutput()
			if err == nil && strings.Contains(string(out), "cap_net_raw") {
				return true
			}
		}
	}
	return false
}
