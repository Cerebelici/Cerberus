package scanner

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

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
// It prioritizes explicit custom paths, the portable binary bundled with the app, PATH
// lookups, and OS-specific standard installation directories.
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

	// 2. Portable binary shipped with the desktop app (tools/nmap on Windows/Linux,
	// Resources/bin on macOS). This is the supported zero-prerequisite install.
	if tools, err := platform.ResolveBundledTools(); err == nil && tools != nil && tools.NmapPath != "" {
		if fi, err := os.Stat(tools.NmapPath); err == nil && !fi.IsDir() {
			return tools.NmapPath
		}
	}

	// 3. Standard LookPath in current PATH
	if p, err := exec.LookPath("nmap"); err == nil {
		return p
	}

	// 4. Check relative to current running executable (e.g. bundled app resources)
	if execPath, err := os.Executable(); err == nil {
		execDir := filepath.Dir(execPath)
		relativeCandidates := []string{
			filepath.Join(execDir, "nmap"),
			filepath.Join(execDir, "nmap.exe"),
			filepath.Join(execDir, "nmap", "bin", "nmap"),
			filepath.Join(execDir, "nmap", "nmap.exe"),
			filepath.Join(execDir, "tools", "nmap", "nmap.exe"),
			filepath.Join(execDir, "..", "Resources", "nmap", "bin", "nmap"),
			filepath.Join(execDir, "..", "Resources", "bin", "nmap"),
		}
		for _, rel := range relativeCandidates {
			if fi, err := os.Stat(rel); err == nil && !fi.IsDir() {
				return rel
			}
		}
	}

	// 5. Standard OS filesystem paths
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
		if _, err := os.Stat(resolved); err != nil {
			return fmt.Errorf("nmap was not found at %s: reinstall Cerberus so its bundled scanner is present", resolved)
		}
		if processIsElevated() {
			return nil
		}

		// The only supported elevated path is the SMJobBless-installed root helper. The
		// system authorization dialog that SMJobBless raises is the Touch ID / password
		// prompt. There is deliberately no osascript or setuid fallback.
		helper := platform.NewHelperClient()
		if helper.IsHelperAvailable() {
			return nil
		}

		blessErr := platform.BlessPrivilegedHelper("com.cerberus.helper")
		if blessErr == nil {
			// launchd starts the freshly blessed daemon asynchronously. Wait briefly for its
			// socket so the daemon can re-run preflight in the same launch instead of
			// reporting an unprivileged mode until the next start.
			deadline := time.Now().Add(5 * time.Second)
			for {
				if helper.IsHelperAvailable() {
					return nil
				}
				if time.Now().After(deadline) {
					break
				}
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-time.After(150 * time.Millisecond):
				}
			}
			blessErr = errors.New("SMJobBless reported success but the helper socket is not reachable")
		}
		return fmt.Errorf("privileged helper installation failed: %w\n"+
			"SMJobBless requires a code-signed Cerberus.app and helper (Contents/Library/LaunchServices/com.cerberus.helper). "+
			"Sign the app and helper with the same Developer ID, then relaunch and approve the Touch ID / administrator prompt", blessErr)

	case "windows":
		// The desktop app requests requireAdministrator in its manifest, so a normal
		// launch is already elevated. Npcap is still mandatory for raw/SYN scans; there is
		// no TCP connect-scan fallback.
		if !processIsElevated() {
			return fmt.Errorf("administrator privileges are required: restart Cerberus and accept the Windows UAC prompt (nmap: %s)", resolved)
		}
		if _, err := os.Stat(resolved); err != nil {
			return fmt.Errorf("nmap was not found at %s: reinstall Cerberus so its bundled scanner is present", resolved)
		}
		if !hasNpcap() {
			return fmt.Errorf("Npcap is required for raw packet capture but is not installed; install Npcap and restart Cerberus")
		}
		return nil

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
	if runtime.GOOS == "windows" {
		return processIsElevated() && hasNpcap()
	}
	if processIsElevated() {
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
