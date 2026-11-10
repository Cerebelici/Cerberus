package scanner

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"sync"

	"github.com/gr0gu/cerberus/internal/config"
	"github.com/gr0gu/cerberus/internal/model"
	"github.com/gr0gu/cerberus/internal/platform"
)

// ErrPrivilegedRequired is returned when a scan is requested without the raw-socket
// privileges the application mandates. There is no unprivileged connect-scan fallback.
var ErrPrivilegedRequired = errors.New("privileged execution is required: grant administrator/root access (macOS: approve the privileged helper with Touch ID; Windows: accept UAC and install Npcap)")

// CommandRunner defines an interface for running external shell commands (enabling mocking).
type CommandRunner interface {
	Run(ctx context.Context, name string, args ...string) ([]byte, error)
}

// DefaultCommandRunner executes commands via os/exec.
type DefaultCommandRunner struct{}

// Run executes the command with context and returns stdout.
func (r *DefaultCommandRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	helper := platform.NewHelperClient()
	if helper.IsHelperAvailable() {
		return helper.ExecutePrivileged(ctx, name, args...)
	}

	cmd := exec.CommandContext(ctx, name, args...)
	configureProcessGroup(cmd)
	if tools, err := platform.ResolveBundledTools(); err == nil && tools != nil && tools.NmapDir != "" {
		if strings.Contains(strings.ToLower(name), "nmap") {
			cmd.Env = append(os.Environ(), "NMAPDIR="+tools.NmapDir)
		}
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		return stdout.Bytes(), fmt.Errorf("command '%s %s' failed: %w (stderr: %s)",
			name, strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return stdout.Bytes(), nil
}

// Scanner exposes the hybrid engine to the scheduler and storage layers.
type Scanner struct {
	cfg        *config.Config
	runner     CommandRunner
	caps       *model.Capabilities
	neighbors  NeighborSource
	mu         sync.RWMutex
	excludeIPs []string
	scanPorts  string
}

// New creates a new Scanner instance with the default command runner.
func New(cfg *config.Config, caps ...*model.Capabilities) *Scanner {
	var c *model.Capabilities
	if len(caps) > 0 {
		c = caps[0]
	}
	s := &Scanner{
		cfg:       cfg,
		runner:    &DefaultCommandRunner{},
		caps:      c,
		neighbors: ReadNeighborTable,
	}
	if cfg != nil && cfg.ScanPorts != "" {
		s.scanPorts = cfg.ScanPorts
	}
	return s
}

// NewWithRunner creates a Scanner with a custom CommandRunner (for unit tests).
func NewWithRunner(cfg *config.Config, runner CommandRunner, caps ...*model.Capabilities) *Scanner {
	var c *model.Capabilities
	if len(caps) > 0 {
		c = caps[0]
	}
	s := &Scanner{
		cfg:    cfg,
		runner: runner,
		caps:   c,
	}
	if cfg != nil && cfg.ScanPorts != "" {
		s.scanPorts = cfg.ScanPorts
	}
	return s
}

// SetNeighborSource sets where the engine reads recently resolved link-layer neighbors from.
// A nil source turns the ARP table merge off.
func (s *Scanner) SetNeighborSource(src NeighborSource) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.neighbors = src
}

// SetCapabilities updates the capability profile for the scanner.
func (s *Scanner) SetCapabilities(caps *model.Capabilities) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.caps = caps
}

// Capabilities returns the active capability profile.
func (s *Scanner) Capabilities() *model.Capabilities {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.caps
}

// SetExcludeIPs updates the list of host IP addresses excluded from scanning.
func (s *Scanner) SetExcludeIPs(ips ...string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var clean []string
	for _, ip := range ips {
		ip = strings.TrimSpace(ip)
		if ip != "" {
			clean = append(clean, ip)
		}
	}
	s.excludeIPs = clean
}

// SetScanPorts updates the port scope used by vulnerability audits.
func (s *Scanner) SetScanPorts(ports string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.scanPorts = strings.TrimSpace(ports)
}

func (s *Scanner) excludedIPs() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]string(nil), s.excludeIPs...)
}

// ExcludedIPs returns the addresses that must never be reported as discovered devices.
func (s *Scanner) ExcludedIPs() []string {
	return s.excludedIPs()
}

func (s *Scanner) neighborSource() NeighborSource {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.neighbors
}

func (s *Scanner) nmapBinary() string {
	s.mu.RLock()
	if s.caps != nil && s.caps.NmapPath != "" && s.caps.NmapPath != "nmap" {
		p := s.caps.NmapPath
		s.mu.RUnlock()
		return p
	}
	s.mu.RUnlock()
	if s.cfg != nil && s.cfg.NmapPath != "" {
		return ResolveNmapBinary(s.cfg.NmapPath)
	}
	return ResolveNmapBinary("nmap")
}

func (s *Scanner) usePrivilegedFlag() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.caps != nil && s.caps.EffectiveMode == "privileged"
}

// CanScan reports whether the scanner has the privileged raw-socket access required to
// run scans. There is deliberately no unprivileged fallback: when this is false the
// scheduler skips scans and the UI must ask the user to grant administrator/root rights.
func (s *Scanner) CanScan() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.caps != nil && s.caps.RawSocket && s.caps.EffectiveMode == "privileged"
}

func (s *Scanner) portSpec() string {
	s.mu.RLock()
	if s.scanPorts != "" {
		ports := s.scanPorts
		s.mu.RUnlock()
		return ports
	}
	s.mu.RUnlock()
	if s.cfg != nil {
		return strings.TrimSpace(s.cfg.ScanPorts)
	}
	return ""
}

func (s *Scanner) vulnScript() string {
	if s.cfg != nil && s.cfg.VulnScript != "" {
		return s.cfg.VulnScript
	}
	return "vulners"
}

// RunDiscoveryScan discovers live hosts on a CIDR or single address using the hybrid engine.
// Reverse DNS is enabled so live hosts report their local DNS/router hostnames.
func (s *Scanner) RunDiscoveryScan(ctx context.Context, target string) ([]model.Device, error) {
	if strings.HasPrefix(target, "-") {
		return nil, fmt.Errorf("invalid discovery target %q: target must not begin with '-'", target)
	}
	if _, err := netip.ParsePrefix(target); err != nil {
		if _, err := netip.ParseAddr(target); err != nil {
			return nil, fmt.Errorf("invalid discovery target %q: must be a valid CIDR prefix or IP address", target)
		}
	}

	var subnet *net.IPNet
	if _, parsed, err := net.ParseCIDR(target); err == nil {
		subnet = parsed
	}

	engine := NewHybridEngine(s.runner)
	engine.SetNeighborSource(s.neighborSource())
	return engine.Discover(ctx, EngineOptions{
		Target:     target,
		Subnet:     subnet,
		ExcludeIPs: s.excludedIPs(),
		NmapBinary: s.nmapBinary(),
		Privileged: s.usePrivilegedFlag(),
	})
}

// ProbeKnownDevices runs the lightweight liveness check used between full sweeps. It only
// touches the supplied addresses and never probes the rest of the subnet.
func (s *Scanner) ProbeKnownDevices(ctx context.Context, targets []string) []model.Device {
	return ProbeHosts(ctx, targets, s.neighborSource())
}

// RunVulnerabilityScan audits explicit target IPs through the same hybrid engine used by
// discovery: L2 mapping, port discovery, then targeted service/vulnerability scripts.
func (s *Scanner) RunVulnerabilityScan(ctx context.Context, targets []string) ([]model.ScanHostResult, error) {
	if len(targets) == 0 {
		return nil, nil
	}

	var subnet *net.IPNet
	if s.cfg != nil {
		if _, parsed, err := net.ParseCIDR(s.cfg.NetworkCIDR); err == nil {
			subnet = parsed
		}
	}

	engine := NewHybridEngine(s.runner)
	engine.SetNeighborSource(s.neighborSource())
	return engine.Audit(ctx, targets, EngineOptions{
		Subnet:     subnet,
		ExcludeIPs: s.excludedIPs(),
		NmapBinary: s.nmapBinary(),
		RustBinary: platform.ResolveRustScan(),
		VulnScript: s.vulnScript(),
		Ports:      s.portSpec(),
		Privileged: s.usePrivilegedFlag(),
	})
}

func isCompleteNmapOutput(output []byte) bool {
	return bytes.Contains(output, []byte("<runstats>")) && bytes.Contains(output, []byte("exit=\"success\""))
}

// DescribeScanError turns a scan failure into a message for the scan history. A scan cut
// short by shutdown or by its time limit says so, instead of showing the raw "signal:
// killed" error of the stopped nmap process.
func DescribeScanError(ctx context.Context, err error) string {
	switch {
	case errors.Is(ctx.Err(), context.Canceled):
		return "scan interrupted: Cerberus Sentinel stopped before the scan finished"
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		return "scan timed out before it finished"
	case err == nil:
		return ""
	default:
		return err.Error()
	}
}
