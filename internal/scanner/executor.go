package scanner

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/gr0gu/cerberus/internal/config"
	"github.com/gr0gu/cerberus/internal/model"
	"github.com/gr0gu/cerberus/internal/platform"
)

// CommandRunner defines an interface for running external shell commands (enabling mocking).
type CommandRunner interface {
	Run(ctx context.Context, name string, args ...string) ([]byte, error)
}

// DefaultCommandRunner executes commands via os/exec.
type DefaultCommandRunner struct{}

// Run executes the command with context and returns stdout.
func (r *DefaultCommandRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	configureProcessGroup(cmd)
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

// Scanner orchestrates Nmap discovery and vulnerability audits.
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

// SetNeighborSource sets where discovery reads recently resolved link-layer neighbors from.
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

// SetScanPorts updates the port range scanned during vulnerability audits.
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

func (s *Scanner) getExcludeArgs() []string {
	if excluded := s.excludedIPs(); len(excluded) > 0 {
		return []string{"--exclude", strings.Join(excluded, ",")}
	}
	return nil
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

func isCompleteNmapOutput(output []byte) bool {
	return bytes.Contains(output, []byte("<runstats>")) && bytes.Contains(output, []byte("exit=\"success\""))
}

// RunDiscoveryScan executes an Nmap host discovery scan against target CIDR.
// Note: reverse DNS resolution is enabled (no -n flag) so live hosts report their local DNS/router hostnames.
func (s *Scanner) RunDiscoveryScan(ctx context.Context, target string) ([]model.Device, error) {
	if strings.HasPrefix(target, "-") {
		return nil, fmt.Errorf("invalid discovery target %q: target must not begin with '-'", target)
	}
	if _, err := netip.ParsePrefix(target); err != nil {
		if _, err := netip.ParseAddr(target); err != nil {
			return nil, fmt.Errorf("invalid discovery target %q: must be a valid CIDR prefix or IP address", target)
		}
	}

	// Proactively prod subnet with Stage 1 L2 sweep to wake sleeping devices and refresh ARP cache
	if _, ipNet, err := net.ParseCIDR(target); err == nil && ipNet != nil {
		s1Ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
		_, _ = Stage1ARPSweep(s1Ctx, ipNet, s.excludedIPs())
		cancel()
	}

	// Most addresses in a LAN sweep are unused, and an unprivileged TCP ping waits for each
	// probe to time out. A LAN answers in well under 500 ms, so the RTT cap, one retry and a
	// higher minimum parallelism cut a /24 sweep from about 2.5 minutes to about 35 seconds.
	// Hosts that miss the TCP probes are still found through the ARP table merge below.
	args := []string{
		"-sn",
		"-T4",
		"--max-retries", "1",
		"--max-rtt-timeout", "500ms",
		"--min-parallelism", "64",
		"--host-timeout", "30s",
		"-oX", "-",
	}

	if s.usePrivilegedFlag() {
		args = append(args, "--privileged")
	}

	args = append(args, s.getExcludeArgs()...)
	args = append(args, target)

	output, err := s.runner.Run(ctx, s.nmapBinary(), args...)
	if err != nil && !isCompleteNmapOutput(output) {
		return nil, fmt.Errorf("discovery scan failed: %w", err)
	}

	run, parseErr := ParseNmapXML(output)
	if parseErr != nil {
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("failed to parse discovery xml: %w", parseErr)
	}

	devices := ExtractDevices(run)
	if entries := s.readNeighbors(ctx); entries != nil {
		devices = mergeNeighbors(devices, entries, target, s.excludedIPs())
	}
	return devices, nil
}

// readNeighbors returns the recently confirmed ARP entries, or nil when none can be read.
func (s *Scanner) readNeighbors(ctx context.Context) []Neighbor {
	s.mu.RLock()
	neighbors := s.neighbors
	s.mu.RUnlock()
	if neighbors == nil {
		return nil
	}
	entries, err := neighbors(ctx)
	if err != nil {
		log.Printf("[Scanner] Could not read the ARP table: %v", err)
		return nil
	}
	return entries
}

// RunVulnerabilityScan executes service detection, cryptographic identity scripts, and vulnerability scripts against target IPs.
func (s *Scanner) RunVulnerabilityScan(ctx context.Context, targets []string) ([]model.ScanHostResult, error) {
	if len(targets) == 0 {
		return nil, nil
	}

	for _, target := range targets {
		if strings.HasPrefix(target, "-") {
			return nil, fmt.Errorf("invalid scan target %q: target must not begin with '-'", target)
		}
		if _, err := netip.ParseAddr(target); err != nil {
			if _, err := netip.ParsePrefix(target); err != nil {
				return nil, fmt.Errorf("invalid scan target %q: must be a valid IP address or CIDR prefix", target)
			}
		}
	}

	vulnScript := s.cfg.VulnScript
	if vulnScript == "" {
		vulnScript = "vulners"
	}
	scriptSpec := vulnScript
	if !strings.Contains(scriptSpec, "ssh-hostkey") {
		scriptSpec += ",ssh-hostkey,ssl-cert"
	}

	// Tri-stage hybrid scanning:
	// Stage 2 (RustScan) discovers open ports asynchronously across all 65,535 TCP ports.
	// Stage 3 (Targeted Nmap) probes ONLY those open ports, eliminating closed-port timeout penalties.
	if rustBin := platform.ResolveRustScan(); rustBin != "" {
		rustCfg := DefaultRustScanConfig()
		rustCfg.Binary = rustBin
		openPortsMap, rErr := Stage2RustScan(ctx, targets, &rustCfg)
		if rErr == nil {
			macMap := make(map[string]string)
			if entries := s.readNeighbors(ctx); entries != nil {
				for _, n := range entries {
					macMap[n.IP] = n.MAC
				}
			}
			var stage3Targets []Stage3Target
			for _, t := range targets {
				stage3Targets = append(stage3Targets, Stage3Target{
					IP:        t,
					MAC:       macMap[t],
					OpenPorts: openPortsMap[t],
				})
			}
			results, auditErr := Stage3NmapAudit(ctx, s.runner, s.nmapBinary(), vulnScript, stage3Targets)
			if auditErr == nil {
				return results, nil
			}
		}
	}

	// nmap drops every result of a host that hits --host-timeout. Phones and routers that
	// silently drop most of the 1000 probed ports need a few minutes over TCP connect, so the
	// limit is generous; the whole scan stays bounded by ScanTimeout.
	args := []string{
		"-sV",
		"--version-intensity", "5",
		"-T4",
		"--max-retries", "2",
		"--host-timeout", "10m",
		"--script", scriptSpec,
		"-oX", "-",
	}

	if s.usePrivilegedFlag() {
		args = append(args, "--privileged")
	}

	// Port specification: use configurable scan ports or default to top 1000 ports
	scanPorts := ""
	s.mu.RLock()
	if s.scanPorts != "" {
		scanPorts = s.scanPorts
	} else if s.cfg != nil {
		scanPorts = strings.TrimSpace(s.cfg.ScanPorts)
	}
	s.mu.RUnlock()

	if scanPorts != "" {
		if strings.HasPrefix(scanPorts, "--top-ports ") {
			args = append(args, "--top-ports", strings.TrimSpace(strings.TrimPrefix(scanPorts, "--top-ports ")))
		} else if strings.HasPrefix(scanPorts, "--top-ports=") {
			args = append(args, "--top-ports", strings.TrimSpace(strings.TrimPrefix(scanPorts, "--top-ports=")))
		} else if strings.HasPrefix(scanPorts, "-p ") {
			args = append(args, "-p", strings.TrimSpace(strings.TrimPrefix(scanPorts, "-p ")))
		} else if strings.HasPrefix(scanPorts, "-p") && len(scanPorts) > 2 && scanPorts[2] != ' ' {
			args = append(args, "-p", strings.TrimSpace(strings.TrimPrefix(scanPorts, "-p")))
		} else {
			args = append(args, "-p", scanPorts)
		}
	} else {
		// Default to top 1000 ports for fast, responsive scanning (covers 93% of open ports)
		args = append(args, "--top-ports", "1000")
	}

	args = append(args, s.getExcludeArgs()...)
	args = append(args, targets...)

	output, err := s.runner.Run(ctx, s.nmapBinary(), args...)
	if err != nil && !isCompleteNmapOutput(output) {
		return nil, fmt.Errorf("vulnerability scan failed: %w", err)
	}

	run, parseErr := ParseNmapXML(output)
	if parseErr != nil {
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("failed to parse vulnerability xml: %w", parseErr)
	}

	results := ExtractHostResults(run)
	// Unprivileged scans cannot read MAC addresses. Without one, the identity matcher cannot
	// tie the result to the device that discovery recorded with its MAC.
	if entries := s.readNeighbors(ctx); entries != nil {
		macs := make(map[string]string, len(entries))
		for _, n := range entries {
			macs[n.IP] = n.MAC
		}
		for i := range results {
			if results[i].MAC == "" {
				results[i].MAC = macs[results[i].IP]
			}
		}
	}
	return results, nil
}

// RunHybridScan executes the complete tri-stage pipeline (L2 ARP sweep -> RustScan -> Targeted Nmap audit)
// with real-time lifecycle event dispatching.
func (s *Scanner) RunHybridScan(ctx context.Context, subnet *net.IPNet, vulnScript string, listener ScanEventListener) ([]model.ScanHostResult, error) {
	engine := NewHybridEngine(s.runner)
	return engine.RunHybridScan(ctx, EngineOptions{
		Subnet:     subnet,
		ExcludeIPs: s.excludedIPs(),
		NmapBinary: s.nmapBinary(),
		RustBinary: platform.ResolveRustScan(),
		VulnScript: vulnScript,
		Listener:   listener,
	})
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
